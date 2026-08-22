from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sqlite3
from typing import Any

import pytest

from gvr import (
    AuditObservation,
    EvidenceCompleteness,
    EvidenceCoverage,
    SQLiteStorage,
    VerificationExecutionError,
    execute_verification_plan,
)
from gvr.sqlite_storage import SQLiteUnitOfWork

from test_durable_storage_task_23 import (
    _Acquisition,
    _execution_request,
)


CLAIM_ID = "claim-task23"


@dataclass(frozen=True)
class _DurableRun:
    result: Any
    bundle: Any
    claim: Any
    session: Any
    falsification_result: Any | None
    falsification_record: Any | None


def _request(
    prefix: str,
    *,
    order: tuple[int, int] = (0, 1),
    with_falsification: bool = False,
) -> Any:
    acquisitions = (
        _Acquisition("request-1", f"repo-{prefix}-1", "field-1", "revision-1"),
        _Acquisition("request-2", f"repo-{prefix}-2", "field-2", "revision-2"),
    )
    return _execution_request(
        tuple(acquisitions[index] for index in order),
        with_falsification=with_falsification,
    )


def _execute(db: SQLiteStorage, request: Any) -> _DurableRun:
    result = execute_verification_plan(request, storage=db)
    domain_bundle = next(iter(result.bundles.values()))
    bundle = db.get_bundle(domain_bundle.fingerprint)
    claim = db.claim_history(CLAIM_ID)[-1]
    session = db.get_session(result.session.fingerprint)
    falsification_result = next(iter(result.falsification_results.values()), None)
    falsification_record = (
        None
        if falsification_result is None
        else db.get_falsification_result(falsification_result.fingerprint)
    )
    return _DurableRun(
        result=result,
        bundle=bundle,
        claim=claim,
        session=session,
        falsification_result=falsification_result,
        falsification_record=falsification_record,
    )


def _table_counts(path: Path) -> dict[str, int]:
    connection = sqlite3.connect(path)
    try:
        return {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "evidence_artifacts",
                "evidence_slots",
                "evidence_slot_versions",
                "bundle_records",
                "falsification_records",
                "claim_versions",
                "session_records",
                "session_execution_observations",
                "invalidation_events",
            )
        }
    finally:
        connection.close()


def _tamper(path: Path, sql: str, parameters: tuple[Any, ...]) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(sql, parameters)
        connection.commit()
    finally:
        connection.close()


def test_task24_01_reopen_replay_substitutes_the_exact_a_record_after_b(
    tmp_path: Path,
) -> None:
    path = tmp_path / "task24-a-b-a.sqlite3"
    db = SQLiteStorage(path)
    first = _execute(db, _request("a"))
    second = _execute(db, _request("b"))
    assert first.result.session.fingerprint == second.result.session.fingerprint
    assert first.bundle.fingerprint == second.bundle.fingerprint
    assert first.bundle.record_fingerprint != second.bundle.record_fingerprint

    replayed = _execute(SQLiteStorage(path), _request("a", order=(1, 0)))

    assert replayed.result.fingerprint == first.result.fingerprint
    assert replayed.bundle.record_fingerprint == first.bundle.record_fingerprint
    assert replayed.claim.bundle_record_fingerprint == first.bundle.record_fingerprint
    assert replayed.claim.evidence_dependencies == first.claim.evidence_dependencies
    assert replayed.session.bundle_record_fingerprints == (
        first.bundle.record_fingerprint,
    )
    assert replayed.session.current


def test_task24_02_reverse_and_request_order_permutations_are_exactly_invariant(
    tmp_path: Path,
) -> None:
    permutations = (
        ("a", "b", (0, 1), (0, 1), (0, 1)),
        ("a", "b", (1, 0), (0, 1), (1, 0)),
        ("b", "a", (0, 1), (1, 0), (0, 1)),
        ("b", "a", (1, 0), (1, 0), (1, 0)),
    )
    for index, (first_prefix, second_prefix, first_order, second_order, replay_order) in enumerate(
        permutations
    ):
        path = tmp_path / f"task24-order-{index}.sqlite3"
        db = SQLiteStorage(path)
        first = _execute(db, _request(first_prefix, order=first_order))
        _execute(db, _request(second_prefix, order=second_order))
        replayed = _execute(
            SQLiteStorage(path),
            _request(first_prefix, order=replay_order),
        )
        assert replayed.result.fingerprint == first.result.fingerprint
        assert replayed.bundle.record_fingerprint == first.bundle.record_fingerprint
        assert replayed.claim.bundle_record_fingerprint == first.bundle.record_fingerprint
        assert replayed.claim.evidence_dependencies == first.claim.evidence_dependencies
        assert replayed.session.bundle_record_fingerprints == (
            first.bundle.record_fingerprint,
        )


def test_task24_03_exact_falsification_record_threads_through_claim_and_session(
    tmp_path: Path,
) -> None:
    path = tmp_path / "task24-falsification-threading.sqlite3"
    db = SQLiteStorage(path)
    first = _execute(db, _request("a", with_falsification=True))
    second = _execute(db, _request("b", with_falsification=True))
    assert first.falsification_result is not None
    assert first.falsification_record is not None

    competing_record = db.put_falsification_result(
        first.falsification_result,
        evidence_dependencies=second.bundle.evidence_dependencies,
    )
    assert competing_record.record_fingerprint != first.falsification_record.record_fingerprint
    assert competing_record.current
    assert first.falsification_record.current

    replayed = _execute(
        SQLiteStorage(path),
        _request("a", order=(1, 0), with_falsification=True),
    )

    assert replayed.claim.bundle_record_fingerprint == first.bundle.record_fingerprint
    assert replayed.claim.falsification_record_fingerprints == (
        first.falsification_record.record_fingerprint,
    )
    assert replayed.session.bundle_record_fingerprints == (
        first.bundle.record_fingerprint,
    )
    assert replayed.session.falsification_record_fingerprints == (
        first.falsification_record.record_fingerprint,
    )
    assert replayed.session.current


def test_task24_04_semantic_identifier_names_are_valid_and_audit_is_explicitly_nonsemantic() -> None:
    def coverage(
        *,
        run_id: str,
        trace_id: str,
        execution_id: str,
        request_count: int,
        audit_run_id: str,
    ) -> EvidenceCoverage:
        return EvidenceCoverage(
            completeness=EvidenceCompleteness.COMPLETE,
            covered_evidence_kinds=("fixture.state",),
            declared_scope={"run_id": run_id},
            observed_scope={"trace_id": trace_id},
            declared_bounds={"execution_id": execution_id},
            consumed={"request_count": request_count},
            termination={"reason": "COMPLETE"},
            termination_reason="COMPLETE",
            source_identity={"repository": "semantic-repository"},
            snapshot_identity={"revision": "semantic-revision"},
            audit=AuditObservation(metadata={"run_id": audit_run_id}),
        )

    first = coverage(
        run_id="semantic-run-a",
        trace_id="semantic-trace-a",
        execution_id="semantic-execution-a",
        request_count=1,
        audit_run_id="audit-run-a",
    )
    reordered_audit = coverage(
        run_id="semantic-run-a",
        trace_id="semantic-trace-a",
        execution_id="semantic-execution-a",
        request_count=1,
        audit_run_id="audit-run-b",
    )
    semantic_change = coverage(
        run_id="semantic-run-b",
        trace_id="semantic-trace-b",
        execution_id="semantic-execution-b",
        request_count=2,
        audit_run_id="audit-run-a",
    )

    assert first.fingerprint == reordered_audit.fingerprint
    assert first.audit.fingerprint != reordered_audit.audit.fingerprint
    assert first.fingerprint != semantic_change.fingerprint
    assert first.semantic_transport()["declared_scope"]["run_id"] == "semantic-run-a"
    assert "audit" not in first.semantic_transport()


def test_task24_05_exact_record_mismatch_fails_closed_and_rolls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "task24-mismatch-rollback.sqlite3"
    db = SQLiteStorage(path)
    first = _execute(db, _request("a"))
    second = _execute(db, _request("b"))
    before = _table_counts(path)
    original = SQLiteUnitOfWork.put_bundle

    def substitute_wrong_exact_record(
        unit_of_work: SQLiteUnitOfWork,
        bundle: Any,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        written = original(unit_of_work, bundle, *args, **kwargs)
        if kwargs.get("evidence_dependencies") is not None:
            return unit_of_work.get_bundle(
                bundle.fingerprint,
                record_fingerprint=second.bundle.record_fingerprint,
            )
        return written

    monkeypatch.setattr(
        SQLiteUnitOfWork,
        "put_bundle",
        substitute_wrong_exact_record,
    )
    with pytest.raises(VerificationExecutionError, match="failed closed"):
        execute_verification_plan(
            _request("a", order=(1, 0)),
            storage=SQLiteStorage(path),
        )

    reopened = SQLiteStorage(path)
    assert _table_counts(path) == before
    assert reopened.claim_history(CLAIM_ID)[-1].bundle_record_fingerprint == (
        second.bundle.record_fingerprint
    )
    assert reopened.get_bundle(
        first.bundle.fingerprint,
        record_fingerprint=first.bundle.record_fingerprint,
    ).evidence_dependencies == first.bundle.evidence_dependencies


def test_task24_06_exact_record_corruption_fails_closed_and_rolls_back(
    tmp_path: Path,
) -> None:
    for corruption in ("bundle", "falsification", "session"):
        path = tmp_path / f"task24-corrupt-{corruption}.sqlite3"
        db = SQLiteStorage(path)
        first = _execute(db, _request("a", with_falsification=True))
        assert first.falsification_record is not None
        before = _table_counts(path)

        if corruption == "bundle":
            _tamper(
                path,
                """
                UPDATE bundle_record_evidence_links
                SET evidence_fingerprint = ?
                WHERE record_fingerprint = ? AND ordinal = 0
                """,
                ("0" * 64, first.bundle.record_fingerprint),
            )
        elif corruption == "falsification":
            _tamper(
                path,
                """
                UPDATE falsification_record_evidence_links
                SET evidence_fingerprint = ?
                WHERE record_fingerprint = ? AND ordinal = 0
                """,
                ("0" * 64, first.falsification_record.record_fingerprint),
            )
        else:
            _tamper(
                path,
                """
                UPDATE session_record_bundle_links
                SET bundle_record_fingerprint = ?
                WHERE record_fingerprint = ? AND ordinal = 0
                """,
                ("0" * 64, first.session.record_fingerprint),
            )

        with pytest.raises(VerificationExecutionError, match="failed closed"):
            execute_verification_plan(
                _request("a", order=(1, 0), with_falsification=True),
                storage=SQLiteStorage(path),
            )
        assert _table_counts(path) == before
