from __future__ import annotations

from pathlib import Path
import sqlite3
from typing import Any

import pytest

from gvr import (
    AtomicClaim,
    AtomicClaimBinding,
    ClaimGraph,
    Evidence,
    EvidenceAcquisitionStatus,
    EvidenceCompleteness,
    EvidenceCoverage,
    EvidenceProviderCapability,
    EvidenceProviderCapabilityRegistry,
    EvidenceProviderResult,
    EvidenceProviderRuntimeRegistry,
    EvidenceRequest,
    SQLiteStorage,
    StorageIntegrityError,
    VerificationExecutionLimits,
    VerificationExecutionRequest,
    VerificationPlanningRequest,
    VerificationReport,
    VerificationVerdict,
    VerifierCapability,
    VerifierCapabilityRegistry,
    VerifierCost,
    VerifierDeterminism,
    VerifierRuntimeRegistry,
    compile_verification_plan,
    execute_verification_plan,
)

from test_durable_storage_task_24 import (
    _execute as _execute_task24,
    _request as _request_task24,
)


PROVIDER_ID = "fixture.task25.provider"
VERIFIER_ID = "fixture.task25.verifier"
EVIDENCE_ID = "task25-shared-evidence"


class _ProviderRuntime:
    def __init__(
        self,
        capability: EvidenceProviderCapability,
        values: dict[str, str],
    ) -> None:
        self.provider_id = capability.provider_id
        self.version = capability.version
        self.capability = capability
        self.values = values

    def acquire(self, request: EvidenceRequest) -> EvidenceProviderResult:
        evidence = Evidence(
            id=EVIDENCE_ID,
            kind="fixture.state",
            payload={"value": self.values[request.request_id]},
            source="task25-provider",
            fingerprint="task25-producer-fingerprint",
        )
        return EvidenceProviderResult(
            request_id=request.request_id,
            request_fingerprint=request.fingerprint,
            provider_id=request.provider_id,
            provider_version=request.provider_version,
            status=EvidenceAcquisitionStatus.COMPLETE,
            coverage=EvidenceCoverage(
                completeness=EvidenceCompleteness.COMPLETE,
                covered_evidence_kinds=request.requested_evidence_kinds,
                declared_scope=request.semantic_scope,
                observed_scope=request.semantic_scope,
                declared_bounds=request.bounds,
                consumed={"records": 1},
                termination={"reason": "COMPLETE"},
                termination_reason="COMPLETE",
                source_identity=request.source_context,
                snapshot_identity=request.snapshot_context,
            ),
            evidence=(evidence,),
            capability_fingerprint=self.capability.fingerprint,
            evidence_slot_identities=(
                request.evidence_slot_identity(
                    evidence.id,
                    source_identity=request.source_context,
                ),
            ),
        )


class _VerifierRuntime:
    def __init__(self, capability: VerifierCapability) -> None:
        self.verifier_id = capability.verifier_id
        self.version = capability.version
        self.capability = capability

    def verify(self, verifier_input: Any) -> VerificationReport:
        assert len(verifier_input.acquisitions) == 1
        assert tuple(item.id for item in verifier_input.evidence) == (EVIDENCE_ID,)
        return VerificationReport(
            verdict=VerificationVerdict.PASS,
            verifier=self.verifier_id,
            evidence_ids=(EVIDENCE_ID,),
        )


def _request(
    *,
    claim_order: tuple[str, ...] = ("A", "B"),
    roots: tuple[str, ...] | None = None,
    repositories: dict[str, str] | None = None,
    snapshots: dict[str, str] | None = None,
    values: dict[str, str] | None = None,
) -> VerificationExecutionRequest:
    repository_values = {
        claim_id: f"repo-{claim_id}"
        for claim_id in claim_order
    }
    repository_values.update(repositories or {})
    snapshot_values = {
        claim_id: "same-revision"
        for claim_id in claim_order
    }
    snapshot_values.update(snapshots or {})
    evidence_values = {
        f"request-{claim_id}": "same-domain-content"
        for claim_id in claim_order
    }
    evidence_values.update(values or {})
    verifier_capability = VerifierCapability(
        verifier_id=VERIFIER_ID,
        version="1",
        claim_kinds=("ASSERT_STATE",),
        accepted_evidence_kinds=("fixture.state",),
        required_evidence_kinds=("fixture.state",),
        input_schema={"type": "object"},
        output_schema={"type": "gvr.VerificationReport"},
        determinism=VerifierDeterminism.D1,
        side_effect_free=True,
        cost=VerifierCost.LOW,
        bounds={"max_items": 10},
        coverage={"mode": "DECLARED_SCOPE"},
        authoritative=True,
    )
    provider_capability = EvidenceProviderCapability(
        provider_id=PROVIDER_ID,
        version="1",
        request_kinds=("CAPTURE_STATE",),
        produced_evidence_kinds=("fixture.state",),
        source_classes=("repository",),
        snapshot_classes=("revision",),
        input_schema={"type": "object"},
        output_schema={"type": "gvr.EvidenceProviderResult"},
        determinism=VerifierDeterminism.O1,
        side_effect_free=True,
        cost=VerifierCost.EXTERNAL,
        bounds={"max_items": 10},
        coverage={"mode": "DECLARED_SCOPE"},
    )
    claims = {
        claim_id: AtomicClaim(
            claim_id=claim_id,
            claim_kind="ASSERT_STATE",
            spec={"claim": claim_id, "expected": True},
            verifier=VERIFIER_ID,
        )
        for claim_id in ("A", "B")
    }
    graph = ClaimGraph(nodes=tuple(claims[item] for item in claim_order))
    requests = {
        claim_id: EvidenceRequest(
            request_id=f"request-{claim_id}",
            provider_id=PROVIDER_ID,
            provider_version="1",
            request_kind="CAPTURE_STATE",
            requested_evidence_kinds=("fixture.state",),
            subject={"entity": "shared-subject"},
            spec={"field": "ready"},
            semantic_scope={"repository": repository_values[claim_id]},
            source_context={"repository": repository_values[claim_id]},
            snapshot_context={"revision": snapshot_values[claim_id]},
            bounds={"max_items": 10},
            source_class="repository",
            snapshot_class="revision",
        )
        for claim_id in claim_order
    }
    verifier_capabilities = VerifierCapabilityRegistry((verifier_capability,))
    provider_capabilities = EvidenceProviderCapabilityRegistry((provider_capability,))
    bindings = tuple(
        AtomicClaimBinding(
            claim_id=claim_id,
            verifier_id=VERIFIER_ID,
            verifier_version="1",
            verifier_capability_fingerprint=verifier_capability.fingerprint,
            evidence_requests=(requests[claim_id],),
        )
        for claim_id in claim_order
    )
    planning_request = VerificationPlanningRequest(
        claim_graph=graph,
        bindings=bindings,
        verifier_capability_registry=verifier_capabilities,
        verifier_capability_registry_fingerprint=verifier_capabilities.fingerprint,
        evidence_provider_capability_registry=provider_capabilities,
        evidence_provider_capability_registry_fingerprint=provider_capabilities.fingerprint,
    )
    plan = compile_verification_plan(planning_request)
    return VerificationExecutionRequest(
        plan=plan,
        plan_fingerprint=plan.fingerprint,
        claim_graph=graph,
        claim_graph_fingerprint=graph.fingerprint,
        roots=claim_order if roots is None else roots,
        verifier_runtime_registry=VerifierRuntimeRegistry(
            capability_registry=verifier_capabilities,
            runtime_verifiers={
                (VERIFIER_ID, "1"): _VerifierRuntime(verifier_capability),
            },
        ),
        verifier_capability_registry_fingerprint=verifier_capabilities.fingerprint,
        evidence_provider_runtime_registry=EvidenceProviderRuntimeRegistry(
            capability_registry=provider_capabilities,
            runtime_providers={
                (PROVIDER_ID, "1"): _ProviderRuntime(
                    provider_capability,
                    evidence_values,
                ),
            },
        ),
        evidence_provider_capability_registry_fingerprint=provider_capabilities.fingerprint,
        evidence_requests={
            (item.request_id, item.fingerprint): item
            for item in requests.values()
        },
        limits=VerificationExecutionLimits(),
    )


def _table_counts(path: Path) -> dict[str, int]:
    connection = sqlite3.connect(path)
    try:
        return {
            table: connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in (
                "bundle_records",
                "claim_versions",
                "session_records",
                "session_record_bundle_links",
                "session_execution_observations",
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


def _exact_claim_bundles(
    db: SQLiteStorage,
) -> tuple[Any, Any, Any, Any]:
    claim_a = db.claim_history("A")[-1]
    claim_b = db.claim_history("B")[-1]
    assert claim_a.bundle_fingerprint is not None
    assert claim_b.bundle_fingerprint is not None
    assert claim_a.bundle_record_fingerprint is not None
    assert claim_b.bundle_record_fingerprint is not None
    bundle_a = db.get_bundle(
        claim_a.bundle_fingerprint,
        record_fingerprint=claim_a.bundle_record_fingerprint,
    )
    bundle_b = db.get_bundle(
        claim_b.bundle_fingerprint,
        record_fingerprint=claim_b.bundle_record_fingerprint,
    )
    return claim_a, claim_b, bundle_a, bundle_b


def _competing_bundle_record(db: SQLiteStorage, bundle: Any, slot_id: str) -> Any:
    evidence = bundle.bundle.evidence[0]
    db.put_evidence(evidence, slot_id=slot_id)
    slot = db.get_slot(slot_id)
    assert slot is not None
    return db.put_bundle(
        bundle.bundle,
        evidence_slots={evidence.id: slot},
    )


def test_task25_01_real_execution_allows_same_domain_bundle_multiplicity(
    tmp_path: Path,
) -> None:
    db = SQLiteStorage(tmp_path / "task25-core.sqlite3")

    result = execute_verification_plan(_request(), storage=db)

    assert result.bundles["A"].fingerprint == result.bundles["B"].fingerprint
    claim_a = db.claim_history("A")[-1]
    claim_b = db.claim_history("B")[-1]
    assert claim_a.bundle_record_fingerprint is not None
    assert claim_b.bundle_record_fingerprint is not None
    assert claim_a.bundle_record_fingerprint != claim_b.bundle_record_fingerprint
    assert claim_a.evidence_dependencies[0].slot is not None
    assert claim_b.evidence_dependencies[0].slot is not None
    assert (
        claim_a.evidence_dependencies[0].slot.slot_id
        != claim_b.evidence_dependencies[0].slot.slot_id
    )
    session = db.get_session(result.session.fingerprint)
    assert session.bundle_fingerprints == (
        result.bundles["A"].fingerprint,
        result.bundles["B"].fingerprint,
    )
    assert session.bundle_record_fingerprints == tuple(sorted((
        claim_a.bundle_record_fingerprint,
        claim_b.bundle_record_fingerprint,
    )))
    assert session.current


def test_task25_02_claim_reorder_preserves_exact_session_identity(
    tmp_path: Path,
) -> None:
    path = tmp_path / "task25-reorder.sqlite3"
    first = execute_verification_plan(_request(), storage=SQLiteStorage(path))
    first_session = SQLiteStorage(path).get_session(first.session.fingerprint)

    replayed = execute_verification_plan(
        _request(claim_order=("B", "A"), roots=("B", "A")),
        storage=SQLiteStorage(path),
    )
    replayed_session = SQLiteStorage(path).get_session(
        replayed.session.fingerprint
    )

    assert replayed.session.fingerprint == first.session.fingerprint
    assert replayed.fingerprint == first.fingerprint
    assert replayed_session.record_fingerprint == first_session.record_fingerprint
    assert (
        replayed_session.bundle_record_fingerprints
        == first_session.bundle_record_fingerprints
    )


def test_task25_03_reopen_reads_both_same_domain_exact_records(
    tmp_path: Path,
) -> None:
    path = tmp_path / "task25-reopen.sqlite3"
    result = execute_verification_plan(_request(), storage=SQLiteStorage(path))
    del result

    reopened = SQLiteStorage(path)
    history = reopened.session_history()

    assert len(history) == 1
    assert len(history[0].bundle_record_fingerprints) == 2
    assert len(set(history[0].bundle_fingerprints)) == 1
    assert history[0].current


def test_task25_04_replay_is_idempotent_for_exact_records_and_observation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "task25-idempotent.sqlite3"
    first = execute_verification_plan(_request(), storage=SQLiteStorage(path))
    before = _table_counts(path)

    second = execute_verification_plan(_request(), storage=SQLiteStorage(path))

    assert second.fingerprint == first.fingerprint
    assert _table_counts(path) == before
    assert len(SQLiteStorage(path).claim_history("A")) == 1
    assert len(SQLiteStorage(path).claim_history("B")) == 1


def test_task25_05_advancing_only_a_invalidates_only_a_exact_bundle(
    tmp_path: Path,
) -> None:
    path = tmp_path / "task25-a-only.sqlite3"
    db = SQLiteStorage(path)
    result = execute_verification_plan(_request(), storage=db)
    _, _, bundle_a, bundle_b = _exact_claim_bundles(db)
    original_session = db.get_session(result.session.fingerprint)

    execute_verification_plan(
        _request(
            claim_order=("A",),
            snapshots={"A": "revision-2"},
            values={"request-A": "changed-a-content"},
        ),
        storage=db,
    )

    assert not db.get_bundle(
        bundle_a.fingerprint,
        record_fingerprint=bundle_a.record_fingerprint,
    ).current
    assert db.get_bundle(
        bundle_b.fingerprint,
        record_fingerprint=bundle_b.record_fingerprint,
    ).current
    assert not db.get_session(
        original_session.fingerprint,
        record_fingerprint=original_session.record_fingerprint,
    ).current


def test_task25_06_advancing_only_b_invalidates_only_b_exact_bundle(
    tmp_path: Path,
) -> None:
    path = tmp_path / "task25-b-only.sqlite3"
    db = SQLiteStorage(path)
    result = execute_verification_plan(_request(), storage=db)
    _, _, bundle_a, bundle_b = _exact_claim_bundles(db)
    original_session = db.get_session(result.session.fingerprint)

    execute_verification_plan(
        _request(
            claim_order=("B",),
            snapshots={"B": "revision-2"},
            values={"request-B": "changed-b-content"},
        ),
        storage=db,
    )

    assert db.get_bundle(
        bundle_a.fingerprint,
        record_fingerprint=bundle_a.record_fingerprint,
    ).current
    assert not db.get_bundle(
        bundle_b.fingerprint,
        record_fingerprint=bundle_b.record_fingerprint,
    ).current
    assert not db.get_session(
        original_session.fingerprint,
        record_fingerprint=original_session.record_fingerprint,
    ).current


def test_task25_07_same_exact_record_is_deduplicated_by_record_fingerprint(
    tmp_path: Path,
) -> None:
    db = SQLiteStorage(tmp_path / "task25-same-exact.sqlite3")
    result = execute_verification_plan(
        _request(repositories={"A": "shared", "B": "shared"}),
        storage=db,
    )

    claim_a, claim_b, _, _ = _exact_claim_bundles(db)
    session = db.get_session(result.session.fingerprint)

    assert (
        claim_a.bundle_record_fingerprint
        == claim_b.bundle_record_fingerprint
    )
    assert session.bundle_record_fingerprints == (
        claim_a.bundle_record_fingerprint,
    )
    assert session.bundle_fingerprints == (result.bundles["A"].fingerprint,)


def test_task25_08_wrong_exact_bundle_substitution_rolls_back(
    tmp_path: Path,
) -> None:
    path = tmp_path / "task25-wrong-substitution.sqlite3"
    db = SQLiteStorage(path)
    result = execute_verification_plan(_request(), storage=db)
    claim_a, claim_b, bundle_a, bundle_b = _exact_claim_bundles(db)
    competing = _competing_bundle_record(
        db,
        bundle_a,
        "task25:wrong-substitution",
    )
    wrong_records = tuple(sorted(
        (competing, bundle_b),
        key=lambda item: item.record_fingerprint or "",
    ))
    before = _table_counts(path)

    with pytest.raises(
        StorageIntegrityError,
        match="must match the exact claim records",
    ):
        db.put_session(
            result.session,
            claim_records=(claim_a, claim_b),
            bundle_records=wrong_records,
        )

    assert _table_counts(path) == before


def test_task25_09_missing_exact_session_link_fails_closed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "task25-missing-link.sqlite3"
    db = SQLiteStorage(path)
    result = execute_verification_plan(_request(), storage=db)
    session = db.get_session(result.session.fingerprint)
    assert session.record_fingerprint is not None
    removed = session.bundle_record_fingerprints[0]
    _tamper(
        path,
        """
        DELETE FROM session_record_bundle_links
        WHERE record_fingerprint = ? AND bundle_record_fingerprint = ?
        """,
        (session.record_fingerprint, removed),
    )

    with pytest.raises(StorageIntegrityError):
        SQLiteStorage(path).get_session(
            session.fingerprint,
            record_fingerprint=session.record_fingerprint,
        )


def test_task25_10_corrupt_same_domain_link_substitution_fails_closed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "task25-corrupt-link.sqlite3"
    db = SQLiteStorage(path)
    result = execute_verification_plan(_request(), storage=db)
    _, _, bundle_a, _ = _exact_claim_bundles(db)
    session = db.get_session(result.session.fingerprint)
    assert session.record_fingerprint is not None
    assert bundle_a.record_fingerprint is not None
    competing = _competing_bundle_record(
        db,
        bundle_a,
        "task25:corrupt-substitution",
    )
    assert competing.record_fingerprint is not None
    _tamper(
        path,
        """
        UPDATE session_record_bundle_links
        SET bundle_record_fingerprint = ?
        WHERE record_fingerprint = ? AND bundle_record_fingerprint = ?
        """,
        (
            competing.record_fingerprint,
            session.record_fingerprint,
            bundle_a.record_fingerprint,
        ),
    )

    with pytest.raises(StorageIntegrityError):
        SQLiteStorage(path).get_session(
            session.fingerprint,
            record_fingerprint=session.record_fingerprint,
        )


def test_task25_11_falsification_same_domain_uniqueness_remains_fail_closed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "task25-falsification.sqlite3"
    db = SQLiteStorage(path)
    first = _execute_task24(db, _request_task24("a", with_falsification=True))
    second = _execute_task24(db, _request_task24("b", with_falsification=True))
    assert first.falsification_result is not None
    assert first.falsification_record is not None
    competing = db.put_falsification_result(
        first.falsification_result,
        evidence_dependencies=second.bundle.evidence_dependencies,
    )
    replayed = _execute_task24(
        db,
        _request_task24("a", with_falsification=True),
    )
    assert replayed.falsification_record is not None
    records = tuple(sorted(
        (replayed.falsification_record, competing),
        key=lambda item: (
            item.fingerprint,
            item.record_fingerprint or "",
        ),
    ))

    with pytest.raises(StorageIntegrityError, match="unique by domain"):
        db.record_claim(
            "claim-task23",
            replayed.bundle.bundle,
            verifier_version="1",
            bundle_record=replayed.bundle,
            falsification_records=records,
        )


def test_task25_12_session_derives_exact_records_when_arguments_are_omitted(
    tmp_path: Path,
) -> None:
    db = SQLiteStorage(tmp_path / "task25-derived.sqlite3")
    result = execute_verification_plan(_request(), storage=db)
    claim_a, claim_b, _, _ = _exact_claim_bundles(db)
    original = db.get_session(result.session.fingerprint)

    derived = db.put_session(
        result.session,
        claim_records=(claim_a, claim_b),
    )

    assert derived.record_fingerprint == original.record_fingerprint
    assert derived.bundle_record_fingerprints == tuple(sorted((
        claim_a.bundle_record_fingerprint,
        claim_b.bundle_record_fingerprint,
    )))
