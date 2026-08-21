from __future__ import annotations

import json
from pathlib import Path
import sqlite3

import pytest

from gvr import (
    AtomicClaim,
    ClaimDefinition,
    ClaimGraph,
    Evidence,
    FalsificationCompleteness,
    FalsificationCoverage,
    FalsificationOutcome,
    FalsificationProbe,
    FalsificationProbeOutcome,
    FalsificationProvenance,
    FalsificationResult,
    FalsificationStrategyKind,
    SQLiteStorage,
    StorageIntegrityError,
    StoredTruthError,
    VerificationReport,
    VerificationSession,
    VerificationVerdict,
    build_verification_bundle,
)
from gvr.sqlite_storage import _CLAIM_BASIS_FORMAT, _parts


VERIFIER = "review.verifier"


def _evidence(value: int, evidence_id: str = "review:evidence") -> Evidence:
    return Evidence(
        evidence_id,
        "review.state",
        {"value": value},
        "review:revision",
        f"producer:{value}",
    )


def _bundle(
    evidence: Evidence | None,
    verdict: VerificationVerdict = VerificationVerdict.PASS,
):
    records = () if evidence is None else (evidence,)
    return build_verification_bundle(
        VerificationReport(
            verdict=verdict,
            verifier=VERIFIER,
            evidence_ids=tuple(item.id for item in records),
        ),
        records,
    )


def _basis(db: SQLiteStorage, path: Path, verdict: VerificationVerdict = VerificationVerdict.PASS):
    evidence = _evidence(1)
    written = db.put_evidence(evidence, slot_id="review:slot")
    slot = db.get_slot("review:slot")
    bundle = _bundle(evidence, verdict)
    db.put_bundle(bundle, evidence_slots={evidence.id: slot})
    db.define_claim(ClaimDefinition("review:claim", "review statement", VERIFIER), verifier_version="1")
    claim = db.record_claim("review:claim", bundle, verifier_version="1")
    return written, slot, bundle, claim


def _tamper(path: Path, sql: str, parameters: tuple[object, ...]) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(sql, parameters)
        connection.commit()
    finally:
        connection.close()


def _rewrite_claim_basis(path: Path, mutate) -> None:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            "SELECT * FROM claim_versions WHERE claim_id = 'review:claim' AND version = 1"
        ).fetchone()
        document = json.loads(row["content_json"])
        mutate(document)
        content, canonical, digest = _parts(
            document,
            fingerprint_format=_CLAIM_BASIS_FORMAT,
        )
        connection.execute(
            """
            UPDATE claim_versions
            SET verdict = ?, content_json = ?, canonical_json = ?,
                content_digest = ?, basis_fingerprint = ?
            WHERE claim_id = 'review:claim' AND version = 1
            """,
            (document["verdict"], content, canonical, digest, digest),
        )
        connection.commit()
    finally:
        connection.close()


def _falsification_result(*, claim_id: str) -> FalsificationResult:
    capability_fingerprint = "a" * 64
    claim_fingerprint = "b" * 64
    provenance = FalsificationProvenance(
        binding_id="review:binding",
        declared_verifier_id=VERIFIER,
        strategy_id="review:strategy",
        strategy_version="1",
        strategy_capability_fingerprint=capability_fingerprint,
        claim_id=claim_id,
        claim_fingerprint=claim_fingerprint,
        input_fingerprint="c" * 64,
        parameters_fingerprint="d" * 64,
        implementation_path="review.independent",
        transformation={},
    )
    return FalsificationResult(
        binding_id=provenance.binding_id,
        declared_verifier_id=provenance.declared_verifier_id,
        strategy_id=provenance.strategy_id,
        strategy_version=provenance.strategy_version,
        strategy_kind=FalsificationStrategyKind.COUNTEREXAMPLE_SEARCH,
        strategy_capability_fingerprint=capability_fingerprint,
        claim_id=claim_id,
        claim_fingerprint=claim_fingerprint,
        outcome=FalsificationOutcome.NO_COUNTEREXAMPLE_FOUND,
        probes=(FalsificationProbe(
            probe_id="review:probe",
            predicate_kind="EXACT",
            outcome=FalsificationProbeOutcome.SATISFIED,
            subject="subject",
            expected=True,
            observed=True,
        ),),
        coverage=FalsificationCoverage(
            completeness=FalsificationCompleteness.COMPLETE,
            examined_items=1,
            total_items=1,
            bounds={"finite": True},
        ),
        provenance=provenance,
    )


def test_review_01_slot_pointer_fingerprint_must_match_current_version(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    db = SQLiteStorage(path)
    first = db.put_evidence(_evidence(1), slot_id="review:slot")
    second = db.put_evidence(_evidence(2, "review:other"))
    _tamper(
        path,
        "UPDATE evidence_slots SET current_evidence_fingerprint = ? WHERE slot_id = 'review:slot'",
        (second.fingerprint,),
    )
    with pytest.raises(StorageIntegrityError):
        db.get_slot("review:slot")
    assert first.fingerprint != second.fingerprint


def test_review_02_rehashed_pass_claim_cannot_disagree_with_unknown_bundle(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    db = SQLiteStorage(path)
    _basis(db, path, VerificationVerdict.UNKNOWN)

    def forge(document):
        document["verdict"] = "PASS"
        document["report"]["verdict"] = "PASS"

    _rewrite_claim_basis(path, forge)
    with pytest.raises(StorageIntegrityError):
        db.claim_status("review:claim")


def test_review_03_rehashed_claim_basis_cannot_substitute_definition(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    db = SQLiteStorage(path)
    _basis(db, path)

    def forge(document):
        document["definition_fingerprint"] = "0" * 64

    _rewrite_claim_basis(path, forge)
    with pytest.raises(StorageIntegrityError):
        db.claim_status("review:claim")


def test_review_04_falsification_basis_must_match_exact_claim_identity(tmp_path: Path) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    result = _falsification_result(claim_id="different:claim")
    db.put_falsification_result(result)
    bundle = _bundle(None)
    db.put_bundle(bundle)
    db.define_claim(ClaimDefinition("review:claim", "review statement", VERIFIER), verifier_version="1")
    with pytest.raises(StoredTruthError):
        db.record_claim(
            "review:claim",
            bundle,
            verifier_version="1",
            falsification_fingerprints=(result.fingerprint,),
        )


def test_review_05_rehashed_session_state_cannot_disagree_with_claim_basis(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    db = SQLiteStorage(path)
    _, _, bundle, _ = _basis(db, path)
    graph = ClaimGraph(nodes=(AtomicClaim(
        claim_id="review:claim",
        claim_kind="review.claim",
        spec={"expected": True},
        verifier=VERIFIER,
    ),))
    session = VerificationSession.compose(
        graph=graph,
        roots=("review:claim",),
        bundles={"review:claim": bundle},
    ).seal()
    stored = db.put_session(session)

    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            "SELECT * FROM sessions WHERE fingerprint = ?",
            (stored.fingerprint,),
        ).fetchone()
        document = json.loads(row["session_content_json"])
        document["claims"][0]["stored_verdict"] = "FAIL"
        document["claims"][0]["effective_verdict"] = "FAIL"
        document["root_verdicts"]["review:claim"] = "FAIL"
        content, canonical, digest = _parts(document)
        connection.execute(
            """
            UPDATE sessions
            SET session_content_json = ?, session_canonical_json = ?,
                session_content_digest = ?
            WHERE fingerprint = ?
            """,
            (content, canonical, digest, stored.fingerprint),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(StorageIntegrityError):
        db.get_session(stored.fingerprint)
