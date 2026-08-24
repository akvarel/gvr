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
    FalsificationRequirement,
    FalsificationStrategyBinding,
    FalsificationStrategyCapabilityRegistry,
    EvidenceRequest,
    SQLiteStorage,
    StorageIntegrityError,
    VerificationExecutionLimits,
    VerificationExecutionRequest,
    VerificationPlanningRequest,
    VerificationReport,
    VerificationVerdict,
    builtin_falsification_strategy_capability_registry,
    builtin_falsification_strategy_runtime_registry,
    COUNTEREXAMPLE_SEARCH_STRATEGY_ID,
    VerifierCapability,
    VerifierCapabilityRegistry,
    VerifierCost,
    VerifierDeterminism,
    VerifierRuntimeRegistry,
    compile_verification_plan,
    execute_verification_plan,
)

from test_durable_storage_task_25 import _tamper


PROVIDER_ID = "fixture.task26.provider"
VERIFIER_ID = "fixture.task26.verifier"
EVIDENCE_ID = "task26-shared-evidence"


class _ProviderRuntime:
    def __init__(
        self,
        capability: EvidenceProviderCapability,
        values: dict[str, str],
        *,
        immutable_without_slots: bool = False,
    ) -> None:
        self.provider_id = capability.provider_id
        self.version = capability.version
        self.capability = capability
        self.values = values
        self.immutable_without_slots = immutable_without_slots

    def acquire(self, request: EvidenceRequest) -> EvidenceProviderResult:
        evidence = Evidence(
            id=EVIDENCE_ID,
            kind="fixture.immutable" if self.immutable_without_slots else "fixture.state",
            payload={"value": self.values[request.request_id]},
            source="task26-provider",
            fingerprint="task26-shared-fingerprint",
        )
        slot_identities = ()
        if not self.immutable_without_slots:
            slot_identities = (
                request.evidence_slot_identity(
                    evidence.id,
                    source_identity=request.source_context,
                ),
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
            evidence_slot_identities=slot_identities,
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
    claim_order: tuple[str, ...] = ("A", "B", "C"),
    roots: tuple[str, ...] | None = None,
    repositories: dict[str, str] | None = None,
    snapshots: dict[str, str] | None = None,
    values: dict[str, str] | None = None,
    immutable_without_slots: bool = False,
    with_falsification: bool = False,
) -> VerificationExecutionRequest:
    repository_values = {claim_id: f"repo-{claim_id}" for claim_id in claim_order}
    repository_values.update(repositories or {})
    snapshot_values = {claim_id: "same-revision" for claim_id in claim_order}
    snapshot_values.update(snapshots or {})
    evidence_values = {
        f"request-{claim_id}": "same-domain-content" for claim_id in claim_order
    }
    evidence_values.update(values or {})
    evidence_kind = "fixture.immutable" if immutable_without_slots else "fixture.state"
    falsification_descriptor = None
    falsification_capabilities = None
    accepted_falsification_kinds: tuple[str, ...] = ()
    falsification_requirement = FalsificationRequirement.NONE
    claim_kind = "ASSERT_STATE"
    claim_spec: dict[str, Any] = {"expected": True}
    if with_falsification:
        falsification_descriptor = builtin_falsification_strategy_capability_registry().lookup(
            COUNTEREXAMPLE_SEARCH_STRATEGY_ID,
            "1",
        )
        falsification_capabilities = FalsificationStrategyCapabilityRegistry(
            (falsification_descriptor,)
        )
        accepted_falsification_kinds = (falsification_descriptor.strategy_kind,)
        falsification_requirement = FalsificationRequirement.REQUIRED_BEFORE_PASS
        claim_kind = "gvr.text.sequence_predicate"
        claim_spec = {"candidate": "fixture"}
    verifier_capability = VerifierCapability(
        verifier_id=VERIFIER_ID,
        version="1",
        claim_kinds=(claim_kind,),
        accepted_evidence_kinds=(evidence_kind,),
        required_evidence_kinds=(evidence_kind,),
        input_schema={"type": "object"},
        output_schema={"type": "gvr.VerificationReport"},
        determinism=VerifierDeterminism.D1,
        side_effect_free=True,
        cost=VerifierCost.LOW,
        bounds={"max_items": 10},
        coverage={"mode": "DECLARED_SCOPE"},
        authoritative=True,
        accepted_falsification_strategy_kinds=accepted_falsification_kinds,
        falsification_requirement=falsification_requirement,
    )
    provider_capability = EvidenceProviderCapability(
        provider_id=PROVIDER_ID,
        version="1",
        request_kinds=("CAPTURE_STATE",),
        produced_evidence_kinds=(evidence_kind,),
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
            claim_kind=claim_kind,
            spec={"claim": claim_id, **claim_spec},
            verifier=VERIFIER_ID,
        )
        for claim_id in claim_order
    }
    graph = ClaimGraph(nodes=tuple(claims[item] for item in claim_order))
    requests = {
        claim_id: EvidenceRequest(
            request_id=f"request-{claim_id}",
            provider_id=PROVIDER_ID,
            provider_version="1",
            request_kind="CAPTURE_STATE",
            requested_evidence_kinds=(evidence_kind,),
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
            falsification_bindings=(
                ()
                if falsification_descriptor is None
                else (
                    FalsificationStrategyBinding(
                        binding_id=f"{claim_id}:falsification",
                        verifier_id=VERIFIER_ID,
                        strategy_id=falsification_descriptor.strategy_id,
                        strategy_version=falsification_descriptor.version,
                        strategy_capability_fingerprint=falsification_descriptor.fingerprint,
                        parameters={
                            "input_kind": "gvr.falsification.finite_text_sequence.v1",
                            "corpus": ("a", "b"),
                            "needle": "z",
                            "predicate": {
                                "kind": "EXACT_MEMBERSHIP",
                                "expected_members": (),
                            },
                            "unicode_unit": "CODE_POINT",
                            "normalization": "NFC",
                            "casefold": False,
                            "reverse": False,
                            "duplicate_semantics": "PRESERVE",
                        },
                    ),
                )
            ),
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
        falsification_strategy_capability_registry=falsification_capabilities,
        falsification_strategy_capability_registry_fingerprint=(
            None if falsification_capabilities is None else falsification_capabilities.fingerprint
        ),
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
            runtime_verifiers={(VERIFIER_ID, "1"): _VerifierRuntime(verifier_capability)},
        ),
        verifier_capability_registry_fingerprint=verifier_capabilities.fingerprint,
        evidence_provider_runtime_registry=EvidenceProviderRuntimeRegistry(
            capability_registry=provider_capabilities,
            runtime_providers={
                (PROVIDER_ID, "1"): _ProviderRuntime(
                    provider_capability,
                    evidence_values,
                    immutable_without_slots=immutable_without_slots,
                ),
            },
        ),
        evidence_provider_capability_registry_fingerprint=provider_capabilities.fingerprint,
        evidence_requests={(item.request_id, item.fingerprint): item for item in requests.values()},
        falsification_strategy_runtime_registry=(
            None
            if falsification_capabilities is None
            else builtin_falsification_strategy_runtime_registry(falsification_capabilities)
        ),
        falsification_strategy_capability_registry_fingerprint=(
            None if falsification_capabilities is None else falsification_capabilities.fingerprint
        ),
        limits=VerificationExecutionLimits(),
    )


def _counts(path: Path) -> dict[str, int]:
    connection = sqlite3.connect(path)
    try:
        return {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "bundle_records",
                "claim_versions",
                "session_records",
                "session_record_bundle_links",
                "session_execution_observations",
                "falsification_records",
            )
        }
    finally:
        connection.close()


def _claim_records(db: SQLiteStorage, *claim_ids: str) -> tuple[Any, ...]:
    return tuple(db.claim_history(claim_id)[-1] for claim_id in claim_ids)


def _bundle_records(db: SQLiteStorage, *claim_ids: str) -> tuple[Any, ...]:
    records = []
    for claim in _claim_records(db, *claim_ids):
        assert claim.bundle_fingerprint is not None
        assert claim.bundle_record_fingerprint is not None
        records.append(
            db.get_bundle(
                claim.bundle_fingerprint,
                record_fingerprint=claim.bundle_record_fingerprint,
            )
        )
    return tuple(records)


def _competing_bundle_record(db: SQLiteStorage, bundle: Any, slot_id: str) -> Any:
    evidence = bundle.bundle.evidence[0]
    db.put_evidence(evidence, slot_id=slot_id)
    slot = db.get_slot(slot_id)
    assert slot is not None
    return db.put_bundle(bundle.bundle, evidence_slots={evidence.id: slot})


def test_task26_01_real_executor_allows_three_distinct_same_domain_exact_records(
    tmp_path: Path,
) -> None:
    db = SQLiteStorage(tmp_path / "task26-three.sqlite3")

    result = execute_verification_plan(_request(), storage=db)

    claims = _claim_records(db, "A", "B", "C")
    session = db.get_session(result.session.fingerprint)
    assert len({result.bundles[item].fingerprint for item in ("A", "B", "C")}) == 1
    assert len({claim.bundle_record_fingerprint for claim in claims}) == 3
    assert session.bundle_record_fingerprints == tuple(
        sorted(claim.bundle_record_fingerprint for claim in claims)
    )
    assert session.bundle_fingerprints == tuple(
        result.bundles[item].fingerprint for item in ("A", "B", "C")
    )


def test_task26_02_four_claims_deduplicate_ab_exact_and_keep_cd_distinct(
    tmp_path: Path,
) -> None:
    db = SQLiteStorage(tmp_path / "task26-four.sqlite3")

    result = execute_verification_plan(
        _request(
            claim_order=("A", "B", "C", "D"),
            repositories={"A": "repo-shared", "B": "repo-shared"},
        ),
        storage=db,
    )

    claims = dict(zip(("A", "B", "C", "D"), _claim_records(db, "A", "B", "C", "D")))
    session = db.get_session(result.session.fingerprint)
    assert claims["A"].bundle_record_fingerprint == claims["B"].bundle_record_fingerprint
    assert len({claims[item].bundle_record_fingerprint for item in ("A", "C", "D")}) == 3
    assert len(session.bundle_record_fingerprints) == 3
    assert session.bundle_record_fingerprints == tuple(
        sorted({claim.bundle_record_fingerprint for claim in claims.values()})
    )


def test_task26_03_order_reopen_and_replay_are_invariant(tmp_path: Path) -> None:
    path = tmp_path / "task26-invariance.sqlite3"
    first = execute_verification_plan(_request(), storage=SQLiteStorage(path))
    first_session = SQLiteStorage(path).get_session(first.session.fingerprint)

    reordered = execute_verification_plan(
        _request(claim_order=("C", "B", "A"), roots=("C", "B", "A")),
        storage=SQLiteStorage(path),
    )
    reopened_session = SQLiteStorage(path).session_history()[0]
    before = _counts(path)
    replayed = execute_verification_plan(_request(), storage=SQLiteStorage(path))

    assert reordered.session.fingerprint == first.session.fingerprint
    assert reordered.fingerprint == first.fingerprint
    assert reopened_session.record_fingerprint == first_session.record_fingerprint
    assert reopened_session.bundle_record_fingerprints == first_session.bundle_record_fingerprints
    assert replayed.fingerprint == first.fingerprint
    assert _counts(path) == before


def test_task26_04_advancing_a_then_c_preserves_b_replay_isolation(tmp_path: Path) -> None:
    path = tmp_path / "task26-advance.sqlite3"
    db = SQLiteStorage(path)
    result = execute_verification_plan(_request(), storage=db)
    original_session = db.get_session(result.session.fingerprint)
    bundle_a, bundle_b, bundle_c = _bundle_records(db, "A", "B", "C")

    execute_verification_plan(
        _request(
            claim_order=("A",),
            snapshots={"A": "revision-2"},
            values={"request-A": "changed-a"},
        ),
        storage=db,
    )
    execute_verification_plan(
        _request(
            claim_order=("C",),
            snapshots={"C": "revision-2"},
            values={"request-C": "changed-c"},
        ),
        storage=db,
    )
    execute_verification_plan(_request(claim_order=("B",)), storage=db)

    assert not db.get_bundle(bundle_a.fingerprint, record_fingerprint=bundle_a.record_fingerprint).current
    assert db.get_bundle(bundle_b.fingerprint, record_fingerprint=bundle_b.record_fingerprint).current
    assert not db.get_bundle(bundle_c.fingerprint, record_fingerprint=bundle_c.record_fingerprint).current
    assert not db.get_session(
        original_session.fingerprint,
        record_fingerprint=original_session.record_fingerprint,
    ).current
    assert len(db.claim_history("B")) == 1


def test_task26_05_immutable_evidence_without_slot_identities_supports_three_claims(
    tmp_path: Path,
) -> None:
    path = tmp_path / "task26-immutable.sqlite3"
    db = SQLiteStorage(path)

    result = execute_verification_plan(
        _request(immutable_without_slots=True),
        storage=db,
    )

    claims = _claim_records(db, "A", "B", "C")
    session = db.get_session(result.session.fingerprint)
    assert len({claim.bundle_record_fingerprint for claim in claims}) == 3
    assert all(dependency.slot is None for claim in claims for dependency in claim.evidence_dependencies)
    assert all(dependency.evidence_id == EVIDENCE_ID for claim in claims for dependency in claim.evidence_dependencies)
    connection = sqlite3.connect(db.path)
    try:
        assert connection.execute("SELECT COUNT(*) FROM evidence_slots").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM evidence_slot_versions").fetchone()[0] == 0
    finally:
        connection.close()
    assert session.bundle_record_fingerprints == tuple(
        sorted(claim.bundle_record_fingerprint for claim in claims)
    )

    before = _counts(path)
    replayed = execute_verification_plan(
        _request(
            claim_order=("C", "B", "A"),
            roots=("C", "B", "A"),
            immutable_without_slots=True,
        ),
        storage=SQLiteStorage(path),
    )
    replayed_claims = _claim_records(SQLiteStorage(path), "A", "B", "C")
    reopened_session = SQLiteStorage(path).get_session(replayed.session.fingerprint)
    assert replayed.fingerprint == result.fingerprint
    assert reopened_session.record_fingerprint == session.record_fingerprint
    assert tuple(claim.bundle_record_fingerprint for claim in replayed_claims) == tuple(
        claim.bundle_record_fingerprint for claim in claims
    )
    assert all(
        SQLiteStorage(path).get_bundle(
            claim.bundle_fingerprint,
            record_fingerprint=claim.bundle_record_fingerprint,
        ).current
        for claim in replayed_claims
    )
    assert _counts(path) == before


def test_task26_06_two_claim_same_domain_multiplicity_with_required_falsification(
    tmp_path: Path,
) -> None:
    path = tmp_path / "task26-falsification.sqlite3"
    db = SQLiteStorage(path)

    request = _request(
        claim_order=("A", "B"),
        with_falsification=True,
    )
    result = execute_verification_plan(request, storage=db)
    falsification_result_by_claim = {
        step.claim_id: result.falsification_results[step.step_id]
        for step in request.plan.steps
        if step.step_id in result.falsification_results
    }

    claim_a, claim_b = _claim_records(db, "A", "B")
    bundle_a, bundle_b = _bundle_records(db, "A", "B")
    session = db.get_session(result.session.fingerprint)
    assert falsification_result_by_claim.keys() == {"A", "B"}
    assert result.bundles["A"].fingerprint == result.bundles["B"].fingerprint
    assert bundle_a.fingerprint == bundle_b.fingerprint
    assert bundle_a.record_fingerprint != bundle_b.record_fingerprint
    assert claim_a.bundle_record_fingerprint == bundle_a.record_fingerprint
    assert claim_b.bundle_record_fingerprint == bundle_b.record_fingerprint
    assert len(claim_a.falsification_record_fingerprints) == 1
    assert len(claim_b.falsification_record_fingerprints) == 1
    assert claim_a.falsification_record_fingerprints != claim_b.falsification_record_fingerprints
    falsification_a = db.get_falsification_result(
        falsification_result_by_claim["A"].fingerprint,
        record_fingerprint=claim_a.falsification_record_fingerprints[0],
    )
    falsification_b = db.get_falsification_result(
        falsification_result_by_claim["B"].fingerprint,
        record_fingerprint=claim_b.falsification_record_fingerprints[0],
    )
    assert falsification_a.record_fingerprint in claim_a.falsification_record_fingerprints
    assert falsification_b.record_fingerprint in claim_b.falsification_record_fingerprints
    assert session.bundle_record_fingerprints == tuple(
        sorted((bundle_a.record_fingerprint, bundle_b.record_fingerprint))
    )
    assert session.falsification_record_fingerprints == tuple(
        sorted((falsification_a.record_fingerprint, falsification_b.record_fingerprint))
    )

    before = _counts(path)
    replayed = execute_verification_plan(
        _request(
            claim_order=("B", "A"),
            roots=("B", "A"),
            with_falsification=True,
        ),
        storage=SQLiteStorage(path),
    )
    replayed_claim_a, replayed_claim_b = _claim_records(SQLiteStorage(path), "A", "B")
    replayed_session = SQLiteStorage(path).get_session(replayed.session.fingerprint)
    assert replayed.fingerprint == result.fingerprint
    assert replayed_session.record_fingerprint == session.record_fingerprint
    assert replayed_claim_a.bundle_record_fingerprint == claim_a.bundle_record_fingerprint
    assert replayed_claim_b.bundle_record_fingerprint == claim_b.bundle_record_fingerprint
    assert replayed_claim_a.falsification_record_fingerprints == claim_a.falsification_record_fingerprints
    assert replayed_claim_b.falsification_record_fingerprints == claim_b.falsification_record_fingerprints
    assert _counts(path) == before

    advanced_request = _request(
        claim_order=("A",),
        snapshots={"A": "revision-2"},
        values={"request-A": "changed-a"},
        with_falsification=True,
    )
    advanced = execute_verification_plan(advanced_request, storage=SQLiteStorage(path))
    advanced_falsification_result_by_claim = {
        step.claim_id: advanced.falsification_results[step.step_id]
        for step in advanced_request.plan.steps
        if step.step_id in advanced.falsification_results
    }
    advanced_claim_a = SQLiteStorage(path).claim_history("A")[-1]
    preserved_claim_b = SQLiteStorage(path).claim_history("B")[-1]
    assert advanced_claim_a.bundle_record_fingerprint != claim_a.bundle_record_fingerprint
    assert advanced_claim_a.falsification_record_fingerprints != claim_a.falsification_record_fingerprints
    assert preserved_claim_b.bundle_record_fingerprint == claim_b.bundle_record_fingerprint
    assert preserved_claim_b.falsification_record_fingerprints == claim_b.falsification_record_fingerprints
    assert preserved_claim_b.bundle_record_fingerprint != advanced_claim_a.bundle_record_fingerprint
    assert preserved_claim_b.falsification_record_fingerprints != advanced_claim_a.falsification_record_fingerprints
    assert advanced_falsification_result_by_claim.keys() == {"A"}


def test_task26_07_missing_exact_link_fails_closed_and_rolls_back(tmp_path: Path) -> None:
    path = tmp_path / "task26-missing.sqlite3"
    db = SQLiteStorage(path)
    result = execute_verification_plan(_request(), storage=db)
    session = db.get_session(result.session.fingerprint)
    assert session.record_fingerprint is not None
    removed = session.bundle_record_fingerprints[0]
    before = _counts(path)

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
    assert _counts(path) == {**before, "session_record_bundle_links": before["session_record_bundle_links"] - 1}


def test_task26_08_substituted_exact_link_fails_closed_and_put_session_rolls_back(
    tmp_path: Path,
) -> None:
    path = tmp_path / "task26-substituted.sqlite3"
    db = SQLiteStorage(path)
    result = execute_verification_plan(_request(), storage=db)
    claim_a, claim_b, claim_c = _claim_records(db, "A", "B", "C")
    bundle_a, bundle_b, bundle_c = _bundle_records(db, "A", "B", "C")
    competing = _competing_bundle_record(db, bundle_a, "task26:substituted")
    wrong_records = tuple(sorted((competing, bundle_b, bundle_c), key=lambda item: item.record_fingerprint or ""))
    before = _counts(path)

    with pytest.raises(StorageIntegrityError, match="must match the exact claim records"):
        db.put_session(
            result.session,
            claim_records=(claim_a, claim_b, claim_c),
            bundle_records=wrong_records,
        )

    assert _counts(path) == before


def test_task26_09_extra_exact_link_fails_closed_and_rolls_back(tmp_path: Path) -> None:
    path = tmp_path / "task26-extra.sqlite3"
    db = SQLiteStorage(path)
    result = execute_verification_plan(_request(), storage=db)
    session = db.get_session(result.session.fingerprint)
    assert session.record_fingerprint is not None
    bundle_a = _bundle_records(db, "A")[0]
    extra = _competing_bundle_record(db, bundle_a, "task26:extra")
    assert extra.record_fingerprint is not None
    before = _counts(path)

    _tamper(
        path,
        """
        INSERT INTO session_record_bundle_links(
            record_fingerprint,
            bundle_fingerprint,
            bundle_record_fingerprint,
            ordinal
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            session.record_fingerprint,
            extra.fingerprint,
            extra.record_fingerprint,
            len(session.bundle_record_fingerprints),
        ),
    )

    with pytest.raises(StorageIntegrityError):
        SQLiteStorage(path).get_session(
            session.fingerprint,
            record_fingerprint=session.record_fingerprint,
        )
    assert _counts(path) == {**before, "session_record_bundle_links": before["session_record_bundle_links"] + 1}


def test_task26_10_corrupt_exact_link_fails_closed_and_rolls_back(tmp_path: Path) -> None:
    path = tmp_path / "task26-corrupt.sqlite3"
    db = SQLiteStorage(path)
    result = execute_verification_plan(_request(), storage=db)
    session = db.get_session(result.session.fingerprint)
    assert session.record_fingerprint is not None
    bundle_a = _bundle_records(db, "A")[0]
    competing = _competing_bundle_record(db, bundle_a, "task26:corrupt")
    assert competing.record_fingerprint is not None
    before = _counts(path)

    _tamper(
        path,
        """
        UPDATE session_record_bundle_links
        SET bundle_record_fingerprint = ?
        WHERE record_fingerprint = ? AND bundle_record_fingerprint = ?
        """,
        (competing.record_fingerprint, session.record_fingerprint, bundle_a.record_fingerprint),
    )

    with pytest.raises(StorageIntegrityError):
        SQLiteStorage(path).get_session(
            session.fingerprint,
            record_fingerprint=session.record_fingerprint,
        )
    assert _counts(path) == before
