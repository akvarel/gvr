from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

from gvr import (
    COUNTEREXAMPLE_SEARCH_STRATEGY_ID,
    AtomicClaim,
    AtomicClaimBinding,
    BundleStore,
    ClaimDefinition,
    ClaimGraph,
    ClaimStore,
    DependencyCycleError,
    DependencyIndex,
    DURABLE_STORAGE_SCHEMA_TABLE,
    DURABLE_STORAGE_SCHEMA_VERSION,
    Evidence,
    EvidenceAcquisitionStatus,
    EvidenceCompleteness,
    EvidenceCoverage,
    EvidenceProviderCapability,
    EvidenceProviderCapabilityRegistry,
    EvidenceProviderResult,
    EvidenceProviderRuntimeRegistry,
    EvidenceRequest,
    EvidenceStore,
    FalsificationRequirement,
    FalsificationStrategyBinding,
    FalsificationStrategyCapabilityRegistry,
    SessionStore,
    SQLiteStorage,
    StorageConflictError,
    StorageIntegrityError,
    StorageMigrationError,
    StorageNotFoundError,
    StorageSchemaVersionError,
    StoredTruthError,
    VerificationBundle,
    VerificationExecutionError,
    VerificationExecutionLimits,
    VerificationExecutionRequest,
    VerificationPlanningRequest,
    VerificationReport,
    VerificationSession,
    VerificationVerdict,
    VerifierCapability,
    VerifierCapabilityRegistry,
    VerifierCost,
    VerifierDeterminism,
    VerifierRuntimeRegistry,
    build_verification_bundle,
    builtin_falsification_strategy_capability_registry,
    builtin_falsification_strategy_runtime_registry,
    compile_verification_plan,
    execute_verification_plan,
)


VERIFIER_ID = "fixture.durable.verifier"
VERIFIER_VERSION = "1"


def _evidence(
    value: Any = 1,
    *,
    evidence_id: str = "evidence:state",
    source: str = "revision:A",
) -> Evidence:
    return Evidence(
        id=evidence_id,
        kind="fixture.state",
        payload={"value": value, "nested": {"b": 2, "a": 1}},
        source=source,
        fingerprint=f"producer:{value}",
    )


def _bundle(
    evidence: tuple[Evidence, ...] = (),
    *,
    verdict: VerificationVerdict = VerificationVerdict.PASS,
    verifier: str = VERIFIER_ID,
    claim_dependencies: tuple[str, ...] = (),
) -> VerificationBundle:
    return build_verification_bundle(
        VerificationReport(
            verdict=verdict,
            verifier=verifier,
            evidence_ids=tuple(item.id for item in evidence),
            metadata={"basis": "fixture"},
        ),
        evidence,
        claim_dependency_ids=claim_dependencies,
    )


def _define(db: SQLiteStorage, claim_id: str) -> None:
    db.define_claim(
        ClaimDefinition(claim_id, f"statement:{claim_id}", VERIFIER_ID),
        verifier_version=VERIFIER_VERSION,
    )


def _store_evidence_and_bundle(
    db: SQLiteStorage,
    evidence: Evidence,
    *,
    slot_id: str | None = None,
    claim_dependencies: tuple[str, ...] = (),
    verdict: VerificationVerdict = VerificationVerdict.PASS,
):
    slot_name = evidence.id if slot_id is None else slot_id
    stored_evidence = db.put_evidence(
        evidence,
        slot_id=slot_name,
        provenance={"provider_id": "fixture.provider", "provider_version": "1"},
        source_snapshot={"repository": "demo", "revision": evidence.source},
        bounds={"max_records": 10},
        coverage={"completeness": "COMPLETE", "records": 1},
    )
    slot = db.get_slot(slot_name)
    bundle = _bundle(
        (evidence,),
        verdict=verdict,
        claim_dependencies=claim_dependencies,
    )
    stored_bundle = db.put_bundle(bundle, evidence_slots={evidence.id: slot})
    return stored_evidence, slot, bundle, stored_bundle


def _record_claim(
    db: SQLiteStorage,
    claim_id: str,
    bundle: VerificationBundle,
    *,
    falsification_fingerprints: tuple[str, ...] = (),
):
    _define(db, claim_id)
    return db.record_claim(
        claim_id,
        bundle,
        verifier_version=VERIFIER_VERSION,
        falsification_fingerprints=falsification_fingerprints,
    )


def _session_for(
    db: SQLiteStorage,
    bundles: Mapping[str, VerificationBundle],
    *,
    dependencies: Mapping[str, tuple[str, ...]] | None = None,
    root: str | None = None,
    plan_fingerprint: str = "1" * 64,
    execution_fingerprint: str = "2" * 64,
):
    dependency_map = dict(dependencies or {})
    nodes = tuple(
        AtomicClaim(
            claim_id=claim_id,
            claim_kind="fixture.claim",
            spec={"claim_id": claim_id},
            verifier=VERIFIER_ID,
            dependencies=dependency_map.get(claim_id, ()),
        )
        for claim_id in bundles
    )
    graph = ClaimGraph(nodes=nodes)
    selected_root = root or next(reversed(tuple(bundles)))
    session = VerificationSession.compose(
        graph=graph,
        roots=(selected_root,),
        bundles=bundles,
    ).seal()
    return db.put_session(
        session,
        plan_fingerprint=plan_fingerprint,
        execution_fingerprint=execution_fingerprint,
    )


def _tamper(path: Path, sql: str, parameters: tuple[Any, ...] = ()) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(sql, parameters)
        connection.commit()
    finally:
        connection.close()


# Minimal Task 19 execution fixture.
def _verifier_capability() -> VerifierCapability:
    return VerifierCapability(
        verifier_id=VERIFIER_ID,
        version=VERIFIER_VERSION,
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


def _provider_capability() -> EvidenceProviderCapability:
    return EvidenceProviderCapability(
        provider_id="fixture.durable.provider",
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


class _ProviderRuntime:
    def __init__(self, capability: EvidenceProviderCapability, *, value: Any = True) -> None:
        self.provider_id = capability.provider_id
        self.version = capability.version
        self.capability = capability
        self.value = value

    def acquire(self, request: EvidenceRequest) -> EvidenceProviderResult:
        evidence = _evidence(
            self.value,
            evidence_id="executor:evidence",
            source=str(request.snapshot_context["revision"]),
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
    def __init__(
        self,
        capability: VerifierCapability,
        *,
        verdict: VerificationVerdict = VerificationVerdict.PASS,
    ) -> None:
        self.verifier_id = capability.verifier_id
        self.version = capability.version
        self.capability = capability
        self.verdict = verdict

    def verify(self, verifier_input: Any) -> VerificationReport:
        return VerificationReport(
            verdict=self.verdict,
            verifier=self.verifier_id,
            evidence_ids=tuple(item.id for item in verifier_input.evidence),
        )


def _execution_fixture(*, value: Any = True) -> SimpleNamespace:
    verifier_capability = _verifier_capability()
    provider_capability = _provider_capability()
    verifier_capabilities = VerifierCapabilityRegistry((verifier_capability,))
    provider_capabilities = EvidenceProviderCapabilityRegistry((provider_capability,))
    claim = AtomicClaim(
        claim_id="executor:claim",
        claim_kind="ASSERT_STATE",
        spec={"expected": True},
        verifier=VERIFIER_ID,
    )
    graph = ClaimGraph(nodes=(claim,))
    evidence_request = EvidenceRequest(
        request_id="executor:request",
        provider_id=provider_capability.provider_id,
        provider_version=provider_capability.version,
        request_kind="CAPTURE_STATE",
        requested_evidence_kinds=("fixture.state",),
        subject={"entity": "executor:claim"},
        spec={"field": "ready"},
        semantic_scope={"repository": "demo"},
        source_context={"repository": "demo"},
        snapshot_context={"revision": "executor-revision-A"},
        bounds={"max_items": 10},
        source_class="repository",
        snapshot_class="revision",
    )
    binding = AtomicClaimBinding(
        claim_id=claim.claim_id,
        verifier_id=verifier_capability.verifier_id,
        verifier_version=verifier_capability.version,
        verifier_capability_fingerprint=verifier_capability.fingerprint,
        evidence_requests=(evidence_request,),
    )
    planning_request = VerificationPlanningRequest(
        claim_graph=graph,
        bindings=(binding,),
        verifier_capability_registry=verifier_capabilities,
        verifier_capability_registry_fingerprint=verifier_capabilities.fingerprint,
        evidence_provider_capability_registry=provider_capabilities,
        evidence_provider_capability_registry_fingerprint=provider_capabilities.fingerprint,
    )
    plan = compile_verification_plan(planning_request)
    verifier_runtime = _VerifierRuntime(verifier_capability)
    provider_runtime = _ProviderRuntime(provider_capability, value=value)
    request = VerificationExecutionRequest(
        plan=plan,
        plan_fingerprint=plan.fingerprint,
        claim_graph=graph,
        claim_graph_fingerprint=graph.fingerprint,
        roots=(claim.claim_id,),
        verifier_runtime_registry=VerifierRuntimeRegistry(
            capability_registry=verifier_capabilities,
            runtime_verifiers={
                (verifier_capability.verifier_id, verifier_capability.version): verifier_runtime
            },
        ),
        verifier_capability_registry_fingerprint=verifier_capabilities.fingerprint,
        evidence_provider_runtime_registry=EvidenceProviderRuntimeRegistry(
            capability_registry=provider_capabilities,
            runtime_providers={
                (provider_capability.provider_id, provider_capability.version): provider_runtime
            },
        ),
        evidence_provider_capability_registry_fingerprint=provider_capabilities.fingerprint,
        evidence_requests={(evidence_request.request_id, evidence_request.fingerprint): evidence_request},
        limits=VerificationExecutionLimits(),
    )
    return SimpleNamespace(request=request, claim=claim)


# Minimal Task 20 falsification fixture with no provider dependency.
def _falsification_fixture() -> SimpleNamespace:
    descriptor = builtin_falsification_strategy_capability_registry().lookup(
        COUNTEREXAMPLE_SEARCH_STRATEGY_ID,
        "1",
    )
    falsification_capabilities = FalsificationStrategyCapabilityRegistry((descriptor,))
    verifier_capability = VerifierCapability(
        verifier_id="fixture.falsification.verifier",
        version="1",
        claim_kinds=("gvr.text.sequence_predicate",),
        accepted_evidence_kinds=(),
        required_evidence_kinds=(),
        input_schema={},
        output_schema={},
        determinism=VerifierDeterminism.D1,
        side_effect_free=True,
        cost=VerifierCost.LOW,
        bounds={"finite": True},
        coverage={"mode": "COMPLETE"},
        authoritative=True,
        accepted_falsification_strategy_kinds=(descriptor.strategy_kind,),
        falsification_requirement=FalsificationRequirement.REQUIRED_BEFORE_PASS,
    )
    verifier_capabilities = VerifierCapabilityRegistry((verifier_capability,))
    provider_capabilities = EvidenceProviderCapabilityRegistry()
    claim = AtomicClaim(
        claim_id="falsification:claim",
        claim_kind="gvr.text.sequence_predicate",
        spec={"candidate": "fixture"},
        verifier=verifier_capability.verifier_id,
    )
    graph = ClaimGraph(nodes=(claim,))
    parameters = {
        "input_kind": "gvr.falsification.finite_text_sequence.v1",
        "corpus": ("a", "b"),
        "needle": "z",
        "predicate": {"kind": "EXACT_MEMBERSHIP", "expected_members": ()},
        "unicode_unit": "CODE_POINT",
        "normalization": "NFC",
        "casefold": False,
        "reverse": False,
        "duplicate_semantics": "PRESERVE",
    }
    binding = AtomicClaimBinding(
        claim_id=claim.claim_id,
        verifier_id=verifier_capability.verifier_id,
        verifier_version=verifier_capability.version,
        verifier_capability_fingerprint=verifier_capability.fingerprint,
        falsification_bindings=(FalsificationStrategyBinding(
            binding_id="falsification:binding",
            verifier_id=verifier_capability.verifier_id,
            strategy_id=descriptor.strategy_id,
            strategy_version=descriptor.version,
            strategy_capability_fingerprint=descriptor.fingerprint,
            parameters=parameters,
        ),),
    )
    planning_request = VerificationPlanningRequest(
        claim_graph=graph,
        bindings=(binding,),
        verifier_capability_registry=verifier_capabilities,
        verifier_capability_registry_fingerprint=verifier_capabilities.fingerprint,
        evidence_provider_capability_registry=provider_capabilities,
        evidence_provider_capability_registry_fingerprint=provider_capabilities.fingerprint,
        falsification_strategy_capability_registry=falsification_capabilities,
        falsification_strategy_capability_registry_fingerprint=falsification_capabilities.fingerprint,
    )
    plan = compile_verification_plan(planning_request)
    verifier_runtime = _VerifierRuntime(verifier_capability)
    request = VerificationExecutionRequest(
        plan=plan,
        plan_fingerprint=plan.fingerprint,
        claim_graph=graph,
        claim_graph_fingerprint=graph.fingerprint,
        roots=(claim.claim_id,),
        verifier_runtime_registry=VerifierRuntimeRegistry(
            capability_registry=verifier_capabilities,
            runtime_verifiers={
                (verifier_capability.verifier_id, verifier_capability.version): verifier_runtime
            },
        ),
        verifier_capability_registry_fingerprint=verifier_capabilities.fingerprint,
        evidence_provider_runtime_registry=EvidenceProviderRuntimeRegistry(
            capability_registry=provider_capabilities,
            runtime_providers={},
        ),
        evidence_provider_capability_registry_fingerprint=provider_capabilities.fingerprint,
        evidence_requests={},
        falsification_strategy_runtime_registry=(
            builtin_falsification_strategy_runtime_registry(falsification_capabilities)
        ),
        falsification_strategy_capability_registry_fingerprint=(
            falsification_capabilities.fingerprint
        ),
    )
    return SimpleNamespace(request=request, claim=claim)


def test_01_public_generic_store_interfaces_and_sqlite_reference_adapter(tmp_path: Path) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    assert isinstance(db, EvidenceStore)
    assert isinstance(db, BundleStore)
    assert isinstance(db, ClaimStore)
    assert isinstance(db, SessionStore)
    assert isinstance(db, DependencyIndex)
    assert db.schema_version == DURABLE_STORAGE_SCHEMA_VERSION


def test_02_restart_preserves_immutable_evidence_and_complete_metadata(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    db = SQLiteStorage(path)
    evidence = _evidence()
    written = db.put_evidence(
        evidence,
        slot_id="slot:state",
        provenance={"provider_id": "fixture.provider", "request": "R"},
        source_snapshot={"repository": "demo", "revision": "abc"},
        bounds={"max_items": 10},
        coverage={"completeness": "COMPLETE", "covered": 1},
    )
    del db

    reopened = SQLiteStorage(path)
    read = reopened.get_evidence(written.fingerprint)
    assert read.evidence == evidence
    assert dict(read.provenance) == {"provider_id": "fixture.provider", "request": "R"}
    assert dict(read.source_snapshot) == {"repository": "demo", "revision": "abc"}
    assert dict(read.bounds) == {"max_items": 10}
    assert dict(read.coverage) == {"completeness": "COMPLETE", "covered": 1}
    assert reopened.get_slot("slot:state").evidence_fingerprint == written.fingerprint


def test_03_identical_evidence_and_slot_writes_are_idempotent(tmp_path: Path) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    evidence = _evidence()
    first = db.put_evidence(evidence, slot_id="slot:state", provenance={"a": 1, "b": 2})
    second = db.put_evidence(evidence, slot_id="slot:state", provenance={"b": 2, "a": 1})
    assert second.fingerprint == first.fingerprint
    assert second.slot_version == first.slot_version == 1
    assert len(db.slot_history("slot:state")) == 1
    assert db.invalidation_events() == ()

    bundle = _bundle((evidence,))
    exact_slot = db.get_slot("slot:state")
    first_bundle = db.put_bundle(
        bundle,
        evidence_slots={evidence.id: exact_slot},
    )
    second_bundle = db.put_bundle(bundle)
    assert second_bundle == first_bundle

    definition = ClaimDefinition("idempotent:claim", "same basis", VERIFIER_ID)
    assert db.define_claim(
        definition,
        verifier_version=VERIFIER_VERSION,
    ) == db.define_claim(definition, verifier_version=VERIFIER_VERSION)
    first_claim = db.record_claim(
        definition.id,
        bundle,
        verifier_version=VERIFIER_VERSION,
    )
    second_claim = db.record_claim(
        definition.id,
        bundle,
        verifier_version=VERIFIER_VERSION,
    )
    assert second_claim == first_claim


def test_04_conflicting_content_for_supplied_immutable_identity_is_rejected(tmp_path: Path) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    first = db.put_evidence(_evidence(1))
    with pytest.raises(StorageConflictError):
        db.put_evidence(_evidence(2), expected_fingerprint=first.fingerprint)
    assert db.get_evidence(first.fingerprint).evidence.payload["value"] == 1


def test_05_corrupt_canonical_payload_or_fingerprint_fails_closed_on_read(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    db = SQLiteStorage(path)
    stored = db.put_evidence(_evidence())
    _tamper(
        path,
        "UPDATE evidence_artifacts SET content_json = ? WHERE fingerprint = ?",
        (json.dumps({"corrupt": True}), stored.fingerprint),
    )
    with pytest.raises(StorageIntegrityError):
        db.get_evidence(stored.fingerprint)


def test_06_bundle_read_rejects_missing_or_substituted_exact_evidence_links(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    db = SQLiteStorage(path)
    evidence = _evidence()
    _, _, bundle, _ = _store_evidence_and_bundle(db, evidence)
    _tamper(
        path,
        "DELETE FROM bundle_evidence_links WHERE bundle_fingerprint = ?",
        (bundle.fingerprint,),
    )
    with pytest.raises(StorageIntegrityError):
        db.get_bundle(bundle.fingerprint)


def test_07_pass_basis_persists_exact_bundle_evidence_and_verifier_version(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    db = SQLiteStorage(path)
    evidence = _evidence()
    _, slot, bundle, _ = _store_evidence_and_bundle(db, evidence)
    claim = _record_claim(db, "claim:A", bundle)
    del db

    reopened = SQLiteStorage(path)
    status = reopened.claim_status("claim:A")
    assert status.stored_verdict is VerificationVerdict.PASS
    assert status.effective_verdict is VerificationVerdict.PASS
    assert status.current
    assert claim.verifier_id == VERIFIER_ID
    assert claim.verifier_version == VERIFIER_VERSION
    assert claim.bundle_fingerprint == bundle.fingerprint
    assert claim.evidence_slots == (slot,)


def test_08_pass_without_evidence_claim_or_falsification_basis_is_rejected(tmp_path: Path) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    empty_pass = _bundle()
    db.put_bundle(empty_pass)
    _define(db, "claim:empty")
    with pytest.raises(StoredTruthError):
        db.record_claim("claim:empty", empty_pass, verifier_version=VERIFIER_VERSION)
    with pytest.raises(StorageNotFoundError):
        db.claim_status("claim:empty")


def test_09_slot_replacement_retains_history_and_atomically_advances_pointer(tmp_path: Path) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    first = db.put_evidence(_evidence(1), slot_id="slot:state")
    second = db.put_evidence(_evidence(2), slot_id="slot:state")
    assert (first.slot_version, second.slot_version) == (1, 2)
    assert db.get_slot("slot:state").evidence_fingerprint == second.fingerprint
    assert tuple(item.evidence_fingerprint for item in db.slot_history("slot:state")) == (
        first.fingerprint,
        second.fingerprint,
    )
    assert db.get_evidence(first.fingerprint).evidence.payload["value"] == 1


def test_10_slot_change_invalidates_exact_bundle_claim_and_session(tmp_path: Path) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    evidence = _evidence(1)
    _, _, bundle, _ = _store_evidence_and_bundle(db, evidence, slot_id="slot:state")
    _record_claim(db, "claim:A", bundle)
    stored_session = _session_for(db, {"claim:A": bundle})

    db.put_evidence(_evidence(2), slot_id="slot:state")

    assert not db.get_bundle(bundle.fingerprint).current
    assert not db.claim_status("claim:A").current
    assert db.claim_status("claim:A").effective_verdict is VerificationVerdict.UNKNOWN
    assert not db.get_session(stored_session.fingerprint).current


def test_11_transitive_claim_invalidation_reaches_all_downstream_claims(tmp_path: Path) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    _, _, bundle_a, _ = _store_evidence_and_bundle(db, _evidence(1), slot_id="slot:A")
    _record_claim(db, "A", bundle_a)

    bundle_b = _bundle(claim_dependencies=("A",))
    db.put_bundle(bundle_b)
    _record_claim(db, "B", bundle_b)
    bundle_c = _bundle(claim_dependencies=("B",))
    db.put_bundle(bundle_c)
    _record_claim(db, "C", bundle_c)
    _session_for(
        db,
        {"A": bundle_a, "B": bundle_b, "C": bundle_c},
        dependencies={"B": ("A",), "C": ("B",)},
        root="C",
    )

    db.put_evidence(_evidence(2), slot_id="slot:A")
    assert set(db.stale_claims()) == {"A", "B", "C"}


def test_12_unrelated_bundle_claim_and_session_remain_current(tmp_path: Path) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    _, _, bundle_a, _ = _store_evidence_and_bundle(
        db, _evidence(1, evidence_id="evidence:A"), slot_id="slot:A"
    )
    _, _, bundle_b, _ = _store_evidence_and_bundle(
        db, _evidence(1, evidence_id="evidence:B"), slot_id="slot:B"
    )
    _record_claim(db, "A", bundle_a)
    _record_claim(db, "B", bundle_b)
    session_a = _session_for(db, {"A": bundle_a}, plan_fingerprint="a" * 64)
    session_b = _session_for(db, {"B": bundle_b}, plan_fingerprint="b" * 64)

    db.put_evidence(_evidence(2, evidence_id="evidence:A"), slot_id="slot:A")

    assert not db.get_session(session_a.fingerprint).current
    assert db.get_bundle(bundle_b.fingerprint).current
    assert db.claim_status("B").current
    assert db.get_session(session_b.fingerprint).current


def test_13_invalidation_events_and_stale_state_survive_restart_idempotently(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    db = SQLiteStorage(path)
    _, _, bundle, _ = _store_evidence_and_bundle(db, _evidence(1), slot_id="slot:state")
    _record_claim(db, "A", bundle)
    session = _session_for(db, {"A": bundle})
    replacement = db.put_evidence(_evidence(2), slot_id="slot:state")
    first_events = db.invalidation_events()
    db.put_evidence(_evidence(2), slot_id="slot:state")
    assert db.invalidation_events() == first_events
    del db

    reopened = SQLiteStorage(path)
    assert reopened.get_slot("slot:state").version == replacement.slot_version
    assert reopened.invalidation_events() == first_events
    assert not reopened.get_session(session.fingerprint).current


def test_14_slot_bundle_claim_and_session_histories_are_reconstructible(tmp_path: Path) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    _, _, first_bundle, _ = _store_evidence_and_bundle(db, _evidence(1), slot_id="slot:state")
    first_claim = _record_claim(db, "A", first_bundle)
    first_session = _session_for(db, {"A": first_bundle}, execution_fingerprint="a" * 64)

    _, _, second_bundle, _ = _store_evidence_and_bundle(db, _evidence(2), slot_id="slot:state")
    second_claim = db.record_claim("A", second_bundle, verifier_version=VERIFIER_VERSION)
    second_session = _session_for(db, {"A": second_bundle}, execution_fingerprint="b" * 64)

    assert len(db.slot_history("slot:state")) == 2
    assert tuple(item.bundle_fingerprint for item in db.claim_history("A")) == (
        first_bundle.fingerprint,
        second_bundle.fingerprint,
    )
    assert (first_claim.version, second_claim.version) == (1, 2)
    assert not db.get_session(first_session.fingerprint).current
    assert db.get_session(second_session.fingerprint).current
    assert {item.fingerprint for item in db.session_history()} == {
        first_session.fingerprint,
        second_session.fingerprint,
    }


def test_15_immutable_evidence_and_current_state_do_not_expire_by_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "ledger.sqlite3"
    db = SQLiteStorage(path)
    stored, _, bundle, _ = _store_evidence_and_bundle(db, _evidence(), slot_id="slot:state")
    _record_claim(db, "A", bundle)
    monkeypatch.setattr("time.time", lambda: 9_999_999_999.0)
    reopened = SQLiteStorage(path)
    assert reopened.get_evidence(stored.fingerprint).fingerprint == stored.fingerprint
    assert reopened.get_bundle(bundle.fingerprint).current
    assert reopened.claim_status("A").current


def test_16_unit_of_work_rolls_back_artifact_slot_pointer_and_invalidation(tmp_path: Path) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    with pytest.raises(RuntimeError):
        with db.unit_of_work() as uow:
            written = uow.put_evidence(_evidence(), slot_id="slot:state")
            assert written.slot_version == 1
            raise RuntimeError("rollback")
    assert db.get_slot("slot:state") is None
    assert db.invalidation_events() == ()


def test_17_failed_logical_write_cannot_leave_a_current_pass_claim(tmp_path: Path) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    empty_pass = _bundle()
    _define(db, "A")
    with pytest.raises(StoredTruthError):
        with db.unit_of_work() as uow:
            uow.put_bundle(empty_pass)
            uow.record_claim("A", empty_pass, verifier_version=VERIFIER_VERSION)
    with pytest.raises(StorageNotFoundError):
        db.claim_status("A")


def test_18_concurrent_identical_inserts_are_deterministic_and_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    SQLiteStorage(path)

    def write() -> tuple[str, int | None]:
        stored = SQLiteStorage(path).put_evidence(_evidence(), slot_id="slot:state")
        return stored.fingerprint, stored.slot_version

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = tuple(executor.map(lambda _index: write(), range(8)))
    assert len(set(results)) == 1
    assert len(SQLiteStorage(path).slot_history("slot:state")) == 1


def test_19_concurrent_conflicting_identity_has_one_winner_and_one_rejection(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    SQLiteStorage(path)

    def define(statement: str) -> str:
        try:
            SQLiteStorage(path).define_claim(
                ClaimDefinition("same", statement, VERIFIER_ID),
                verifier_version=VERIFIER_VERSION,
            )
        except StorageConflictError:
            return "conflict"
        return "stored"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(define, ("one", "two")))
    assert sorted(results) == ["conflict", "stored"]


def test_20_future_schema_fails_closed_without_resetting_existing_data(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE sentinel(value TEXT NOT NULL)")
    connection.execute("INSERT INTO sentinel VALUES ('preserve-me')")
    connection.execute(
        f"CREATE TABLE {DURABLE_STORAGE_SCHEMA_TABLE}(singleton INTEGER PRIMARY KEY, version INTEGER NOT NULL)"
    )
    connection.execute(
        f"INSERT INTO {DURABLE_STORAGE_SCHEMA_TABLE} VALUES (1, ?)",
        (DURABLE_STORAGE_SCHEMA_VERSION + 1,),
    )
    connection.commit()
    connection.close()

    with pytest.raises(StorageSchemaVersionError):
        SQLiteStorage(path)
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("SELECT value FROM sentinel").fetchone() == ("preserve-me",)
    finally:
        connection.close()


def test_21_failed_migration_rolls_back_bootstrap_transaction(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"

    def fail_migration(connection: sqlite3.Connection) -> None:
        connection.execute("CREATE TABLE migration_probe(value TEXT)")
        raise RuntimeError("injected migration failure")

    with pytest.raises(StorageMigrationError):
        SQLiteStorage(path, migration_hooks={1: fail_migration})
    connection = sqlite3.connect(path)
    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert "migration_probe" not in tables
        assert DURABLE_STORAGE_SCHEMA_TABLE not in tables
    finally:
        connection.close()


def test_22_claim_dependency_cycles_are_rejected_without_changing_current_basis(tmp_path: Path) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    _, _, bundle_a, _ = _store_evidence_and_bundle(
        db, _evidence(1, evidence_id="evidence:A"), slot_id="slot:A"
    )
    _record_claim(db, "A", bundle_a)
    bundle_b = _bundle(claim_dependencies=("A",))
    db.put_bundle(bundle_b)
    _record_claim(db, "B", bundle_b)
    original_a = db.claim_status("A")

    cyclic_bundle_a = _bundle(claim_dependencies=("B",))
    db.put_bundle(cyclic_bundle_a)
    with pytest.raises(DependencyCycleError):
        db.record_claim("A", cyclic_bundle_a, verifier_version=VERIFIER_VERSION)
    assert db.claim_status("A") == original_a


def test_23_sessions_persist_exact_graph_plan_execution_statuses_termination_and_counters(tmp_path: Path) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    fixture = _execution_fixture()
    result = execute_verification_plan(fixture.request, storage=db)
    stored = db.get_session(result.session.fingerprint)
    assert stored.session_document == result.session.to_dict()
    assert stored.graph_fingerprint == result.claim_graph_fingerprint
    assert stored.plan_fingerprint == result.plan_fingerprint
    assert stored.execution_fingerprint == result.fingerprint
    assert stored.execution_document == result.to_dict()
    assert stored.termination == result.session.termination_reason.value
    assert stored.counters == result.session.consumption.to_dict()
    assert stored.current


def test_24_sessions_distinguish_historical_from_current_after_reverification(tmp_path: Path) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    _, _, first_bundle, _ = _store_evidence_and_bundle(db, _evidence(1), slot_id="slot:state")
    _record_claim(db, "A", first_bundle)
    first = _session_for(db, {"A": first_bundle}, execution_fingerprint="a" * 64)
    _, _, second_bundle, _ = _store_evidence_and_bundle(db, _evidence(2), slot_id="slot:state")
    db.record_claim("A", second_bundle, verifier_version=VERIFIER_VERSION)
    second = _session_for(db, {"A": second_bundle}, execution_fingerprint="b" * 64)
    assert {item.fingerprint for item in db.current_sessions()} == {second.fingerprint}
    assert first.fingerprint in {item.fingerprint for item in db.historical_sessions()}


def test_25_task19_executor_records_completed_session_bundle_claim_atomically(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    db = SQLiteStorage(path)
    fixture = _execution_fixture()
    expected = execute_verification_plan(_execution_fixture().request)
    result = execute_verification_plan(fixture.request, storage=db)
    assert result.fingerprint == expected.fingerprint
    assert result.session.fingerprint == expected.session.fingerprint
    assert result.session.root_verdicts == {"executor:claim": VerificationVerdict.PASS}
    assert db.claim_status("executor:claim").effective_verdict is VerificationVerdict.PASS
    bundle = next(iter(result.bundles.values()))
    assert db.get_bundle(bundle.fingerprint).current
    slot_identity = next(
        iter(result.provider_results.values())
    ).evidence_slot_identities[0]
    assert db.get_slot("executor:evidence") is None
    stored_evidence = db.get_evidence_by_slot(slot_identity.slot_id)
    assert stored_evidence.source_snapshot["revision"] == "executor-revision-A"
    assert stored_evidence.coverage["completeness"] == "COMPLETE"
    reopened = SQLiteStorage(path)
    assert reopened.get_session(result.session.fingerprint).current


def test_26_executor_storage_failure_raises_and_never_returns_unstored_pass() -> None:
    fixture = _execution_fixture()

    class FailingStorage:
        def record_execution(self, _request: Any, _result: Any) -> None:
            raise StorageIntegrityError("injected durable failure")

    with pytest.raises(VerificationExecutionError, match="durable"):
        execute_verification_plan(fixture.request, storage=FailingStorage())


def test_27_task20_falsification_result_and_claim_basis_persist_exactly(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    db = SQLiteStorage(path)
    fixture = _falsification_fixture()
    expected = execute_verification_plan(_falsification_fixture().request)
    result = execute_verification_plan(fixture.request, storage=db)
    assert result.fingerprint == expected.fingerprint
    assert result.session.fingerprint == expected.session.fingerprint
    falsification = next(iter(result.falsification_results.values()))
    stored = db.get_falsification_result(falsification.fingerprint)
    assert stored.result == falsification
    claim = db.claim_history(fixture.claim.claim_id)[-1]
    assert claim.falsification_fingerprints == (falsification.fingerprint,)
    del db
    assert SQLiteStorage(path).get_falsification_result(falsification.fingerprint).result == falsification


def test_28_falsification_evidence_dependency_invalidates_claim_and_session(tmp_path: Path) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    fixture = _falsification_fixture()
    result = execute_verification_plan(fixture.request)
    falsification = next(iter(result.falsification_results.values()))
    evidence = _evidence(1, evidence_id="falsification:input")
    db.put_evidence(evidence, slot_id="slot:falsification-input")
    slot = db.get_slot("slot:falsification-input")
    db.put_falsification_result(falsification, evidence_slots=(slot,))
    pass_bundle = next(iter(result.bundles.values()))
    db.put_bundle(pass_bundle)
    db.define_claim(
        ClaimDefinition(
            fixture.claim.claim_id,
            json.dumps(fixture.claim.semantic_definition(), sort_keys=True),
            fixture.claim.verifier,
        ),
        verifier_version="1",
    )
    db.record_claim(
        fixture.claim.claim_id,
        pass_bundle,
        verifier_version="1",
        falsification_fingerprints=(falsification.fingerprint,),
    )
    stored_session = db.put_session(
        result.session,
        plan_fingerprint=result.plan_fingerprint,
        execution_fingerprint=result.fingerprint,
        falsification_fingerprints=(falsification.fingerprint,),
    )

    db.put_evidence(
        _evidence(2, evidence_id="falsification:input"),
        slot_id="slot:falsification-input",
    )
    assert not db.get_falsification_result(falsification.fingerprint).current
    assert not db.claim_status(fixture.claim.claim_id).current
    assert not db.get_session(stored_session.fingerprint).current


def test_29_cache_clear_is_not_authoritative_and_cannot_hide_database_corruption(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    db = SQLiteStorage(path)
    stored = db.put_evidence(_evidence())
    assert db.get_evidence(stored.fingerprint).fingerprint == stored.fingerprint
    _tamper(
        path,
        "UPDATE evidence_artifacts SET canonical_json = '{}' WHERE fingerprint = ?",
        (stored.fingerprint,),
    )
    db.clear_cache()
    with pytest.raises(StorageIntegrityError):
        db.get_evidence(stored.fingerprint)


def test_30_corrupted_claim_report_basis_cannot_be_observed_as_pass(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    db = SQLiteStorage(path)
    _, _, bundle, _ = _store_evidence_and_bundle(db, _evidence(), slot_id="slot:state")
    claim = _record_claim(db, "A", bundle)
    _tamper(
        path,
        "UPDATE claim_versions SET verdict = 'UNKNOWN' WHERE claim_id = ? AND version = ?",
        (claim.claim_id, claim.version),
    )
    with pytest.raises(StorageIntegrityError):
        db.claim_status("A")


def test_31_schema_and_records_are_generic_without_product_or_ttl_fields(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    SQLiteStorage(path)
    connection = sqlite3.connect(path)
    try:
        schema = "\n".join(
            str(row[0])
            for row in connection.execute(
                "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name"
            )
        ).lower()
    finally:
        connection.close()
    for forbidden in ("graphify", "bugzero", "tenant_id", "product_id", "expires_at", "ttl"):
        assert forbidden not in schema


def test_32_reverse_dependency_lookup_uses_index_without_serialized_session_scan(tmp_path: Path) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    written = db.put_evidence(_evidence(), slot_id="slot:state")
    slot = db.get_slot("slot:state")
    plan = " ".join(db.explain_reverse_dependency_lookup(slot.object_key)).lower()
    assert "idx_object_dependencies_dependency" in plan
    assert "sessions" not in plan
    assert written.slot_version == 1


def test_33_executor_uses_explicit_caller_owned_unit_of_work_and_outer_rollback(tmp_path: Path) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    fixture = _execution_fixture()
    with pytest.raises(RuntimeError, match="outer rollback"):
        with db.unit_of_work() as uow:
            result = execute_verification_plan(
                fixture.request,
                unit_of_work=uow,
            )
            assert result.session.root_verdicts == {
                "executor:claim": VerificationVerdict.PASS
            }
            assert (
                uow.claim_status("executor:claim").effective_verdict
                is VerificationVerdict.PASS
            )
            raise RuntimeError("outer rollback")
    with pytest.raises(StorageNotFoundError):
        db.claim_status("executor:claim")
