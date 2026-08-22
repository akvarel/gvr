from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
from typing import Any, Mapping

import pytest

import gvr
from gvr import (
    COUNTEREXAMPLE_SEARCH_STRATEGY_ID,
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
    FalsificationRequirement,
    FalsificationStrategyBinding,
    FalsificationStrategyCapabilityRegistry,
    SQLiteStorage,
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
    builtin_falsification_strategy_capability_registry,
    builtin_falsification_strategy_runtime_registry,
    compile_verification_plan,
    execute_verification_plan,
)


VERIFIER_ID = "fixture.task22.verifier"
RAW_EVIDENCE_ID = "shared-raw-id"


@dataclass(frozen=True)
class _ProviderBehavior:
    value: Any = True
    evidence_source: str = "semantic-source"
    producer_fingerprint: str = "producer:stable"
    replaceable: bool = True


class _ProviderRuntime:
    def __init__(
        self,
        capability: EvidenceProviderCapability,
        behavior: _ProviderBehavior,
    ) -> None:
        self.provider_id = capability.provider_id
        self.version = capability.version
        self.capability = capability
        self.behavior = behavior

    def acquire(self, request: EvidenceRequest) -> EvidenceProviderResult:
        evidence = Evidence(
            id=RAW_EVIDENCE_ID,
            kind="fixture.state",
            payload={"value": self.behavior.value},
            source=self.behavior.evidence_source,
            fingerprint=self.behavior.producer_fingerprint,
        )
        slot_identities: tuple[Any, ...] = ()
        slot_identity_factory = getattr(request, "evidence_slot_identity", None)
        if self.behavior.replaceable and slot_identity_factory is not None:
            slot_identities = (
                slot_identity_factory(
                    evidence.id,
                    source_identity=request.source_context,
                ),
            )
        result_kwargs: dict[str, Any] = {}
        if slot_identities:
            result_kwargs["evidence_slot_identities"] = slot_identities
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
            **result_kwargs,
        )


class _VerifierRuntime:
    def __init__(self, capability: VerifierCapability) -> None:
        self.verifier_id = capability.verifier_id
        self.version = capability.version
        self.capability = capability

    def verify(self, verifier_input: Any) -> VerificationReport:
        return VerificationReport(
            verdict=VerificationVerdict.PASS,
            verifier=self.verifier_id,
            evidence_ids=tuple(item.id for item in verifier_input.evidence),
        )


@dataclass(frozen=True)
class _ExecutionFixture:
    request: VerificationExecutionRequest
    evidence_request: EvidenceRequest


def _execution_fixture(
    *,
    claim_id: str = "claim-a",
    request_id: str = "request-a",
    provider_id: str = "fixture.task22.provider",
    provider_version: str = "1",
    source_identity: Mapping[str, Any] | None = None,
    snapshot_identity: Mapping[str, Any] | None = None,
    request_spec: Mapping[str, Any] | None = None,
    semantic_scope: Mapping[str, Any] | None = None,
    behavior: _ProviderBehavior = _ProviderBehavior(),
    correlation_id: str | None = None,
    with_falsification: bool = False,
) -> _ExecutionFixture:
    source = dict(source_identity or {"repository": "repo-a"})
    snapshot = dict(snapshot_identity or {"revision": "rev-a"})
    scope = dict(semantic_scope or source)
    spec = dict(request_spec or {"field": "ready"})

    falsification_descriptor = None
    falsification_capabilities = None
    falsification_bindings: tuple[FalsificationStrategyBinding, ...] = ()
    accepted_falsification_kinds: tuple[str, ...] = ()
    falsification_requirement = FalsificationRequirement.NONE
    claim_kind = "ASSERT_STATE"
    claim_spec: Mapping[str, Any] = {"expected": True}
    if with_falsification:
        falsification_descriptor = (
            builtin_falsification_strategy_capability_registry().lookup(
                COUNTEREXAMPLE_SEARCH_STRATEGY_ID,
                "1",
            )
        )
        falsification_capabilities = FalsificationStrategyCapabilityRegistry(
            (falsification_descriptor,)
        )
        accepted_falsification_kinds = (falsification_descriptor.strategy_kind,)
        falsification_requirement = FalsificationRequirement.REQUIRED_BEFORE_PASS
        claim_kind = "gvr.text.sequence_predicate"
        claim_spec = {"candidate": "fixture"}
        falsification_bindings = (
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

    verifier_capability = VerifierCapability(
        verifier_id=VERIFIER_ID,
        version="1",
        claim_kinds=(claim_kind,),
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
        accepted_falsification_strategy_kinds=accepted_falsification_kinds,
        falsification_requirement=falsification_requirement,
    )
    provider_capability = EvidenceProviderCapability(
        provider_id=provider_id,
        version=provider_version,
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
    verifier_capabilities = VerifierCapabilityRegistry((verifier_capability,))
    provider_capabilities = EvidenceProviderCapabilityRegistry((provider_capability,))
    claim = AtomicClaim(
        claim_id=claim_id,
        claim_kind=claim_kind,
        spec=claim_spec,
        verifier=VERIFIER_ID,
    )
    graph = ClaimGraph(nodes=(claim,))
    evidence_request = EvidenceRequest(
        request_id=request_id,
        provider_id=provider_id,
        provider_version=provider_version,
        request_kind="CAPTURE_STATE",
        requested_evidence_kinds=("fixture.state",),
        subject={"entity": "shared-subject"},
        spec=spec,
        semantic_scope=scope,
        source_context=source,
        snapshot_context=snapshot,
        bounds={"max_items": 10},
        source_class="repository",
        snapshot_class="revision",
    )
    binding = AtomicClaimBinding(
        claim_id=claim_id,
        verifier_id=VERIFIER_ID,
        verifier_version="1",
        verifier_capability_fingerprint=verifier_capability.fingerprint,
        evidence_requests=(evidence_request,),
        falsification_bindings=falsification_bindings,
    )
    planning_request = VerificationPlanningRequest(
        claim_graph=graph,
        bindings=(binding,),
        verifier_capability_registry=verifier_capabilities,
        verifier_capability_registry_fingerprint=verifier_capabilities.fingerprint,
        evidence_provider_capability_registry=provider_capabilities,
        evidence_provider_capability_registry_fingerprint=provider_capabilities.fingerprint,
        falsification_strategy_capability_registry=falsification_capabilities,
        falsification_strategy_capability_registry_fingerprint=(
            None
            if falsification_capabilities is None
            else falsification_capabilities.fingerprint
        ),
    )
    plan = compile_verification_plan(planning_request)
    execution_request = VerificationExecutionRequest(
        plan=plan,
        plan_fingerprint=plan.fingerprint,
        claim_graph=graph,
        claim_graph_fingerprint=graph.fingerprint,
        roots=(claim_id,),
        verifier_runtime_registry=VerifierRuntimeRegistry(
            capability_registry=verifier_capabilities,
            runtime_verifiers={
                (VERIFIER_ID, "1"): _VerifierRuntime(verifier_capability)
            },
        ),
        verifier_capability_registry_fingerprint=verifier_capabilities.fingerprint,
        evidence_provider_runtime_registry=EvidenceProviderRuntimeRegistry(
            capability_registry=provider_capabilities,
            runtime_providers={
                (provider_id, provider_version): _ProviderRuntime(
                    provider_capability,
                    behavior,
                )
            },
        ),
        evidence_provider_capability_registry_fingerprint=provider_capabilities.fingerprint,
        evidence_requests={
            (evidence_request.request_id, evidence_request.fingerprint): evidence_request
        },
        falsification_strategy_runtime_registry=(
            None
            if falsification_capabilities is None
            else builtin_falsification_strategy_runtime_registry(
                falsification_capabilities
            )
        ),
        falsification_strategy_capability_registry_fingerprint=(
            None
            if falsification_capabilities is None
            else falsification_capabilities.fingerprint
        ),
        limits=VerificationExecutionLimits(),
        correlation_id=correlation_id,
    )
    return _ExecutionFixture(execution_request, evidence_request)


def _record(db: SQLiteStorage, **kwargs: Any):
    fixture = _execution_fixture(**kwargs)
    result = execute_verification_plan(fixture.request, storage=db)
    return fixture, result


def _slot_identity(result: Any) -> Any:
    provider_result = next(iter(result.provider_results.values()))
    identities = provider_result.evidence_slot_identities
    assert len(identities) == 1
    return identities[0]


def _current_session_records(db: SQLiteStorage, session_fingerprint: str) -> tuple[Any, ...]:
    return tuple(
        item
        for item in db.session_record_history(session_fingerprint)
        if item.current
    )


def _drop_v2_tables_and_project_raw_legacy_slot(path: Path) -> None:
    v2_tables = (
        "session_execution_observations",
        "session_record_falsification_links",
        "session_record_bundle_links",
        "session_record_claim_links",
        "session_records",
        "claim_falsification_record_links",
        "claim_evidence_dependency_links",
        "claim_bundle_record_links",
        "falsification_record_evidence_links",
        "falsification_records",
        "bundle_record_evidence_links",
        "bundle_records",
        "evidence_slot_identities",
    )
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        row = connection.execute(
            "SELECT slot_id FROM evidence_slots ORDER BY slot_id LIMIT 1"
        ).fetchone()
        assert row is not None
        semantic_slot_id = row[0]
        for table in (
            "evidence_slot_versions",
            "evidence_slots",
            "bundle_evidence_links",
            "claim_evidence_links",
            "falsification_evidence_links",
        ):
            columns = {
                item[1]
                for item in connection.execute(f"PRAGMA table_info({table})")
            }
            if "slot_id" in columns:
                connection.execute(
                    f"UPDATE {table} SET slot_id = ? WHERE slot_id = ?",
                    (RAW_EVIDENCE_ID, semantic_slot_id),
                )
        connection.execute(
            "UPDATE object_dependencies "
            "SET dependency_key = replace(dependency_key, ?, ?) "
            "WHERE dependency_key LIKE ?",
            (semantic_slot_id, RAW_EVIDENCE_ID, f"slot-version:{semantic_slot_id}:%"),
        )
        for row in connection.execute(
            "SELECT claim_id, version, content_json FROM claim_versions"
        ).fetchall():
            document = json.loads(row[2])
            document["schema_version"] = 1
            document.pop("bundle_record_fingerprint", None)
            document.pop("evidence_dependencies", None)
            document.pop("falsification_record_fingerprints", None)
            for slot in document.get("evidence_slots", ()):
                slot["slot_id"] = RAW_EVIDENCE_ID
            content = json.dumps(
                document,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            canonical = gvr.canonical_json(
                document,
                fingerprint_format="gvr.storage.claim_basis.ieee754-json.v1",
            )
            digest = gvr.canonical_fingerprint(
                document,
                fingerprint_format="gvr.storage.claim_basis.ieee754-json.v1",
            )
            connection.execute(
                """
                UPDATE claim_versions
                SET content_json = ?, canonical_json = ?,
                    content_digest = ?, basis_fingerprint = ?
                WHERE claim_id = ? AND version = ?
                """,
                (content, canonical, digest, digest, row[0], row[1]),
            )
        for table in v2_tables:
            connection.execute(f"DROP TABLE IF EXISTS {table}")
        connection.execute(
            f"UPDATE {gvr.DURABLE_STORAGE_SCHEMA_TABLE} SET version = 1 "
            "WHERE singleton = 1"
        )
        connection.commit()
    finally:
        connection.close()


# Matrix A: audit correlation is nonsemantic to durable truth identity.
def test_task22_01_request_id_only_change_is_same_slot_version_and_current_basis(
    tmp_path: Path,
) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    first_fixture, first = _record(db, request_id="request-a")
    _, second = _record(db, request_id="request-b")

    first_identity = _slot_identity(first)
    second_identity = _slot_identity(second)
    first_provider_result = next(iter(first.provider_results.values()))
    second_provider_result = next(iter(second.provider_results.values()))
    assert first_identity == second_identity
    assert first_provider_result.request_fingerprint == second_provider_result.request_fingerprint
    assert first_provider_result.fingerprint == second_provider_result.fingerprint
    assert first_identity.slot_id != RAW_EVIDENCE_ID
    assert db.get_slot(RAW_EVIDENCE_ID) is None
    assert len(db.slot_history(first_identity.slot_id)) == 1
    assert db.invalidation_events() == ()
    assert len(db.claim_history("claim-a")) == 1
    assert db.claim_status("claim-a").current
    assert first.session.fingerprint == second.session.fingerprint
    assert len(_current_session_records(db, first.session.fingerprint)) == 1
    observations = db.session_execution_observations(first.session.fingerprint)
    assert {item.request_ids for item in observations} == {
        ("request-a",),
        ("request-b",),
    }
    capability = (
        first_fixture.request.evidence_provider_runtime_registry
        .capability_registry.lookup(
            first_provider_result.provider_id,
            first_provider_result.provider_version,
        )
    )
    protocol = gvr.handle_request({
        "schema_version": 1,
        "op": "validate_evidence_provider_result",
        "payload": {
            "request": first_fixture.evidence_request.to_dict(),
            "capability": capability.to_dict(),
            "result": first_provider_result.to_dict(),
        },
    })
    assert protocol["payload"]["evidence_slot_identities"][0]["slot_id"] == (
        first_identity.slot_id
    )


def test_task22_02_execution_correlation_only_is_audit_not_slot_or_session_basis(
    tmp_path: Path,
) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    _, first = _record(db, correlation_id="trace-a")
    _, second = _record(db, correlation_id="trace-b")

    identity = _slot_identity(first)
    assert _slot_identity(second) == identity
    assert first.fingerprint == second.fingerprint
    assert first.session.fingerprint == second.session.fingerprint
    assert len(db.slot_history(identity.slot_id)) == 1
    assert db.invalidation_events() == ()
    assert len(db.claim_history("claim-a")) == 1
    assert len(_current_session_records(db, first.session.fingerprint)) == 1
    assert {
        item.correlation_id
        for item in db.session_execution_observations(first.session.fingerprint)
    } == {"trace-a", "trace-b"}


# Matrix B: raw producer IDs are scoped by canonical provider/source/request semantics.
def test_task22_03_same_raw_id_in_different_sources_never_collides(
    tmp_path: Path,
) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    _, first = _record(
        db,
        claim_id="claim-a",
        request_id="request-a",
        source_identity={"repository": "repo-a"},
        snapshot_identity={"revision": "same"},
    )
    _, second = _record(
        db,
        claim_id="claim-b",
        request_id="request-b",
        source_identity={"repository": "repo-b"},
        snapshot_identity={"revision": "same"},
    )

    first_identity = _slot_identity(first)
    second_identity = _slot_identity(second)
    assert first_identity.slot_id != second_identity.slot_id
    assert db.get_slot(RAW_EVIDENCE_ID) is None
    assert len(db.slot_history(first_identity.slot_id)) == 1
    assert len(db.slot_history(second_identity.slot_id)) == 1
    assert db.invalidation_events() == ()
    assert db.claim_status("claim-a").current
    assert db.claim_status("claim-b").current
    assert db.get_session(first.session.fingerprint).current
    assert db.get_session(second.session.fingerprint).current


def test_task22_04_same_raw_id_in_different_request_parameters_never_collides(
    tmp_path: Path,
) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    _, first = _record(
        db,
        claim_id="claim-a",
        request_id="request-a",
        request_spec={"field": "ready"},
    )
    _, second = _record(
        db,
        claim_id="claim-b",
        request_id="request-b",
        request_spec={"field": "enabled"},
    )

    assert _slot_identity(first).slot_id != _slot_identity(second).slot_id
    assert db.invalidation_events() == ()
    assert db.claim_status("claim-a").current
    assert db.claim_status("claim-b").current


def test_task22_05_same_request_id_cannot_alias_different_semantic_sources(
    tmp_path: Path,
) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    _, first = _record(
        db,
        claim_id="claim-a",
        request_id="shared-request-id",
        source_identity={"repository": "repo-a"},
    )
    _, second = _record(
        db,
        claim_id="claim-b",
        request_id="shared-request-id",
        source_identity={"repository": "repo-b"},
    )

    assert _slot_identity(first).slot_id != _slot_identity(second).slot_id
    assert db.invalidation_events() == ()
    assert db.claim_status("claim-a").current
    assert db.claim_status("claim-b").current


def test_task22_06_provider_identity_scopes_slots_but_provider_version_advances_same_slot(
    tmp_path: Path,
) -> None:
    isolated = SQLiteStorage(tmp_path / "isolated.sqlite3")
    _, provider_a = _record(
        isolated,
        claim_id="claim-a",
        provider_id="fixture.provider-a",
    )
    _, provider_b = _record(
        isolated,
        claim_id="claim-b",
        provider_id="fixture.provider-b",
    )
    assert _slot_identity(provider_a).slot_id != _slot_identity(provider_b).slot_id
    assert isolated.invalidation_events() == ()

    versioned = SQLiteStorage(tmp_path / "versioned.sqlite3")
    _, first = _record(versioned, provider_version="1")
    _, second = _record(versioned, provider_version="2")
    identity = _slot_identity(first)
    assert _slot_identity(second) == identity
    assert [item.version for item in versioned.slot_history(identity.slot_id)] == [1, 2]
    assert len(versioned.bundle_history(next(iter(first.bundles.values())).fingerprint)) == 2
    assert len(versioned.claim_history("claim-a")) == 2
    assert versioned.claim_status("claim-a").current


# Matrix C: snapshot/content replacement advances exactly once and invalidates exact dependents.
def test_task22_07_snapshot_change_with_identical_content_versions_bundle_claim_and_session_once(
    tmp_path: Path,
) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    _, first = _record(db, snapshot_identity={"revision": "rev-a"})
    _, second = _record(db, snapshot_identity={"revision": "rev-b"})
    _, replay = _record(db, snapshot_identity={"revision": "rev-b"})

    identity = _slot_identity(first)
    assert _slot_identity(second) == _slot_identity(replay) == identity
    assert [item.version for item in db.slot_history(identity.slot_id)] == [1, 2]
    assert sum(
        item.kind == "slot_version_changed"
        for item in db.invalidation_events()
    ) == 1
    bundle_fingerprint = next(iter(first.bundles.values())).fingerprint
    bundles = db.bundle_history(bundle_fingerprint)
    assert len(bundles) == 2
    assert [item.current for item in bundles] == [False, True]
    claims = db.claim_history("claim-a")
    assert len(claims) == 2
    assert [item.current for item in claims] == [False, True]
    sessions = db.session_record_history(first.session.fingerprint)
    assert len(sessions) == 2
    assert [item.current for item in sessions] == [False, True]


def test_task22_08_content_change_stales_exact_only_and_leaves_unrelated_current(
    tmp_path: Path,
) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    _, unrelated = _record(
        db,
        claim_id="claim-unrelated",
        request_id="request-unrelated",
        source_identity={"repository": "repo-unrelated"},
        behavior=_ProviderBehavior(value="unrelated"),
    )
    _, first = _record(db, behavior=_ProviderBehavior(value=1))
    _, second = _record(db, behavior=_ProviderBehavior(value=2))
    _, replay = _record(db, behavior=_ProviderBehavior(value=2))

    identity = _slot_identity(first)
    assert _slot_identity(second) == _slot_identity(replay) == identity
    assert [item.version for item in db.slot_history(identity.slot_id)] == [1, 2]
    assert sum(
        item.kind == "slot_version_changed"
        for item in db.invalidation_events()
    ) == 1
    assert len(db.claim_history("claim-a")) == 2
    assert db.claim_status("claim-a").current
    assert db.claim_status("claim-unrelated").current
    assert db.get_session(unrelated.session.fingerprint).current


def test_task22_09_falsification_tracks_exact_semantic_slot_version_transitively(
    tmp_path: Path,
) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    _, first = _record(
        db,
        snapshot_identity={"revision": "rev-a"},
        with_falsification=True,
    )
    _, second = _record(
        db,
        snapshot_identity={"revision": "rev-b"},
        with_falsification=True,
    )

    first_falsification = next(iter(first.falsification_results.values()))
    second_falsification = next(iter(second.falsification_results.values()))
    first_stored = db.get_falsification_result(first_falsification.fingerprint)
    second_stored = db.get_falsification_result(second_falsification.fingerprint)
    assert not first_stored.current
    assert second_stored.current
    assert [item.current for item in db.claim_history("claim-a")] == [False, True]
    assert [
        item.current
        for item in db.session_record_history(first.session.fingerprint)
    ] == [False, True]
    targets = {
        target
        for event in db.invalidation_events()
        for target in event.targets
    }
    assert any(target.startswith("falsification-record:") for target in targets)


# Matrix D: evidence is immutable unless acquisition explicitly declares replacement semantics.
def test_task22_10_undeclared_evidence_remains_immutable_without_fake_slots(
    tmp_path: Path,
) -> None:
    db = SQLiteStorage(tmp_path / "ledger.sqlite3")
    _, first = _record(
        db,
        claim_id="claim-a",
        request_id="request-a",
        behavior=_ProviderBehavior(value=1, replaceable=False),
    )
    _, second = _record(
        db,
        claim_id="claim-b",
        request_id="request-b",
        behavior=_ProviderBehavior(value=2, replaceable=False),
    )

    assert next(iter(first.provider_results.values())).evidence_slot_identities == ()
    assert next(iter(second.provider_results.values())).evidence_slot_identities == ()
    assert db.get_slot(RAW_EVIDENCE_ID) is None
    assert db.invalidation_events() == ()
    assert db.claim_status("claim-a").current
    assert db.claim_status("claim-b").current
    first_bundle = db.get_bundle(next(iter(first.bundles.values())).fingerprint)
    second_bundle = db.get_bundle(next(iter(second.bundles.values())).fingerprint)
    assert all(not dependency.replaceable for dependency in first_bundle.evidence_dependencies)
    assert all(not dependency.replaceable for dependency in second_bundle.evidence_dependencies)


# Matrix E: transactional durability, migration, reopen, and replay stay fail-closed.
def test_task22_11_outer_rollback_removes_slot_advance_and_all_transitive_records(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.sqlite3"
    db = SQLiteStorage(path)
    _, first = _record(db, snapshot_identity={"revision": "rev-a"})
    identity = _slot_identity(first)

    with pytest.raises(RuntimeError, match="rollback task22"):
        with db.unit_of_work() as unit_of_work:
            fixture = _execution_fixture(snapshot_identity={"revision": "rev-b"})
            execute_verification_plan(fixture.request, unit_of_work=unit_of_work)
            assert unit_of_work.get_slot(identity.slot_id).version == 2
            assert len(unit_of_work.claim_history("claim-a")) == 2
            raise RuntimeError("rollback task22")

    reopened = SQLiteStorage(path)
    assert [item.version for item in reopened.slot_history(identity.slot_id)] == [1]
    assert reopened.invalidation_events() == ()
    assert len(reopened.claim_history("claim-a")) == 1
    assert len(reopened.session_record_history(first.session.fingerprint)) == 1
    assert reopened.claim_status("claim-a").current


def test_task22_12_v1_migration_marks_ambiguous_raw_slots_stale_and_restart_replay_is_idempotent(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.sqlite3"
    db = SQLiteStorage(path)
    _, first = _record(db)
    first_session = first.session.fingerprint
    _drop_v2_tables_and_project_raw_legacy_slot(path)

    def fail_migration(connection: sqlite3.Connection) -> None:
        connection.execute(
            "CREATE TABLE task22_migration_must_rollback(value INTEGER)"
        )
        raise RuntimeError("injected task22 migration failure")

    with pytest.raises(gvr.StorageMigrationError):
        SQLiteStorage(path, migration_hooks={2: fail_migration})
    connection = sqlite3.connect(path)
    try:
        assert connection.execute(
            f"SELECT version FROM {gvr.DURABLE_STORAGE_SCHEMA_TABLE} "
            "WHERE singleton = 1"
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE type = 'table' AND name = 'task22_migration_must_rollback'"
        ).fetchone() is None
        assert connection.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE type = 'table' AND name = 'evidence_slot_identities'"
        ).fetchone() is None
    finally:
        connection.close()

    migrated = SQLiteStorage(path)
    assert migrated.schema_version == gvr.DURABLE_STORAGE_SCHEMA_VERSION == 3
    ambiguous = migrated.get_slot(RAW_EVIDENCE_ID)
    assert ambiguous is not None
    assert not ambiguous.current
    assert not migrated.claim_status("claim-a").current
    assert not migrated.get_session(first_session).current

    _, repaired = _record(migrated)
    repaired_identity = _slot_identity(repaired)
    assert repaired_identity.slot_id != RAW_EVIDENCE_ID
    assert migrated.get_slot(RAW_EVIDENCE_ID).current is False
    assert migrated.get_slot(repaired_identity.slot_id).current
    before = (
        tuple(migrated.slot_history(repaired_identity.slot_id)),
        tuple(migrated.invalidation_events()),
        tuple(migrated.claim_history("claim-a")),
        tuple(migrated.session_record_history(repaired.session.fingerprint)),
    )

    reopened = SQLiteStorage(path)
    _, replay = _record(reopened)
    assert _slot_identity(replay) == repaired_identity
    after = (
        tuple(reopened.slot_history(repaired_identity.slot_id)),
        tuple(reopened.invalidation_events()),
        tuple(reopened.claim_history("claim-a")),
        tuple(reopened.session_record_history(repaired.session.fingerprint)),
    )
    assert after == before
    assert reopened.claim_status("claim-a").current
    assert reopened.get_session(repaired.session.fingerprint).current
