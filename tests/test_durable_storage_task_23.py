from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
import sqlite3
from typing import Any

import pytest

import gvr
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
    EvidenceProviderError,
    EvidenceProviderResult,
    EvidenceProviderRuntimeRegistry,
    EvidenceRequest,
    ProtocolError,
    SQLiteStorage,
    StorageIntegrityError,
    VerificationExecutionError,
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


PROVIDER_ID = "fixture.task23.provider"
VERIFIER_ID = "fixture.task23.verifier"
RAW_EVIDENCE_ID = "task23-shared-raw-id"


@dataclass(frozen=True)
class _Acquisition:
    request_id: str
    repository: str
    field: str
    revision: str


class _ProviderRuntime:
    def __init__(self, capability: EvidenceProviderCapability) -> None:
        self.provider_id = capability.provider_id
        self.version = capability.version
        self.capability = capability

    def acquire(self, request: EvidenceRequest) -> EvidenceProviderResult:
        evidence = Evidence(
            id=RAW_EVIDENCE_ID,
            kind="fixture.state",
            payload={"value": "same-immutable-content"},
            source="task23-provider",
            fingerprint="task23-producer-fingerprint",
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
        assert len(verifier_input.acquisitions) == 2
        return VerificationReport(
            verdict=VerificationVerdict.PASS,
            verifier=self.verifier_id,
            evidence_ids=tuple(item.id for item in verifier_input.evidence),
        )


def _execution_request(
    acquisitions: tuple[_Acquisition, ...],
) -> VerificationExecutionRequest:
    assert len(acquisitions) >= 2
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
    verifier_capabilities = VerifierCapabilityRegistry((verifier_capability,))
    provider_capabilities = EvidenceProviderCapabilityRegistry((provider_capability,))
    claim = AtomicClaim(
        claim_id="claim-task23",
        claim_kind="ASSERT_STATE",
        spec={"expected": True},
        verifier=VERIFIER_ID,
    )
    graph = ClaimGraph(nodes=(claim,))
    evidence_requests = tuple(
        EvidenceRequest(
            request_id=item.request_id,
            provider_id=PROVIDER_ID,
            provider_version="1",
            request_kind="CAPTURE_STATE",
            requested_evidence_kinds=("fixture.state",),
            subject={"entity": "shared-subject"},
            spec={"field": item.field},
            semantic_scope={"repository": item.repository},
            source_context={"repository": item.repository},
            snapshot_context={"revision": item.revision},
            bounds={"max_items": 10},
            source_class="repository",
            snapshot_class="revision",
        )
        for item in acquisitions
    )
    binding = AtomicClaimBinding(
        claim_id=claim.claim_id,
        verifier_id=VERIFIER_ID,
        verifier_version="1",
        verifier_capability_fingerprint=verifier_capability.fingerprint,
        evidence_requests=evidence_requests,
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
    return VerificationExecutionRequest(
        plan=plan,
        plan_fingerprint=plan.fingerprint,
        claim_graph=graph,
        claim_graph_fingerprint=graph.fingerprint,
        roots=(claim.claim_id,),
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
                (PROVIDER_ID, "1"): _ProviderRuntime(provider_capability),
            },
        ),
        evidence_provider_capability_registry_fingerprint=provider_capabilities.fingerprint,
        evidence_requests={
            (item.request_id, item.fingerprint): item
            for item in evidence_requests
        },
        limits=VerificationExecutionLimits(),
    )


def _slot_by_repository(result: Any) -> dict[str, Any]:
    slots: dict[str, Any] = {}
    for provider_result in result.provider_results.values():
        assert len(provider_result.evidence_slot_identities) == 1
        identity = provider_result.evidence_slot_identities[0]
        repository = str(identity.source_identity["repository"])
        slots[repository] = identity
    return slots


def _dependency_set(dependencies: tuple[Any, ...]) -> set[tuple[str, int]]:
    return {
        (item.slot.slot_id, item.slot.version)
        for item in dependencies
        if item.slot is not None
    }


def _project_dependency_tables_to_v2(path: Path) -> None:
    table_definitions = {
        "bundle_record_evidence_links": """
            CREATE TABLE bundle_record_evidence_links (
                record_fingerprint TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                evidence_fingerprint TEXT NOT NULL,
                dependency_kind TEXT NOT NULL
                    CHECK (dependency_kind IN ('IMMUTABLE', 'SLOT')),
                slot_id TEXT,
                slot_version INTEGER,
                ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                PRIMARY KEY (record_fingerprint, evidence_id),
                UNIQUE (record_fingerprint, ordinal),
                CHECK (
                    (dependency_kind = 'IMMUTABLE'
                     AND slot_id IS NULL AND slot_version IS NULL)
                    OR
                    (dependency_kind = 'SLOT'
                     AND slot_id IS NOT NULL AND slot_version IS NOT NULL)
                )
            )
        """,
        "falsification_record_evidence_links": """
            CREATE TABLE falsification_record_evidence_links (
                record_fingerprint TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                evidence_fingerprint TEXT NOT NULL,
                dependency_kind TEXT NOT NULL
                    CHECK (dependency_kind IN ('IMMUTABLE', 'SLOT')),
                slot_id TEXT,
                slot_version INTEGER,
                ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                PRIMARY KEY (record_fingerprint, evidence_id),
                UNIQUE (record_fingerprint, ordinal),
                CHECK (
                    (dependency_kind = 'IMMUTABLE'
                     AND slot_id IS NULL AND slot_version IS NULL)
                    OR
                    (dependency_kind = 'SLOT'
                     AND slot_id IS NOT NULL AND slot_version IS NOT NULL)
                )
            )
        """,
        "claim_evidence_dependency_links": """
            CREATE TABLE claim_evidence_dependency_links (
                claim_id TEXT NOT NULL,
                claim_version INTEGER NOT NULL,
                evidence_id TEXT NOT NULL,
                evidence_fingerprint TEXT NOT NULL,
                dependency_kind TEXT NOT NULL
                    CHECK (dependency_kind IN ('IMMUTABLE', 'SLOT')),
                slot_id TEXT,
                slot_version INTEGER,
                ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                PRIMARY KEY (claim_id, claim_version, evidence_id),
                UNIQUE (claim_id, claim_version, ordinal),
                CHECK (
                    (dependency_kind = 'IMMUTABLE'
                     AND slot_id IS NULL AND slot_version IS NULL)
                    OR
                    (dependency_kind = 'SLOT'
                     AND slot_id IS NOT NULL AND slot_version IS NOT NULL)
                )
            )
        """,
    }
    indexes = {
        "bundle_record_evidence_links": (
            "idx_bundle_record_slot",
            "slot_id, slot_version",
        ),
        "falsification_record_evidence_links": (
            "idx_falsification_record_slot",
            "slot_id, slot_version",
        ),
        "claim_evidence_dependency_links": (
            "idx_claim_evidence_dependency_slot",
            "slot_id, slot_version",
        ),
    }
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("BEGIN IMMEDIATE")
        for table, definition in table_definitions.items():
            index_name, columns = indexes[table]
            connection.execute(f"DROP INDEX IF EXISTS {index_name}")
            connection.execute(f"ALTER TABLE {table} RENAME TO {table}_v3")
            connection.execute(definition)
            if table.startswith("claim_"):
                connection.execute(f"""
                    INSERT INTO {table}(
                        claim_id, claim_version, evidence_id,
                        evidence_fingerprint, dependency_kind,
                        slot_id, slot_version, ordinal
                    )
                    SELECT claim_id, claim_version, evidence_id,
                           evidence_fingerprint, dependency_kind,
                           slot_id, slot_version, ordinal
                    FROM {table}_v3
                """)
            else:
                connection.execute(f"""
                    INSERT INTO {table}(
                        record_fingerprint, evidence_id,
                        evidence_fingerprint, dependency_kind,
                        slot_id, slot_version, ordinal
                    )
                    SELECT record_fingerprint, evidence_id,
                           evidence_fingerprint, dependency_kind,
                           slot_id, slot_version, ordinal
                    FROM {table}_v3
                """)
            connection.execute(f"DROP TABLE {table}_v3")
            connection.execute(
                f"CREATE INDEX {index_name} ON {table}({columns})"
            )
        connection.execute(
            f"UPDATE {gvr.DURABLE_STORAGE_SCHEMA_TABLE} "
            "SET version = 2 WHERE singleton = 1"
        )
        connection.commit()
    finally:
        connection.close()


class _AuditProviderRuntime:
    def __init__(
        self,
        capability: EvidenceProviderCapability,
        metadata: dict[str, Any],
    ) -> None:
        self.provider_id = capability.provider_id
        self.version = capability.version
        self.capability = capability
        self.metadata = metadata

    def acquire(self, request: EvidenceRequest) -> EvidenceProviderResult:
        evidence = Evidence(
            id="shared-raw-id",
            kind="fixture.state",
            payload={"value": True},
            source="semantic-source",
            fingerprint="producer:stable",
        )
        audit_type = getattr(gvr, "AuditObservation")
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
                details={"semantic_sample_count": 1},
                audit=audit_type(metadata=self.metadata),
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


def _task22_request_with_audit(
    metadata: dict[str, Any],
) -> tuple[VerificationExecutionRequest, EvidenceRequest, EvidenceProviderCapability]:
    from test_durable_storage_slot_identity import _execution_fixture

    fixture = _execution_fixture(with_falsification=True)
    original = fixture.request
    capability = (
        original.evidence_provider_runtime_registry.capability_registry.lookup(
            fixture.evidence_request.provider_id,
            fixture.evidence_request.provider_version,
        )
    )
    runtime_registry = EvidenceProviderRuntimeRegistry(
        capability_registry=(
            original.evidence_provider_runtime_registry.capability_registry
        ),
        runtime_providers={
            (capability.provider_id, capability.version): _AuditProviderRuntime(
                capability,
                metadata,
            ),
        },
    )
    request = VerificationExecutionRequest(
        plan=original.plan,
        plan_fingerprint=original.plan_fingerprint,
        claim_graph=original.claim_graph,
        claim_graph_fingerprint=original.claim_graph_fingerprint,
        roots=original.roots,
        verifier_runtime_registry=original.verifier_runtime_registry,
        verifier_capability_registry_fingerprint=(
            original.verifier_capability_registry_fingerprint
        ),
        evidence_provider_runtime_registry=runtime_registry,
        evidence_provider_capability_registry_fingerprint=(
            original.evidence_provider_capability_registry_fingerprint
        ),
        evidence_requests=original.evidence_requests,
        falsification_strategy_runtime_registry=(
            original.falsification_strategy_runtime_registry
        ),
        falsification_strategy_capability_registry_fingerprint=(
            original.falsification_strategy_capability_registry_fingerprint
        ),
        limits=original.limits,
        correlation_id=original.correlation_id,
    )
    return request, fixture.evidence_request, capability


def _coverage(
    *,
    audit_metadata: dict[str, Any] | None = None,
    details: dict[str, Any] | None = None,
    consumed: dict[str, Any] | None = None,
    termination: dict[str, Any] | None = None,
    declared_scope: dict[str, Any] | None = None,
    observed_scope: dict[str, Any] | None = None,
    declared_bounds: dict[str, Any] | None = None,
    source_identity: dict[str, Any] | None = None,
    snapshot_identity: dict[str, Any] | None = None,
) -> EvidenceCoverage:
    audit_type = getattr(gvr, "AuditObservation")
    scope = {"repository": "repo-a"}
    return EvidenceCoverage(
        completeness=EvidenceCompleteness.COMPLETE,
        covered_evidence_kinds=("fixture.state",),
        declared_scope=scope if declared_scope is None else declared_scope,
        observed_scope=scope if observed_scope is None else observed_scope,
        declared_bounds={"max_items": 10} if declared_bounds is None else declared_bounds,
        consumed={"records": 1} if consumed is None else consumed,
        termination={"reason": "COMPLETE"} if termination is None else termination,
        termination_reason="COMPLETE",
        source_identity=scope if source_identity is None else source_identity,
        snapshot_identity=(
            {"revision": "rev-a"}
            if snapshot_identity is None
            else snapshot_identity
        ),
        details={"semantic_sample_count": 1} if details is None else details,
        audit=audit_type(metadata={} if audit_metadata is None else audit_metadata),
    )


def test_task23_01_coverage_rejects_recursive_audit_ids_and_fingerprints_semantics() -> None:
    invalid_cases = (
        ("details", {"transport": {"trace": {"id": "trace-a"}}}),
        ("details", {"transport": {"traceID": "trace-a"}}),
        ("consumed", {"runner": {"run-id": "run-a"}}),
        ("termination", {"metadata": {"correlationId": "corr-a"}}),
        ("declared_scope", {"request": {"identifier": "request-a"}}),
        ("observed_scope", {"span_id": "span-a"}),
        ("declared_bounds", {"executionRunId": "run-a"}),
        ("source_identity", {"trace_identifier": "trace-a"}),
        ("snapshot_identity", {"correlation": {"id": "corr-a"}}),
    )
    for field, value in invalid_cases:
        with pytest.raises(EvidenceProviderError, match="audit"):
            _coverage(**{field: value})

    first = _coverage(audit_metadata={
        "trace_id": "trace-a",
        "nested": {"runId": "run-a", "correlation-id": "corr-a"},
    })
    reordered = _coverage(audit_metadata={
        "nested": {"correlation-id": "corr-a", "runId": "run-a"},
        "trace_id": "trace-a",
    })
    audit_changed = _coverage(audit_metadata={
        "trace_id": "trace-b",
        "nested": {"runId": "run-b", "correlation-id": "corr-b"},
    })
    semantic_changed = _coverage(
        audit_metadata={"trace_id": "trace-a"},
        details={"semantic_sample_count": 2},
    )
    assert first.fingerprint == reordered.fingerprint == audit_changed.fingerprint
    assert first.audit.fingerprint == reordered.audit.fingerprint
    assert first.audit.fingerprint != audit_changed.audit.fingerprint
    assert first.fingerprint != semantic_changed.fingerprint


def test_task23_02_audit_only_change_is_retrievable_without_truth_churn(
    tmp_path: Path,
) -> None:
    path = tmp_path / "task23-audit.sqlite3"
    first_request, _, _ = _task22_request_with_audit({
        "trace_id": "trace-a",
        "nested": {"runId": "run-a", "correlation-id": "corr-a"},
    })
    second_request, _, _ = _task22_request_with_audit({
        "nested": {"correlation-id": "corr-b", "runId": "run-b"},
        "trace_id": "trace-b",
    })
    db = SQLiteStorage(path)
    first = execute_verification_plan(first_request, storage=db)
    second = execute_verification_plan(second_request, storage=db)

    first_provider = next(iter(first.provider_results.values()))
    second_provider = next(iter(second.provider_results.values()))
    assert first_provider.coverage.fingerprint == second_provider.coverage.fingerprint
    assert first_provider.coverage.audit.fingerprint != second_provider.coverage.audit.fingerprint
    assert first_provider.fingerprint == second_provider.fingerprint
    assert first.fingerprint == second.fingerprint
    assert first.session.fingerprint == second.session.fingerprint
    first_falsification = next(iter(first.falsification_results.values()))
    second_falsification = next(iter(second.falsification_results.values()))
    assert first_falsification.fingerprint == second_falsification.fingerprint

    identity = first_provider.evidence_slot_identities[0]
    assert len(db.slot_history(identity.slot_id)) == 1
    bundle_fingerprint = next(iter(first.bundles.values())).fingerprint
    assert len(db.bundle_history(bundle_fingerprint)) == 1
    assert len(db.falsification_history(first_falsification.fingerprint)) == 1
    assert len(db.claim_history("claim-a")) == 1
    assert len(db.session_record_history(first.session.fingerprint)) == 1
    assert db.invalidation_events() == ()
    assert db.claim_status("claim-a").current
    session = db.get_session(first.session.fingerprint)
    assert session.current

    stored_bundle = db.get_bundle(bundle_fingerprint)
    assert stored_bundle.record_fingerprint is not None
    assert len(stored_bundle.evidence_dependencies) == 1
    dependency = stored_bundle.evidence_dependencies[0]
    stored_evidence = db.get_evidence(dependency.evidence_fingerprint)
    assert "audit" not in stored_evidence.coverage
    observations = db.session_execution_observations(first.session.fingerprint)
    assert len(observations) == 2
    assert len({item.observation_fingerprint for item in observations}) == 2
    assert {
        item.session_record_fingerprint for item in observations
    } == {session.record_fingerprint}
    audit_documents = tuple(
        item.execution_document["provider_results"][0]["result"]["coverage"]["audit"]
        for item in observations
    )
    assert {item["metadata"]["trace_id"] for item in audit_documents} == {
        "trace-a",
        "trace-b",
    }
    assert {
        item["fingerprint"] for item in audit_documents
    } == {
        first_provider.coverage.audit.fingerprint,
        second_provider.coverage.audit.fingerprint,
    }


def test_task23_03_one_execution_keeps_same_raw_id_acquisitions_independent(
    tmp_path: Path,
) -> None:
    path = tmp_path / "task23-multi.sqlite3"
    first_request = _execution_request((
        _Acquisition("request-a", "repo-a", "field-a", "rev-a1"),
        _Acquisition("request-b", "repo-b", "field-b", "rev-b1"),
    ))
    db = SQLiteStorage(path)
    first = execute_verification_plan(first_request, storage=db)

    first_slots = _slot_by_repository(first)
    assert set(first_slots) == {"repo-a", "repo-b"}
    assert first_slots["repo-a"].slot_id != first_slots["repo-b"].slot_id
    assert db.get_slot(RAW_EVIDENCE_ID) is None
    first_bundle = db.get_bundle(
        next(iter(first.bundles.values())).fingerprint,
    )
    first_claim = db.claim_history("claim-task23")[-1]
    expected_first = {
        (first_slots["repo-a"].slot_id, 1),
        (first_slots["repo-b"].slot_id, 1),
    }
    assert _dependency_set(first_bundle.evidence_dependencies) == expected_first
    assert _dependency_set(first_claim.evidence_dependencies) == expected_first
    assert first_claim.bundle_record_fingerprint == first_bundle.record_fingerprint
    assert db.claim_status("claim-task23").current
    assert db.get_session(first.session.fingerprint).current

    reopened = SQLiteStorage(path)
    replay = execute_verification_plan(first_request, storage=reopened)
    assert replay.fingerprint == first.fingerprint
    assert len(reopened.slot_history(first_slots["repo-a"].slot_id)) == 1
    assert len(reopened.slot_history(first_slots["repo-b"].slot_id)) == 1
    assert len(reopened.claim_history("claim-task23")) == 1
    assert len(reopened.session_record_history(first.session.fingerprint)) == 1

    second_request = _execution_request((
        _Acquisition("request-a", "repo-a", "field-a", "rev-a1"),
        _Acquisition("request-b", "repo-b", "field-b", "rev-b2"),
    ))
    second = execute_verification_plan(second_request, storage=reopened)
    second_slots = _slot_by_repository(second)
    assert second_slots == first_slots
    assert [
        item.version
        for item in reopened.slot_history(first_slots["repo-a"].slot_id)
    ] == [1]
    assert [
        item.version
        for item in reopened.slot_history(first_slots["repo-b"].slot_id)
    ] == [1, 2]
    current_bundle = reopened.get_bundle(
        next(iter(second.bundles.values())).fingerprint,
    )
    current_claim = reopened.claim_history("claim-task23")[-1]
    expected_second = {
        (first_slots["repo-a"].slot_id, 1),
        (first_slots["repo-b"].slot_id, 2),
    }
    assert _dependency_set(current_bundle.evidence_dependencies) == expected_second
    assert _dependency_set(current_claim.evidence_dependencies) == expected_second
    assert reopened.get_slot(first_slots["repo-a"].slot_id).version == 1
    assert reopened.get_slot(first_slots["repo-a"].slot_id).current
    assert reopened.claim_status("claim-task23").current
    assert reopened.get_session(second.session.fingerprint).current
    assert reopened.schema_version == 3

    from test_durable_storage_slot_identity import _record, _slot_identity

    migration_path = tmp_path / "task23-v2-migration.sqlite3"
    legacy_v2 = SQLiteStorage(migration_path)
    _, legacy_result = _record(legacy_v2)
    legacy_identity = _slot_identity(legacy_result)
    legacy_session_fingerprint = legacy_result.session.fingerprint
    _project_dependency_tables_to_v2(migration_path)

    migrated = SQLiteStorage(migration_path)
    assert migrated.schema_version == 3
    assert migrated.get_slot(legacy_identity.slot_id).authoritative
    assert migrated.claim_status("claim-a").current
    assert migrated.get_session(legacy_session_fingerprint).current
    _, replayed = _record(migrated)
    assert replayed.fingerprint == legacy_result.fingerprint
    assert len(migrated.slot_history(legacy_identity.slot_id)) == 1
    assert len(migrated.claim_history("claim-a")) == 1
    assert len(migrated.session_record_history(legacy_session_fingerprint)) == 1


def test_task23_04_semantic_dimension_properties_match_documented_slot_rules(
    tmp_path: Path,
) -> None:
    from test_durable_storage_slot_identity import _ProviderBehavior, _record, _slot_identity

    isolated_cases = (
        (
            "source",
            {"source_identity": {"repository": "repo-a"}},
            {"source_identity": {"repository": "repo-b"}},
        ),
        (
            "request",
            {"request_spec": {"field": "ready"}},
            {"request_spec": {"field": "enabled"}},
        ),
    )
    for name, first_kwargs, second_kwargs in isolated_cases:
        db = SQLiteStorage(tmp_path / f"task23-{name}.sqlite3")
        _, first = _record(db, claim_id=f"claim-{name}-a", **first_kwargs)
        _, second = _record(db, claim_id=f"claim-{name}-b", **second_kwargs)
        assert _slot_identity(first).slot_id != _slot_identity(second).slot_id
        assert db.invalidation_events() == ()

    replacement_cases = (
        (
            "snapshot",
            {"snapshot_identity": {"revision": "rev-a"}},
            {"snapshot_identity": {"revision": "rev-b"}},
        ),
        (
            "content",
            {"behavior": _ProviderBehavior(value=1)},
            {"behavior": _ProviderBehavior(value=2)},
        ),
        (
            "provider-version",
            {"provider_version": "1"},
            {"provider_version": "2"},
        ),
    )
    for name, first_kwargs, second_kwargs in replacement_cases:
        db = SQLiteStorage(tmp_path / f"task23-{name}.sqlite3")
        _, first = _record(db, **first_kwargs)
        _, second = _record(db, **second_kwargs)
        first_identity = _slot_identity(first)
        assert _slot_identity(second) == first_identity
        assert [
            item.version for item in db.slot_history(first_identity.slot_id)
        ] == [1, 2]
        assert db.claim_status("claim-a").current


def test_task23_05_protocol_preserves_audit_boundary_and_rejects_forgery() -> None:
    request, evidence_request, capability = _task22_request_with_audit({
        "trace_id": "trace-a",
        "nested": {"runId": "run-a"},
    })
    result = execute_verification_plan(request)
    provider_result = next(iter(result.provider_results.values()))
    response = gvr.handle_request({
        "schema_version": 1,
        "op": "validate_evidence_provider_result",
        "payload": {
            "request": evidence_request.to_dict(),
            "capability": capability.to_dict(),
            "result": provider_result.to_dict(),
        },
    })
    audit = response["payload"]["coverage"]["audit"]
    assert audit["metadata"]["trace_id"] == "trace-a"
    assert audit["fingerprint"] == provider_result.coverage.audit.fingerprint
    assert response["payload"]["fingerprint"] == provider_result.fingerprint

    forged_audit = provider_result.to_dict()
    forged_audit["coverage"]["audit"]["fingerprint"] = "0" * 64
    with pytest.raises(ProtocolError, match="audit"):
        gvr.handle_request({
            "schema_version": 1,
            "op": "validate_evidence_provider_result",
            "payload": {
                "request": evidence_request.to_dict(),
                "capability": capability.to_dict(),
                "result": forged_audit,
            },
        })

    ambiguous = provider_result.to_dict()
    ambiguous["coverage"].pop("fingerprint", None)
    ambiguous.pop("fingerprint", None)
    ambiguous["coverage"]["details"] = {
        "transport": {"traceID": "trace-forged"},
    }
    with pytest.raises(ProtocolError, match="audit"):
        gvr.handle_request({
            "schema_version": 1,
            "op": "validate_evidence_provider_result",
            "payload": {
                "request": evidence_request.to_dict(),
                "capability": capability.to_dict(),
                "result": ambiguous,
            },
        })

    wrong_channel = provider_result.to_dict()
    wrong_channel["audit"] = deepcopy(wrong_channel["coverage"]["audit"])
    with pytest.raises(ProtocolError, match="unexpected"):
        gvr.handle_request({
            "schema_version": 1,
            "op": "validate_evidence_provider_result",
            "payload": {
                "request": evidence_request.to_dict(),
                "capability": capability.to_dict(),
                "result": wrong_channel,
            },
        })


def test_task23_06_multi_acquisition_injected_failure_rolls_back_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gvr.sqlite_storage import SQLiteUnitOfWork

    path = tmp_path / "task23-rollback.sqlite3"
    db = SQLiteStorage(path)
    request = _execution_request((
        _Acquisition("request-a", "repo-a", "field-a", "rev-a1"),
        _Acquisition("request-b", "repo-b", "field-b", "rev-b1"),
    ))
    reached_injection = False

    def fail_after_all_acquisitions(
        unit_of_work: Any,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        nonlocal reached_injection
        reached_injection = True
        assert unit_of_work._conn().execute(
            "SELECT COUNT(*) FROM evidence_slot_versions"
        ).fetchone()[0] == 2
        raise StorageIntegrityError("injected task23 multi-acquisition failure")

    monkeypatch.setattr(
        SQLiteUnitOfWork,
        "put_bundle",
        fail_after_all_acquisitions,
    )
    with pytest.raises(VerificationExecutionError, match="failed closed"):
        execute_verification_plan(request, storage=db)
    assert reached_injection

    connection = sqlite3.connect(path)
    try:
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
        ):
            assert connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0] == 0
    finally:
        connection.close()
