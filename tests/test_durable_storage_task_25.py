from __future__ import annotations

from pathlib import Path
from typing import Any

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


PROVIDER_ID = "fixture.task25.provider"
VERIFIER_ID = "fixture.task25.verifier"
EVIDENCE_ID = "task25-shared-evidence"


class _ProviderRuntime:
    def __init__(self, capability: EvidenceProviderCapability) -> None:
        self.provider_id = capability.provider_id
        self.version = capability.version
        self.capability = capability

    def acquire(self, request: EvidenceRequest) -> EvidenceProviderResult:
        evidence = Evidence(
            id=EVIDENCE_ID,
            kind="fixture.state",
            payload={"value": "same-domain-content"},
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
    roots: tuple[str, ...] = ("A", "B"),
) -> VerificationExecutionRequest:
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
            semantic_scope={"repository": f"repo-{claim_id}"},
            source_context={"repository": f"repo-{claim_id}"},
            snapshot_context={"revision": "same-revision"},
            bounds={"max_items": 10},
            source_class="repository",
            snapshot_class="revision",
        )
        for claim_id in ("A", "B")
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
        roots=roots,
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
            for item in requests.values()
        },
        limits=VerificationExecutionLimits(),
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
