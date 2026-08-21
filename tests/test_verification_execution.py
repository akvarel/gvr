from __future__ import annotations

from dataclasses import FrozenInstanceError, dataclass, replace
import json
import os
import subprocess
import sys
from typing import Any, Mapping

import pytest

import gvr
from gvr import (
    AtomicClaim,
    AtomicClaimBinding,
    ClaimGraph,
    ClaimOperator,
    CompositeClaim,
    Evidence,
    EvidenceAcquisitionStatus,
    EvidenceCompleteness,
    EvidenceCoverage,
    EvidenceProviderCapability,
    EvidenceProviderCapabilityRegistry,
    EvidenceProviderResult,
    EvidenceProviderRuntimeRegistry,
    EvidenceRequest,
    VerificationExecutionError,
    VerificationExecutionLimits,
    VerificationExecutionRequest,
    VerificationExecutionStepStatus,
    VerificationExecutionTermination,
    VerificationIssue,
    VerificationPlanningRequest,
    VerificationReport,
    VerificationSessionError,
    VerificationVerdict,
    VerifierCapability,
    VerifierCapabilityRegistry,
    VerifierCost,
    VerifierDeterminism,
    VerifierRuntimeRegistry,
    builtin_verifier_runtime_registry,
    compile_verification_plan,
    execute_verification_plan,
    handle_request,
    safe_handle_request,
)


DATA_FLOW_VERIFIER = "gvr.graphify.data_flow.v1"


def verifier_capability(**overrides: Any) -> VerifierCapability:
    values: dict[str, Any] = {
        "verifier_id": "fixture.state.verifier",
        "version": "1",
        "claim_kinds": ("ASSERT_STATE",),
        "accepted_evidence_kinds": ("state.snapshot",),
        "required_evidence_kinds": ("state.snapshot",),
        "input_schema": {"type": "object"},
        "output_schema": {"type": "gvr.VerificationReport"},
        "determinism": VerifierDeterminism.D1,
        "side_effect_free": True,
        "cost": VerifierCost.LOW,
        "bounds": {"max_items": 10},
        "coverage": {"mode": "DECLARED_SCOPE"},
        "authoritative": True,
        "description": "fixture verifier",
    }
    values.update(overrides)
    return VerifierCapability(**values)


def provider_capability(**overrides: Any) -> EvidenceProviderCapability:
    values: dict[str, Any] = {
        "provider_id": "fixture.state.provider",
        "version": "1",
        "request_kinds": ("CAPTURE_STATE",),
        "produced_evidence_kinds": ("state.snapshot",),
        "source_classes": ("repository",),
        "snapshot_classes": ("revision",),
        "input_schema": {"type": "object"},
        "output_schema": {"type": "gvr.EvidenceProviderResult"},
        "determinism": VerifierDeterminism.O1,
        "side_effect_free": True,
        "cost": VerifierCost.EXTERNAL,
        "bounds": {"max_items": 10},
        "coverage": {"mode": "DECLARED_SCOPE"},
        "description": "fixture provider",
    }
    values.update(overrides)
    return EvidenceProviderCapability(**values)


def evidence_request(request_id: str = "request-A", **overrides: Any) -> EvidenceRequest:
    values: dict[str, Any] = {
        "request_id": request_id,
        "provider_id": "fixture.state.provider",
        "provider_version": "1",
        "request_kind": "CAPTURE_STATE",
        "requested_evidence_kinds": ("state.snapshot",),
        "subject": {"entity": "A"},
        "spec": {"field": "ready"},
        "semantic_scope": {"repository": "demo"},
        "source_context": {"repository": "demo"},
        "snapshot_context": {"revision": "abc"},
        "bounds": {"max_items": 10},
        "source_class": "repository",
        "snapshot_class": "revision",
    }
    values.update(overrides)
    return EvidenceRequest(**values)


def atomic_claim(
    claim_id: str = "A",
    *,
    dependencies: tuple[str, ...] = (),
    verifier: str = "fixture.state.verifier",
    claim_kind: str = "ASSERT_STATE",
    spec: Mapping[str, Any] | None = None,
    scope: Mapping[str, Any] | None = None,
) -> AtomicClaim:
    return AtomicClaim(
        claim_id=claim_id,
        claim_kind=claim_kind,
        spec={"entity": claim_id, "expected": True} if spec is None else spec,
        verifier=verifier,
        scope={"repository": "demo"} if scope is None else scope,
        dependencies=dependencies,
    )


def complete_result(
    request: EvidenceRequest,
    capability: EvidenceProviderCapability,
    *,
    evidence_id: str | None = None,
    value: Any = True,
) -> EvidenceProviderResult:
    evidence = Evidence(
        id=evidence_id or f"evidence:{request.request_id}",
        kind=request.requested_evidence_kinds[0],
        payload={"value": value, "request_id": request.request_id},
        source="fixture",
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
        capability_fingerprint=capability.fingerprint,
    )


def unavailable_result(
    request: EvidenceRequest,
    capability: EvidenceProviderCapability,
) -> EvidenceProviderResult:
    return EvidenceProviderResult(
        request_id=request.request_id,
        request_fingerprint=request.fingerprint,
        provider_id=request.provider_id,
        provider_version=request.provider_version,
        status=EvidenceAcquisitionStatus.UNAVAILABLE,
        coverage=EvidenceCoverage(
            completeness=EvidenceCompleteness.UNKNOWN,
            covered_evidence_kinds=(),
            declared_scope=request.semantic_scope,
            observed_scope={},
            declared_bounds=request.bounds,
            consumed={},
            termination={"reason": "UNAVAILABLE"},
            termination_reason="UNAVAILABLE",
            source_identity=request.source_context,
            snapshot_identity=request.snapshot_context,
        ),
        evidence=(),
        capability_fingerprint=capability.fingerprint,
    )


class ProviderRuntime:
    def __init__(
        self,
        capability: EvidenceProviderCapability,
        *,
        evidence_ids: Mapping[str, str] | None = None,
        unavailable: bool = False,
        error: BaseException | None = None,
        malformed: Any = None,
    ) -> None:
        self.provider_id = capability.provider_id
        self.version = capability.version
        self.capability = capability
        self.evidence_ids = dict(evidence_ids or {})
        self.unavailable = unavailable
        self.error = error
        self.malformed = malformed
        self.calls: list[EvidenceRequest] = []

    def acquire(self, request: EvidenceRequest) -> EvidenceProviderResult:
        self.calls.append(request)
        if self.error is not None:
            raise self.error
        if self.malformed is not None:
            return self.malformed
        if self.unavailable:
            return unavailable_result(request, self.capability)
        return complete_result(
            request,
            self.capability,
            evidence_id=self.evidence_ids.get(request.request_id),
        )


class VerifierRuntime:
    def __init__(
        self,
        capability: VerifierCapability,
        *,
        verdicts: Mapping[str, VerificationVerdict] | None = None,
        error: BaseException | None = None,
        forced_report: VerificationReport | None = None,
    ) -> None:
        self.verifier_id = capability.verifier_id
        self.version = capability.version
        self.capability = capability
        self.verdicts = dict(verdicts or {})
        self.error = error
        self.forced_report = forced_report
        self.calls: list[Any] = []

    def verify(self, verifier_input: Any) -> VerificationReport:
        self.calls.append(verifier_input)
        if self.error is not None:
            raise self.error
        if self.forced_report is not None:
            return self.forced_report
        verdict = self.verdicts.get(
            verifier_input.claim.claim_id,
            VerificationVerdict.PASS,
        )
        evidence_ids = tuple(item.id for item in verifier_input.evidence)
        return VerificationReport(
            verdict=verdict,
            verifier=self.verifier_id,
            evidence_ids=evidence_ids,
        )


@dataclass
class Fixture:
    request: VerificationExecutionRequest
    provider: ProviderRuntime | None
    verifier: VerifierRuntime


def execution_fixture(
    *,
    graph: ClaimGraph | None = None,
    roots: tuple[str, ...] = ("A",),
    requests_by_claim: Mapping[str, tuple[EvidenceRequest, ...]] | None = None,
    verifier_cap: VerifierCapability | None = None,
    provider_cap: EvidenceProviderCapability | None = None,
    verifier: VerifierRuntime | None = None,
    provider: ProviderRuntime | None = None,
    limits: VerificationExecutionLimits | None = None,
    correlation_id: str | None = None,
) -> Fixture:
    claim_graph = graph or ClaimGraph(nodes=(atomic_claim(),))
    vcap = verifier_cap or verifier_capability()
    pcap = provider_cap or provider_capability()
    per_claim = dict(requests_by_claim or {
        claim.claim_id: (evidence_request(subject={"entity": claim.claim_id}),)
        for claim in claim_graph.atomic_claims
    })
    bindings = tuple(
        AtomicClaimBinding(
            claim_id=claim.claim_id,
            verifier_id=vcap.verifier_id,
            verifier_version=vcap.version,
            verifier_capability_fingerprint=vcap.fingerprint,
            evidence_requests=per_claim.get(claim.claim_id, ()),
        )
        for claim in claim_graph.atomic_claims
    )
    verifier_caps = VerifierCapabilityRegistry((vcap,))
    provider_caps = EvidenceProviderCapabilityRegistry(
        (pcap,) if any(per_claim.values()) else ()
    )
    planning = VerificationPlanningRequest(
        claim_graph=claim_graph,
        bindings=bindings,
        verifier_capability_registry=verifier_caps,
        verifier_capability_registry_fingerprint=verifier_caps.fingerprint,
        evidence_provider_capability_registry=provider_caps,
        evidence_provider_capability_registry_fingerprint=provider_caps.fingerprint,
    )
    plan = compile_verification_plan(planning)
    assert plan.termination.value == "COMPLETE"

    verifier_runtime = verifier or VerifierRuntime(vcap)
    verifier_registry = VerifierRuntimeRegistry(
        capability_registry=verifier_caps,
        runtime_verifiers={(vcap.verifier_id, vcap.version): verifier_runtime},
    )

    provider_runtime: ProviderRuntime | None = None
    provider_mapping: dict[tuple[str, str], Any] = {}
    if provider_caps.capabilities:
        provider_runtime = provider or ProviderRuntime(pcap)
        provider_mapping[(pcap.provider_id, pcap.version)] = provider_runtime
    provider_registry = EvidenceProviderRuntimeRegistry(
        capability_registry=provider_caps,
        runtime_providers=provider_mapping,
    )

    exact_requests = {
        (item.request_id, item.fingerprint): item
        for values in per_claim.values()
        for item in values
    }
    request = VerificationExecutionRequest(
        plan=plan,
        plan_fingerprint=plan.fingerprint,
        claim_graph=claim_graph,
        claim_graph_fingerprint=claim_graph.fingerprint,
        roots=roots,
        verifier_runtime_registry=verifier_registry,
        verifier_capability_registry_fingerprint=verifier_caps.fingerprint,
        evidence_provider_runtime_registry=provider_registry,
        evidence_provider_capability_registry_fingerprint=provider_caps.fingerprint,
        evidence_requests=exact_requests,
        limits=limits or VerificationExecutionLimits(),
        correlation_id=correlation_id,
    )
    return Fixture(request=request, provider=provider_runtime, verifier=verifier_runtime)


def issue_codes(result: Any) -> tuple[str, ...]:
    return tuple(item.code for item in result.issues)


def visit_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        keys.update(value)
        for nested in value.values():
            keys.update(visit_keys(nested))
    elif isinstance(value, (list, tuple)):
        for nested in value:
            keys.update(visit_keys(nested))
    return keys


def test_01_request_and_result_are_strict_immutable_exact_and_public() -> None:
    fixture = execution_fixture(correlation_id="trace-1")
    result = execute_verification_plan(fixture.request)

    assert result.termination is VerificationExecutionTermination.COMPLETE
    assert result.session.root_verdicts == {"A": VerificationVerdict.PASS}
    assert result.plan_fingerprint == fixture.request.plan.fingerprint
    assert result.request_fingerprint == fixture.request.fingerprint
    assert result.correlation_id == "trace-1"
    assert tuple(result.bundles) == ("A",)
    assert tuple(result.provider_results) == tuple(fixture.request.evidence_requests)
    with pytest.raises(FrozenInstanceError):
        fixture.request.correlation_id = "changed"  # type: ignore[misc]
    with pytest.raises(TypeError):
        fixture.request.evidence_requests[("x", "0" * 64)] = evidence_request()  # type: ignore[index]
    with pytest.raises(TypeError):
        result.bundles["B"] = result.bundles["A"]  # type: ignore[index]
    for name in (
        "VerificationExecutionError",
        "VerificationExecutionLimits",
        "VerificationExecutionRequest",
        "VerificationExecutionResult",
        "VerificationExecutionStepStatus",
        "VerificationExecutionTermination",
        "VerifierRuntimeRegistry",
        "execute_verification_plan",
    ):
        assert name in gvr.__all__
        assert getattr(gvr, name) is not None


def test_02_plan_and_claim_graph_identity_substitutions_fail_before_execution() -> None:
    fixture = execution_fixture()
    with pytest.raises(VerificationExecutionError):
        replace(fixture.request, plan_fingerprint="0" * 64)
    with pytest.raises(VerificationExecutionError):
        replace(fixture.request, claim_graph_fingerprint="0" * 64)

    substituted = ClaimGraph(nodes=(atomic_claim(spec={"expected": False}),))
    with pytest.raises(VerificationExecutionError):
        replace(
            fixture.request,
            claim_graph=substituted,
            claim_graph_fingerprint=substituted.fingerprint,
        )
    assert fixture.provider is not None and fixture.provider.calls == []
    assert fixture.verifier.calls == []


def test_03_capability_and_runtime_registry_substitutions_fail_before_execution() -> None:
    fixture = execution_fixture()
    with pytest.raises(VerificationExecutionError):
        replace(
            fixture.request,
            verifier_capability_registry_fingerprint="0" * 64,
        )
    with pytest.raises(VerificationExecutionError):
        replace(
            fixture.request,
            evidence_provider_capability_registry_fingerprint="0" * 64,
        )

    replacement_cap = verifier_capability(version="2")
    replacement_registry = VerifierCapabilityRegistry((replacement_cap,))
    replacement_runtime = VerifierRuntime(replacement_cap)
    with pytest.raises(VerificationExecutionError):
        replace(
            fixture.request,
            verifier_runtime_registry=VerifierRuntimeRegistry(
                capability_registry=replacement_registry,
                runtime_verifiers={(replacement_cap.verifier_id, "2"): replacement_runtime},
            ),
            verifier_capability_registry_fingerprint=replacement_registry.fingerprint,
        )


def test_04_exact_evidence_request_keys_ids_and_fingerprints_cannot_be_substituted() -> None:
    fixture = execution_fixture()
    ((key, request),) = fixture.request.evidence_requests.items()
    with pytest.raises(VerificationExecutionError):
        replace(fixture.request, evidence_requests={("other", key[1]): request})
    with pytest.raises(VerificationExecutionError):
        replace(fixture.request, evidence_requests={(key[0], "0" * 64): request})
    changed = evidence_request(request_id=request.request_id, spec={"field": "other"})
    with pytest.raises(VerificationExecutionError):
        replace(
            fixture.request,
            evidence_requests={(changed.request_id, changed.fingerprint): changed},
        )


def test_05_plan_steps_dag_dependencies_and_exact_versions_are_revalidated() -> None:
    fixture = execution_fixture()
    plan = fixture.request.plan
    verify_step = next(step for step in plan.steps if step.claim_id == "A")
    original_dependencies = verify_step.dependency_step_ids
    object.__setattr__(verify_step, "dependency_step_ids", ())
    try:
        with pytest.raises(VerificationExecutionError):
            replace(fixture.request)
    finally:
        object.__setattr__(verify_step, "dependency_step_ids", original_dependencies)

    original_version = verify_step.verifier_version
    object.__setattr__(verify_step, "verifier_version", "2")
    try:
        with pytest.raises(VerificationExecutionError):
            replace(fixture.request)
    finally:
        object.__setattr__(verify_step, "verifier_version", original_version)


def test_06_mutated_provider_runtime_identity_is_rechecked_immediately_before_call() -> None:
    fixture = execution_fixture()
    assert fixture.provider is not None
    fixture.provider.version = "2"
    with pytest.raises(VerificationExecutionError):
        execute_verification_plan(fixture.request)
    assert fixture.provider.calls == []
    assert fixture.verifier.calls == []


def test_07_mutated_verifier_runtime_identity_is_rechecked_immediately_before_call() -> None:
    fixture = execution_fixture()
    fixture.verifier.version = "2"
    with pytest.raises(VerificationExecutionError):
        execute_verification_plan(fixture.request)
    assert fixture.provider is not None and fixture.provider.calls == []
    assert fixture.verifier.calls == []


def test_08_malformed_provider_result_fails_closed_and_never_invokes_verifier() -> None:
    cap = provider_capability()
    provider = ProviderRuntime(cap, malformed={"not": "a result"})
    fixture = execution_fixture(provider_cap=cap, provider=provider)

    result = execute_verification_plan(fixture.request)

    assert result.termination is VerificationExecutionTermination.FAILED_CLOSED
    assert "PROVIDER_RESULT_INVALID" in issue_codes(result)
    assert result.session.root_verdicts == {"A": VerificationVerdict.UNKNOWN}
    assert fixture.verifier.calls == []
    assert [step.status for step in result.steps] == [
        VerificationExecutionStepStatus.FAILED,
        VerificationExecutionStepStatus.BLOCKED,
    ]


def test_09_provider_exception_is_stable_secret_safe_and_fail_closed() -> None:
    cap = provider_capability()
    first = execution_fixture(
        provider_cap=cap,
        provider=ProviderRuntime(cap, error=RuntimeError("secret-one at 0x111")),
    )
    second = execution_fixture(
        provider_cap=cap,
        provider=ProviderRuntime(cap, error=RuntimeError("secret-two at 0x222")),
    )

    a = execute_verification_plan(first.request)
    b = execute_verification_plan(second.request)

    assert a.fingerprint == b.fingerprint
    assert a.session.root_verdicts == {"A": VerificationVerdict.UNKNOWN}
    serialized = json.dumps(a.to_dict(), sort_keys=True)
    assert "secret-one" not in serialized
    assert "RuntimeError" not in serialized
    assert "0x111" not in serialized
    assert first.verifier.calls == []


def test_10_verifier_exception_materializes_unknown_bundle_without_exception_text() -> None:
    vcap = verifier_capability()
    first = execution_fixture(
        verifier_cap=vcap,
        verifier=VerifierRuntime(vcap, error=RuntimeError("secret-one at 0x111")),
    )
    second = execution_fixture(
        verifier_cap=vcap,
        verifier=VerifierRuntime(vcap, error=RuntimeError("secret-two at 0x222")),
    )

    a = execute_verification_plan(first.request)
    b = execute_verification_plan(second.request)

    assert a.fingerprint == b.fingerprint
    assert a.termination is VerificationExecutionTermination.FAILED_CLOSED
    assert a.session.root_verdicts == {"A": VerificationVerdict.UNKNOWN}
    assert a.bundles["A"].report.verdict is VerificationVerdict.UNKNOWN
    assert a.bundles["A"].report.issues[0].code == "VERIFIER_EXECUTION_ERROR"
    serialized = json.dumps(a.to_dict(), sort_keys=True)
    assert "secret-one" not in serialized
    assert "RuntimeError" not in serialized


def test_11_invalid_acquisition_prerequisite_can_never_be_upgraded_to_pass() -> None:
    vcap = verifier_capability()
    pcap = provider_capability()
    verifier = VerifierRuntime(vcap, verdicts={"A": VerificationVerdict.PASS})
    provider = ProviderRuntime(pcap, unavailable=True)
    fixture = execution_fixture(
        verifier_cap=vcap,
        provider_cap=pcap,
        verifier=verifier,
        provider=provider,
    )

    result = execute_verification_plan(fixture.request)

    assert verifier.calls == []
    assert result.session.root_verdicts == {"A": VerificationVerdict.UNKNOWN}
    assert result.bundles["A"].report.verdict is VerificationVerdict.UNKNOWN
    assert "INVALID_VERIFICATION_PREREQUISITE" in issue_codes(result)


def test_12_verifier_receives_only_directly_reachable_evidence() -> None:
    graph = ClaimGraph(nodes=(atomic_claim("A"), atomic_claim("B")))
    request_a = evidence_request("request-A", subject={"entity": "A"})
    request_b = evidence_request("request-B", subject={"entity": "B"})
    fixture = execution_fixture(
        graph=graph,
        roots=("A", "B"),
        requests_by_claim={"A": (request_a,), "B": (request_b,)},
    )

    execute_verification_plan(fixture.request)

    by_claim = {call.claim.claim_id: call for call in fixture.verifier.calls}
    assert tuple(item.id for item in by_claim["A"].evidence) == ("evidence:request-A",)
    assert tuple(item.id for item in by_claim["B"].evidence) == ("evidence:request-B",)


def test_13_verifier_receives_only_exact_claim_dependencies() -> None:
    vcap = verifier_capability(required_evidence_kinds=(), accepted_evidence_kinds=())
    graph = ClaimGraph(nodes=(
        atomic_claim("A"),
        atomic_claim("B"),
        atomic_claim("C", dependencies=("A",)),
    ))
    verifier = VerifierRuntime(vcap)
    fixture = execution_fixture(
        graph=graph,
        roots=("C",),
        requests_by_claim={"A": (), "B": (), "C": ()},
        verifier_cap=vcap,
        verifier=verifier,
    )

    execute_verification_plan(fixture.request)

    call_c = next(call for call in verifier.calls if call.claim.claim_id == "C")
    assert tuple(item.claim_id for item in call_c.dependencies) == ("A",)
    assert all(item.claim_id != "B" for item in call_c.dependencies)


def test_14_one_exact_request_shared_across_claims_is_acquired_once() -> None:
    graph = ClaimGraph(nodes=(atomic_claim("A"), atomic_claim("B")))
    shared = evidence_request(subject={"entity": "shared"})
    fixture = execution_fixture(
        graph=graph,
        roots=("A", "B"),
        requests_by_claim={"A": (shared,), "B": (shared,)},
    )

    result = execute_verification_plan(fixture.request)

    assert fixture.provider is not None
    assert [item.request_id for item in fixture.provider.calls] == ["request-A"]
    assert result.consumption.acquisitions == 1
    assert len(result.provider_results) == 1
    assert len(fixture.verifier.calls) == 2


def test_15_same_semantics_under_two_request_ids_execute_twice() -> None:
    graph = ClaimGraph(nodes=(atomic_claim("A"),))
    first = evidence_request("request-A")
    second = evidence_request("request-B")
    assert first.fingerprint == second.fingerprint
    fixture = execution_fixture(
        graph=graph,
        requests_by_claim={"A": (first, second)},
    )

    result = execute_verification_plan(fixture.request)

    assert fixture.provider is not None
    assert [item.request_id for item in fixture.provider.calls] == ["request-A", "request-B"]
    assert result.consumption.acquisitions == 2
    assert len(result.provider_results) == 2
    assert tuple(item.id for item in fixture.verifier.calls[0].evidence) == (
        "evidence:request-A",
        "evidence:request-B",
    )


def composite_result(
    operator: ClaimOperator,
    values: tuple[VerificationVerdict, ...],
) -> VerificationVerdict:
    vcap = verifier_capability(required_evidence_kinds=(), accepted_evidence_kinds=())
    nodes = tuple(atomic_claim(chr(65 + index)) for index in range(len(values)))
    root = CompositeClaim(
        claim_id="ROOT",
        operator=operator,
        dependencies=tuple(node.claim_id for node in nodes),
    )
    graph = ClaimGraph(nodes=(*nodes, root))
    verifier = VerifierRuntime(
        vcap,
        verdicts={node.claim_id: value for node, value in zip(nodes, values)},
    )
    fixture = execution_fixture(
        graph=graph,
        roots=("ROOT",),
        requests_by_claim={node.claim_id: () for node in nodes},
        verifier_cap=vcap,
        verifier=verifier,
    )
    result = execute_verification_plan(fixture.request)
    return result.session.root_verdicts["ROOT"]


@pytest.mark.parametrize(
    "values,expected",
    [
        ((VerificationVerdict.PASS, VerificationVerdict.PASS), VerificationVerdict.PASS),
        ((VerificationVerdict.PASS, VerificationVerdict.UNKNOWN), VerificationVerdict.UNKNOWN),
        ((VerificationVerdict.PASS, VerificationVerdict.FAIL), VerificationVerdict.FAIL),
    ],
)
def test_16_and_composition_uses_exact_tri_state(
    values: tuple[VerificationVerdict, ...],
    expected: VerificationVerdict,
) -> None:
    assert composite_result(ClaimOperator.AND, values) is expected


@pytest.mark.parametrize(
    "values,expected",
    [
        ((VerificationVerdict.FAIL, VerificationVerdict.FAIL), VerificationVerdict.FAIL),
        ((VerificationVerdict.FAIL, VerificationVerdict.UNKNOWN), VerificationVerdict.UNKNOWN),
        ((VerificationVerdict.FAIL, VerificationVerdict.PASS), VerificationVerdict.PASS),
    ],
)
def test_17_or_composition_uses_exact_tri_state(
    values: tuple[VerificationVerdict, ...],
    expected: VerificationVerdict,
) -> None:
    assert composite_result(ClaimOperator.OR, values) is expected


@pytest.mark.parametrize(
    "value,expected",
    [
        (VerificationVerdict.PASS, VerificationVerdict.FAIL),
        (VerificationVerdict.FAIL, VerificationVerdict.PASS),
        (VerificationVerdict.UNKNOWN, VerificationVerdict.UNKNOWN),
    ],
)
def test_18_not_composition_uses_exact_tri_state(
    value: VerificationVerdict,
    expected: VerificationVerdict,
) -> None:
    assert composite_result(ClaimOperator.NOT, (value,)) is expected


def test_19_reports_bundles_and_session_preserve_exact_pass_fail_unknown() -> None:
    vcap = verifier_capability(required_evidence_kinds=(), accepted_evidence_kinds=())
    graph = ClaimGraph(nodes=(atomic_claim("A"), atomic_claim("B"), atomic_claim("C")))
    verifier = VerifierRuntime(vcap, verdicts={
        "A": VerificationVerdict.PASS,
        "B": VerificationVerdict.FAIL,
        "C": VerificationVerdict.UNKNOWN,
    })
    fixture = execution_fixture(
        graph=graph,
        roots=("A", "B", "C"),
        requests_by_claim={"A": (), "B": (), "C": ()},
        verifier_cap=vcap,
        verifier=verifier,
    )

    result = execute_verification_plan(fixture.request)

    assert {claim_id: bundle.report.verdict for claim_id, bundle in result.bundles.items()} == {
        "A": VerificationVerdict.PASS,
        "B": VerificationVerdict.FAIL,
        "C": VerificationVerdict.UNKNOWN,
    }
    assert result.session.root_verdicts == {
        "A": VerificationVerdict.PASS,
        "B": VerificationVerdict.FAIL,
        "C": VerificationVerdict.UNKNOWN,
    }


def test_20_replay_is_deterministic_and_correlation_is_nonsemantic() -> None:
    first_fixture = execution_fixture(correlation_id="trace-one")
    second_fixture = execution_fixture(correlation_id="trace-two")

    first = execute_verification_plan(first_fixture.request)
    second = execute_verification_plan(second_fixture.request)

    assert first_fixture.request.fingerprint == second_fixture.request.fingerprint
    assert first.fingerprint == second.fingerprint
    assert first.session.fingerprint == second.session.fingerprint
    assert first.to_dict()["correlation_id"] == "trace-one"
    assert second.to_dict()["correlation_id"] == "trace-two"


def test_21_changed_evidence_identity_changes_result_bundle_and_session_identity() -> None:
    pcap = provider_capability()
    first = execution_fixture(
        provider_cap=pcap,
        provider=ProviderRuntime(pcap, evidence_ids={"request-A": "evidence:first"}),
    )
    second = execution_fixture(
        provider_cap=pcap,
        provider=ProviderRuntime(pcap, evidence_ids={"request-A": "evidence:second"}),
    )

    a = execute_verification_plan(first.request)
    b = execute_verification_plan(second.request)

    assert a.fingerprint != b.fingerprint
    assert a.bundles["A"].fingerprint != b.bundles["A"].fingerprint
    assert a.session.fingerprint != b.session.fingerprint


def test_22_deterministic_limits_emit_lifecycle_counters_and_termination() -> None:
    fixture = execution_fixture(
        limits=VerificationExecutionLimits(max_verifier_invocations=0),
    )

    result = execute_verification_plan(fixture.request)

    assert result.termination is VerificationExecutionTermination.LIMIT_EXHAUSTED
    assert result.consumption.acquisitions == 1
    assert result.consumption.verifier_invocations == 0
    assert result.consumption.blocked_steps == 1
    assert [step.status for step in result.steps] == [
        VerificationExecutionStepStatus.COMPLETED,
        VerificationExecutionStepStatus.BLOCKED,
    ]
    assert result.session.root_verdicts == {"A": VerificationVerdict.UNKNOWN}
    assert "EXECUTION_LIMIT_EXHAUSTED" in issue_codes(result)


def test_23_conflicting_reachable_evidence_ids_fail_closed_before_verifier() -> None:
    graph = ClaimGraph(nodes=(atomic_claim("A"),))
    first = evidence_request("request-A")
    second = evidence_request("request-B", spec={"field": "other"})
    pcap = provider_capability()

    class ConflictingProvider(ProviderRuntime):
        def acquire(self, request: EvidenceRequest) -> EvidenceProviderResult:
            self.calls.append(request)
            return complete_result(
                request,
                self.capability,
                evidence_id="shared-id",
                value=request.request_id,
            )

    provider = ConflictingProvider(pcap)
    fixture = execution_fixture(
        graph=graph,
        requests_by_claim={"A": (first, second)},
        provider_cap=pcap,
        provider=provider,
    )

    result = execute_verification_plan(fixture.request)

    assert fixture.verifier.calls == []
    assert result.session.root_verdicts == {"A": VerificationVerdict.UNKNOWN}
    assert "CONFLICTING_REACHABLE_EVIDENCE_ID" in issue_codes(result)


def test_24_malformed_or_unreachable_verifier_report_fails_closed() -> None:
    vcap = verifier_capability()
    malformed = VerificationReport(
        verdict=VerificationVerdict.PASS,
        verifier="other.verifier",
        evidence_ids=("unreachable",),
        issues=(VerificationIssue(
            code="BAD",
            message="bad",
            verdict=VerificationVerdict.PASS,
            evidence_ids=("unreachable",),
        ),),
    )
    fixture = execution_fixture(
        verifier_cap=vcap,
        verifier=VerifierRuntime(vcap, forced_report=malformed),
    )

    result = execute_verification_plan(fixture.request)

    assert result.termination is VerificationExecutionTermination.FAILED_CLOSED
    assert result.session.root_verdicts == {"A": VerificationVerdict.UNKNOWN}
    assert result.bundles["A"].report.verdict is VerificationVerdict.UNKNOWN
    assert "VERIFIER_RESULT_INVALID" in issue_codes(result)


def test_25_execution_contract_has_no_product_policy_fallback_ranking_or_llm_fields() -> None:
    fixture = execution_fixture()
    result = execute_verification_plan(fixture.request)
    forbidden = {
        "approve",
        "approval",
        "broaden",
        "broadening",
        "confidence",
        "decision",
        "fallback",
        "llm",
        "model",
        "policy",
        "prompt",
        "rank",
        "ranking",
        "recommendation",
        "score",
    }

    assert forbidden.isdisjoint(visit_keys(fixture.request.to_dict()))
    assert forbidden.isdisjoint(visit_keys(result.to_dict()))


def builtin_cli_request() -> dict[str, Any]:
    capability = gvr.builtin_verifier_capability_registry().lookup(
        DATA_FLOW_VERIFIER,
        "1",
    )
    verifier_caps = VerifierCapabilityRegistry((capability,))
    provider_caps = EvidenceProviderCapabilityRegistry(())
    graph = ClaimGraph(nodes=(atomic_claim(
        verifier=DATA_FLOW_VERIFIER,
        claim_kind="CAN_FLOW_TO",
        spec={
            "start": "symbol:a",
            "target": "symbol:b",
            "scope": {
                "direction": "FORWARD",
                "effective_allowed_relations": ["FLOWS_TO"],
                "stop_nodes": [],
            },
            "evidence_namespace": "cli-smoke",
        },
        scope={},
    ),))
    planning = VerificationPlanningRequest(
        claim_graph=graph,
        bindings=(AtomicClaimBinding(
            claim_id="A",
            verifier_id=capability.verifier_id,
            verifier_version=capability.version,
            verifier_capability_fingerprint=capability.fingerprint,
            evidence_requests=(),
        ),),
        verifier_capability_registry=verifier_caps,
        verifier_capability_registry_fingerprint=verifier_caps.fingerprint,
        evidence_provider_capability_registry=provider_caps,
        evidence_provider_capability_registry_fingerprint=provider_caps.fingerprint,
    )
    plan = compile_verification_plan(planning)
    verifier_runtime = builtin_verifier_runtime_registry(verifier_caps)
    provider_runtime = EvidenceProviderRuntimeRegistry(provider_caps, {})
    execution = VerificationExecutionRequest(
        plan=plan,
        plan_fingerprint=plan.fingerprint,
        claim_graph=graph,
        claim_graph_fingerprint=graph.fingerprint,
        roots=("A",),
        verifier_runtime_registry=verifier_runtime,
        verifier_capability_registry_fingerprint=verifier_caps.fingerprint,
        evidence_provider_runtime_registry=provider_runtime,
        evidence_provider_capability_registry_fingerprint=provider_caps.fingerprint,
        evidence_requests={},
    )
    return {
        "schema_version": 1,
        "op": "execute_verification_plan",
        "payload": execution.to_dict(),
    }


def test_26_schema_v1_protocol_cli_strict_errors_and_backward_compatibility() -> None:
    fixture = execution_fixture()
    wire = {
        "schema_version": 1,
        "op": "execute_verification_plan",
        "payload": fixture.request.to_dict(),
    }
    first = handle_request(
        wire,
        verifier_runtime_registry=fixture.request.verifier_runtime_registry,
        evidence_provider_runtime_registry=fixture.request.evidence_provider_runtime_registry,
    )
    second = handle_request(
        wire,
        verifier_runtime_registry=fixture.request.verifier_runtime_registry,
        evidence_provider_runtime_registry=fixture.request.evidence_provider_runtime_registry,
    )
    assert first == second
    assert first["kind"] == "verification_execution_result"
    assert first["payload"]["session"]["root_verdicts"] == {"A": "PASS"}

    unknown = safe_handle_request(
        {
            **wire,
            "payload": {**wire["payload"], "unknown": True},
        },
        verifier_runtime_registry=fixture.request.verifier_runtime_registry,
        evidence_provider_runtime_registry=fixture.request.evidence_provider_runtime_registry,
    )
    assert unknown["payload"]["code"] == "INVALID_VERIFICATION_EXECUTION_REQUEST"
    mismatch = safe_handle_request(
        {
            **wire,
            "payload": {**wire["payload"], "fingerprint": "0" * 64},
        },
        verifier_runtime_registry=fixture.request.verifier_runtime_registry,
        evidence_provider_runtime_registry=fixture.request.evidence_provider_runtime_registry,
    )
    assert mismatch["payload"]["code"] == "INVALID_VERIFICATION_EXECUTION_REQUEST"

    proc = subprocess.run(
        [sys.executable, "-m", "gvr"],
        input=json.dumps(builtin_cli_request()),
        text=True,
        capture_output=True,
        env={**os.environ, "PYTHONPATH": "src"},
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    output = json.loads(proc.stdout)
    assert output["kind"] == "verification_execution_result"
    assert output["payload"]["session"]["root_verdicts"] == {"A": "UNKNOWN"}

    legacy = handle_request({
        "schema_version": 1,
        "op": "verify_goal",
        "payload": {
            "initial_state": {"ready": True},
            "goal": [{"slot": "ready", "op": "truthy"}],
            "actions": [],
        },
    })
    assert legacy["kind"] == "verification_report"
    assert legacy["payload"]["verdict"] == "PASS"


def test_27_execution_result_seals_session_and_preserves_fingerprint() -> None:
    fixture = execution_fixture()
    result = execute_verification_plan(fixture.request)
    before = result.to_dict()

    with pytest.raises(VerificationSessionError):
        result.session.remove_evidence("evidence:request-A")

    assert result.to_dict() == before
    assert result.session.root_verdicts == {"A": VerificationVerdict.PASS}


def test_28_capability_descriptions_are_nonsemantic_for_execution_identity() -> None:
    first = execution_fixture(
        verifier_cap=verifier_capability(description="first verifier description"),
        provider_cap=provider_capability(description="first provider description"),
    )
    second = execution_fixture(
        verifier_cap=verifier_capability(description="second verifier description"),
        provider_cap=provider_capability(description="second provider description"),
    )

    assert first.request.plan.fingerprint == second.request.plan.fingerprint
    assert (
        first.request.verifier_runtime_registry.fingerprint
        == second.request.verifier_runtime_registry.fingerprint
    )
    assert (
        first.request.evidence_provider_runtime_registry.fingerprint
        == second.request.evidence_provider_runtime_registry.fingerprint
    )
    assert first.request.fingerprint == second.request.fingerprint
    assert (
        execute_verification_plan(first.request).fingerprint
        == execute_verification_plan(second.request).fingerprint
    )
    wire_result = handle_request(
        {
            "schema_version": 1,
            "op": "execute_verification_plan",
            "payload": first.request.to_dict(),
        },
        verifier_runtime_registry=second.request.verifier_runtime_registry,
        evidence_provider_runtime_registry=(
            second.request.evidence_provider_runtime_registry
        ),
    )
    assert wire_result["kind"] == "verification_execution_result"
