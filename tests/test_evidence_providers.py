from __future__ import annotations

from dataclasses import FrozenInstanceError
from typing import Any

import pytest

from gvr import (
    Evidence,
    VerificationIssue,
    VerificationVerdict,
    VerifierCapability,
    VerifierCost,
    VerifierDeterminism,
    handle_request,
    safe_handle_request,
)
from gvr.evidence_providers import (
    BUILTIN_EVIDENCE_PROVIDER_REGISTRY,
    EVIDENCE_PROVIDER_CAPABILITY_FINGERPRINT_FORMAT,
    EVIDENCE_PROVIDER_CAPABILITY_REGISTRY_FINGERPRINT_FORMAT,
    EvidenceAcquisitionStatus,
    EvidenceCompleteness,
    EvidenceCoverage,
    EvidenceProvider,
    EvidenceProviderCapability,
    EvidenceProviderError,
    EvidenceProviderRegistry,
    EvidenceProviderResult,
    EvidenceRequest,
    UnknownEvidenceProviderError,
    builtin_evidence_provider_registry,
    provider_capability_is_compatible_with_verifier,
    validate_evidence_provider_result,
)


def request(**overrides: Any) -> EvidenceRequest:
    values = {
        "request_id": "req-1",
        "provider_id": "provider.alpha",
        "provider_version": "1",
        "request_kind": "CAN_FLOW_TO",
        "requested_evidence_kinds": ("graphify.data_flow_query_result",),
        "subject": {"target": "x"},
        "spec": {},
        "semantic_scope": {"scope": ["a", "b"]},
        "source_context": {},
        "snapshot_context": {},
        "bounds": {"max_depth": 3},
    }
    values.update(overrides)
    return EvidenceRequest(**values)


def capability(**overrides: Any) -> EvidenceProviderCapability:
    values = {
        "provider_id": "provider.alpha",
        "version": "1",
        "request_kinds": ("CAN_FLOW_TO",),
        "produced_evidence_kinds": ("graphify.data_flow_query_result", "graphify.data_flow_edge"),
        "input_schema": {},
        "output_schema": {},
        "determinism": VerifierDeterminism.O1,
        "side_effect_free": True,
        "cost": VerifierCost.EXTERNAL,
        "bounds": {"max_depth": 3},
        "coverage": {"graph": "materialized"},
        "description": "alpha",
    }
    values.update(overrides)
    return EvidenceProviderCapability(**values)


def result(**overrides: Any) -> EvidenceProviderResult:
    cap = capability()
    req = request()
    values = {
        "request_id": req.request_id,
        "request_fingerprint": req.fingerprint,
        "provider_id": cap.provider_id,
        "provider_version": cap.version,
        "status": EvidenceAcquisitionStatus.COMPLETE,
        "coverage": EvidenceCoverage(
            completeness=EvidenceCompleteness.COMPLETE,
            covered_evidence_kinds=("graphify.data_flow_query_result",),
            declared_scope=req.semantic_scope,
            observed_scope=req.semantic_scope,
            declared_bounds=req.bounds,
            source_identity=req.source_context,
            snapshot_identity=req.snapshot_context,
            truncated=False,
            details={"nodes_examined": 2},
        ),
        "evidence": (
            Evidence(
                id="ev-1",
                kind="graphify.data_flow_query_result",
                payload={"complete": True},
                source="graphify",
            ),
        ),
        "issues": (),
        "capability_fingerprint": cap.fingerprint,
    }
    values.update(overrides)
    return EvidenceProviderResult(**values)


def test_evidence_request_is_strict_immutable_and_detached() -> None:
    payload = {"z": [1]}
    req = request(subject=payload)
    payload["z"].append(2)
    assert req.subject["z"] == (1,)
    with pytest.raises(FrozenInstanceError):
        req.request_id = "changed"  # type: ignore[misc]
    with pytest.raises(TypeError):
        req.subject["new"] = True  # type: ignore[index]


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_id", ""),
        ("request_id", " req"),
        ("provider_id", "provider id"),
        ("provider_version", ""),
        ("request_kind", "CAN FLOW"),
        ("requested_evidence_kinds", ("x", "x")),
        ("subject", {1: "bad"}),
        ("bounds", {"bad": float("nan")}),
    ],
)
def test_request_rejects_invalid_values(field: str, value: Any) -> None:
    with pytest.raises(EvidenceProviderError):
        request(**{field: value})


def test_coverage_complete_partial_unknown_invariants() -> None:
    complete = EvidenceCoverage(EvidenceCompleteness.COMPLETE, ("b", "a"), False, {})
    assert complete.covered_evidence_kinds == ("a", "b")
    with pytest.raises(EvidenceProviderError):
        EvidenceCoverage(EvidenceCompleteness.COMPLETE, (), True, {})
    partial = EvidenceCoverage(EvidenceCompleteness.PARTIAL, (), False, {})
    assert partial.truncated is False
    with pytest.raises(EvidenceProviderError):
        EvidenceCoverage(EvidenceCompleteness.UNKNOWN, ("x",), False, {})


@pytest.mark.parametrize("status", list(EvidenceAcquisitionStatus))
def test_result_statuses_have_no_verdict(status: EvidenceAcquisitionStatus) -> None:
    res = result(status=status, coverage=EvidenceCoverage(EvidenceCompleteness.PARTIAL if status is EvidenceAcquisitionStatus.PARTIAL else EvidenceCompleteness.UNKNOWN if status is not EvidenceAcquisitionStatus.COMPLETE else EvidenceCompleteness.COMPLETE, ("graphify.data_flow_query_result",) if status in (EvidenceAcquisitionStatus.COMPLETE, EvidenceAcquisitionStatus.PARTIAL) else (), status is EvidenceAcquisitionStatus.PARTIAL, {}), evidence=() if status is not EvidenceAcquisitionStatus.COMPLETE else result().evidence)
    assert not hasattr(res, "verdict")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"evidence": (Evidence("ev-1", "graphify.data_flow_query_result"), Evidence("ev-1", "graphify.data_flow_edge"))},
        {"status": EvidenceAcquisitionStatus.COMPLETE, "coverage": EvidenceCoverage(EvidenceCompleteness.PARTIAL, ("graphify.data_flow_query_result",), True, {})},
        {"status": EvidenceAcquisitionStatus.PARTIAL, "coverage": EvidenceCoverage(EvidenceCompleteness.COMPLETE, ("graphify.data_flow_query_result",), False, {})},
        {"status": EvidenceAcquisitionStatus.UNAVAILABLE, "evidence": (Evidence("ev-2", "graphify.data_flow_query_result"),)},
        {"issues": (VerificationIssue("I", "msg", VerificationVerdict.PASS),)},
        {"capability_fingerprint": ""},
    ],
)
def test_result_rejects_adversarial_shapes(kwargs: dict[str, Any]) -> None:
    with pytest.raises(EvidenceProviderError):
        result(**kwargs)


def test_capability_fingerprint_is_canonical_and_distinct_from_verifier_domain() -> None:
    a = capability(produced_evidence_kinds=("b", "a"), coverage={"z": 1, "a": [2]})
    b = capability(produced_evidence_kinds=("a", "b"), coverage={"a": [2], "z": 1})
    assert a.fingerprint == b.fingerprint
    assert a.to_dict()["fingerprint_format"] == EVIDENCE_PROVIDER_CAPABILITY_FINGERPRINT_FORMAT
    assert EVIDENCE_PROVIDER_CAPABILITY_FINGERPRINT_FORMAT != EVIDENCE_PROVIDER_CAPABILITY_REGISTRY_FINGERPRINT_FORMAT


@pytest.mark.parametrize(
    "field,value",
    [
        ("provider_id", ""),
        ("version", "bad version"),
        ("request_kinds", ("x", "x")),
        ("request_kinds", ()),
        ("produced_evidence_kinds", ("x", "x")),
        ("produced_evidence_kinds", ()),
        ("input_schema", {1: "bad"}),
        ("determinism", "BAD"),
        ("cost", "FREE"),
        ("side_effect_free", "yes"),
    ],
)
def test_capability_rejects_invalid_values(field: str, value: Any) -> None:
    with pytest.raises(EvidenceProviderError):
        capability(**{field: value})


def test_registry_is_deterministic_exact_and_rejects_conflicting_duplicates() -> None:
    a = capability(provider_id="provider.b")
    b = capability(provider_id="provider.a")
    reg = EvidenceProviderRegistry((a, b, a))
    assert [c.provider_id for c in reg.list()] == ["provider.a", "provider.b"]
    assert reg.lookup("provider.a", "1") is b
    with pytest.raises(UnknownEvidenceProviderError):
        reg.lookup("provider.a", "2")
    with pytest.raises(EvidenceProviderError):
        EvidenceProviderRegistry((a, capability(provider_id="provider.b", request_kinds=("NO_SUPPORTED_PATH",))))


def test_builtin_provider_registry_is_honestly_empty_and_exported() -> None:
    assert builtin_evidence_provider_registry().list() == ()
    assert BUILTIN_EVIDENCE_PROVIDER_REGISTRY.to_dict()["capabilities"] == []
    response = handle_request({"schema_version": 1, "op": "describe_evidence_provider_capabilities", "payload": {}})
    assert response["kind"] == "evidence_provider_capability_registry"
    assert response["payload"]["capabilities"] == []


class Provider:
    def __init__(self, res: EvidenceProviderResult | BaseException, cap: EvidenceProviderCapability | None = None) -> None:
        self.calls: list[EvidenceRequest] = []
        self.res = res
        self.capability = capability() if cap is None else cap
        self.provider_id = self.capability.provider_id
        self.version = self.capability.version

    def acquire(self, req: EvidenceRequest) -> EvidenceProviderResult:
        self.calls.append(req)
        if isinstance(self.res, BaseException):
            raise self.res
        return self.res


def test_runtime_registry_invokes_exact_provider_without_fallback_and_fails_closed() -> None:
    req = request(provider_id="provider.alpha")
    alpha_cap = capability()
    fallback_cap = capability(provider_id="provider.fallback")
    provider = Provider(result(request_id=req.request_id), alpha_cap)
    fallback = Provider(result(provider_id="provider.fallback"), fallback_cap)
    reg = EvidenceProviderRegistry((alpha_cap, fallback_cap), runtime_providers={("provider.alpha", "1"): provider, ("provider.fallback", "1"): fallback})
    assert isinstance(provider, EvidenceProvider)
    acquired = reg.acquire(req)
    assert acquired.request_id == req.request_id
    assert provider.calls == [req]
    assert fallback.calls == []

    with pytest.raises(UnknownEvidenceProviderError):
        reg.acquire(request(provider_version="2"))

    failing_cap = capability()
    failing = EvidenceProviderRegistry((failing_cap,), runtime_providers={("provider.alpha", "1"): Provider(RuntimeError("boom"), failing_cap)})
    closed = failing.acquire(request(), fail_closed=True)
    assert closed.status is EvidenceAcquisitionStatus.UNAVAILABLE
    assert closed.evidence == ()
    assert closed.issues[0].code == "PROVIDER_EXCEPTION"


def test_validate_result_catches_request_provider_capability_and_kind_mismatches() -> None:
    cap = capability()
    req = request()
    validate_evidence_provider_result(result(), req, cap)
    adversarial = [
        result(request_id="other"),
        result(provider_id="other"),
        result(provider_version="2"),
        result(capability_fingerprint="0" * 64),
        result(evidence=(Evidence("ev", "unsupported"),)),
        result(coverage=EvidenceCoverage(EvidenceCompleteness.COMPLETE, ("graphify.data_flow_edge",), False, {})),
    ]
    for item in adversarial:
        with pytest.raises(EvidenceProviderError):
            validate_evidence_provider_result(item, req, cap)


def test_provider_to_verifier_compatibility_is_exact_and_never_upgrades_truth() -> None:
    provider_cap = capability(request_kinds=("CAN_FLOW_TO", "NO_SUPPORTED_PATH"), produced_evidence_kinds=("graphify.data_flow_edge", "graphify.data_flow_query_result", "graphify.data_flow_boundary"))
    verifier_cap = VerifierCapability(
        verifier_id="gvr.graphify.data_flow.v1",
        version="1",
        claim_kinds=("CAN_FLOW_TO",),
        accepted_evidence_kinds=("graphify.data_flow_edge", "graphify.data_flow_query_result"),
        required_evidence_kinds=("graphify.data_flow_query_result",),
        input_schema={},
        output_schema={},
        determinism=VerifierDeterminism.O1,
        side_effect_free=True,
        cost=VerifierCost.EXTERNAL,
        bounds={},
        coverage={},
        authoritative=True,
    )
    compatibility = provider_capability_is_compatible_with_verifier(provider_cap, verifier_cap, claim_kind="CAN_FLOW_TO")
    assert compatibility.compatible is True
    assert compatibility.truth_upgraded is False
    assert compatibility.evidence_kinds == ("graphify.data_flow_edge", "graphify.data_flow_query_result")
    assert provider_capability_is_compatible_with_verifier(provider_cap, verifier_cap, claim_kind="NO_SUPPORTED_PATH").compatible is False


def test_registry_queries_by_request_and_evidence_kind_not_claim_kind() -> None:
    alpha = capability(provider_id="provider.alpha", request_kinds=("CAN_FLOW_TO",), produced_evidence_kinds=("graphify.data_flow_query_result",))
    beta = capability(provider_id="provider.beta", request_kinds=("NO_SUPPORTED_PATH",), produced_evidence_kinds=("graphify.data_flow_edge",))
    reg = EvidenceProviderRegistry((beta, alpha))

    assert reg.query(request_kind="CAN_FLOW_TO") == (alpha,)
    assert reg.query(evidence_kind="graphify.data_flow_edge") == (beta,)
    assert reg.query(request_kind="NO_SUPPORTED_PATH", evidence_kind="graphify.data_flow_query_result") == ()
    with pytest.raises(TypeError):
        reg.query(claim_kind="CAN_FLOW_TO")  # type: ignore[call-arg]


def test_describe_evidence_provider_capabilities_rejects_claim_kind_filter() -> None:
    response = safe_handle_request({"schema_version": 1, "op": "describe_evidence_provider_capabilities", "payload": {"claim_kind": "CAN_FLOW_TO"}})
    assert response["kind"] == "protocol_error"
    assert response["payload"]["code"] == "INVALID_PAYLOAD"
    assert "claim_kind" in response["payload"]["message"]


def test_validate_evidence_provider_result_protocol_operation_normalizes_serialized_result() -> None:
    cap = capability()
    req = request()
    res = result()
    response = handle_request({
        "schema_version": 1,
        "op": "validate_evidence_provider_result",
        "payload": {
            "request": req.to_dict(),
            "capability": cap.to_dict(),
            "result": res.to_dict(),
        },
    })

    assert response["kind"] == "evidence_provider_result"
    assert response["payload"]["request_id"] == "req-1"
    assert response["payload"]["coverage"]["covered_evidence_kinds"] == ["graphify.data_flow_query_result"]
    assert response["payload"]["evidence"][0]["payload"] == {"complete": True}


def test_validate_evidence_provider_result_protocol_operation_returns_machine_readable_errors() -> None:
    cap = capability()
    req = request()
    bad = result(capability_fingerprint="0" * 64).to_dict()
    response = safe_handle_request({
        "schema_version": 1,
        "op": "validate_evidence_provider_result",
        "payload": {
            "request": req.to_dict(),
            "capability": cap.to_dict(),
            "result": bad,
        },
    })

    assert response["kind"] == "protocol_error"
    assert response["payload"]["code"] == "INVALID_EVIDENCE_PROVIDER_RESULT"
    assert "fingerprint" in response["payload"]["message"]


def test_validate_evidence_provider_result_protocol_operation_defaults_omitted_coverage_fields() -> None:
    cap = capability()
    req = request()
    res = result()
    res_dict = res.to_dict()
    del res_dict["coverage"]["truncated"]
    del res_dict["coverage"]["termination_reason"]
    response = handle_request({
        "schema_version": 1,
        "op": "validate_evidence_provider_result",
        "payload": {
            "request": req.to_dict(),
            "capability": cap.to_dict(),
            "result": res_dict,
        },
    })
    assert response["kind"] == "evidence_provider_result"
    assert response["payload"]["coverage"]["truncated"] is False
    assert response["payload"]["coverage"]["termination_reason"] == "UNKNOWN"
