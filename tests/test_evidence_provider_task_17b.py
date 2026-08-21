from __future__ import annotations

from typing import Any

import pytest

from gvr import VerifierCapability, VerifierCost, VerifierDeterminism, safe_handle_request
from gvr import evidence_providers as ep
from gvr.model import Evidence, VerificationIssue, VerificationVerdict


REQUEST_KIND = "graphify.data_flow_query"
CLAIM_KIND = "CAN_FLOW_TO"
QUERY_RESULT = "graphify.data_flow_query_result"
EDGE = "graphify.data_flow_edge"
SOURCE_CLASS = "git.repository"
SNAPSHOT_CLASS = "git.commit"


def request(**overrides: Any) -> ep.EvidenceRequest:
    values: dict[str, Any] = {
        "request_id": "req-17b",
        "provider_id": "provider.alpha",
        "provider_version": "1",
        "request_kind": REQUEST_KIND,
        "requested_evidence_kinds": (QUERY_RESULT, EDGE),
        "subject": {"start": "src", "target": "sink"},
        "spec": {"claim_kind": CLAIM_KIND},
        "semantic_scope": {"direction": "FORWARD"},
        "source_class": SOURCE_CLASS,
        "snapshot_class": SNAPSHOT_CLASS,
        "source_context": {"repository": "example/repo"},
        "snapshot_context": {"revision": "abc123"},
        "bounds": {"max_depth": 3},
    }
    values.update(overrides)
    return ep.EvidenceRequest(**values)


def capability(**overrides: Any) -> ep.EvidenceProviderCapability:
    values: dict[str, Any] = {
        "provider_id": "provider.alpha",
        "version": "1",
        "request_kinds": (REQUEST_KIND,),
        "produced_evidence_kinds": (QUERY_RESULT, EDGE),
        "source_classes": (SOURCE_CLASS,),
        "snapshot_classes": (SNAPSHOT_CLASS,),
        "input_schema": {},
        "output_schema": {},
        "determinism": VerifierDeterminism.O1,
        "side_effect_free": True,
        "cost": VerifierCost.EXTERNAL,
        "bounds": {"max_depth": 3},
        "coverage": {"graph": "materialized"},
    }
    values.update(overrides)
    return ep.EvidenceProviderCapability(**values)


def coverage(**overrides: Any) -> ep.EvidenceCoverage:
    req = request()
    values: dict[str, Any] = {
        "completeness": ep.EvidenceCompleteness.COMPLETE,
        "covered_evidence_kinds": req.requested_evidence_kinds,
        "declared_scope": req.semantic_scope,
        "observed_scope": req.semantic_scope,
        "declared_bounds": req.bounds,
        "consumed": {"nodes": 2},
        "termination": {"exhausted": True},
        "termination_reason": "SOURCE_EXHAUSTED",
        "source_identity": req.source_context,
        "snapshot_identity": req.snapshot_context,
    }
    values.update(overrides)
    return ep.EvidenceCoverage(**values)


def evidence(evidence_id: str, kind: str) -> Evidence:
    return Evidence(evidence_id, kind, {"observed": True}, source="graphify")


def result(**overrides: Any) -> ep.EvidenceProviderResult:
    req = request()
    cap = capability()
    values: dict[str, Any] = {
        "request_id": req.request_id,
        "request_fingerprint": req.fingerprint,
        "provider_id": cap.provider_id,
        "provider_version": cap.version,
        "status": ep.EvidenceAcquisitionStatus.COMPLETE,
        "coverage": coverage(),
        "evidence": (evidence("ev-query", QUERY_RESULT), evidence("ev-edge", EDGE)),
        "issues": (),
        "capability_fingerprint": cap.fingerprint,
    }
    values.update(overrides)
    return ep.EvidenceProviderResult(**values)


def verifier(**overrides: Any) -> VerifierCapability:
    values: dict[str, Any] = {
        "verifier_id": "gvr.graphify.data_flow.v1",
        "version": "1",
        "claim_kinds": (CLAIM_KIND,),
        "accepted_evidence_kinds": (QUERY_RESULT, EDGE),
        "required_evidence_kinds": (QUERY_RESULT,),
        "input_schema": {},
        "output_schema": {},
        "determinism": VerifierDeterminism.O1,
        "side_effect_free": True,
        "cost": VerifierCost.EXTERNAL,
        "bounds": {},
        "coverage": {},
        "authoritative": True,
    }
    values.update(overrides)
    return VerifierCapability(**values)


class Provider:
    def __init__(self, outcome: ep.EvidenceProviderResult | BaseException) -> None:
        self.provider_id = "provider.alpha"
        self.version = "1"
        self.capability = capability()
        self.outcome = outcome
        self.calls: list[ep.EvidenceRequest] = []

    def acquire(self, item: ep.EvidenceRequest) -> ep.EvidenceProviderResult:
        self.calls.append(item)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def runtime_registry(provider: Provider) -> ep.EvidenceProviderRuntimeRegistry:
    capabilities = ep.EvidenceProviderCapabilityRegistry((capability(),))
    return ep.EvidenceProviderRuntimeRegistry(
        capabilities,
        {("provider.alpha", "1"): provider},
    )


def test_capability_and_runtime_registries_are_separate_contracts() -> None:
    capabilities = ep.EvidenceProviderCapabilityRegistry((capability(),))
    provider = Provider(result())
    runtime = ep.EvidenceProviderRuntimeRegistry(
        capabilities,
        {("provider.alpha", "1"): provider},
    )

    assert capabilities.list() == (capability(),)
    assert not hasattr(capabilities, "runtime_providers")
    assert not hasattr(capabilities, "acquire")
    assert runtime.capability_registry is capabilities
    assert runtime.acquire(request()).request_fingerprint == request().fingerprint
    assert ep.builtin_evidence_provider_capability_registry().list() == ()


def test_runtime_validates_request_contract_before_invoking_provider() -> None:
    provider = Provider(result())
    runtime = runtime_registry(provider)

    with pytest.raises(ep.EvidenceProviderError, match="request must be EvidenceRequest"):
        runtime.acquire(object())  # type: ignore[arg-type]
    with pytest.raises(ep.EvidenceProviderError, match="request kind"):
        runtime.acquire(request(request_kind="unsupported.request"))
    with pytest.raises(ep.EvidenceProviderError, match="requested evidence"):
        runtime.acquire(request(requested_evidence_kinds=("unsupported.evidence",)))

    assert provider.calls == []


def test_runtime_rechecks_mutable_provider_identity_and_capability_before_each_call() -> None:
    provider = Provider(result())
    runtime = runtime_registry(provider)
    provider.provider_id = "provider.mutated"

    with pytest.raises(ep.EvidenceProviderError, match="runtime provider identity"):
        runtime.acquire(request())
    assert provider.calls == []

    provider.provider_id = "provider.alpha"
    provider.capability = capability(produced_evidence_kinds=(QUERY_RESULT,))
    with pytest.raises(ep.EvidenceProviderError, match="runtime provider capability"):
        runtime.acquire(request())
    assert provider.calls == []

    provider.capability = capability()
    provider.acquire = None  # type: ignore[method-assign]
    with pytest.raises(ep.EvidenceProviderError, match="acquire must be callable"):
        runtime.acquire(request(), fail_closed=True)
    assert provider.calls == []


def test_fail_closed_only_converts_provider_execution_exceptions() -> None:
    execution_failure = Provider(RuntimeError("token=super-secret"))
    closed = runtime_registry(execution_failure).acquire(request(), fail_closed=True)

    assert closed.status is ep.EvidenceAcquisitionStatus.UNAVAILABLE
    assert closed.coverage.termination == {
        "category": "PROVIDER_EXCEPTION",
        "phase": "provider_execution",
    }
    assert closed.issues == (
        ep.EvidenceProviderIssue(
            "PROVIDER_EXECUTION_ERROR",
            ep.EvidenceProviderIssueCategory.PROVIDER_EXCEPTION,
        ),
    )
    assert "super-secret" not in repr(closed.to_dict())
    assert "RuntimeError" not in repr(closed.to_dict())

    other = runtime_registry(Provider(ValueError("password=other-secret"))).acquire(
        request(), fail_closed=True
    )
    assert other.fingerprint == closed.fingerprint

    invalid_result = result(request_id="wrong-request")
    with pytest.raises(ep.EvidenceProviderError, match="request_id"):
        runtime_registry(Provider(invalid_result)).acquire(request(), fail_closed=True)


def test_provider_issue_has_no_verdict_and_protocol_rejects_verdict() -> None:
    issue = ep.EvidenceProviderIssue("SOURCE_UNAVAILABLE", evidence_ids=("ev-query",))
    assert not hasattr(issue, "verdict")
    assert not hasattr(issue, "message")
    assert issue.to_dict() == {
        "code": "SOURCE_UNAVAILABLE",
        "category": None,
        "evidence_ids": ["ev-query"],
    }
    with pytest.raises(ep.EvidenceProviderError, match="EvidenceProviderIssue"):
        result(issues=(VerificationIssue("X", "bad", VerificationVerdict.UNKNOWN),))

    wire = {
        "schema_version": 1,
        "op": "validate_evidence_provider_result",
        "payload": {
            "request": request().to_dict(),
            "capability": capability().to_dict(),
            "result": result(issues=(issue,)).to_dict(),
        },
    }
    assert safe_handle_request(wire)["kind"] == "evidence_provider_result"
    wire["payload"]["result"]["issues"][0]["verdict"] = "UNKNOWN"
    rejected = safe_handle_request(wire)
    assert rejected["kind"] == "protocol_error"
    assert "verdict" in rejected["payload"]["message"]


def test_request_kind_and_verifier_claim_kind_are_distinct_compatibility_inputs() -> None:
    compatible = ep.provider_capability_is_compatible_with_verifier(
        capability(),
        verifier(),
        request_kind=REQUEST_KIND,
        claim_kind=CLAIM_KIND,
    )
    assert compatible.compatible is True
    assert compatible.unsupported_request_kind is False
    assert compatible.unsupported_claim_kind is False
    assert not hasattr(compatible, "truth_upgraded")

    wrong_request = ep.provider_capability_is_compatible_with_verifier(
        capability(), verifier(), request_kind="other.request", claim_kind=CLAIM_KIND
    )
    assert wrong_request.unsupported_request_kind is True
    assert wrong_request.unsupported_claim_kind is False

    wrong_claim = ep.provider_capability_is_compatible_with_verifier(
        capability(), verifier(), request_kind=REQUEST_KIND, claim_kind="OTHER_CLAIM"
    )
    assert wrong_claim.unsupported_request_kind is False
    assert wrong_claim.unsupported_claim_kind is True

    with pytest.raises(ep.EvidenceProviderError, match="request_kind and claim_kind"):
        ep.provider_capability_is_compatible_with_verifier(
            capability(), verifier(), request_kind=REQUEST_KIND
        )


def test_verifier_input_exposes_structural_compatibility_facts_not_sufficiency() -> None:
    adapted = ep.provider_result_for_verifier(result(), verifier())
    assert adapted.emitted_evidence_kinds == (EDGE, QUERY_RESULT)
    assert adapted.present_required_evidence_kinds == (QUERY_RESULT,)
    assert adapted.missing_required_evidence_kinds == ()
    assert adapted.compatible is True
    assert not hasattr(adapted, "sufficient")
    assert not hasattr(adapted, "truth_upgraded")

    partial = result(
        status=ep.EvidenceAcquisitionStatus.PARTIAL,
        coverage=coverage(
            completeness=ep.EvidenceCompleteness.PARTIAL,
            covered_evidence_kinds=(EDGE,),
            observed_scope={"direction": "FORWARD", "truncated_at": "midpoint"},
            termination={"bound_reached": True},
            truncated=True,
            termination_reason="BOUND_REACHED",
        ),
        evidence=(evidence("ev-edge", EDGE),),
    )
    adapted_partial = ep.provider_result_for_verifier(partial, verifier())
    assert adapted_partial.present_required_evidence_kinds == ()
    assert adapted_partial.missing_required_evidence_kinds == (QUERY_RESULT,)


def test_capability_source_and_snapshot_classes_are_fingerprinted_and_in_protocol() -> None:
    cap = capability()
    exported = cap.to_dict()
    assert exported["source_classes"] == [SOURCE_CLASS]
    assert exported["snapshot_classes"] == [SNAPSHOT_CLASS]
    assert cap.fingerprint != capability(source_classes=("database",)).fingerprint
    assert cap.fingerprint != capability(snapshot_classes=("working_tree",)).fingerprint

    wire = {
        "schema_version": 1,
        "op": "validate_evidence_provider_result",
        "payload": {
            "request": request().to_dict(),
            "capability": exported,
            "result": result().to_dict(),
        },
    }
    assert safe_handle_request(wire)["kind"] == "evidence_provider_result"
    del wire["payload"]["capability"]["source_classes"]
    assert safe_handle_request(wire)["kind"] == "protocol_error"


def test_result_validation_hardens_coverage_partial_and_truth_like_metadata() -> None:
    with pytest.raises(ep.EvidenceProviderError, match="emitted evidence kinds"):
        ep.validate_evidence_provider_result(
            result(
                coverage=coverage(covered_evidence_kinds=(QUERY_RESULT,)),
                evidence=(evidence("ev-edge", EDGE),),
            ),
            request(),
            capability(),
        )

    contradictory_partial = result(
        status=ep.EvidenceAcquisitionStatus.PARTIAL,
        coverage=coverage(
            completeness=ep.EvidenceCompleteness.PARTIAL,
            truncated=False,
        ),
    )
    with pytest.raises(ep.EvidenceProviderError, match="partial result contradicts"):
        ep.validate_evidence_provider_result(
            contradictory_partial, request(), capability()
        )

    for field in ("verdict", "passed", "sufficient", "truth"):
        with pytest.raises(ep.EvidenceProviderError, match="truth-like"):
            coverage(details={field: True})
        with pytest.raises(ep.EvidenceProviderError, match="truth-like"):
            coverage(termination={field: True})
