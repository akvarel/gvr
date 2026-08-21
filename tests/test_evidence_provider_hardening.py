from __future__ import annotations

from types import MappingProxyType
from typing import Any

import pytest

from gvr import Evidence, VerifierCapability, VerifierCost, VerifierDeterminism, handle_request, safe_handle_request
from gvr import evidence_providers as ep


REQUEST_KIND = "graphify.data_flow_query"
QUERY_RESULT = "graphify.data_flow_query_result"
EDGE = "graphify.data_flow_edge"


def request(**overrides: Any) -> ep.EvidenceRequest:
    values: dict[str, Any] = {
        "request_id": "req-1",
        "provider_id": "provider.alpha",
        "provider_version": "1",
        "request_kind": REQUEST_KIND,
        "requested_evidence_kinds": (QUERY_RESULT, EDGE),
        "subject": {"start": "src", "target": "sink"},
        "spec": {"relation": "CAN_FLOW_TO"},
        "semantic_scope": {"direction": "FORWARD", "relations": ["CALLS", "READS"]},
        "source_class": "git.repository",
        "snapshot_class": "git.commit",
        "source_context": {"repository": "example/repo", "revision": "abc123"},
        "snapshot_context": {"snapshot_id": "snap-7", "content_digest": "sha256:123"},
        "bounds": {"max_depth": 3, "max_nodes": 100},
    }
    values.update(overrides)
    return ep.EvidenceRequest(**values)


def coverage(**overrides: Any) -> ep.EvidenceCoverage:
    req = request()
    values: dict[str, Any] = {
        "completeness": ep.EvidenceCompleteness.COMPLETE,
        "covered_evidence_kinds": req.requested_evidence_kinds,
        "declared_scope": req.semantic_scope,
        "observed_scope": req.semantic_scope,
        "declared_bounds": req.bounds,
        "consumed": {"nodes": 2, "depth": 1},
        "termination": {"exhausted": True},
        "truncated": False,
        "termination_reason": "SOURCE_EXHAUSTED",
        "source_identity": req.source_context,
        "snapshot_identity": req.snapshot_context,
    }
    values.update(overrides)
    return ep.EvidenceCoverage(**values)


def capability(**overrides: Any) -> ep.EvidenceProviderCapability:
    values: dict[str, Any] = {
        "provider_id": "provider.alpha",
        "version": "1",
        "request_kinds": (REQUEST_KIND,),
        "produced_evidence_kinds": (QUERY_RESULT, EDGE),
        "source_classes": ("git.repository",),
        "snapshot_classes": ("git.commit",),
        "input_schema": {},
        "output_schema": {},
        "determinism": VerifierDeterminism.O1,
        "side_effect_free": True,
        "cost": VerifierCost.EXTERNAL,
        "bounds": {"max_depth": 3, "max_nodes": 100},
        "coverage": {"graph": "materialized"},
        "description": "alpha",
    }
    values.update(overrides)
    return ep.EvidenceProviderCapability(**values)


def evidence(evidence_id: str = "ev-1", *, kind: str = QUERY_RESULT, payload: Any = None, source: str = "graphify", fingerprint: str = "producer-fp-1") -> Evidence:
    return Evidence(
        id=evidence_id,
        kind=kind,
        payload={"complete": True, "nested": {"paths": ["a", "b"]}} if payload is None else payload,
        source=source,
        fingerprint=fingerprint,
    )


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
        "evidence": (evidence("ev-b", kind=EDGE), evidence("ev-a")),
        "issues": (ep.EvidenceProviderIssue("OBSERVATION_NOTE", evidence_ids=("ev-a",)),),
        "capability_fingerprint": cap.fingerprint,
    }
    values.update(overrides)
    return ep.EvidenceProviderResult(**values)


def verifier(**overrides: Any) -> VerifierCapability:
    values: dict[str, Any] = {
        "verifier_id": "gvr.graphify.data_flow.v1",
        "version": "1",
        "claim_kinds": ("CAN_FLOW_TO",),
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


def request_wire(req: ep.EvidenceRequest) -> dict[str, Any]:
    return req.to_dict()


def validation_wire(res: ep.EvidenceProviderResult | None = None) -> dict[str, Any]:
    req = request()
    cap = capability()
    return {
        "schema_version": 1,
        "op": "validate_evidence_provider_result",
        "payload": {
            "request": request_wire(req),
            "capability": cap.to_dict(),
            "result": (result() if res is None else res).to_dict(),
        },
    }


def test_request_has_versioned_kind_and_nonsemantic_correlation_id() -> None:
    left = request(request_id="correlation-a")
    right = request(request_id="correlation-b")

    assert left.schema_version == ep.EVIDENCE_REQUEST_SCHEMA_VERSION == 1
    assert left.kind == ep.EVIDENCE_REQUEST_KIND == "gvr.evidence_request"
    assert left.fingerprint_format == ep.EVIDENCE_REQUEST_FINGERPRINT_FORMAT
    assert left.fingerprint == right.fingerprint
    assert left.to_dict()["request_id"] == "correlation-a"
    assert left.to_dict()["fingerprint"] == left.fingerprint
    assert not hasattr(left, "claim_kind")


def test_request_fingerprint_covers_every_semantic_field_and_is_order_independent() -> None:
    base = request(requested_evidence_kinds=(EDGE, QUERY_RESULT), semantic_scope={"z": [2, 1], "a": True})
    reordered = request(requested_evidence_kinds=(QUERY_RESULT, EDGE), semantic_scope={"a": True, "z": [2, 1]})
    assert base.fingerprint == reordered.fingerprint

    mutations = {
        "provider_id": "provider.beta",
        "provider_version": "2",
        "request_kind": "other.request",
        "requested_evidence_kinds": (QUERY_RESULT,),
        "subject": {"start": "other"},
        "spec": {"relation": "NO_SUPPORTED_PATH"},
        "semantic_scope": {"direction": "REVERSE"},
        "source_class": "workspace.directory",
        "snapshot_class": "workspace.state",
        "source_context": {"repository": "other", "revision": "abc123"},
        "snapshot_context": {"snapshot_id": "snap-8"},
        "bounds": {"max_depth": 4},
    }
    assert all(request(**{field: value}).fingerprint != request().fingerprint for field, value in mutations.items())


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", 2),
        ("schema_version", True),
        ("kind", "gvr.wrong"),
        ("fingerprint_format", "wrong"),
        ("request_kind", "bad kind"),
        ("requested_evidence_kinds", (QUERY_RESULT, QUERY_RESULT)),
        ("requested_evidence_kinds", ()),
        ("subject", {1: "bad"}),
        ("spec", {"bad": float("nan")}),
        ("semantic_scope", []),
        ("source_class", "bad class"),
        ("snapshot_class", 1),
        ("source_context", "source"),
        ("snapshot_context", None),
    ],
)
def test_request_rejects_invalid_versioned_and_semantic_values(field: str, value: Any) -> None:
    with pytest.raises(ep.EvidenceProviderError):
        request(**{field: value})


def test_coverage_is_explicit_detached_fingerprinted_and_order_independent() -> None:
    scope = {"relations": ["CALLS"], "nested": {"a": [1]}}
    item = coverage(declared_scope=scope, observed_scope=scope)
    scope["nested"]["a"].append(2)

    assert item.schema_version == ep.EVIDENCE_COVERAGE_SCHEMA_VERSION == 1
    assert item.kind == ep.EVIDENCE_COVERAGE_KIND == "gvr.evidence_coverage"
    assert item.declared_scope["nested"]["a"] == (1,)
    assert isinstance(item.declared_scope, MappingProxyType)
    assert item.to_dict()["fingerprint_format"] == ep.EVIDENCE_COVERAGE_FINGERPRINT_FORMAT
    assert item.fingerprint == coverage(
        covered_evidence_kinds=(EDGE, QUERY_RESULT),
        declared_scope={"nested": {"a": [1]}, "relations": ["CALLS"]},
        observed_scope={"nested": {"a": [1]}, "relations": ["CALLS"]},
    ).fingerprint
    assert item.fingerprint != coverage(consumed={"nodes": 3}).fingerprint
    assert item.fingerprint != coverage(termination_reason="BOUND_REACHED", truncated=True, completeness=ep.EvidenceCompleteness.PARTIAL).fingerprint


@pytest.mark.parametrize(
    "kwargs",
    [
        {"schema_version": 2},
        {"kind": "wrong"},
        {"fingerprint_format": "wrong"},
        {"completeness": ep.EvidenceCompleteness.COMPLETE, "truncated": True},
        {"completeness": ep.EvidenceCompleteness.UNKNOWN, "covered_evidence_kinds": (QUERY_RESULT,)},
        {"termination_reason": ""},
        {"declared_scope": []},
        {"observed_scope": {"bad": float("inf")}},
        {"declared_bounds": None},
        {"consumed": "all"},
        {"termination": []},
        {"source_identity": None},
        {"snapshot_identity": "snapshot"},
    ],
)
def test_coverage_rejects_invalid_values(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ep.EvidenceProviderError):
        coverage(**kwargs)


def test_result_deeply_snapshots_evidence_deduplicates_identical_ids_and_is_order_independent() -> None:
    payload = {"nested": {"values": [1]}}
    first = evidence("ev-1", payload=payload)
    duplicate = evidence("ev-1", payload={"nested": {"values": [1]}})
    second = evidence("ev-2", kind=EDGE, fingerprint="producer-fp-2")
    item = result(evidence=(second, first, duplicate), issues=())
    payload["nested"]["values"].append(2)

    assert item.schema_version == ep.EVIDENCE_PROVIDER_RESULT_SCHEMA_VERSION == 1
    assert item.kind == ep.EVIDENCE_PROVIDER_RESULT_KIND == "gvr.evidence_provider_result"
    assert item.fingerprint_format == ep.EVIDENCE_PROVIDER_RESULT_FINGERPRINT_FORMAT
    assert [record.id for record in item.evidence] == ["ev-1", "ev-2"]
    assert item.evidence[0].payload["nested"]["values"] == (1,)
    with pytest.raises(TypeError):
        item.evidence[0].payload["new"] = True  # type: ignore[index]
    assert item.fingerprint == result(
        evidence=(evidence("ev-1", payload={"nested": {"values": [1]}}), second),
        issues=(),
    ).fingerprint
    assert item.to_dict()["evidence"][0]["fingerprint"] == "producer-fp-1"


def test_result_rejects_conflicting_duplicate_evidence_ids() -> None:
    with pytest.raises(ep.EvidenceProviderError, match="conflicting evidence"):
        result(evidence=(evidence("same"), evidence("same", payload={"different": True})))


def test_result_fingerprint_covers_request_provider_status_coverage_evidence_issues_and_capability() -> None:
    base = result()
    mutations = (
        result(request_fingerprint="f" * 64),
        result(provider_id="provider.beta"),
        result(provider_version="2"),
        result(status=ep.EvidenceAcquisitionStatus.PARTIAL, coverage=coverage(completeness=ep.EvidenceCompleteness.PARTIAL, truncated=True, termination_reason="BOUND_REACHED")),
        result(coverage=coverage(consumed={"nodes": 9})),
        result(evidence=(evidence("other"),), issues=()),
        result(issues=()),
        result(capability_fingerprint="c" * 64),
    )
    assert all(item.fingerprint != base.fingerprint for item in mutations)


@pytest.mark.parametrize("field,value", [("schema_version", 2), ("schema_version", True), ("kind", "wrong"), ("fingerprint_format", "wrong"), ("request_fingerprint", ""), ("request_fingerprint", "short"), ("capability_fingerprint", "short"), ("provider_id", "bad provider")])
def test_result_rejects_invalid_versioned_values(field: str, value: Any) -> None:
    with pytest.raises(ep.EvidenceProviderError):
        result(**{field: value})


def test_validate_prevents_same_id_cross_request_replay_and_checks_capability_request_contract() -> None:
    cap = capability()
    original = request()
    replay_target = request(subject={"start": "different", "target": "sink"})
    assert original.request_id == replay_target.request_id

    with pytest.raises(ep.EvidenceProviderError, match="request fingerprint"):
        ep.validate_evidence_provider_result(result(), replay_target, cap)
    with pytest.raises(ep.EvidenceProviderError, match="request kind"):
        ep.validate_evidence_provider_result(result(), original, capability(request_kinds=("other.request",)))
    with pytest.raises(ep.EvidenceProviderError, match="requested evidence"):
        ep.validate_evidence_provider_result(result(), original, capability(produced_evidence_kinds=(QUERY_RESULT,)))


def test_result_for_request_a_cannot_validate_against_same_semantics_request_b() -> None:
    request_a = request(request_id="req-A")
    request_b = request(request_id="req-B")
    provider_result = result(
        request_id=request_a.request_id,
        request_fingerprint=request_a.fingerprint,
    )

    assert request_a.fingerprint == request_b.fingerprint
    with pytest.raises(ep.EvidenceProviderError, match="request_id"):
        ep.validate_evidence_provider_result(
            provider_result,
            request_b,
            capability(),
        )


def test_validate_requires_exact_coverage_scope_bounds_source_snapshot_and_complete_kinds() -> None:
    req = request()
    cap = capability()
    adversarial = (
        result(coverage=coverage(declared_scope={"direction": "REVERSE"})),
        result(coverage=coverage(declared_bounds={"max_depth": 9})),
        result(coverage=coverage(source_identity={"repository": "other"})),
        result(coverage=coverage(snapshot_identity={"snapshot_id": "other"})),
        result(coverage=coverage(covered_evidence_kinds=(QUERY_RESULT,))),
    )
    for item in adversarial:
        with pytest.raises(ep.EvidenceProviderError):
            ep.validate_evidence_provider_result(item, req, cap)


def test_provider_protocol_declares_exact_identity_version_and_capability() -> None:
    cap = capability()

    class Provider:
        provider_id = cap.provider_id
        version = cap.version
        capability = cap

        def acquire(self, req: ep.EvidenceRequest) -> ep.EvidenceProviderResult:
            return result(request_id=req.request_id, request_fingerprint=req.fingerprint)

    class AcquireOnly:
        def acquire(self, req: ep.EvidenceRequest) -> ep.EvidenceProviderResult:
            return result()

    assert isinstance(Provider(), ep.EvidenceProvider)
    assert not isinstance(AcquireOnly(), ep.EvidenceProvider)


def test_registry_runtime_mappings_are_detached_immutable_and_exact() -> None:
    cap = capability()

    class Provider:
        provider_id = cap.provider_id
        version = cap.version
        capability = cap

        def acquire(self, req: ep.EvidenceRequest) -> ep.EvidenceProviderResult:
            return result(request_id=req.request_id, request_fingerprint=req.fingerprint)

    runtime: dict[tuple[str, str], Any] = {(cap.provider_id, cap.version): Provider()}
    capability_registry = ep.EvidenceProviderCapabilityRegistry((cap,))
    registry = ep.EvidenceProviderRuntimeRegistry(capability_registry, runtime)
    runtime.clear()
    assert registry.acquire(request()).request_fingerprint == request().fingerprint
    assert isinstance(registry.runtime_providers, MappingProxyType)
    with pytest.raises(TypeError):
        registry.runtime_providers[(cap.provider_id, cap.version)] = Provider()  # type: ignore[index]

    wrong_capability = capability(produced_evidence_kinds=(QUERY_RESULT,))
    wrong = Provider()
    wrong.capability = wrong_capability
    with pytest.raises(ep.EvidenceProviderError, match="capability"):
        ep.EvidenceProviderRuntimeRegistry(
            ep.EvidenceProviderCapabilityRegistry((cap,)),
            {(cap.provider_id, cap.version): wrong},
        )


def test_provider_result_to_verifier_helper_preserves_acquisition_and_never_upgrades_truth() -> None:
    res = result()
    adapted = ep.provider_result_for_verifier(res, verifier())
    assert adapted.status is res.status
    assert adapted.coverage is res.coverage
    assert adapted.evidence is res.evidence
    assert adapted.compatible is True
    assert adapted.emitted_evidence_kinds == (EDGE, QUERY_RESULT)
    assert adapted.present_required_evidence_kinds == (QUERY_RESULT,)
    assert adapted.missing_required_evidence_kinds == ()
    assert adapted.result_fingerprint == res.fingerprint

    with pytest.raises(ep.EvidenceProviderError, match="not accepted"):
        ep.provider_result_for_verifier(res, verifier(accepted_evidence_kinds=(QUERY_RESULT,), required_evidence_kinds=(QUERY_RESULT,)))


def test_provider_result_to_verifier_helper_allows_empty_only_as_compatibility() -> None:
    empty = result(
        status=ep.EvidenceAcquisitionStatus.UNAVAILABLE,
        coverage=coverage(
            completeness=ep.EvidenceCompleteness.UNKNOWN,
            covered_evidence_kinds=(),
            observed_scope={},
            consumed={},
            termination={"available": False},
            termination_reason="SOURCE_UNAVAILABLE",
        ),
        evidence=(),
        issues=(),
    )
    adapted = ep.provider_result_for_verifier(empty, verifier())
    assert adapted.compatible is True
    assert adapted.present_required_evidence_kinds == ()
    assert adapted.missing_required_evidence_kinds == (QUERY_RESULT,)
    assert adapted.evidence == ()


def test_protocol_normalizes_full_request_coverage_and_result_fingerprints() -> None:
    response = handle_request(validation_wire())
    payload = response["payload"]
    assert payload["schema_version"] == 1
    assert payload["kind"] == ep.EVIDENCE_PROVIDER_RESULT_KIND
    assert payload["request_fingerprint"] == request().fingerprint
    assert payload["coverage"]["declared_scope"] == request().to_dict()["semantic_scope"]
    assert payload["coverage"]["termination_reason"] == "SOURCE_EXHAUSTED"
    assert payload["coverage"]["fingerprint"] == coverage().fingerprint
    assert payload["fingerprint"] == result().fingerprint
    assert [record["id"] for record in payload["evidence"]] == ["ev-a", "ev-b"]


@pytest.mark.parametrize("target", ["request", "coverage", "result", "capability"])
def test_protocol_rejects_every_claimed_fingerprint_mismatch(target: str) -> None:
    wire = validation_wire()
    payload = wire["payload"]
    if target == "coverage":
        payload["result"]["coverage"]["fingerprint"] = "0" * 64
    else:
        payload[target]["fingerprint"] = "0" * 64
    response = safe_handle_request(wire)
    assert response["kind"] == "protocol_error"
    assert "fingerprint" in response["payload"]["message"]


@pytest.mark.parametrize(
    "target,field",
    [
        ("request", "claim_kind"),
        ("capability", "claim_kinds"),
        ("result", "verdict"),
        ("coverage", "covered_scope"),
    ],
)
def test_protocol_rejects_obsolete_or_unknown_nested_fields(target: str, field: str) -> None:
    wire = validation_wire()
    destination = wire["payload"]["result"]["coverage"] if target == "coverage" else wire["payload"][target]
    destination[field] = "obsolete"
    response = safe_handle_request(wire)
    assert response["kind"] == "protocol_error"
    assert field in response["payload"]["message"]


def test_protocol_rejects_capability_fingerprint_domain_mismatch() -> None:
    wire = validation_wire()
    wire["payload"]["capability"]["fingerprint_format"] = ep.EVIDENCE_REQUEST_FINGERPRINT_FORMAT
    response = safe_handle_request(wire)
    assert response["kind"] == "protocol_error"
    assert "fingerprint_format" in response["payload"]["message"]


def test_all_provider_canonical_domains_are_distinct() -> None:
    formats = {
        ep.EVIDENCE_REQUEST_FINGERPRINT_FORMAT,
        ep.EVIDENCE_COVERAGE_FINGERPRINT_FORMAT,
        ep.EVIDENCE_PROVIDER_RESULT_FINGERPRINT_FORMAT,
        ep.EVIDENCE_PROVIDER_CAPABILITY_FINGERPRINT_FORMAT,
        ep.EVIDENCE_PROVIDER_CAPABILITY_REGISTRY_FINGERPRINT_FORMAT,
    }
    assert len(formats) == 5
