from __future__ import annotations

import asyncio
from concurrent.futures import CancelledError as FuturesCancelledError
from typing import Any

import pytest

import gvr
from gvr import VerifierCost, VerifierDeterminism, safe_handle_request
from gvr import evidence_providers as ep


REQUEST_KIND = "graphify.data_flow_query"
EVIDENCE_KIND = "graphify.data_flow_query_result"
SOURCE_CLASS = "git.repository"
SNAPSHOT_CLASS = "git.commit"


def request(**overrides: Any) -> ep.EvidenceRequest:
    values: dict[str, Any] = {
        "request_id": "req-17c",
        "provider_id": "provider.alpha",
        "provider_version": "1",
        "request_kind": REQUEST_KIND,
        "requested_evidence_kinds": (EVIDENCE_KIND,),
        "subject": {"target": "sink"},
        "spec": {"relation": "CAN_FLOW_TO"},
        "semantic_scope": {"direction": "FORWARD"},
        "source_context": {"repository": "example/repo"},
        "snapshot_context": {"revision": "abc123"},
        "bounds": {"max_depth": 3},
        "source_class": SOURCE_CLASS,
        "snapshot_class": SNAPSHOT_CLASS,
    }
    values.update(overrides)
    return ep.EvidenceRequest(**values)


def capability(**overrides: Any) -> ep.EvidenceProviderCapability:
    values: dict[str, Any] = {
        "provider_id": "provider.alpha",
        "version": "1",
        "request_kinds": (REQUEST_KIND,),
        "produced_evidence_kinds": (EVIDENCE_KIND,),
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


def unavailable_result(
    req: ep.EvidenceRequest,
    cap: ep.EvidenceProviderCapability,
    *,
    issues: tuple[ep.EvidenceProviderIssue, ...] = (),
) -> ep.EvidenceProviderResult:
    return ep.EvidenceProviderResult(
        request_id=req.request_id,
        request_fingerprint=req.fingerprint,
        provider_id=req.provider_id,
        provider_version=req.provider_version,
        status=ep.EvidenceAcquisitionStatus.UNAVAILABLE,
        coverage=ep.EvidenceCoverage(
            completeness=ep.EvidenceCompleteness.UNKNOWN,
            declared_scope=req.semantic_scope,
            declared_bounds=req.bounds,
            source_identity=req.source_context,
            snapshot_identity=req.snapshot_context,
        ),
        evidence=(),
        issues=issues,
        capability_fingerprint=cap.fingerprint,
    )


class Provider:
    def __init__(
        self,
        cap: ep.EvidenceProviderCapability,
        outcome: BaseException | None = None,
    ) -> None:
        self.provider_id = cap.provider_id
        self.version = cap.version
        self.capability = cap
        self.outcome = outcome
        self.calls: list[ep.EvidenceRequest] = []

    def acquire(self, item: ep.EvidenceRequest) -> ep.EvidenceProviderResult:
        self.calls.append(item)
        if self.outcome is not None:
            raise self.outcome
        return unavailable_result(item, self.capability)


def runtime(
    cap: ep.EvidenceProviderCapability,
    provider: Provider,
) -> ep.EvidenceProviderRuntimeRegistry:
    return ep.EvidenceProviderRuntimeRegistry(
        ep.EvidenceProviderCapabilityRegistry((cap,)),
        {(cap.provider_id, cap.version): provider},
    )


def validation_wire(
    req: ep.EvidenceRequest,
    cap: ep.EvidenceProviderCapability,
    result: ep.EvidenceProviderResult,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "op": "validate_evidence_provider_result",
        "payload": {
            "request": req.to_dict(),
            "capability": cap.to_dict(),
            "result": result.to_dict(),
        },
    }


def test_request_source_and_snapshot_classes_are_explicit_semantics_and_protocol_fields() -> None:
    base = request()
    different_source = request(source_class="workspace.directory")
    different_snapshot = request(snapshot_class="workspace.state")
    unclassified = request(source_class=None, snapshot_class=None)

    assert base.to_dict()["source_class"] == SOURCE_CLASS
    assert base.to_dict()["snapshot_class"] == SNAPSHOT_CLASS
    assert len({base.fingerprint, different_source.fingerprint, different_snapshot.fingerprint, unclassified.fingerprint}) == 4

    cap = capability()
    parsed = safe_handle_request(validation_wire(base, cap, unavailable_result(base, cap)))
    assert parsed["kind"] == "evidence_provider_result"
    assert parsed["payload"]["request_fingerprint"] == base.fingerprint


@pytest.mark.parametrize(
    "capability_classes,request_class,compatible",
    [
        ((), None, True),
        ((SOURCE_CLASS,), SOURCE_CLASS, True),
        ((SOURCE_CLASS,), None, False),
        ((SOURCE_CLASS,), "workspace.directory", False),
        ((), SOURCE_CLASS, False),
    ],
)
def test_source_class_compatibility_is_exact_and_empty_capability_is_meaningful(
    capability_classes: tuple[str, ...],
    request_class: str | None,
    compatible: bool,
) -> None:
    cap = capability(source_classes=capability_classes)
    req = request(source_class=request_class)
    registry = ep.EvidenceProviderCapabilityRegistry((cap,))

    if compatible:
        assert registry.validate_request(req) is cap
    else:
        with pytest.raises(ep.EvidenceProviderError, match="source class"):
            registry.validate_request(req)


@pytest.mark.parametrize(
    "capability_classes,request_class,compatible",
    [
        ((), None, True),
        ((SNAPSHOT_CLASS,), SNAPSHOT_CLASS, True),
        ((SNAPSHOT_CLASS,), None, False),
        ((SNAPSHOT_CLASS,), "workspace.state", False),
        ((), SNAPSHOT_CLASS, False),
    ],
)
def test_snapshot_class_compatibility_is_exact_and_empty_capability_is_meaningful(
    capability_classes: tuple[str, ...],
    request_class: str | None,
    compatible: bool,
) -> None:
    cap = capability(snapshot_classes=capability_classes)
    req = request(snapshot_class=request_class)
    registry = ep.EvidenceProviderCapabilityRegistry((cap,))

    if compatible:
        assert registry.validate_request(req) is cap
    else:
        with pytest.raises(ep.EvidenceProviderError, match="snapshot class"):
            registry.validate_request(req)


def test_runtime_uses_public_registry_validation_and_never_calls_class_incompatible_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cap = capability()
    provider = Provider(cap)
    registry = ep.EvidenceProviderCapabilityRegistry((cap,))
    execution = ep.EvidenceProviderRuntimeRegistry(
        registry,
        {(cap.provider_id, cap.version): provider},
    )
    original = ep.EvidenceProviderCapabilityRegistry.validate_request
    validated: list[ep.EvidenceRequest] = []

    def tracking_validate_request(
        self: ep.EvidenceProviderCapabilityRegistry,
        item: ep.EvidenceRequest,
    ) -> ep.EvidenceProviderCapability:
        validated.append(item)
        return original(self, item)

    monkeypatch.setattr(
        ep.EvidenceProviderCapabilityRegistry,
        "validate_request",
        tracking_validate_request,
    )

    valid = request()
    execution.acquire(valid)
    assert validated == [valid]
    assert provider.calls == [valid]

    invalid_requests = (
        request(source_class=None),
        request(source_class="workspace.directory"),
        request(snapshot_class=None),
        request(snapshot_class="workspace.state"),
    )
    for invalid in invalid_requests:
        with pytest.raises(ep.EvidenceProviderError):
            execution.acquire(invalid, fail_closed=True)
    assert provider.calls == [valid]

    empty_cap = capability(source_classes=(), snapshot_classes=())
    empty_provider = Provider(empty_cap)
    empty_runtime = runtime(empty_cap, empty_provider)
    with pytest.raises(ep.EvidenceProviderError):
        empty_runtime.acquire(request(source_class=SOURCE_CLASS, snapshot_class=None))
    with pytest.raises(ep.EvidenceProviderError):
        empty_runtime.acquire(request(source_class=None, snapshot_class=SNAPSHOT_CLASS))
    assert empty_provider.calls == []


def test_provider_issue_exports_only_stable_code_optional_category_and_evidence_ids() -> None:
    issue = ep.EvidenceProviderIssue(
        code="PROVIDER_EXECUTION_FAILED",
        category=ep.EvidenceProviderIssueCategory.TIMEOUT,
        evidence_ids=("ev-2", "ev-1"),
    )

    assert gvr.EvidenceProviderIssueCategory is ep.EvidenceProviderIssueCategory
    assert issue.to_dict() == {
        "code": "PROVIDER_EXECUTION_FAILED",
        "category": "TIMEOUT",
        "evidence_ids": ["ev-1", "ev-2"],
    }
    assert not hasattr(issue, "message")
    assert not hasattr(issue, "verdict")
    with pytest.raises(ep.EvidenceProviderError, match="category"):
        ep.EvidenceProviderIssue("SOURCE_FAILURE", category="arbitrary provider prose")


@pytest.mark.parametrize(
    "field,value",
    [
        ("code", "PASS"),
        ("code", "SOURCE_FAIL"),
        ("code", "UNKNOWN"),
        ("code", "CLAIM_VERDICT_NOTE"),
        ("code", "VERIFIED_SOURCE"),
        ("code", "EVIDENCE_SUFFICIENT"),
        ("code", "TRUTH"),
        ("category", "PASS"),
        ("category", "PROVIDER_FAIL"),
        ("category", "UNKNOWN"),
        ("category", "CLAIM_VERDICT"),
        ("category", "VERIFIED"),
        ("category", "SUFFICIENT_EVIDENCE"),
        ("category", "SOURCE_TRUTH"),
    ],
)
def test_provider_issue_rejects_direct_and_tokenized_truth_like_codes_and_categories(
    field: str,
    value: str,
) -> None:
    values: dict[str, Any] = {"code": "SOURCE_FAILURE", "category": None}
    values[field] = value
    with pytest.raises(ep.EvidenceProviderError, match="truth-like"):
        ep.EvidenceProviderIssue(**values)


@pytest.mark.parametrize("obsolete_field", ["message", "verdict"])
def test_protocol_rejects_obsolete_provider_issue_message_and_verdict(obsolete_field: str) -> None:
    req = request()
    cap = capability()
    issue = ep.EvidenceProviderIssue("SOURCE_FAILURE")
    wire = validation_wire(req, cap, unavailable_result(req, cap, issues=(issue,)))
    wire["payload"]["result"]["issues"][0][obsolete_field] = "UNKNOWN"

    rejected = safe_handle_request(wire)
    assert rejected["kind"] == "protocol_error"
    assert obsolete_field in rejected["payload"]["message"]


@pytest.mark.parametrize(
    "failure,category",
    [
        (TimeoutError("endpoint A exceeded 5s"), "TIMEOUT"),
        (PermissionError("token=secret has no access"), "ACCESS_DENIED"),
        (ConnectionError("host=db.internal refused"), "CONNECTION"),
        (OSError("path=/secret failed"), "IO"),
        (FuturesCancelledError("cancel reason secret"), "CANCELLED"),
        (asyncio.CancelledError("async cancel secret"), "CANCELLED"),
        (RuntimeError("password=hunter2"), "PROVIDER_EXCEPTION"),
    ],
)
def test_fail_closed_maps_execution_failures_to_safe_stable_categories(
    failure: BaseException,
    category: str,
) -> None:
    cap = capability()
    closed = runtime(cap, Provider(cap, failure)).acquire(request(), fail_closed=True)
    exported = repr(closed.to_dict())

    assert closed.issues == (
        ep.EvidenceProviderIssue(
            code="PROVIDER_EXECUTION_FAILED",
            category=category,
        ),
    )
    assert closed.coverage.termination_reason == "PROVIDER_EXECUTION_FAILED"
    assert closed.coverage.termination == {
        "category": category,
        "phase": "provider_execution",
    }
    assert str(failure) not in exported
    assert failure.__class__.__name__ not in exported


def test_fail_closed_identity_depends_on_category_not_raw_exception_text_or_class() -> None:
    cap = capability()

    timeout_a = runtime(cap, Provider(cap, TimeoutError("secret endpoint A"))).acquire(
        request(), fail_closed=True
    )
    timeout_b = runtime(cap, Provider(cap, TimeoutError("secret endpoint B"))).acquire(
        request(), fail_closed=True
    )
    generic_a = runtime(cap, Provider(cap, RuntimeError("secret A"))).acquire(
        request(), fail_closed=True
    )
    generic_b = runtime(cap, Provider(cap, ValueError("secret B"))).acquire(
        request(), fail_closed=True
    )
    denied = runtime(cap, Provider(cap, PermissionError("secret A"))).acquire(
        request(), fail_closed=True
    )

    assert timeout_a.fingerprint == timeout_b.fingerprint
    assert generic_a.fingerprint == generic_b.fingerprint
    assert timeout_a.fingerprint != denied.fingerprint
    assert generic_a.fingerprint != denied.fingerprint
