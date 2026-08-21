from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace

import pytest

from gvr import (
    AtomicClaim,
    COMPOSITE_CLAIM_VERIFIER,
    DATA_FLOW_VERIFIER,
    REGRESSION_TEST_OBLIGATION_VERIFIER,
    DataFlowClaim,
    DataFlowClaimKind,
    VerifierCapability,
    VerifierCapabilityRegistry,
    VerifierCost,
    VerifierDeterminism,
    UnknownVerifierCapabilityError,
    builtin_verifier_capability_registry,
    handle_request,
    verify_data_flow_claim_bundle,
)


_COMPLETE_DATA_FLOW_COVERAGE = "COMPLETE_FOR_SUPPORTED_CONSTRUCT"
_DATA_FLOW_RELATIONS = (
    "FLOWS_TO",
    "PASSED_AS_ARGUMENT",
    "READ_FROM",
    "RETURNED_AS",
    "TRANSFORMED_BY",
    "WRITTEN_TO",
)


def _cap(**overrides: object) -> VerifierCapability:
    values: dict[str, object] = {
        "verifier_id": "fixture.verifier",
        "version": "1",
        "claim_kinds": ("BETA", "ALPHA"),
        "accepted_evidence_kinds": ("fixture.z", "fixture.a"),
        "required_evidence_kinds": ("fixture.a",),
        "input_schema": {"type": "object", "required": ["claim"]},
        "output_schema": {"type": "gvr.VerificationReport"},
        "determinism": VerifierDeterminism.D1,
        "side_effect_free": True,
        "cost": VerifierCost.MEDIUM,
        "bounds": {"scope": {"kind": "fixture"}, "max_items": 10},
        "coverage": {"mode": "COMPLETE_FOR_DECLARED_BOUNDS"},
        "authoritative": True,
        "description": "fixture descriptor",
    }
    values.update(overrides)
    return VerifierCapability(**values)


def _atomic(
    *,
    verifier: str = "fixture.verifier",
    claim_kind: str = "ALPHA",
) -> AtomicClaim:
    return AtomicClaim(
        claim_id="A",
        claim_kind=claim_kind,
        spec={"subject": "A"},
        verifier=verifier,
    )


def _data_flow_evidence_key(item: dict[str, object]) -> str:
    fields = [
        ("r", str(item.get("relation") or "")),
        ("s", str(item.get("source") or "")),
        ("t", str(item.get("target") or "")),
        ("f", str(item.get("source_file") or "")),
        ("l", str(item.get("source_location") or "")),
        ("p", str(item.get("provenance") or "")),
    ]
    canonical = json.dumps(sorted(fields), sort_keys=True, separators=(",", ":"))
    return "df:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _data_flow_edge(source: str, target: str) -> dict[str, object]:
    item: dict[str, object] = {
        "relation": "FLOWS_TO",
        "source": source,
        "target": target,
        "source_file": "src/Flow.java",
        "source_location": f"{source}->{target}",
        "provenance": "STATIC_AST",
        "confidence_score": 1.0,
        "argument_index": None,
        "receiver_confidence": "PROVEN",
        "analysis_completeness": _COMPLETE_DATA_FLOW_COVERAGE,
    }
    item["key"] = _data_flow_evidence_key(item)
    return item


def _data_flow_path(*items: dict[str, object]) -> dict[str, object]:
    return {
        "steps": [
            {
                "source": item["source"],
                "target": item["target"],
                "relation": item["relation"],
                "evidence": deepcopy(item),
            }
            for item in items
        ],
        "supporting_evidence": [deepcopy(item) for item in items],
        "path_identity": [item["key"] for item in items],
        "path_exactness": "EXACT_FOR_RETURNED_PATH",
        "path_receiver_confidence": "PROVEN",
        "path_coverage": _COMPLETE_DATA_FLOW_COVERAGE,
    }


def _data_flow_result(
    paths: list[dict[str, object]],
    *,
    start: str = "A",
    target: str = "C",
    complete_supported_search: bool = True,
    search_coverage: str = _COMPLETE_DATA_FLOW_COVERAGE,
    boundary_events: list[dict[str, object]] | None = None,
    max_depth: int = 4,
) -> dict[str, object]:
    expanded_count = sum(len(path["steps"]) for path in paths)
    return {
        "paths": deepcopy(paths),
        "start": start,
        "target": target,
        "direction": "FORWARD",
        "visited_count": 1 + expanded_count,
        "expanded_count": expanded_count,
        "truncated": False,
        "termination_reason": "COMPLETE",
        "query_bounds": {
            "direction": "FORWARD",
            "max_depth": max_depth,
            "max_paths": 50,
            "max_expansions": 2000,
            "requested_allowed_relations": list(_DATA_FLOW_RELATIONS),
            "effective_allowed_relations": list(_DATA_FLOW_RELATIONS),
            "rejected_relations": [],
            "stop_nodes": [],
        },
        "boundary_events": deepcopy(boundary_events or []),
        "search_coverage": search_coverage,
        "complete_supported_search": complete_supported_search,
        "start_node_found": True,
        "target_node_found": True,
        "query_validity": True,
        "input_resolution": "RESOLVED",
        "rejected_relations": [],
        "encountered_partial_evidence": False,
        "encountered_unknown_evidence": False,
        "encountered_may_evidence": False,
    }


def _data_flow_claim(
    kind: DataFlowClaimKind = DataFlowClaimKind.CAN_FLOW_TO,
    *,
    start: str = "A",
    target: str = "C",
) -> DataFlowClaim:
    return DataFlowClaim(
        kind=kind,
        start=start,
        target=target,
        evidence_namespace="capability-tests",
        source_context="rev1",
    )


def _direct_path_bundle():
    edge = _data_flow_edge("A", "C")
    return verify_data_flow_claim_bundle(
        _data_flow_claim(),
        _data_flow_result([_data_flow_path(edge)]),
    )


def _complete_absence_bundle():
    return verify_data_flow_claim_bundle(
        _data_flow_claim(DataFlowClaimKind.NO_SUPPORTED_PATH),
        _data_flow_result([]),
    )


def _zero_step_identity_bundle():
    return verify_data_flow_claim_bundle(
        _data_flow_claim(start="A", target="A"),
        _data_flow_result(
            [_data_flow_path()],
            start="A",
            target="A",
            max_depth=0,
        ),
    )


def _blocking_boundary_bundle():
    boundary = {
        "type": "boundary_event",
        "boundary_evidence_key": "bnd:ambiguous-call",
        "diagnostic_evidence_key": "diag:42",
        "resolution": "AMBIGUOUS",
        "reason": "overload ambiguity",
        "canonical_caller_file": "src/Flow.java",
        "caller_location": "L42",
    }
    return verify_data_flow_claim_bundle(
        _data_flow_claim(DataFlowClaimKind.NO_SUPPORTED_PATH),
        _data_flow_result(
            [],
            complete_supported_search=False,
            search_coverage="PARTIAL",
            boundary_events=[boundary],
        ),
    )


def _runtime_evidence_kinds(*bundles) -> frozenset[str]:
    return frozenset(
        evidence.kind
        for bundle in bundles
        for evidence in bundle.evidence
    )


def _runtime_evidence_kinds_missing_from_capability(
    capability: VerifierCapability,
    *bundles,
) -> frozenset[str]:
    return _runtime_evidence_kinds(*bundles) - frozenset(
        capability.accepted_evidence_kinds
    )


def test_descriptor_reorders_claim_evidence_and_bounds_without_identity_drift():
    left = _cap()
    right = _cap(
        claim_kinds=("ALPHA", "BETA"),
        accepted_evidence_kinds=("fixture.a", "fixture.z"),
        bounds={"max_items": 10, "scope": {"kind": "fixture"}},
    )
    assert left.claim_kinds == ("ALPHA", "BETA")
    assert left.accepted_evidence_kinds == ("fixture.a", "fixture.z")
    assert left.fingerprint == right.fingerprint


def test_each_semantic_contract_change_changes_descriptor_fingerprint():
    base = _cap()
    changes = (
        replace(base, claim_kinds=("OTHER",)),
        replace(base, accepted_evidence_kinds=("fixture.a",)),
        replace(base, input_schema={"type": "array"}),
        replace(base, output_schema={"type": "object"}),
        replace(base, bounds={"max_items": 11}),
        replace(base, coverage={"mode": "PARTIAL"}),
        replace(base, cost=VerifierCost.HIGH),
        replace(base, version="2"),
    )
    assert all(item.fingerprint != base.fingerprint for item in changes)


def test_determinism_change_changes_descriptor_fingerprint():
    base = _cap()
    changed = replace(base, determinism=VerifierDeterminism.O1)
    assert changed.fingerprint != base.fingerprint


def test_side_effect_change_changes_descriptor_fingerprint():
    base = _cap()
    changed = replace(base, side_effect_free=False)
    assert changed.fingerprint != base.fingerprint


def test_authoritative_change_changes_descriptor_fingerprint():
    base = _cap()
    changed = replace(base, authoritative=False)
    assert changed.fingerprint != base.fingerprint


def test_description_is_non_semantic_but_exported():
    base = _cap(description="first")
    changed = replace(base, description="second")
    assert changed.fingerprint == base.fingerprint
    assert base.to_dict()["description"] == "first"
    assert changed.to_dict()["description"] == "second"


def test_invalid_verifier_id_is_rejected_strictly():
    for value in ("", " leading", "contains space", 7):
        with pytest.raises((TypeError, ValueError)):
            _cap(verifier_id=value)


def test_invalid_version_is_rejected_strictly():
    for value in ("", "1 beta", 1):
        with pytest.raises((TypeError, ValueError)):
            _cap(version=value)


def test_invalid_determinism_cost_and_authoritative_m1_are_rejected():
    with pytest.raises((TypeError, ValueError)):
        _cap(determinism="D9")
    with pytest.raises((TypeError, ValueError)):
        _cap(cost="VARIABLE")
    with pytest.raises(ValueError):
        _cap(determinism=VerifierDeterminism.M1, authoritative=True)


def test_required_evidence_must_be_accepted_and_contract_lists_have_no_duplicates():
    with pytest.raises(ValueError):
        _cap(required_evidence_kinds=("fixture.missing",))
    with pytest.raises(ValueError):
        _cap(claim_kinds=("ALPHA", "ALPHA"))
    with pytest.raises(ValueError):
        _cap(accepted_evidence_kinds=("fixture.a", "fixture.a"))


def test_unsupported_schema_or_bounds_object_is_rejected():
    class Unsupported:
        pass

    for field_name in ("input_schema", "output_schema", "bounds", "coverage"):
        with pytest.raises((TypeError, ValueError)):
            _cap(**{field_name: {"bad": Unsupported()}})


def test_descriptor_is_deeply_immutable_and_detached_from_inputs():
    input_schema = {"properties": {"claim": {"type": "string"}}}
    capability = _cap(input_schema=input_schema)
    input_schema["properties"]["claim"]["type"] = "integer"
    assert capability.to_dict()["input_schema"]["properties"]["claim"]["type"] == "string"
    with pytest.raises(TypeError):
        capability.input_schema["new"] = True  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        capability.version = "2"  # type: ignore[misc]


def test_unicode_is_canonical_and_registry_order_uses_utf8_bytes():
    composed = _cap(verifier_id="é.verifier", claim_kinds=("É",))
    decomposed = _cap(verifier_id="e.verifier", claim_kinds=("E\u0301",))
    registry = VerifierCapabilityRegistry((composed, decomposed))
    assert tuple(item.verifier_id for item in registry.list()) == (
        "e.verifier",
        "é.verifier",
    )
    assert registry.fingerprint == VerifierCapabilityRegistry((decomposed, composed)).fingerprint


def test_registry_rejects_conflicting_duplicate_id_and_version():
    base = _cap()
    conflict = replace(base, claim_kinds=("OTHER",))
    with pytest.raises(ValueError):
        VerifierCapabilityRegistry((base, conflict))


def test_registry_collapses_identical_duplicates_deterministically():
    base = _cap()
    registry = VerifierCapabilityRegistry((base, replace(base)))
    assert registry.list() == (base,)
    assert registry.fingerprint == VerifierCapabilityRegistry((base,)).fingerprint


def test_registry_input_reordering_preserves_listing_export_and_fingerprint():
    first = _cap(verifier_id="z.verifier")
    second = _cap(verifier_id="a.verifier", version="2")
    left = VerifierCapabilityRegistry((first, second))
    right = VerifierCapabilityRegistry((second, first))
    assert left.list() == right.list()
    assert left.to_dict() == right.to_dict()
    assert left.fingerprint == right.fingerprint


def test_registry_lookup_requires_exact_id_and_version():
    v1 = _cap(version="1")
    v2 = _cap(version="2")
    registry = VerifierCapabilityRegistry((v2, v1))
    assert registry.lookup("fixture.verifier", "1") == v1
    assert registry.lookup("fixture.verifier", "2") == v2
    with pytest.raises(LookupError):
        registry.lookup("fixture.verifier", "3")
    with pytest.raises(LookupError):
        registry.lookup("missing.verifier", "1")


def test_same_claim_kind_query_is_deterministic_and_unranked():
    items = (
        _cap(verifier_id="z.verifier", cost=VerifierCost.LOW),
        _cap(verifier_id="a.verifier", cost=VerifierCost.HIGH),
        _cap(verifier_id="m.verifier", version="2"),
    )
    registry = VerifierCapabilityRegistry(tuple(reversed(items)))
    assert tuple((item.verifier_id, item.version) for item in registry.query(claim_kind="ALPHA")) == (
        ("a.verifier", "1"),
        ("m.verifier", "2"),
        ("z.verifier", "1"),
    )


def test_authoritative_query_excludes_m1_and_non_authoritative_capabilities():
    authoritative = _cap(verifier_id="authoritative")
    advisory = _cap(verifier_id="advisory", authoritative=False)
    proposal = _cap(
        verifier_id="proposal",
        determinism=VerifierDeterminism.M1,
        authoritative=False,
    )
    registry = VerifierCapabilityRegistry((proposal, advisory, authoritative))
    assert registry.query(claim_kind="ALPHA", authoritative_only=True) == (authoritative,)


def test_validate_atomic_claim_uses_exact_verifier_and_version_without_substitution():
    capability = _cap()
    registry = VerifierCapabilityRegistry((capability,))
    claim = _atomic()
    assert registry.validate_atomic_claim(claim, version="1") == capability
    assert claim.validate_capability(registry, version="1") == capability
    with pytest.raises(LookupError):
        registry.validate_atomic_claim(claim, version="2")


def test_validate_atomic_claim_rejects_unknown_verifier():
    registry = VerifierCapabilityRegistry((_cap(),))
    with pytest.raises(LookupError):
        registry.validate_atomic_claim(_atomic(verifier="unknown.verifier"), version="1")


def test_validate_atomic_claim_rejects_unsupported_claim_kind():
    registry = VerifierCapabilityRegistry((_cap(),))
    with pytest.raises(ValueError):
        registry.validate_atomic_claim(_atomic(claim_kind="UNSUPPORTED"), version="1")


@pytest.mark.parametrize(
    "capability",
    (
        _cap(authoritative=False),
        _cap(
            determinism=VerifierDeterminism.M1,
            authoritative=False,
        ),
    ),
)
def test_validate_atomic_claim_rejects_non_authoritative_capabilities(capability):
    registry = VerifierCapabilityRegistry((capability,))

    with pytest.raises(ValueError, match="authoritative"):
        registry.validate_atomic_claim(_atomic(), version="1")


def test_builtin_snapshot_audits_all_runtime_verifier_contracts():
    registry = builtin_verifier_capability_registry()
    expected = {
        "preconditions": (VerifierDeterminism.D0, VerifierCost.LOW),
        "effect_support": (VerifierDeterminism.D0, VerifierCost.LOW),
        "goal_satisfaction": (VerifierDeterminism.D0, VerifierCost.LOW),
        "text_search": (VerifierDeterminism.D0, VerifierCost.LOW),
        "functional_regression": (VerifierDeterminism.D1, VerifierCost.MEDIUM),
        DATA_FLOW_VERIFIER: (VerifierDeterminism.O1, VerifierCost.EXTERNAL),
        COMPOSITE_CLAIM_VERIFIER: (
            VerifierDeterminism.D1,
            VerifierCost.MEDIUM,
        ),
        REGRESSION_TEST_OBLIGATION_VERIFIER: (
            VerifierDeterminism.D1,
            VerifierCost.MEDIUM,
        ),
    }

    assert len(registry.list()) == 8
    with pytest.raises(UnknownVerifierCapabilityError, match="unknown verifier capability"):
        registry.lookup("registry", "1")
    assert {
        item.verifier_id: (item.determinism, item.cost)
        for item in registry.list()
    } == expected
    assert all(item.version == "1" for item in registry.list())
    assert all(item.side_effect_free for item in registry.list())
    assert all(item.authoritative for item in registry.list())
    assert all(not item.required_evidence_kinds for item in registry.list())

    data_flow = registry.lookup(DATA_FLOW_VERIFIER, "1")
    assert data_flow.claim_kinds == ("CAN_FLOW_TO", "NO_SUPPORTED_PATH")
    assert all(
        not item.claim_kinds and not item.accepted_evidence_kinds
        for item in registry.list()
        if item.verifier_id not in {
            DATA_FLOW_VERIFIER,
            REGRESSION_TEST_OBLIGATION_VERIFIER,
        }
    )


@pytest.mark.parametrize(
    ("bundle_factory", "expected_kind"),
    (
        (_direct_path_bundle, "graphify.data_flow_edge"),
        (_complete_absence_bundle, "graphify.data_flow_query_result"),
        (_zero_step_identity_bundle, "graphify.data_flow_query_result"),
        (_blocking_boundary_bundle, "graphify.data_flow_boundary"),
    ),
    ids=(
        "direct-path-edge",
        "complete-absence-query-result",
        "zero-step-identity-query-result",
        "blocking-boundary",
    ),
)
def test_data_flow_runtime_cases_emit_their_conditional_evidence_kind(
    bundle_factory,
    expected_kind,
):
    bundle = bundle_factory()

    assert _runtime_evidence_kinds(bundle) == frozenset({expected_kind})


def test_data_flow_capability_accepts_exactly_the_runtime_evidence_union():
    capability = builtin_verifier_capability_registry().lookup(
        DATA_FLOW_VERIFIER,
        "1",
    )
    bundles = (
        _direct_path_bundle(),
        _complete_absence_bundle(),
        _zero_step_identity_bundle(),
        _blocking_boundary_bundle(),
    )
    runtime_kinds = _runtime_evidence_kinds(*bundles)

    assert _runtime_evidence_kinds_missing_from_capability(
        capability,
        *bundles,
    ) == frozenset()
    assert frozenset(capability.accepted_evidence_kinds) == runtime_kinds
    assert capability.required_evidence_kinds == ()


def test_runtime_evidence_audit_helper_detects_a_synthetic_omission():
    capability = builtin_verifier_capability_registry().lookup(
        DATA_FLOW_VERIFIER,
        "1",
    )
    synthetic_omission = replace(
        capability,
        accepted_evidence_kinds=tuple(
            kind
            for kind in capability.accepted_evidence_kinds
            if kind != "graphify.data_flow_edge"
        ),
    )

    assert _runtime_evidence_kinds_missing_from_capability(
        synthetic_omission,
        _direct_path_bundle(),
    ) == frozenset({"graphify.data_flow_edge"})


def test_registry_fingerprint_changes_when_one_capability_changes_semantically():
    base = _cap()
    left = VerifierCapabilityRegistry((base,))
    right = VerifierCapabilityRegistry((replace(base, coverage={"mode": "PARTIAL"}),))
    assert left.fingerprint != right.fingerprint


def test_describe_verifier_capabilities_protocol_is_schema_v1_and_deterministic():
    request = {
        "schema_version": 1,
        "op": "describe_verifier_capabilities",
        "payload": {"claim_kind": "CAN_FLOW_TO", "authoritative_only": True},
    }
    first = handle_request(request)
    second = handle_request({
        "payload": dict(reversed(tuple(request["payload"].items()))),
        "op": request["op"],
        "schema_version": 1,
    })
    assert first == second
    assert first["schema_version"] == 1
    assert first["kind"] == "verifier_capability_registry"
    assert [item["verifier_id"] for item in first["payload"]["capabilities"]] == [
        DATA_FLOW_VERIFIER
    ]
    assert first["payload"]["fingerprint"]
