from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from gvr import (
    AtomicClaim,
    DATA_FLOW_VERIFIER,
    COMPOSITE_CLAIM_VERIFIER,
    VerifierCapability,
    VerifierCapabilityRegistry,
    VerifierCost,
    VerifierDeterminism,
    builtin_verifier_capability_registry,
    handle_request,
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
    assert registry.validate_atomic_claim(_atomic(), version="1") == capability
    with pytest.raises(LookupError):
        registry.validate_atomic_claim(_atomic(), version="2")


def test_validate_atomic_claim_rejects_unknown_verifier():
    registry = VerifierCapabilityRegistry((_cap(),))
    with pytest.raises(LookupError):
        registry.validate_atomic_claim(_atomic(verifier="unknown.verifier"), version="1")


def test_validate_atomic_claim_rejects_unsupported_claim_kind():
    registry = VerifierCapabilityRegistry((_cap(),))
    with pytest.raises(ValueError):
        registry.validate_atomic_claim(_atomic(claim_kind="UNSUPPORTED"), version="1")


def test_builtin_snapshot_matches_runtime_verifier_ids_and_honest_contracts():
    registry = builtin_verifier_capability_registry()
    expected = {
        "preconditions": VerifierDeterminism.D0,
        "effect_support": VerifierDeterminism.D0,
        "goal_satisfaction": VerifierDeterminism.D0,
        "registry": VerifierDeterminism.D1,
        "text_search": VerifierDeterminism.D0,
        "functional_regression": VerifierDeterminism.D1,
        DATA_FLOW_VERIFIER: VerifierDeterminism.O1,
        COMPOSITE_CLAIM_VERIFIER: VerifierDeterminism.D1,
    }
    assert {item.verifier_id: item.determinism for item in registry.list()} == expected
    data_flow = registry.lookup(DATA_FLOW_VERIFIER, "1")
    assert data_flow.claim_kinds == ("CAN_FLOW_TO", "NO_SUPPORTED_PATH")
    assert data_flow.accepted_evidence_kinds == (
        "graphify.data_flow_boundary",
        "graphify.data_flow_edge",
    )
    assert all(
        not item.claim_kinds and not item.accepted_evidence_kinds
        for item in registry.list()
        if item.verifier_id != DATA_FLOW_VERIFIER
    )


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
    second = handle_request({"payload": dict(reversed(tuple(request["payload"].items()))), "op": request["op"], "schema_version": 1})
    assert first == second
    assert first["schema_version"] == 1
    assert first["kind"] == "verifier_capability_registry"
    assert [item["verifier_id"] for item in first["payload"]["capabilities"]] == [
        DATA_FLOW_VERIFIER
    ]
    assert first["payload"]["fingerprint"]
