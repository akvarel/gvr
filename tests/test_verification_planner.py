from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from typing import Any

import pytest

import gvr
from gvr import (
    AtomicClaim,
    AtomicClaimBinding,
    ClaimGraph,
    ClaimGraphValidationError,
    ClaimOperator,
    CompositeClaim,
    EvidenceProviderCapability,
    EvidenceProviderCapabilityRegistry,
    EvidenceRequest,
    VerificationPlanStepKind,
    VerificationPlanTermination,
    VerificationPlanningBudget,
    VerificationPlanningError,
    VerificationPlanningRequest,
    VerifierCapability,
    VerifierCapabilityRegistry,
    VerifierCost,
    VerifierDeterminism,
    compile_verification_plan,
    handle_request,
    safe_handle_request,
)


def verifier_capability(**overrides: Any) -> VerifierCapability:
    values: dict[str, Any] = {
        "verifier_id": "fixture.state.verifier",
        "version": "1",
        "claim_kinds": ("ASSERT_STATE",),
        "accepted_evidence_kinds": ("state.audit", "state.snapshot"),
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
        "produced_evidence_kinds": ("state.audit", "state.snapshot"),
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


def evidence_request(**overrides: Any) -> EvidenceRequest:
    values: dict[str, Any] = {
        "request_id": "request-A",
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
    verifier: str = "fixture.state.verifier",
    claim_kind: str = "ASSERT_STATE",
    dependencies: tuple[str, ...] = (),
    spec: dict[str, Any] | None = None,
) -> AtomicClaim:
    return AtomicClaim(
        claim_id=claim_id,
        claim_kind=claim_kind,
        spec={"entity": claim_id, "expected": True} if spec is None else spec,
        verifier=verifier,
        scope={"repository": "demo"},
        dependencies=dependencies,
    )


def binding(
    claim_id: str = "A",
    *,
    verifier: VerifierCapability | None = None,
    requests: tuple[EvidenceRequest, ...] | None = None,
    verifier_id: str | None = None,
    verifier_version: str | None = None,
    verifier_capability_fingerprint: str | None = None,
) -> AtomicClaimBinding:
    capability = verifier or verifier_capability()
    return AtomicClaimBinding(
        claim_id=claim_id,
        verifier_id=verifier_id or capability.verifier_id,
        verifier_version=verifier_version or capability.version,
        verifier_capability_fingerprint=(
            verifier_capability_fingerprint or capability.fingerprint
        ),
        evidence_requests=(evidence_request() if requests is None else None,)
        if requests is None
        else requests,
    )


def planning_request(
    *,
    graph: ClaimGraph | None = None,
    bindings: tuple[AtomicClaimBinding, ...] | None = None,
    verifiers: tuple[VerifierCapability, ...] | None = None,
    providers: tuple[EvidenceProviderCapability, ...] | None = None,
    budget: VerificationPlanningBudget | None = None,
) -> VerificationPlanningRequest:
    claim_graph = graph or ClaimGraph(nodes=(atomic_claim(),))
    verifier_registry = VerifierCapabilityRegistry(
        verifiers or (verifier_capability(),)
    )
    provider_registry = EvidenceProviderCapabilityRegistry(
        providers or (provider_capability(),)
    )
    return VerificationPlanningRequest(
        claim_graph=claim_graph,
        bindings=bindings or (binding(),),
        verifier_capability_registry=verifier_registry,
        verifier_capability_registry_fingerprint=verifier_registry.fingerprint,
        evidence_provider_capability_registry=provider_registry,
        evidence_provider_capability_registry_fingerprint=provider_registry.fingerprint,
        budget=budget or VerificationPlanningBudget(),
    )


def issue_codes(plan: Any) -> tuple[str, ...]:
    return tuple(issue.code for issue in plan.issues)


def test_01_compatible_atomic_flow_is_strict_immutable_and_canonical() -> None:
    request = planning_request()
    plan = compile_verification_plan(request)

    assert plan.termination is VerificationPlanTermination.COMPLETE
    assert tuple(step.kind for step in plan.steps) == (
        VerificationPlanStepKind.ACQUIRE_EVIDENCE,
        VerificationPlanStepKind.VERIFY_ATOMIC_CLAIM,
    )
    assert plan.steps[1].dependency_step_ids == (plan.steps[0].step_id,)
    assert plan.request_fingerprint == request.fingerprint
    with pytest.raises(FrozenInstanceError):
        request.fingerprint = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        request.bindings[0].claim_id = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        plan.steps = ()  # type: ignore[misc]


def test_02_provider_request_kind_is_distinct_from_verifier_claim_kind() -> None:
    plan = compile_verification_plan(planning_request())
    acquire, verify = plan.steps
    assert acquire.request_kind == "CAPTURE_STATE"
    assert verify.claim_kind == "ASSERT_STATE"
    assert acquire.request_kind != verify.claim_kind


def test_03_unknown_verifier_capability_fails_closed() -> None:
    unknown = binding(
        verifier_id="unknown.verifier",
        verifier_capability_fingerprint="0" * 64,
    )
    graph = ClaimGraph(nodes=(atomic_claim(verifier="unknown.verifier"),))
    plan = compile_verification_plan(
        planning_request(graph=graph, bindings=(unknown,))
    )
    assert plan.termination is VerificationPlanTermination.UNSUPPORTED_CLAIM
    assert issue_codes(plan) == ("UNKNOWN_VERIFIER_CAPABILITY",)
    assert plan.steps == ()


def test_04_binding_verifier_id_must_match_atomic_claim() -> None:
    other = verifier_capability(verifier_id="fixture.other.verifier")
    plan = compile_verification_plan(
        planning_request(
            bindings=(binding(verifier=other),),
            verifiers=(verifier_capability(), other),
        )
    )
    assert issue_codes(plan) == ("VERIFIER_ID_MISMATCH",)


def test_05_unknown_exact_verifier_version_fails_closed() -> None:
    plan = compile_verification_plan(
        planning_request(bindings=(binding(verifier_version="2"),))
    )
    assert issue_codes(plan) == ("UNKNOWN_VERIFIER_CAPABILITY",)


def test_06_verifier_capability_fingerprint_must_match_exact_descriptor() -> None:
    plan = compile_verification_plan(
        planning_request(
            bindings=(binding(verifier_capability_fingerprint="f" * 64),)
        )
    )
    assert issue_codes(plan) == ("VERIFIER_CAPABILITY_FINGERPRINT_MISMATCH",)


def test_07_unsupported_claim_kind_fails_closed() -> None:
    graph = ClaimGraph(nodes=(atomic_claim(claim_kind="OTHER_CLAIM"),))
    plan = compile_verification_plan(planning_request(graph=graph))
    assert issue_codes(plan) == ("UNSUPPORTED_CLAIM_KIND",)


def test_08_non_authoritative_verifier_capability_fails_closed() -> None:
    verifier = verifier_capability(authoritative=False)
    plan = compile_verification_plan(
        planning_request(
            bindings=(binding(verifier=verifier),),
            verifiers=(verifier,),
        )
    )
    assert issue_codes(plan) == ("NON_AUTHORITATIVE_VERIFIER",)


def test_09_unknown_provider_capability_fails_closed() -> None:
    request = evidence_request(provider_id="unknown.provider")
    plan = compile_verification_plan(
        planning_request(bindings=(binding(requests=(request,)),))
    )
    assert issue_codes(plan) == (
        "MISSING_REQUIRED_EVIDENCE_KIND",
        "UNKNOWN_EVIDENCE_PROVIDER_CAPABILITY",
    )


def test_10_unknown_exact_provider_version_fails_closed() -> None:
    request = evidence_request(provider_version="2")
    plan = compile_verification_plan(
        planning_request(bindings=(binding(requests=(request,)),))
    )
    assert issue_codes(plan) == (
        "MISSING_REQUIRED_EVIDENCE_KIND",
        "UNKNOWN_EVIDENCE_PROVIDER_CAPABILITY",
    )


def test_11_unsupported_provider_request_kind_fails_closed() -> None:
    request = evidence_request(request_kind="OTHER_CAPTURE")
    plan = compile_verification_plan(
        planning_request(bindings=(binding(requests=(request,)),))
    )
    assert issue_codes(plan) == (
        "MISSING_REQUIRED_EVIDENCE_KIND",
        "UNSUPPORTED_REQUEST_KIND",
    )


def test_12_provider_must_produce_every_requested_evidence_kind() -> None:
    request = evidence_request(requested_evidence_kinds=("state.unknown",))
    plan = compile_verification_plan(
        planning_request(bindings=(binding(requests=(request,)),))
    )
    assert issue_codes(plan) == (
        "MISSING_REQUIRED_EVIDENCE_KIND",
        "UNSUPPORTED_REQUESTED_EVIDENCE_KIND",
    )


def test_13_source_class_must_match_exact_provider_contract() -> None:
    request = evidence_request(source_class="workspace")
    plan = compile_verification_plan(
        planning_request(bindings=(binding(requests=(request,)),))
    )
    assert issue_codes(plan) == (
        "MISSING_REQUIRED_EVIDENCE_KIND",
        "UNSUPPORTED_SOURCE_CLASS",
    )


def test_14_snapshot_class_must_match_exact_provider_contract() -> None:
    request = evidence_request(snapshot_class="working-tree")
    plan = compile_verification_plan(
        planning_request(bindings=(binding(requests=(request,)),))
    )
    assert issue_codes(plan) == (
        "MISSING_REQUIRED_EVIDENCE_KIND",
        "UNSUPPORTED_SNAPSHOT_CLASS",
    )


def test_15_provider_and_verifier_require_a_structural_evidence_intersection() -> None:
    verifier = verifier_capability(
        accepted_evidence_kinds=("state.snapshot",),
        required_evidence_kinds=(),
    )
    provider = provider_capability(
        produced_evidence_kinds=("state.audit",),
    )
    request = evidence_request(requested_evidence_kinds=("state.audit",))
    plan = compile_verification_plan(
        planning_request(
            bindings=(binding(verifier=verifier, requests=(request,)),),
            verifiers=(verifier,),
            providers=(provider,),
        )
    )
    assert issue_codes(plan) == ("STRUCTURAL_EVIDENCE_INCOMPATIBILITY",)


def test_16_all_required_evidence_kinds_must_be_requested() -> None:
    verifier = verifier_capability(
        required_evidence_kinds=("state.audit", "state.snapshot"),
    )
    plan = compile_verification_plan(
        planning_request(
            bindings=(binding(verifier=verifier),),
            verifiers=(verifier,),
        )
    )
    assert issue_codes(plan) == ("MISSING_REQUIRED_EVIDENCE_KIND",)
    assert plan.issues[0].details["evidence_kinds"] == ("state.audit",)


def test_17_required_evidence_without_a_request_fails_closed() -> None:
    plan = compile_verification_plan(
        planning_request(bindings=(binding(requests=()),))
    )
    assert issue_codes(plan) == ("MISSING_EVIDENCE_REQUEST",)


def test_18_identical_request_fingerprint_is_acquired_once_and_shared() -> None:
    shared = evidence_request()
    graph = ClaimGraph(
        nodes=(
            atomic_claim("A"),
            atomic_claim("B"),
            CompositeClaim(
                claim_id="ROOT",
                operator=ClaimOperator.AND,
                dependencies=("A", "B"),
            ),
        )
    )
    plan = compile_verification_plan(
        planning_request(
            graph=graph,
            bindings=(
                binding("A", requests=(shared,)),
                binding("B", requests=(shared,)),
            ),
        )
    )
    acquisitions = tuple(
        step for step in plan.steps
        if step.kind is VerificationPlanStepKind.ACQUIRE_EVIDENCE
    )
    verifications = tuple(
        step for step in plan.steps
        if step.kind is VerificationPlanStepKind.VERIFY_ATOMIC_CLAIM
    )
    assert len(acquisitions) == 1
    assert acquisitions[0].request_id == "request-A"
    assert all(acquisitions[0].step_id in step.dependency_step_ids for step in verifications)


def test_19_same_request_id_with_different_semantics_is_rejected() -> None:
    graph = ClaimGraph(nodes=(atomic_claim("A"), atomic_claim("B")))
    first = evidence_request(subject={"entity": "A"})
    second = evidence_request(subject={"entity": "B"})
    with pytest.raises(VerificationPlanningError, match="request ID conflict"):
        planning_request(
            graph=graph,
            bindings=(
                binding("A", requests=(first,)),
                binding("B", requests=(second,)),
            ),
        )


def test_20_evidence_request_order_is_nonsemantic() -> None:
    first_provider = provider_capability()
    second_provider = provider_capability(
        provider_id="fixture.audit.provider",
        request_kinds=("CAPTURE_AUDIT",),
        produced_evidence_kinds=("state.audit",),
    )
    snapshot = evidence_request()
    audit = evidence_request(
        request_id="request-B",
        provider_id=second_provider.provider_id,
        request_kind="CAPTURE_AUDIT",
        requested_evidence_kinds=("state.audit",),
    )
    first = planning_request(
        bindings=(binding(requests=(snapshot, audit)),),
        providers=(first_provider, second_provider),
    )
    second = planning_request(
        bindings=(binding(requests=(audit, snapshot)),),
        providers=(second_provider, first_provider),
    )
    assert first.fingerprint == second.fingerprint
    assert compile_verification_plan(first).to_dict() == compile_verification_plan(second).to_dict()


def test_21_atomic_binding_order_is_nonsemantic() -> None:
    graph = ClaimGraph(nodes=(atomic_claim("A"), atomic_claim("B")))
    request_a = evidence_request(request_id="request-A", subject={"entity": "A"})
    request_b = evidence_request(request_id="request-B", subject={"entity": "B"})
    first = planning_request(
        graph=graph,
        bindings=(
            binding("A", requests=(request_a,)),
            binding("B", requests=(request_b,)),
        ),
    )
    second = planning_request(
        graph=graph,
        bindings=(
            binding("B", requests=(request_b,)),
            binding("A", requests=(request_a,)),
        ),
    )
    assert first.fingerprint == second.fingerprint
    assert compile_verification_plan(first).fingerprint == compile_verification_plan(second).fingerprint


def test_22_claim_graph_insertion_order_is_nonsemantic() -> None:
    first_graph = ClaimGraph(
        nodes=(
            atomic_claim("A"),
            atomic_claim("B"),
            CompositeClaim(
                claim_id="ROOT",
                operator=ClaimOperator.OR,
                dependencies=("B", "A"),
            ),
        )
    )
    second_graph = ClaimGraph(
        nodes=(
            CompositeClaim(
                claim_id="ROOT",
                operator=ClaimOperator.OR,
                dependencies=("A", "B"),
            ),
            atomic_claim("B"),
            atomic_claim("A"),
        )
    )
    bindings = (
        binding("A", requests=(evidence_request(request_id="request-A"),)),
        binding(
            "B",
            requests=(
                evidence_request(
                    request_id="request-B",
                    subject={"entity": "B"},
                ),
            ),
        ),
    )
    first = compile_verification_plan(planning_request(graph=first_graph, bindings=bindings))
    second = compile_verification_plan(planning_request(graph=second_graph, bindings=tuple(reversed(bindings))))
    assert first.to_dict() == second.to_dict()


def test_23_provider_identity_change_changes_plan_identity() -> None:
    first = compile_verification_plan(planning_request())
    provider = provider_capability(provider_id="fixture.changed.provider")
    request = evidence_request(provider_id=provider.provider_id)
    second = compile_verification_plan(
        planning_request(
            bindings=(binding(requests=(request,)),),
            providers=(provider,),
        )
    )
    assert first.fingerprint != second.fingerprint
    assert first.steps[0].provider_id != second.steps[0].provider_id


def test_24_verifier_identity_or_version_change_changes_plan_identity() -> None:
    first = compile_verification_plan(planning_request())
    verifier = verifier_capability(verifier_id="fixture.changed.verifier", version="2")
    graph = ClaimGraph(nodes=(atomic_claim(verifier=verifier.verifier_id),))
    second = compile_verification_plan(
        planning_request(
            graph=graph,
            bindings=(binding(verifier=verifier),),
            verifiers=(verifier,),
        )
    )
    assert first.fingerprint != second.fingerprint


def test_25_claim_identity_or_spec_change_changes_plan_identity() -> None:
    first = compile_verification_plan(planning_request())
    graph = ClaimGraph(nodes=(atomic_claim(spec={"entity": "A", "expected": False}),))
    second = compile_verification_plan(planning_request(graph=graph))
    assert first.fingerprint != second.fingerprint


def test_26_request_identity_or_semantics_change_changes_plan_identity() -> None:
    first = compile_verification_plan(planning_request())
    changed_id = evidence_request(request_id="request-Z")
    second = compile_verification_plan(
        planning_request(bindings=(binding(requests=(changed_id,)),))
    )
    changed_semantics = evidence_request(subject={"entity": "Z"})
    third = compile_verification_plan(
        planning_request(bindings=(binding(requests=(changed_semantics,)),))
    )
    assert len({first.fingerprint, second.fingerprint, third.fingerprint}) == 3


def test_27_dependency_identity_change_changes_plan_and_step_dependencies() -> None:
    first_graph = ClaimGraph(
        nodes=(atomic_claim("A"), atomic_claim("B", dependencies=("A",)))
    )
    second_graph = ClaimGraph(nodes=(atomic_claim("A"), atomic_claim("B")))
    bindings = (
        binding("A", requests=(evidence_request(request_id="request-A"),)),
        binding("B", requests=(evidence_request(request_id="request-B"),)),
    )
    first = compile_verification_plan(planning_request(graph=first_graph, bindings=bindings))
    second = compile_verification_plan(planning_request(graph=second_graph, bindings=bindings))
    first_verify = next(step for step in first.steps if step.claim_id == "B")
    second_verify = next(step for step in second.steps if step.claim_id == "B")
    assert first.fingerprint != second.fingerprint
    assert len(first_verify.dependency_step_ids) == len(second_verify.dependency_step_ids) + 1


def test_28_and_or_not_steps_follow_deterministic_topological_order() -> None:
    graph = ClaimGraph(
        nodes=(
            CompositeClaim(
                claim_id="ROOT",
                operator=ClaimOperator.AND,
                dependencies=("ANY", "NOT_C"),
            ),
            CompositeClaim(
                claim_id="NOT_C",
                operator=ClaimOperator.NOT,
                dependencies=("C",),
            ),
            atomic_claim("C"),
            CompositeClaim(
                claim_id="ANY",
                operator=ClaimOperator.OR,
                dependencies=("A", "B"),
            ),
            atomic_claim("B"),
            atomic_claim("A"),
        )
    )
    bindings = tuple(
        binding(
            claim_id,
            requests=(evidence_request(request_id=f"request-{claim_id}"),),
        )
        for claim_id in ("C", "B", "A")
    )
    plan = compile_verification_plan(planning_request(graph=graph, bindings=bindings))
    claim_steps = tuple(
        step.claim_id for step in plan.steps
        if step.kind is not VerificationPlanStepKind.ACQUIRE_EVIDENCE
    )
    assert claim_steps == graph.evaluation_order
    assert tuple(
        step.operator for step in plan.steps
        if step.kind is VerificationPlanStepKind.COMPOSE_CLAIM
    ) == (ClaimOperator.OR, ClaimOperator.NOT, ClaimOperator.AND)


def test_29_claim_dependency_cycles_are_rejected_before_planning() -> None:
    with pytest.raises(ClaimGraphValidationError, match="cycle"):
        ClaimGraph(
            nodes=(
                atomic_claim("A", dependencies=("B",)),
                atomic_claim("B", dependencies=("A",)),
            )
        )


def budget_fixture(*, reverse: bool = False) -> VerificationPlanningRequest:
    graph = ClaimGraph(
        nodes=(
            atomic_claim("A"),
            atomic_claim("B", dependencies=("A",)),
            CompositeClaim(
                claim_id="ROOT",
                operator=ClaimOperator.AND,
                dependencies=("A", "B"),
            ),
        )
    )
    bindings = (
        binding("A", requests=(evidence_request(request_id="request-A"),)),
        binding(
            "B",
            requests=(
                evidence_request(
                    request_id="request-B",
                    subject={"entity": "B"},
                ),
            ),
        ),
    )
    if reverse:
        graph = ClaimGraph(nodes=tuple(reversed(graph.nodes)))
        bindings = tuple(reversed(bindings))
    return planning_request(graph=graph, bindings=bindings)


def test_30_exact_deterministic_budgets_are_accepted() -> None:
    base = budget_fixture()
    exact = replace(
        base,
        budget=VerificationPlanningBudget(
            max_atomic_claims=2,
            max_composite_claims=1,
            max_steps=5,
            max_requests=2,
            max_dependency_edges=3,
            max_requests_per_claim=1,
            max_depth=3,
        ),
    )
    plan = compile_verification_plan(exact)
    assert plan.termination is VerificationPlanTermination.COMPLETE
    assert plan.consumption.to_dict() == {
        "atomic_claims": 2,
        "composite_claims": 1,
        "steps": 5,
        "requests": 2,
        "dependency_edges": 3,
        "requests_per_claim": 1,
        "depth": 3,
    }


@pytest.mark.parametrize(
    "field,limit",
    [
        ("max_atomic_claims", 1),
        ("max_composite_claims", 0),
        ("max_steps", 4),
        ("max_requests", 1),
        ("max_dependency_edges", 2),
        ("max_requests_per_claim", 0),
        ("max_depth", 2),
    ],
)
def test_31_budget_overflow_is_stable_and_insertion_invariant(
    field: str,
    limit: int,
) -> None:
    budget = VerificationPlanningBudget(**{field: limit})
    first = replace(budget_fixture(), budget=budget)
    second = replace(budget_fixture(reverse=True), budget=budget)
    first_plan = compile_verification_plan(first)
    second_plan = compile_verification_plan(second)
    assert first_plan.termination is VerificationPlanTermination.BUDGET_EXHAUSTED
    assert issue_codes(first_plan) == ("BUDGET_EXHAUSTED",)
    assert first_plan.steps == ()
    assert first_plan.to_dict() == second_plan.to_dict()
    assert first_plan.issues[0].details["budget"] == field


def test_32_plan_contains_no_truth_or_diagnostic_text_fields() -> None:
    plan_dict = compile_verification_plan(planning_request()).to_dict()

    forbidden = {
        "claim_verdict",
        "message",
        "metadata",
        "sufficient",
        "sufficiency",
        "truth",
        "verdict",
    }

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            assert forbidden.isdisjoint(value)
            for nested in value.values():
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(plan_dict)


def test_33_protocol_is_deterministic_strict_fingerprinted_and_public() -> None:
    request = planning_request()
    payload = request.to_dict()
    protocol_request = {
        "schema_version": 1,
        "op": "compile_verification_plan",
        "payload": payload,
    }
    first = handle_request(protocol_request)
    second = handle_request(protocol_request)
    assert first == second
    assert first["kind"] == "verification_plan"
    assert first["payload"]["fingerprint"] == compile_verification_plan(request).fingerprint

    unknown = safe_handle_request({
        **protocol_request,
        "payload": {**payload, "unknown": True},
    })
    assert unknown["payload"]["code"] == "INVALID_VERIFICATION_PLANNING_REQUEST"

    outer_mismatch = safe_handle_request({
        **protocol_request,
        "payload": {**payload, "fingerprint": "0" * 64},
    })
    assert outer_mismatch["payload"]["code"] == "INVALID_VERIFICATION_PLANNING_REQUEST"

    nested = payload["bindings"][0]["evidence_requests"][0]
    nested_mismatch_payload = {
        **payload,
        "bindings": [{
            **payload["bindings"][0],
            "evidence_requests": [{**nested, "fingerprint": "0" * 64}],
        }],
    }
    nested_mismatch = safe_handle_request({
        **protocol_request,
        "payload": nested_mismatch_payload,
    })
    assert nested_mismatch["payload"]["code"] == "INVALID_VERIFICATION_PLANNING_REQUEST"

    duplicate_binding_payload = {
        **payload,
        "bindings": [payload["bindings"][0], payload["bindings"][0]],
    }
    duplicate = safe_handle_request({
        **protocol_request,
        "payload": duplicate_binding_payload,
    })
    assert duplicate["payload"]["code"] == "INVALID_VERIFICATION_PLANNING_REQUEST"

    for name in (
        "AtomicClaimBinding",
        "VerificationPlan",
        "VerificationPlanStep",
        "VerificationPlanStepKind",
        "VerificationPlanTermination",
        "VerificationPlanningBudget",
        "VerificationPlanningRequest",
        "compile_verification_plan",
    ):
        assert name in gvr.__all__
        assert getattr(gvr, name) is not None


def test_34_invalid_requests_cannot_hide_missing_required_evidence_kinds() -> None:
    verifier = verifier_capability(
        accepted_evidence_kinds=("state.audit", "state.snapshot"),
        required_evidence_kinds=("state.audit", "state.snapshot"),
    )
    snapshot = evidence_request(
        request_id="request-snapshot",
        requested_evidence_kinds=("state.snapshot",),
    )
    invalid_audit = evidence_request(
        request_id="request-audit",
        request_kind="UNSUPPORTED_CAPTURE",
        requested_evidence_kinds=("state.audit",),
    )

    plan = compile_verification_plan(planning_request(
        bindings=(binding(
            verifier=verifier,
            requests=(snapshot, invalid_audit),
        ),),
        verifiers=(verifier,),
    ))

    assert issue_codes(plan) == (
        "MISSING_REQUIRED_EVIDENCE_KIND",
        "UNSUPPORTED_REQUEST_KIND",
    )
    missing = next(
        issue
        for issue in plan.issues
        if issue.code == "MISSING_REQUIRED_EVIDENCE_KIND"
    )
    assert missing.details == {"evidence_kinds": ("state.audit",)}


def test_35_exact_registries_reject_subclasses_that_can_substitute_contracts() -> None:
    honest_verifier = verifier_capability()
    substituted_verifier = verifier_capability(coverage={"mode": "SUBSTITUTED"})

    class SubstitutingVerifierRegistry(VerifierCapabilityRegistry):
        def lookup(self, verifier_id: str, version: str) -> VerifierCapability:
            return substituted_verifier

    verifier_registry = SubstitutingVerifierRegistry((honest_verifier,))
    base = planning_request()
    with pytest.raises(VerificationPlanningError, match="exact VerifierCapabilityRegistry"):
        VerificationPlanningRequest(
            claim_graph=base.claim_graph,
            bindings=(binding(verifier=substituted_verifier),),
            verifier_capability_registry=verifier_registry,
            verifier_capability_registry_fingerprint=verifier_registry.fingerprint,
            evidence_provider_capability_registry=(
                base.evidence_provider_capability_registry
            ),
            evidence_provider_capability_registry_fingerprint=(
                base.evidence_provider_capability_registry.fingerprint
            ),
        )

    honest_provider = provider_capability()
    substituted_provider = provider_capability(coverage={"mode": "SUBSTITUTED"})

    class SubstitutingProviderRegistry(EvidenceProviderCapabilityRegistry):
        def lookup(
            self,
            provider_id: str,
            version: str,
        ) -> EvidenceProviderCapability:
            return substituted_provider

    provider_registry = SubstitutingProviderRegistry((honest_provider,))
    with pytest.raises(
        VerificationPlanningError,
        match="exact EvidenceProviderCapabilityRegistry",
    ):
        VerificationPlanningRequest(
            claim_graph=base.claim_graph,
            bindings=base.bindings,
            verifier_capability_registry=base.verifier_capability_registry,
            verifier_capability_registry_fingerprint=(
                base.verifier_capability_registry.fingerprint
            ),
            evidence_provider_capability_registry=provider_registry,
            evidence_provider_capability_registry_fingerprint=(
                provider_registry.fingerprint
            ),
        )


@pytest.mark.parametrize(
    "remove_fingerprint",
    (
        lambda payload: payload["bindings"][0]["evidence_requests"][0].pop(
            "fingerprint"
        ),
        lambda payload: payload["evidence_provider_capability_registry"][
            "capabilities"
        ][0].pop("fingerprint"),
    ),
    ids=("evidence-request", "evidence-provider-capability"),
)
def test_36_protocol_rejects_omitted_nested_fingerprints(
    remove_fingerprint: Any,
) -> None:
    payload = planning_request().to_dict()
    remove_fingerprint(payload)

    response = safe_handle_request({
        "schema_version": 1,
        "op": "compile_verification_plan",
        "payload": payload,
    })

    assert response["payload"]["code"] == "INVALID_VERIFICATION_PLANNING_REQUEST"


@pytest.mark.parametrize(
    "details",
    (
        {"status": "PASS"},
        {"outcome": "FAIL"},
        {"result": "UNKNOWN"},
        {"truth_value": True},
        {"is_sufficient": True},
        {"evidence_adequacy": "complete"},
        {"nested": {"Truth-Value": True}},
        {"STATUS": "PASS"},
        {"claim_status": "PASS"},
        {"evidence-sufficiency": True},
        {"PASS": True},
        {"UNKNOWN": True},
    ),
)
def test_37_planner_issues_reject_verdict_and_sufficiency_metadata_aliases(
    details: dict[str, Any],
) -> None:
    with pytest.raises(VerificationPlanningError, match="unsupported field"):
        gvr.VerificationPlannerIssue(code="TEST_ISSUE", details=details)


def same_semantics_different_ids_request(
    *,
    reverse: bool = False,
    budget: VerificationPlanningBudget | None = None,
) -> VerificationPlanningRequest:
    graph = ClaimGraph(nodes=(atomic_claim("A"), atomic_claim("B")))
    request_a = evidence_request(request_id="request-A")
    request_b = evidence_request(request_id="request-B")
    assert request_a.fingerprint == request_b.fingerprint
    bindings = (
        binding("A", requests=(request_a,)),
        binding("B", requests=(request_b,)),
    )
    if reverse:
        graph = ClaimGraph(nodes=tuple(reversed(graph.nodes)))
        bindings = tuple(reversed(bindings))
    return planning_request(graph=graph, bindings=bindings, budget=budget)


def acquisition_steps(plan: gvr.VerificationPlan) -> tuple[gvr.VerificationPlanStep, ...]:
    return tuple(
        step
        for step in plan.steps
        if step.kind is VerificationPlanStepKind.ACQUIRE_EVIDENCE
    )


def test_38_same_semantics_different_request_ids_are_exact_executions() -> None:
    plan = compile_verification_plan(same_semantics_different_ids_request())
    acquisitions = acquisition_steps(plan)

    assert tuple(step.request_id for step in acquisitions) == (
        "request-A",
        "request-B",
    )
    assert len({step.request_fingerprint for step in acquisitions}) == 1
    assert plan.consumption.requests == 2
    assert plan.consumption.steps == 4
    assert len(plan.steps) == plan.consumption.steps

    dependencies_by_claim = {
        step.claim_id: step.dependency_step_ids
        for step in plan.steps
        if step.kind is VerificationPlanStepKind.VERIFY_ATOMIC_CLAIM
    }
    assert dependencies_by_claim == {
        "A": (acquisitions[0].step_id,),
        "B": (acquisitions[1].step_id,),
    }


def test_39_request_budget_counts_same_semantics_different_ids() -> None:
    plan = compile_verification_plan(same_semantics_different_ids_request(
        budget=VerificationPlanningBudget(max_requests=1),
    ))

    assert plan.termination is VerificationPlanTermination.BUDGET_EXHAUSTED
    assert plan.consumption.requests == 2
    assert plan.steps == ()
    assert tuple(issue.to_dict() for issue in plan.issues) == ({
        "code": "BUDGET_EXHAUSTED",
        "claim_id": None,
        "request_id": None,
        "details": {
            "budget": "max_requests",
            "limit": 1,
            "required": 2,
        },
    },)


def test_40_request_id_only_changes_acquisition_and_plan_identity() -> None:
    first = compile_verification_plan(planning_request())
    second = compile_verification_plan(planning_request(
        bindings=(binding(requests=(evidence_request(request_id="request-B"),)),),
    ))
    first_acquisition = acquisition_steps(first)[0]
    second_acquisition = acquisition_steps(second)[0]

    assert first_acquisition.request_fingerprint == second_acquisition.request_fingerprint
    assert first_acquisition.request_id == "request-A"
    assert second_acquisition.request_id == "request-B"
    assert first_acquisition.step_id != second_acquisition.step_id
    assert first.fingerprint != second.fingerprint


def test_41_protocol_preserves_same_semantics_different_request_identities() -> None:
    request = same_semantics_different_ids_request()
    response = handle_request({
        "schema_version": 1,
        "op": "compile_verification_plan",
        "payload": request.to_dict(),
    })
    acquisitions = tuple(
        step
        for step in response["payload"]["steps"]
        if step["kind"] == VerificationPlanStepKind.ACQUIRE_EVIDENCE.value
    )

    assert tuple(step["request_id"] for step in acquisitions) == (
        "request-A",
        "request-B",
    )
    assert len({step["request_fingerprint"] for step in acquisitions}) == 1
    assert "request_ids" not in acquisitions[0]
    assert response["payload"] == compile_verification_plan(request).to_dict()


def test_42_reordering_exact_request_set_remains_deterministic() -> None:
    first = compile_verification_plan(same_semantics_different_ids_request())
    second = compile_verification_plan(
        same_semantics_different_ids_request(reverse=True)
    )

    assert first.to_dict() == second.to_dict()
    assert tuple(step.request_id for step in acquisition_steps(first)) == (
        "request-A",
        "request-B",
    )
