from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from copy import deepcopy

import pytest

from gvr import (
    ClaimDefinition,
    ClaimLedger,
    Evidence,
    Freshness,
    VerificationVerdict,
    builtin_verifier_capability_registry,
    safe_handle_request,
)
from gvr import regression_test_obligations as rto


FACT = rto.BehaviorFactClass.CHANGE
KIND = "gvr.test.behavior_change"


def evidence(
    evidence_id: str = "ev-change",
    *,
    kind: str = KIND,
    subject: str = "checkout.total",
    behavior: str = "applies the revised discount rule",
    extra: dict[str, object] | None = None,
) -> Evidence:
    payload: dict[str, object] = {
        "subject": subject,
        "behavior": behavior,
        "source_revision": "candidate-1",
    }
    if extra:
        payload.update(extra)
    return Evidence(
        id=evidence_id,
        kind=kind,
        payload=payload,
        source="static-analysis",
        fingerprint=f"fp-{evidence_id}",
    )


def coverage(
    fact_class: rto.BehaviorFactClass = FACT,
    completeness: rto.FactCoverageCompleteness = rto.FactCoverageCompleteness.COMPLETE,
    evidence_ids: tuple[str, ...] = ("ev-change",),
) -> rto.FactClassCoverage:
    return rto.FactClassCoverage(
        fact_class=fact_class,
        completeness=completeness,
        evidence_ids=evidence_ids,
        scope={"revision": "candidate-1"},
    )


def inventory(
    records: tuple[Evidence, ...] = (evidence(),),
    coverages: tuple[rto.FactClassCoverage, ...] = (coverage(),),
) -> rto.BehaviorEvidenceInventory:
    return rto.BehaviorEvidenceInventory(
        evidence=records,
        coverage=coverages,
    )


def obligation(**overrides: object) -> rto.TestObligation:
    values: dict[str, object] = {
        "obligation_id": "obl-change-checkout-total",
        "kind": rto.TestObligationKind.REGRESSION,
        "subject": "checkout.total",
        "expected_behavior": "applies the revised discount rule",
        "rationale": "Changed behavior must remain observable.",
        "fact_classes": (FACT,),
        "evidence_ids": ("ev-change",),
        "test_level": rto.TestLevel.UNIT,
    }
    values.update(overrides)
    return rto.TestObligation(**values)


def test_01_behavior_evidence_vocabulary_is_exact_stable_and_namespaced() -> None:
    assert rto.BEHAVIOR_EVIDENCE_KINDS == (
        "gvr.test.behavior_contract",
        "gvr.test.behavior_change",
        "gvr.test.input_partition",
        "gvr.test.output_observation",
        "gvr.test.branch_condition",
        "gvr.test.exception_behavior",
        "gvr.test.state_transition",
        "gvr.test.side_effect",
        "gvr.test.collaborator_interaction",
        "gvr.test.data_flow",
        "gvr.test.concurrency_behavior",
        "gvr.test.existing_test",
        "gvr.test.coverage_observation",
    )
    assert len(set(rto.BEHAVIOR_EVIDENCE_KINDS)) == 13


def test_02_inventory_rejects_non_vocabulary_and_truth_like_evidence() -> None:
    with pytest.raises(rto.RegressionObligationError, match="unsupported behavior evidence kind"):
        inventory((evidence(kind="source.code"),), ())
    with pytest.raises(rto.RegressionObligationError, match="truth-like"):
        inventory((evidence(extra={"verdict": "PASS"}),), ())


def test_03_inventory_normalizes_order_deduplicates_identical_records_and_rejects_conflicts() -> None:
    first = evidence("b")
    second = evidence("a", subject="cart.total")
    normalized = inventory((first, second, deepcopy(first)), ())
    assert tuple(item.id for item in normalized.evidence) == ("a", "b")
    with pytest.raises(rto.RegressionObligationError, match="conflicting evidence"):
        inventory((first, evidence("b", behavior="different")), ())


def test_04_inventory_is_deeply_immutable_and_snapshots_caller_payloads() -> None:
    payload = {"subject": "checkout.total", "behavior": "stable", "nested": {"items": [1]}}
    item = Evidence("ev", KIND, payload, "source", "fp")
    snapshot = inventory((item,), (coverage(evidence_ids=("ev",)),))
    payload["nested"]["items"].append(2)  # type: ignore[index,union-attr]
    assert snapshot.evidence[0].payload["nested"]["items"] == (1,)
    with pytest.raises(TypeError):
        snapshot.evidence[0].payload["subject"] = "mutated"  # type: ignore[index]


def test_05_inventory_coverage_is_per_fact_class_and_missing_is_unknown() -> None:
    item = inventory()
    assert item.coverage_for(FACT).completeness is rto.FactCoverageCompleteness.COMPLETE
    missing = item.coverage_for(rto.BehaviorFactClass.BRANCH)
    assert missing.completeness is rto.FactCoverageCompleteness.UNKNOWN
    assert missing.evidence_ids == ()


def test_06_complete_and_partial_coverage_must_be_backed_by_matching_inventory_evidence() -> None:
    with pytest.raises(rto.RegressionObligationError, match="unavailable evidence"):
        inventory((evidence(),), (coverage(evidence_ids=("missing",)),))
    with pytest.raises(rto.RegressionObligationError, match="does not support fact class"):
        inventory(
            (evidence("ev-branch", kind="gvr.test.branch_condition"),),
            (coverage(evidence_ids=("ev-branch",)),),
        )


def test_07_unknown_coverage_cannot_launder_positive_evidence_ids() -> None:
    with pytest.raises(rto.RegressionObligationError, match="unknown coverage"):
        coverage(
            completeness=rto.FactCoverageCompleteness.UNKNOWN,
            evidence_ids=("ev-change",),
        )


def test_08_test_obligation_kind_has_nine_minimum_rule_classes() -> None:
    assert tuple(kind.value for kind in rto.TestObligationKind) == (
        "CHARACTERIZATION",
        "REGRESSION",
        "BOUNDARY",
        "OUTPUT",
        "BRANCH",
        "EXCEPTION",
        "STATE_TRANSITION",
        "SIDE_EFFECT",
        "INTERACTION",
    )
    assert set(rto.OBLIGATION_RULES) == set(rto.TestObligationKind)


def test_09_test_obligation_is_strict_normalized_immutable_and_fingerprinted() -> None:
    item = obligation(evidence_ids=("z", "ev-change"), fact_classes=(FACT, FACT))
    assert item.evidence_ids == ("ev-change", "z")
    assert item.fact_classes == (FACT,)
    assert len(item.fingerprint) == 64
    with pytest.raises(FrozenInstanceError):
        item.subject = "other"  # type: ignore[misc]


def test_10_test_obligation_rejects_empty_ambiguous_and_truth_like_fields() -> None:
    with pytest.raises(rto.RegressionObligationError, match="subject"):
        obligation(subject=" ")
    with pytest.raises(rto.RegressionObligationError, match="evidence_ids"):
        obligation(evidence_ids=())
    with pytest.raises(rto.RegressionObligationError, match="metadata.*truth-like"):
        obligation(metadata={"authorized": True})


def test_11_obligation_grounding_pass_requires_exact_compatible_evidence_and_complete_coverage() -> None:
    report = rto.verify_test_obligation_grounding(obligation(), inventory())
    assert report.verdict is VerificationVerdict.PASS
    assert report.verifier == rto.REGRESSION_TEST_OBLIGATION_VERIFIER
    assert report.evidence_ids == ("ev-change",)
    assert report.metadata["claim_kind"] == rto.TEST_OBLIGATION_GROUNDED


def test_12_obligation_laundering_via_unrelated_fact_kind_is_unknown_not_pass() -> None:
    inv = inventory(
        (evidence("ev-change", kind="gvr.test.branch_condition"),),
        (
            coverage(
                rto.BehaviorFactClass.BRANCH,
                evidence_ids=("ev-change",),
            ),
        ),
    )
    report = rto.verify_test_obligation_grounding(obligation(), inv)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert {issue.code for issue in report.issues} == {"OBLIGATION_EVIDENCE_INCOMPATIBLE"}


def test_13_obligation_laundering_via_subject_mismatch_is_unknown_not_pass() -> None:
    inv = inventory((evidence(subject="unrelated.subject"),), (coverage(),))
    report = rto.verify_test_obligation_grounding(obligation(), inv)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "OBLIGATION_SUBJECT_MISMATCH" in {issue.code for issue in report.issues}


def test_14_partial_or_unknown_fact_coverage_never_produces_grounded_pass() -> None:
    partial = inventory(
        (evidence(),),
        (coverage(completeness=rto.FactCoverageCompleteness.PARTIAL),),
    )
    report = rto.verify_test_obligation_grounding(obligation(), partial)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "OBLIGATION_COVERAGE_INCOMPLETE" in {issue.code for issue in report.issues}


def test_15_grounding_bundle_contains_exactly_the_report_dependency_manifest() -> None:
    bundle = rto.verify_test_obligation_grounding_bundle(obligation(), inventory())
    assert bundle.report.verdict is VerificationVerdict.PASS
    assert tuple(item.id for item in bundle.evidence) == bundle.report.evidence_ids
    assert bundle.claim_dependency_ids == ()


def test_16_grounding_bundle_can_be_recorded_and_changed_evidence_makes_claim_stale() -> None:
    item = obligation()
    bundle = rto.verify_test_obligation_grounding_bundle(item, inventory())
    ledger = ClaimLedger()
    ledger.define(
        ClaimDefinition(
            id=item.claim_id,
            statement=rto.TEST_OBLIGATION_GROUNDED,
            verifier=rto.REGRESSION_TEST_OBLIGATION_VERIFIER,
        )
    )
    ledger.record_bundle(item.claim_id, bundle)
    assert ledger.status(item.claim_id).freshness is Freshness.FRESH
    ledger.put_evidence_record(evidence(behavior="changed again"))
    assert ledger.status(item.claim_id).freshness is Freshness.STALE
    assert ledger.status(item.claim_id).effective_verdict is VerificationVerdict.UNKNOWN


def test_17_derivation_is_deterministic_across_input_order_and_semantic_duplicates() -> None:
    a = evidence("a", subject="cart.total")
    b = evidence("b", subject="checkout.total")
    c_a = coverage(evidence_ids=("a",))
    c_b = coverage(evidence_ids=("b",))
    left = rto.derive_regression_test_obligations(inventory((b, a), (c_b, c_a)))
    right = rto.derive_regression_test_obligations(inventory((a, b, deepcopy(a)), (c_a, c_b)))
    assert left.fingerprint == right.fingerprint
    assert left.to_dict() == right.to_dict()


def test_18_derivation_emits_ordered_obligation_and_bundle_pairs() -> None:
    plan = rto.derive_regression_test_obligations(inventory())
    assert len(plan.obligations) == len(plan.bundles) == 1
    assert plan.bundles[0].report.metadata["obligation_id"] == plan.obligations[0].obligation_id
    assert plan.bundles[0].report.verdict is VerificationVerdict.PASS


def test_19_rule_table_derives_every_minimum_obligation_kind() -> None:
    records: list[Evidence] = []
    coverages: list[rto.FactClassCoverage] = []
    for index, rule in enumerate(rto.OBLIGATION_RULES.values()):
        fact_class = rule.fact_classes[0]
        kind = rto.EVIDENCE_KIND_BY_FACT_CLASS[fact_class][0]
        eid = f"ev-{index}"
        records.append(evidence(eid, kind=kind, subject=f"subject.{index}"))
        coverages.append(coverage(fact_class, evidence_ids=(eid,)))
    plan = rto.derive_regression_test_obligations(inventory(tuple(records), tuple(coverages)))
    assert {item.kind for item in plan.obligations} == set(rto.TestObligationKind)


def test_20_derivation_deduplicates_same_semantic_obligation_without_hiding_sources() -> None:
    first = evidence("a")
    second = evidence("b")
    plan = rto.derive_regression_test_obligations(
        inventory((second, first), (coverage(evidence_ids=("a", "b")),))
    )
    assert len(plan.obligations) == 1
    assert plan.obligations[0].evidence_ids == ("a", "b")
    assert plan.consumption.deduplicated_obligations == 1


def test_21_budget_bounds_obligations_bundles_evidence_and_steps_deterministically() -> None:
    inv = inventory(
        tuple(evidence(f"ev-{index}", subject=f"subject.{index}") for index in range(8)),
        tuple(coverage(evidence_ids=(f"ev-{index}",)) for index in range(8)),
    )
    budget = rto.RegressionObligationBudget(
        max_obligations=3,
        max_bundles=3,
        max_evidence_records=3,
        max_steps=4,
    )
    first = rto.derive_regression_test_obligations(inv, budget=budget)
    second = rto.derive_regression_test_obligations(inv, budget=budget)
    assert len(first.obligations) <= 3
    assert first.termination is rto.RegressionObligationTermination.BUDGET_EXHAUSTED
    assert first.fingerprint == second.fingerprint


def test_22_zero_budget_returns_bounded_blocked_plan_not_unbounded_work() -> None:
    plan = rto.derive_regression_test_obligations(
        inventory(),
        budget=rto.RegressionObligationBudget(
            max_obligations=0,
            max_bundles=0,
            max_evidence_records=0,
            max_steps=0,
        ),
    )
    assert plan.obligations == ()
    assert plan.termination is rto.RegressionObligationTermination.BUDGET_EXHAUSTED
    assert plan.readiness is rto.RegressionObligationReadiness.BLOCKED


def test_23_stable_gap_taxonomy_covers_incomplete_unknown_malformed_and_budget_cases() -> None:
    assert tuple(code.value for code in rto.RegressionObligationGapCode) == (
        "PARTIAL_FACT_COVERAGE",
        "UNKNOWN_FACT_COVERAGE",
        "MISSING_REQUIRED_FIELD",
        "NO_DERIVATION_RULE",
        "UNGROUNDED_OBLIGATION",
        "BUDGET_EXHAUSTED",
        "CONFLICTING_FACTS",
    )


def test_24_partial_coverage_produces_stable_gap_and_blocked_readiness() -> None:
    plan = rto.derive_regression_test_obligations(
        inventory(
            (evidence(),),
            (coverage(completeness=rto.FactCoverageCompleteness.PARTIAL),),
        )
    )
    assert plan.readiness is rto.RegressionObligationReadiness.BLOCKED
    assert rto.RegressionObligationGapCode.PARTIAL_FACT_COVERAGE in {gap.code for gap in plan.gaps}


def test_25_unknown_coverage_produces_unknown_readiness_without_authorization() -> None:
    plan = rto.derive_regression_test_obligations(inventory((evidence(),), ()))
    assert plan.readiness is rto.RegressionObligationReadiness.UNKNOWN
    exported = plan.to_dict()
    assert "authorized" not in exported
    assert "can_merge" not in exported
    assert "can_deploy" not in exported


def test_26_complete_grounded_plan_is_ready_but_does_not_authorize_action() -> None:
    plan = rto.derive_regression_test_obligations(inventory())
    assert plan.readiness is rto.RegressionObligationReadiness.READY
    assert plan.termination is rto.RegressionObligationTermination.COMPLETE
    assert all(bundle.report.verdict is VerificationVerdict.PASS for bundle in plan.bundles)
    assert not hasattr(plan, "authorized")


def test_27_plan_is_deeply_immutable_and_fingerprint_is_semantically_sensitive() -> None:
    plan = rto.derive_regression_test_obligations(inventory())
    with pytest.raises(FrozenInstanceError):
        plan.readiness = rto.RegressionObligationReadiness.UNKNOWN  # type: ignore[misc]
    changed = rto.derive_regression_test_obligations(
        inventory((evidence(behavior="different behavior"),), (coverage(),))
    )
    assert changed.fingerprint != plan.fingerprint


def test_28_plan_constructor_rejects_bundle_misalignment_and_duplicate_obligation_ids() -> None:
    plan = rto.derive_regression_test_obligations(inventory())
    with pytest.raises(rto.RegressionObligationError, match="one bundle"):
        replace(plan, bundles=())
    with pytest.raises(rto.RegressionObligationError, match="duplicate obligation"):
        replace(
            plan,
            obligations=(plan.obligations[0], plan.obligations[0]),
            bundles=(plan.bundles[0], plan.bundles[0]),
        )


def test_29_builtin_capability_truthfully_matches_runtime_contract() -> None:
    capability = builtin_verifier_capability_registry().lookup(
        rto.REGRESSION_TEST_OBLIGATION_VERIFIER,
        "1",
    )
    assert capability.claim_kinds == (rto.TEST_OBLIGATION_GROUNDED,)
    assert capability.accepted_evidence_kinds == tuple(sorted(rto.BEHAVIOR_EVIDENCE_KINDS))
    assert capability.required_evidence_kinds == ()
    assert capability.authoritative is True
    assert capability.bounds["max_obligations"] == rto.DEFAULT_REGRESSION_OBLIGATION_BUDGET.max_obligations
    assert capability.coverage["pass_requires"] == "COMPLETE_REFERENCED_FACT_COVERAGE"


def test_30_capability_rejects_claim_kind_or_evidence_outside_runtime() -> None:
    capability = builtin_verifier_capability_registry().lookup(
        rto.REGRESSION_TEST_OBLIGATION_VERIFIER,
        "1",
    )
    assert capability.supports_claim_kind(rto.TEST_OBLIGATION_GROUNDED)
    assert not capability.supports_claim_kind("TEST_OBLIGATION_EXISTS")
    assert "source.code" not in capability.accepted_evidence_kinds


def test_31_schema_v1_derive_operation_returns_deterministic_plan() -> None:
    item = inventory()
    request = {
        "schema_version": 1,
        "op": "derive_regression_test_obligations",
        "payload": {
            "inventory": item.to_dict(),
            "budget": rto.DEFAULT_REGRESSION_OBLIGATION_BUDGET.to_dict(),
        },
    }
    first = safe_handle_request(deepcopy(request))
    second = safe_handle_request(deepcopy(request))
    assert first["kind"] == "regression_obligation_plan"
    assert first == second
    assert first["payload"]["readiness"] == "READY"


def test_32_schema_v1_derive_operation_rejects_unknown_fields_and_forged_fingerprint() -> None:
    data = inventory().to_dict()
    data["fingerprint"] = "0" * 64
    forged = safe_handle_request(
        {
            "schema_version": 1,
            "op": "derive_regression_test_obligations",
            "payload": {"inventory": data},
        }
    )
    assert forged["kind"] == "protocol_error"
    assert forged["payload"]["code"] == "INVALID_REGRESSION_OBLIGATION_REQUEST"
    extra = safe_handle_request(
        {
            "schema_version": 1,
            "op": "derive_regression_test_obligations",
            "payload": {"inventory": inventory().to_dict(), "provider": "forbidden"},
        }
    )
    assert extra["kind"] == "protocol_error"
    assert extra["payload"]["code"] == "INVALID_PAYLOAD"


def test_33_derivation_uses_no_provider_llm_browser_codegen_or_external_executor_hooks(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("external execution is forbidden")

    monkeypatch.setattr("gvr.evidence_providers.EvidenceProviderRuntimeRegistry.acquire", forbidden)
    plan = rto.derive_regression_test_obligations(inventory())
    assert plan.readiness is rto.RegressionObligationReadiness.READY
