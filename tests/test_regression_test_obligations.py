from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError, replace

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


SUBJECT = "checkout.order"
SURFACE = "/checkout"
ACTION = "submit_order"
SCOPE = {"subject": SUBJECT, "surface": SURFACE, "action": ACTION}


def fact(evidence_id: str, kind: str, **payload: object) -> Evidence:
    return Evidence(
        id=evidence_id,
        kind=kind,
        payload=payload,
        source="task-18-contract-fixture",
        fingerprint=f"fp-{evidence_id}",
    )


def complete_journey() -> tuple[Evidence, ...]:
    return (
        fact(
            "surface-checkout",
            "gvr.test.surface",
            subject=SUBJECT,
            surface=SURFACE,
            navigation="route:/checkout",
        ),
        fact(
            "action-submit",
            "gvr.test.action",
            subject=SUBJECT,
            surface=SURFACE,
            action=ACTION,
            surface_id="surface-checkout",
            precondition="cart contains at least one purchasable item",
        ),
        fact(
            "outcome-accepted",
            "gvr.test.observable_outcome",
            subject=SUBJECT,
            surface=SURFACE,
            action=ACTION,
            surface_id="surface-checkout",
            action_id="action-submit",
            oracle="order confirmation is shown",
        ),
        fact(
            "field-email",
            "gvr.test.field",
            subject=SUBJECT,
            surface=SURFACE,
            action=ACTION,
            surface_id="surface-checkout",
            action_id="action-submit",
            field="email",
        ),
        fact(
            "constraint-required",
            "gvr.test.constraint",
            subject=SUBJECT,
            surface=SURFACE,
            action=ACTION,
            surface_id="surface-checkout",
            action_id="action-submit",
            field_id="field-email",
            constraint="required",
        ),
        fact(
            "constraint-format",
            "gvr.test.constraint",
            subject=SUBJECT,
            surface=SURFACE,
            action=ACTION,
            surface_id="surface-checkout",
            action_id="action-submit",
            field_id="field-email",
            constraint="format",
            format="email",
        ),
        fact(
            "partition-invalid-email",
            "gvr.test.data_partition",
            subject=SUBJECT,
            surface=SURFACE,
            action=ACTION,
            surface_id="surface-checkout",
            action_id="action-submit",
            field_id="field-email",
            constraint_id="constraint-format",
            partition="invalid_format",
            values=("missing-at-sign", "missing-domain"),
        ),
        fact(
            "constraint-boundary",
            "gvr.test.constraint",
            subject=SUBJECT,
            surface=SURFACE,
            action=ACTION,
            surface_id="surface-checkout",
            action_id="action-submit",
            field_id="field-email",
            constraint="boundary",
            boundary="length",
        ),
        fact(
            "partition-email-boundary",
            "gvr.test.data_partition",
            subject=SUBJECT,
            surface=SURFACE,
            action=ACTION,
            surface_id="surface-checkout",
            action_id="action-submit",
            field_id="field-email",
            constraint_id="constraint-boundary",
            partition="boundary_value",
            values=(0, 1, 254, 255),
        ),
        fact(
            "transition-created",
            "gvr.test.state_transition",
            subject=SUBJECT,
            surface=SURFACE,
            action=ACTION,
            surface_id="surface-checkout",
            action_id="action-submit",
            outcome_id="outcome-accepted",
            from_state="CART_READY",
            to_state="ORDER_CREATED",
        ),
        fact(
            "role-buyer",
            "gvr.test.actor_role",
            subject=SUBJECT,
            surface=SURFACE,
            surface_id="surface-checkout",
            role="buyer",
        ),
        fact(
            "permission-buyer-submit",
            "gvr.test.permission_relation",
            subject=SUBJECT,
            surface=SURFACE,
            action=ACTION,
            surface_id="surface-checkout",
            action_id="action-submit",
            role_id="role-buyer",
            outcome_id="outcome-accepted",
            permission="allow",
            authenticated=True,
        ),
        fact(
            "persistence-order-readback",
            "gvr.test.persistence_relation",
            subject=SUBJECT,
            surface=SURFACE,
            action=ACTION,
            surface_id="surface-checkout",
            action_id="action-submit",
            outcome_id="outcome-accepted",
            relation="read_back",
            read_surface="/orders/{order_id}",
            read_action="view_order",
        ),
        fact(
            "recovery-payment-timeout",
            "gvr.test.error_recovery",
            subject=SUBJECT,
            surface=SURFACE,
            action=ACTION,
            surface_id="surface-checkout",
            action_id="action-submit",
            outcome_id="outcome-accepted",
            error="payment_timeout",
            recovery="retry preserves the cart and creates at most one order",
        ),
        fact(
            "dependency-payment",
            "gvr.test.dependency",
            subject=SUBJECT,
            surface=SURFACE,
            action=ACTION,
            surface_id="surface-checkout",
            action_id="action-submit",
            outcome_id="outcome-accepted",
            dependency="payment_gateway",
            interaction="request_response",
            supported=True,
        ),
        fact(
            "safety-checkout",
            "gvr.test.execution_safety",
            subject=SUBJECT,
            surface=SURFACE,
            action=ACTION,
            surface_id="surface-checkout",
            action_id="action-submit",
            mode="isolated_fixture",
            bounded=True,
        ),
    )


def coverage_for_records(
    records: tuple[Evidence, ...],
    *,
    completeness: rto.FactCoverageCompleteness = rto.FactCoverageCompleteness.COMPLETE,
    scope: dict[str, object] | None = None,
) -> tuple[rto.FactClassCoverage, ...]:
    ids_by_class: dict[rto.BehaviorFactClass, list[str]] = {}
    for record in records:
        fact_class = rto.EVIDENCE_FACT_CLASS[record.kind]
        ids_by_class.setdefault(fact_class, []).append(record.id)
    return tuple(
        rto.FactClassCoverage(
            fact_class=fact_class,
            completeness=completeness,
            evidence_ids=tuple(evidence_ids),
            scope=SCOPE if scope is None else scope,
        )
        for fact_class, evidence_ids in ids_by_class.items()
    )


def inventory(
    records: tuple[Evidence, ...] | None = None,
    coverages: tuple[rto.FactClassCoverage, ...] | None = None,
) -> rto.BehaviorEvidenceInventory:
    actual_records = complete_journey() if records is None else records
    actual_coverage = coverage_for_records(actual_records) if coverages is None else coverages
    return rto.BehaviorEvidenceInventory(
        evidence=actual_records,
        coverage=actual_coverage,
    )


def codes(plan: rto.RegressionObligationPlan) -> set[rto.RegressionObligationGapCode]:
    return {gap.code for gap in plan.gaps}


def kinds(plan: rto.RegressionObligationPlan) -> set[rto.TestObligationKind]:
    return {item.kind for item in plan.obligations}


def replace_fact(records: tuple[Evidence, ...], evidence_id: str, **payload: object) -> tuple[Evidence, ...]:
    result: list[Evidence] = []
    for record in records:
        if record.id != evidence_id:
            result.append(record)
            continue
        merged = dict(record.payload)
        merged.update(payload)
        result.append(fact(record.id, record.kind, **merged))
    return tuple(result)


def test_01_public_evidence_vocabulary_is_exact_and_stable() -> None:
    assert rto.BEHAVIOR_EVIDENCE_KINDS == (
        "gvr.test.surface",
        "gvr.test.actor_role",
        "gvr.test.action",
        "gvr.test.field",
        "gvr.test.constraint",
        "gvr.test.data_partition",
        "gvr.test.observable_outcome",
        "gvr.test.state_transition",
        "gvr.test.persistence_relation",
        "gvr.test.permission_relation",
        "gvr.test.dependency",
        "gvr.test.error_recovery",
        "gvr.test.execution_safety",
    )
    assert tuple(item.value for item in rto.BehaviorEvidenceKind) == rto.BEHAVIOR_EVIDENCE_KINDS
    assert len(rto.EVIDENCE_FACT_CLASS) == 13


def test_02_public_obligation_kinds_and_rules_are_exact() -> None:
    assert tuple(item.value for item in rto.TestObligationKind) == (
        "HAPPY_PATH",
        "REQUIRED_FIELD",
        "INVALID_FORMAT",
        "BOUNDARY_VALUE",
        "STATE_TRANSITION",
        "ROLE_PERMISSION",
        "PERSISTENCE_READ_BACK",
        "ERROR_RECOVERY",
        "DEPENDENCY",
    )
    assert set(rto.OBLIGATION_RULES) == set(rto.TestObligationKind)


def test_03_public_gap_vocabulary_contains_all_required_stable_codes() -> None:
    assert {item.value for item in rto.RegressionObligationGapCode} >= {
        "MISSING_NAVIGATION",
        "MISSING_PRECONDITION",
        "MISSING_ACTION",
        "MISSING_ORACLE",
        "MISSING_CONSTRAINT",
        "MISSING_TEST_DATA_PARTITION",
        "MISSING_ROLE_EVIDENCE",
        "MISSING_PERSISTENCE_READ_BACK",
        "AUTHENTICATION_UNPROVEN",
        "EXECUTION_SAFETY_UNKNOWN",
        "COVERAGE_PARTIAL",
        "COVERAGE_UNKNOWN",
        "CONTRADICTORY_EVIDENCE",
        "UNSUPPORTED_INTERACTION",
        "BUDGET_EXHAUSTED",
    }


def test_04_inventory_rejects_old_generic_and_truth_like_evidence() -> None:
    with pytest.raises(rto.RegressionObligationError, match="unsupported behavior evidence kind"):
        inventory((fact("old", "gvr.test.behavior_change", subject=SUBJECT),), ())
    with pytest.raises(rto.RegressionObligationError, match="truth-like"):
        inventory((fact("surface", "gvr.test.surface", subject=SUBJECT, verdict="PASS"),), ())


def test_05_inventory_is_deterministic_immutable_and_rejects_conflicting_ids() -> None:
    records = complete_journey()
    left = inventory(tuple(reversed(records)), tuple(reversed(coverage_for_records(records))))
    right = inventory(records + (deepcopy(records[0]),), coverage_for_records(records))
    assert left.fingerprint == right.fingerprint
    with pytest.raises(TypeError):
        left.evidence[0].payload["subject"] = "other"  # type: ignore[index]
    with pytest.raises(rto.RegressionObligationError, match="conflicting evidence"):
        inventory((records[0], fact(records[0].id, records[0].kind, subject="other")), ())


def test_06_complete_empty_coverage_is_valid_negative_evidence_but_unknown_cannot_cite_ids() -> None:
    empty = rto.FactClassCoverage(
        fact_class=rto.BehaviorFactClass.ACTION,
        completeness=rto.FactCoverageCompleteness.COMPLETE,
        evidence_ids=(),
        scope=SCOPE,
    )
    assert empty.evidence_ids == ()
    with pytest.raises(rto.RegressionObligationError, match="unknown coverage"):
        replace(empty, completeness=rto.FactCoverageCompleteness.UNKNOWN, evidence_ids=("x",))


@pytest.mark.parametrize(
    "record",
    (
        fact("route", "gvr.test.surface", subject=SUBJECT, surface=SURFACE, navigation="route:/checkout"),
        fact("button", "gvr.test.action", subject=SUBJECT, surface=SURFACE, action=ACTION, surface_id="route", precondition="ready"),
        fact("field", "gvr.test.field", subject=SUBJECT, surface=SURFACE, action=ACTION, surface_id="route", action_id="button", field="email"),
        fact("requirement", "gvr.test.constraint", subject=SUBJECT, surface=SURFACE, action=ACTION, surface_id="route", action_id="button", field_id="field", constraint="required"),
    ),
)
def test_07_route_button_field_or_requirement_alone_never_manufactures_obligation(record: Evidence) -> None:
    plan = rto.derive_regression_test_obligations(inventory((record,), coverage_for_records((record,))))
    assert plan.obligations == ()


def test_08_exact_linked_facts_derive_all_nine_obligation_kinds() -> None:
    plan = rto.derive_regression_test_obligations(inventory())
    assert kinds(plan) == set(rto.TestObligationKind)
    assert len(plan.obligations) == len(plan.bundles) == 9
    assert all(bundle.report.verdict is VerificationVerdict.PASS for bundle in plan.bundles)
    assert plan.readiness is rto.RegressionObligationReadiness.READY


@pytest.mark.parametrize(
    ("evidence_id", "changed"),
    (
        ("outcome-accepted", {"action_id": "different-action"}),
        ("outcome-accepted", {"subject": "different.subject"}),
        ("outcome-accepted", {"surface": "/different"}),
        ("outcome-accepted", {"action": "different_action"}),
        ("action-submit", {"surface_id": "different-surface"}),
    ),
)
def test_09_wrong_payload_ids_or_subject_action_surface_semantics_do_not_link(
    evidence_id: str,
    changed: dict[str, object],
) -> None:
    records = replace_fact(complete_journey(), evidence_id, **changed)
    plan = rto.derive_regression_test_obligations(inventory(records, coverage_for_records(records)))
    assert rto.TestObligationKind.HAPPY_PATH not in kinds(plan)


def test_10_partial_positive_local_grounding_derives_obligations_but_plan_remains_partial() -> None:
    records = complete_journey()
    coverages = list(coverage_for_records(records))
    outcome_class = rto.BehaviorFactClass.OBSERVABLE_OUTCOME
    coverages = [
        replace(item, completeness=rto.FactCoverageCompleteness.PARTIAL)
        if item.fact_class is outcome_class
        else item
        for item in coverages
    ]
    plan = rto.derive_regression_test_obligations(inventory(records, tuple(coverages)))
    assert len(plan.obligations) == 9
    assert any(bundle.report.verdict is VerificationVerdict.UNKNOWN for bundle in plan.bundles)
    assert rto.RegressionObligationGapCode.COVERAGE_PARTIAL in codes(plan)
    assert plan.readiness is rto.RegressionObligationReadiness.BLOCKED


def test_11_wrong_scope_complete_empty_coverage_is_not_proof_of_absence() -> None:
    surface = complete_journey()[0]
    wrong_scope = rto.FactClassCoverage(
        fact_class=rto.BehaviorFactClass.ACTION,
        completeness=rto.FactCoverageCompleteness.COMPLETE,
        evidence_ids=(),
        scope={"subject": "other.subject", "surface": "/other", "action": ACTION},
    )
    plan = rto.derive_regression_test_obligations(
        inventory((surface,), coverage_for_records((surface,)) + (wrong_scope,))
    )
    assert rto.RegressionObligationGapCode.MISSING_ACTION not in codes(plan)
    assert rto.RegressionObligationGapCode.COVERAGE_UNKNOWN in codes(plan)


def test_12_matching_complete_empty_coverage_can_prove_missing_action() -> None:
    surface = complete_journey()[0]
    local_absence = rto.FactClassCoverage(
        fact_class=rto.BehaviorFactClass.ACTION,
        completeness=rto.FactCoverageCompleteness.COMPLETE,
        evidence_ids=(),
        scope=SCOPE,
    )
    plan = rto.derive_regression_test_obligations(
        inventory((surface,), coverage_for_records((surface,)) + (local_absence,))
    )
    assert rto.RegressionObligationGapCode.MISSING_ACTION in codes(plan)


def test_13_data_partitions_are_bounded_records_not_obligation_multipliers() -> None:
    records = replace_fact(
        complete_journey(),
        "partition-email-boundary",
        values=tuple(range(10_000)),
    )
    plan = rto.derive_regression_test_obligations(inventory(records, coverage_for_records(records)))
    assert len(plan.obligations) == 9
    assert sum(item.kind is rto.TestObligationKind.BOUNDARY_VALUE for item in plan.obligations) == 1


def test_14_required_field_invalid_format_and_boundary_rules_are_strict() -> None:
    records = tuple(
        record for record in complete_journey()
        if record.id not in {"constraint-required", "partition-invalid-email", "partition-email-boundary"}
    )
    plan = rto.derive_regression_test_obligations(inventory(records, coverage_for_records(records)))
    assert rto.TestObligationKind.REQUIRED_FIELD not in kinds(plan)
    assert rto.TestObligationKind.INVALID_FORMAT not in kinds(plan)
    assert rto.TestObligationKind.BOUNDARY_VALUE not in kinds(plan)
    assert rto.RegressionObligationGapCode.MISSING_TEST_DATA_PARTITION in codes(plan)


def test_15_role_permission_requires_exact_role_link_and_proven_authentication() -> None:
    wrong_role = replace_fact(complete_journey(), "permission-buyer-submit", role_id="role-admin")
    wrong_plan = rto.derive_regression_test_obligations(inventory(wrong_role, coverage_for_records(wrong_role)))
    assert rto.TestObligationKind.ROLE_PERMISSION not in kinds(wrong_plan)
    assert rto.RegressionObligationGapCode.MISSING_ROLE_EVIDENCE in codes(wrong_plan)

    unproven = replace_fact(complete_journey(), "permission-buyer-submit", authenticated=False)
    unproven_plan = rto.derive_regression_test_obligations(inventory(unproven, coverage_for_records(unproven)))
    assert rto.TestObligationKind.ROLE_PERMISSION not in kinds(unproven_plan)
    assert rto.RegressionObligationGapCode.AUTHENTICATION_UNPROVEN in codes(unproven_plan)


def test_16_persistence_requires_explicit_linked_read_back_relation() -> None:
    records = replace_fact(complete_journey(), "persistence-order-readback", relation="write_only")
    plan = rto.derive_regression_test_obligations(inventory(records, coverage_for_records(records)))
    assert rto.TestObligationKind.PERSISTENCE_READ_BACK not in kinds(plan)
    assert rto.RegressionObligationGapCode.MISSING_PERSISTENCE_READ_BACK in codes(plan)


def test_17_error_recovery_requires_exact_action_and_oracle_links() -> None:
    records = replace_fact(complete_journey(), "recovery-payment-timeout", outcome_id="different-outcome")
    plan = rto.derive_regression_test_obligations(inventory(records, coverage_for_records(records)))
    assert rto.TestObligationKind.ERROR_RECOVERY not in kinds(plan)


def test_18_dependency_requires_supported_exact_interaction() -> None:
    records = replace_fact(complete_journey(), "dependency-payment", supported=False)
    plan = rto.derive_regression_test_obligations(inventory(records, coverage_for_records(records)))
    assert rto.TestObligationKind.DEPENDENCY not in kinds(plan)
    assert rto.RegressionObligationGapCode.UNSUPPORTED_INTERACTION in codes(plan)


def test_19_state_transition_requires_exact_linked_oracle() -> None:
    records = replace_fact(complete_journey(), "transition-created", outcome_id="different-outcome")
    plan = rto.derive_regression_test_obligations(inventory(records, coverage_for_records(records)))
    assert rto.TestObligationKind.STATE_TRANSITION not in kinds(plan)


def test_20_missing_execution_safety_is_unknown_not_ready() -> None:
    records = tuple(record for record in complete_journey() if record.kind != "gvr.test.execution_safety")
    plan = rto.derive_regression_test_obligations(inventory(records, coverage_for_records(records)))
    assert rto.RegressionObligationGapCode.EXECUTION_SAFETY_UNKNOWN in codes(plan)
    assert plan.readiness is rto.RegressionObligationReadiness.UNKNOWN


def test_21_contradictory_oracles_are_reported_and_never_ready() -> None:
    records = complete_journey() + (
        fact(
            "outcome-rejected",
            "gvr.test.observable_outcome",
            subject=SUBJECT,
            surface=SURFACE,
            action=ACTION,
            surface_id="surface-checkout",
            action_id="action-submit",
            oracle="order confirmation is not shown",
        ),
    )
    plan = rto.derive_regression_test_obligations(inventory(records, coverage_for_records(records)))
    assert rto.RegressionObligationGapCode.CONTRADICTORY_EVIDENCE in codes(plan)
    assert plan.readiness is rto.RegressionObligationReadiness.BLOCKED


def test_22_grounding_rechecks_exact_payload_links_not_only_kind_membership() -> None:
    plan = rto.derive_regression_test_obligations(inventory())
    happy = next(item for item in plan.obligations if item.kind is rto.TestObligationKind.HAPPY_PATH)
    changed = replace_fact(complete_journey(), "outcome-accepted", action_id="other")
    report = rto.verify_test_obligation_grounding(happy, inventory(changed, coverage_for_records(changed)))
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "OBLIGATION_LINK_MISMATCH" in {issue.code for issue in report.issues}


def test_23_grounding_bundle_and_claim_ledger_staleness_are_preserved() -> None:
    plan = rto.derive_regression_test_obligations(inventory())
    obligation = next(item for item in plan.obligations if item.kind is rto.TestObligationKind.HAPPY_PATH)
    bundle = next(
        item for item in plan.bundles
        if item.report.metadata["obligation_id"] == obligation.obligation_id
    )
    assert tuple(item.id for item in bundle.evidence) == bundle.report.evidence_ids
    ledger = ClaimLedger()
    ledger.define(ClaimDefinition(
        id=obligation.claim_id,
        statement=rto.TEST_OBLIGATION_GROUNDED,
        verifier=rto.REGRESSION_TEST_OBLIGATION_VERIFIER,
    ))
    ledger.record_bundle(obligation.claim_id, bundle)
    assert ledger.status(obligation.claim_id).freshness is Freshness.FRESH
    original = next(item for item in complete_journey() if item.id == "outcome-accepted")
    ledger.put_evidence_record(fact(original.id, original.kind, **{**original.payload, "oracle": "changed"}))
    assert ledger.status(obligation.claim_id).freshness is Freshness.STALE


def test_24_budget_exhaustion_is_deterministic_and_bounded() -> None:
    budget = rto.RegressionObligationBudget(
        max_obligations=3,
        max_bundles=3,
        max_evidence_records=100,
        max_steps=100,
    )
    first = rto.derive_regression_test_obligations(inventory(), budget=budget)
    second = rto.derive_regression_test_obligations(inventory(), budget=budget)
    assert len(first.obligations) == len(first.bundles) == 3
    assert first.fingerprint == second.fingerprint
    assert first.termination is rto.RegressionObligationTermination.BUDGET_EXHAUSTED
    assert rto.RegressionObligationGapCode.BUDGET_EXHAUSTED in codes(first)


def test_25_capability_matches_exact_runtime_vocabulary() -> None:
    capability = builtin_verifier_capability_registry().lookup(
        rto.REGRESSION_TEST_OBLIGATION_VERIFIER,
        "1",
    )
    assert capability.claim_kinds == (rto.TEST_OBLIGATION_GROUNDED,)
    assert capability.accepted_evidence_kinds == tuple(sorted(rto.BEHAVIOR_EVIDENCE_KINDS))
    assert capability.required_evidence_kinds == ()
    assert capability.coverage["pass_requires"] == "COMPLETE_EXACT_LINKED_FACT_COVERAGE"


def test_26_schema_v1_protocol_round_trips_the_remediated_plan() -> None:
    item = inventory()
    request = {
        "schema_version": 1,
        "op": "derive_regression_test_obligations",
        "payload": {"inventory": item.to_dict()},
    }
    first = safe_handle_request(deepcopy(request))
    second = safe_handle_request(deepcopy(request))
    assert first == second
    assert first["kind"] == "regression_obligation_plan"
    assert first["payload"]["readiness"] == "READY"
    assert {item["kind"] for item in first["payload"]["obligations"]} == {
        item.value for item in rto.TestObligationKind
    }


def test_27_plan_and_semantic_records_remain_immutable_and_fingerprinted() -> None:
    plan = rto.derive_regression_test_obligations(inventory())
    assert len(plan.fingerprint) == 64
    assert all(len(item.fingerprint) == 64 for item in plan.obligations)
    with pytest.raises(FrozenInstanceError):
        plan.readiness = rto.RegressionObligationReadiness.UNKNOWN  # type: ignore[misc]
    with pytest.raises(TypeError):
        plan.obligations[0].metadata["surface"] = "/other"  # type: ignore[index]


def test_28_derivation_uses_no_provider_or_external_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("external execution is forbidden")

    monkeypatch.setattr("gvr.evidence_providers.EvidenceProviderRuntimeRegistry.acquire", forbidden)
    plan = rto.derive_regression_test_obligations(inventory())
    assert plan.readiness is rto.RegressionObligationReadiness.READY
