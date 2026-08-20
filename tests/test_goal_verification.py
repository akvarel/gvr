from gvr import Action, Goal, Predicate, Proposal, StateEffect, VerificationContext, VerificationVerdict, default_registry, INDETERMINATE, MISSING, evaluate_predicate


def test_car_wash_walk_fails_drive_passes():
    context = VerificationContext(
        initial_state={"person": "home", "car": "home"},
        goal=Goal((Predicate("car", "eq", "wash"),)),
    )
    walk = Proposal((Action("walk", effects=(StateEffect("person", "wash"),)),))
    drive = Proposal((Action("drive", effects=(StateEffect("person", "wash"), StateEffect("car", "wash"))),))
    registry = default_registry()
    assert registry.verify(walk, context).verdict is VerificationVerdict.FAIL
    assert registry.verify(drive, context).verdict is VerificationVerdict.PASS


def test_failed_precondition_does_not_apply_effects():
    context = VerificationContext({"fuel": False, "car": "home"}, Goal((Predicate("car", "eq", "wash"),)))
    p = Proposal((Action("drive", preconditions=(Predicate("fuel", "eq", True),), effects=(StateEffect("car", "wash"),)),))
    report = default_registry().verify(p, context)
    assert report.verdict is VerificationVerdict.FAIL
    assert report.metadata["by_verifier"]["goal_satisfaction"].metadata["final_state"]["car"] == "home"


def test_unknown_precondition_taints_affected_slot():
    context = VerificationContext({}, Goal((Predicate("car", "eq", "wash"),)))
    p = Proposal((Action("drive", preconditions=(Predicate("fuel", "eq", True),), effects=(StateEffect("car", "wash"),)),))
    report = default_registry().verify(p, context)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert report.metadata["by_verifier"]["goal_satisfaction"].metadata["final_state"]["car"] is INDETERMINATE


def test_missing_is_distinct_from_null():
    assert evaluate_predicate(Predicate("x", "exists"), {}) is VerificationVerdict.FAIL
    assert evaluate_predicate(Predicate("x", "exists"), {"x": None}) is VerificationVerdict.PASS
    assert evaluate_predicate(Predicate("x", "eq", None), {}) is VerificationVerdict.UNKNOWN
    assert evaluate_predicate(Predicate("x", "eq", None), {"x": None}) is VerificationVerdict.PASS


def test_registry_fails_impossible_action_even_if_goal_already_true():
    context = VerificationContext({"goal": True, "fuel": False}, Goal((Predicate("goal", "eq", True),)))
    proposal = Proposal((Action("irrelevant-impossible", preconditions=(Predicate("fuel", "eq", True),)),))
    report = default_registry().verify(proposal, context)
    assert report.verdict is VerificationVerdict.FAIL
    assert any(i.code == "ACTION_PRECONDITION_FAILED" for i in report.issues)


def test_unsupported_effect_makes_registry_unknown_when_goal_depends_on_it():
    context = VerificationContext({}, Goal((Predicate("x", "eq", 1),)))
    proposal = Proposal((Action("unsupported", effects=(StateEffect("x", 1, supported=False),)),))
    report = default_registry().verify(proposal, context)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert any(i.code == "UNSUPPORTED_EFFECT" for i in report.issues)
