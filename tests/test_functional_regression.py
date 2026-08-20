from gvr import (
    ClaimDefinition,
    ClaimLedger,
    Coverage,
    FunctionalSnapshot,
    Observable,
    RevisionRef,
    VerificationVerdict,
    verify_functional_regression,
)


def snap(rev, observables=(), **coverage):
    return FunctionalSnapshot(
        RevisionRef("repo", rev),
        tuple(observables),
        {kind: Coverage(value) for kind, value in coverage.items()},
    )


def obs(key, value, evidence=(), *, receiver="PROVEN", completeness="COMPLETE_FOR_SUPPORTED_CONSTRUCT"):
    return Observable("DATA_FLOW", key, value, tuple(evidence), receiver, completeness)


def test_preserved_functionality_passes_with_complete_coverage():
    baseline = snap("A", [obs("x->y", True, ("a",))], DATA_FLOW="COMPLETE")
    candidate = snap("B", [obs("x->y", True, ("b",))], DATA_FLOW="COMPLETE")
    delta, report = verify_functional_regression(baseline, candidate)
    assert report.verdict is VerificationVerdict.PASS
    assert report.evidence_ids == ("a", "b")
    assert not delta.has_proven_regression


def test_proven_removal_fails_no_regression_claim():
    baseline = snap("A", [obs("x->y", True, ("a",))], DATA_FLOW="COMPLETE")
    candidate = snap("B", [], DATA_FLOW="COMPLETE")
    _, report = verify_functional_regression(baseline, candidate)
    assert report.verdict is VerificationVerdict.FAIL
    assert report.evidence_ids == ("a",)
    assert report.issues[0].code == "FUNCTIONAL_REGRESSION"


def test_proven_change_fails_no_regression_claim():
    baseline = snap("A", [obs("x->y", {"path": 1}, ("a",))], DATA_FLOW="COMPLETE")
    candidate = snap("B", [obs("x->y", {"path": 2}, ("b",))], DATA_FLOW="COMPLETE")
    _, report = verify_functional_regression(baseline, candidate)
    assert report.verdict is VerificationVerdict.FAIL
    assert report.evidence_ids == ("a", "b")


def test_partial_coverage_is_unknown_without_proven_regression():
    baseline = snap("A", [obs("x->y", True)], DATA_FLOW="COMPLETE")
    candidate = snap("B", [obs("x->y", True)], DATA_FLOW="PARTIAL")
    _, report = verify_functional_regression(baseline, candidate)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert any(issue.code == "FUNCTIONAL_COVERAGE_INCOMPLETE" for issue in report.issues)


def test_may_observable_is_unknown():
    baseline = snap("A", [obs("x->y", True)], DATA_FLOW="COMPLETE")
    candidate = snap("B", [obs("x->y", True, receiver="MAY")], DATA_FLOW="COMPLETE")
    _, report = verify_functional_regression(baseline, candidate)
    assert report.verdict is VerificationVerdict.UNKNOWN


def test_no_scope_is_unknown():
    _, report = verify_functional_regression(snap("A"), snap("B"))
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert report.issues[0].code == "FUNCTIONAL_SCOPE_UNKNOWN"


def test_explicit_empty_complete_scope_can_pass():
    baseline = snap("A", DATA_FLOW="COMPLETE")
    candidate = snap("B", DATA_FLOW="COMPLETE")
    _, report = verify_functional_regression(baseline, candidate, required_kinds=("DATA_FLOW",))
    assert report.verdict is VerificationVerdict.PASS


def test_proven_regression_dominates_other_unknowns():
    removed = Observable("EXTERNAL_CALL", "removed", True, ("removed-e",))
    baseline = snap(
        "A",
        [removed, obs("uncertain", 1, ("u1",))],
        DATA_FLOW="COMPLETE",
        EXTERNAL_CALL="COMPLETE",
    )
    candidate = snap(
        "B",
        [obs("uncertain", 2, ("u2",), receiver="MAY")],
        DATA_FLOW="PARTIAL",
        EXTERNAL_CALL="COMPLETE",
    )
    _, report = verify_functional_regression(baseline, candidate)
    assert report.verdict is VerificationVerdict.FAIL
    assert report.evidence_ids == ("removed-e",)


def test_claim_ledger_invalidates_pass_when_supporting_evidence_changes():
    ledger = ClaimLedger()
    ledger.define(ClaimDefinition("no-regression", "candidate preserves data flow", "functional_regression"))
    ledger.put_evidence("a", {"revision": "A", "path": ["x", "y"]})
    ledger.put_evidence("b", {"revision": "B", "path": ["x", "y"]})

    baseline = snap("A", [obs("x->y", True, ("a",))], DATA_FLOW="COMPLETE")
    candidate = snap("B", [obs("x->y", True, ("b",))], DATA_FLOW="COMPLETE")
    _, report = verify_functional_regression(baseline, candidate)
    ledger.record_verification("no-regression", report)
    assert ledger.status("no-regression").effective_verdict is VerificationVerdict.PASS

    ledger.put_evidence("b", {"revision": "B", "path": ["x", "z", "y"]})
    assert ledger.status("no-regression").effective_verdict is VerificationVerdict.UNKNOWN
