import pytest
from gvr import (
    Coverage, DeltaKind, FunctionalSnapshot, Observable, RevisionRef,
    VerificationVerdict, compare_functionality,
)


def snap(rev, observables, **coverage):
    return FunctionalSnapshot(
        RevisionRef("repo", rev), tuple(observables),
        {k: Coverage(v) for k, v in coverage.items()},
    )


def obs(kind, key, value, evidence=(), receiver="PROVEN", completeness="COMPLETE_FOR_SUPPORTED_CONSTRUCT"):
    return Observable(kind, key, value, tuple(evidence), receiver, completeness)


def test_preserved_ignores_evidence_identity_churn():
    b = snap("A", [obs("DATA_FLOW", "discount->pricing", {"path": ["a", "b"]}, ("e1",))], DATA_FLOW="COMPLETE")
    c = snap("B", [obs("DATA_FLOW", "discount->pricing", {"path": ["a", "b"]}, ("e2",))], DATA_FLOW="COMPLETE")
    item = compare_functionality(b, c).items[0]
    assert item.delta is DeltaKind.PRESERVED
    assert item.verdict is VerificationVerdict.PASS
    assert item.evidence_ids == ("e1", "e2")


def test_exact_changed_observable_is_proven_changed():
    b = snap("A", [obs("EXTERNAL_CALL", "pricing", {"target": "v1"})], EXTERNAL_CALL="COMPLETE")
    c = snap("B", [obs("EXTERNAL_CALL", "pricing", {"target": "v2"})], EXTERNAL_CALL="COMPLETE")
    item = compare_functionality(b, c).items[0]
    assert item.delta is DeltaKind.CHANGED
    assert item.verdict is VerificationVerdict.PASS


def test_removed_requires_candidate_complete_coverage():
    baseline_obs = obs("DATA_FLOW", "discount->pricing", True, ("e1",))
    b = snap("A", [baseline_obs], DATA_FLOW="COMPLETE")
    incomplete = snap("B", [], DATA_FLOW="PARTIAL")
    complete = snap("C", [], DATA_FLOW="COMPLETE")
    unknown = compare_functionality(b, incomplete).items[0]
    removed = compare_functionality(b, complete).items[0]
    assert unknown.delta is DeltaKind.UNKNOWN
    assert unknown.verdict is VerificationVerdict.UNKNOWN
    assert removed.delta is DeltaKind.REMOVED
    assert removed.verdict is VerificationVerdict.PASS


def test_added_requires_baseline_complete_coverage():
    candidate_obs = obs("EXTERNAL_CALL", "fraud", {"target": "FraudService"}, ("e2",))
    b_partial = snap("A", [], EXTERNAL_CALL="UNKNOWN")
    b_complete = snap("A2", [], EXTERNAL_CALL="COMPLETE")
    c = snap("B", [candidate_obs], EXTERNAL_CALL="COMPLETE")
    assert compare_functionality(b_partial, c).items[0].delta is DeltaKind.UNKNOWN
    assert compare_functionality(b_complete, c).items[0].delta is DeltaKind.ADDED


def test_may_or_partial_observable_cannot_prove_change():
    b = snap("A", [obs("DATA_FLOW", "x", 1)], DATA_FLOW="COMPLETE")
    c = snap("B", [obs("DATA_FLOW", "x", 2, receiver="MAY")], DATA_FLOW="COMPLETE")
    item = compare_functionality(b, c).items[0]
    assert item.delta is DeltaKind.UNKNOWN
    assert item.verdict is VerificationVerdict.UNKNOWN


def test_partial_preserved_is_unknown_not_pass():
    b = snap("A", [obs("DATA_FLOW", "x", 1)], DATA_FLOW="COMPLETE")
    c = snap("B", [obs("DATA_FLOW", "x", 1, completeness="PARTIAL")], DATA_FLOW="PARTIAL")
    item = compare_functionality(b, c).items[0]
    assert item.delta is DeltaKind.PRESERVED
    assert item.verdict is VerificationVerdict.UNKNOWN


def test_proven_regression_only_counts_proven_removed_or_changed():
    b = snap("A", [obs("DATA_FLOW", "x", 1)], DATA_FLOW="COMPLETE")
    c_unknown = snap("B", [], DATA_FLOW="PARTIAL")
    c_removed = snap("C", [], DATA_FLOW="COMPLETE")
    assert not compare_functionality(b, c_unknown).has_proven_regression
    assert compare_functionality(b, c_removed).has_proven_regression


def test_duplicate_observable_identity_rejected():
    duplicate = [obs("DATA_FLOW", "x", 1), obs("DATA_FLOW", "x", 2)]
    with pytest.raises(ValueError):
        compare_functionality(snap("A", duplicate, DATA_FLOW="COMPLETE"), snap("B", [], DATA_FLOW="COMPLETE"))


def test_different_observable_kinds_do_not_collide():
    b = snap("A", [obs("DATA_FLOW", "x", 1), obs("DB_WRITE", "x", 1)], DATA_FLOW="COMPLETE", DB_WRITE="COMPLETE")
    c = snap("B", [obs("DATA_FLOW", "x", 1), obs("DB_WRITE", "x", 1)], DATA_FLOW="COMPLETE", DB_WRITE="COMPLETE")
    result = compare_functionality(b, c)
    assert len(result.items) == 2
    assert all(i.delta is DeltaKind.PRESERVED for i in result.items)
