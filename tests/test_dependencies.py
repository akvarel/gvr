import pytest
from gvr import ClaimDependencyGraph, DependencyCycleError, EvidenceState, Freshness, VerificationVerdict


def _fresh_claim(g, cid, verdict=VerificationVerdict.PASS):
    g.put_claim(cid, verdict)
    return g.mark_reverified(cid, verdict)


def test_evidence_change_stales_direct_claim():
    g = ClaimDependencyGraph()
    ev = g.put_evidence("E1", {"value": 1})
    g.put_claim("C1", VerificationVerdict.PASS)
    g.add_dependency("C1", "E1")
    g.mark_reverified("C1", VerificationVerdict.PASS)
    assert g.is_fresh("C1")
    g.put_evidence("E1", {"value": 2})
    assert not g.is_fresh("C1")
    assert g.claims["C1"].freshness is Freshness.STALE


def test_identical_evidence_does_not_stale_claim():
    g = ClaimDependencyGraph()
    first = g.put_evidence("E1", {"b": 2, "a": 1})
    g.put_claim("C1", VerificationVerdict.PASS)
    g.add_dependency("C1", "E1")
    g.mark_reverified("C1", VerificationVerdict.PASS)
    second = g.put_evidence("E1", {"a": 1, "b": 2})
    assert second.version == first.version
    assert g.is_fresh("C1")


def test_removed_evidence_stales_claim_and_prevents_freshening():
    g = ClaimDependencyGraph()
    g.put_evidence("E1", {"value": 1})
    g.put_claim("C1", VerificationVerdict.PASS)
    g.add_dependency("C1", "E1")
    g.mark_reverified("C1", VerificationVerdict.PASS)
    removed = g.remove_evidence("E1")
    assert removed.state is EvidenceState.REMOVED
    assert not g.is_fresh("C1")
    with pytest.raises(ValueError):
        g.mark_reverified("C1", VerificationVerdict.PASS)


def test_transitive_invalidation_claim_dependency():
    g = ClaimDependencyGraph()
    g.put_evidence("E1", {"value": 1})
    g.put_claim("C1", VerificationVerdict.PASS)
    g.add_dependency("C1", "E1")
    g.mark_reverified("C1", VerificationVerdict.PASS)
    g.put_claim("C2", VerificationVerdict.PASS)
    g.add_dependency("C2", "C1")
    g.mark_reverified("C2", VerificationVerdict.PASS)
    assert g.is_fresh("C2")
    g.put_evidence("E1", {"value": 9})
    assert set(g.stale_claims()) == {"C1", "C2"}


def test_reverification_requires_fresh_claim_dependencies():
    g = ClaimDependencyGraph()
    g.put_evidence("E1", {"value": 1})
    g.put_claim("C1", VerificationVerdict.PASS)
    g.add_dependency("C1", "E1")
    g.mark_reverified("C1", VerificationVerdict.PASS)
    g.put_claim("C2", VerificationVerdict.PASS)
    g.add_dependency("C2", "C1")
    g.mark_reverified("C2", VerificationVerdict.PASS)
    g.put_evidence("E1", {"value": 2})
    with pytest.raises(ValueError):
        g.mark_reverified("C2", VerificationVerdict.PASS)
    g.mark_reverified("C1", VerificationVerdict.FAIL)
    g.mark_reverified("C2", VerificationVerdict.FAIL)
    assert g.is_fresh("C2")


def test_claim_cycles_rejected():
    g = ClaimDependencyGraph()
    g.put_claim("A", VerificationVerdict.PASS)
    g.put_claim("B", VerificationVerdict.PASS)
    g.add_dependency("A", "B")
    with pytest.raises(DependencyCycleError):
        g.add_dependency("B", "A")


def test_claim_reverification_with_changed_basis_stales_dependent_even_same_verdict():
    g = ClaimDependencyGraph()
    g.put_evidence("E1", {"value": 1})
    g.put_claim("C1", VerificationVerdict.PASS)
    g.add_dependency("C1", "E1")
    g.mark_reverified("C1", VerificationVerdict.PASS)
    g.put_claim("C2", VerificationVerdict.PASS)
    g.add_dependency("C2", "C1")
    g.mark_reverified("C2", VerificationVerdict.PASS)
    c1v = g.claims["C1"].version
    assert g.is_fresh("C2")

    g.put_evidence("E1", {"value": 2})
    g.mark_reverified("C1", VerificationVerdict.PASS)
    assert g.claims["C1"].version != c1v
    assert not g.is_fresh("C2")


def test_noop_claim_reverification_does_not_stale_dependents():
    g = ClaimDependencyGraph()
    g.put_evidence("E1", {"value": 1})
    g.put_claim("C1", VerificationVerdict.PASS)
    g.add_dependency("C1", "E1")
    g.mark_reverified("C1", VerificationVerdict.PASS)
    g.put_claim("C2", VerificationVerdict.PASS)
    g.add_dependency("C2", "C1")
    g.mark_reverified("C2", VerificationVerdict.PASS)
    v = g.claims["C1"].version
    g.mark_reverified("C1", VerificationVerdict.PASS)
    assert g.claims["C1"].version == v
    assert g.is_fresh("C2")


def test_claim_verdict_change_stales_dependent():
    g = ClaimDependencyGraph()
    g.put_claim("C1", VerificationVerdict.PASS)
    g.mark_reverified("C1", VerificationVerdict.PASS)
    g.put_claim("C2", VerificationVerdict.PASS)
    g.add_dependency("C2", "C1")
    g.mark_reverified("C2", VerificationVerdict.PASS)
    g.mark_reverified("C1", VerificationVerdict.FAIL)
    assert not g.is_fresh("C2")
