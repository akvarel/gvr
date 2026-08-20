import pytest
from gvr import (
    ClaimDefinition, ClaimLedger, Freshness, VerificationReport, VerificationVerdict,
)


def _report(verdict, evidence=()):
    return VerificationReport(verdict=verdict, verifier="v", evidence_ids=tuple(evidence))


def test_stale_pass_effective_verdict_becomes_unknown():
    ledger = ClaimLedger()
    ledger.define(ClaimDefinition("C", "x is true", "v"))
    ledger.put_evidence("E", {"x": True})
    ledger.record_verification("C", _report(VerificationVerdict.PASS, ("E",)))
    assert ledger.status("C").effective_verdict is VerificationVerdict.PASS
    ledger.put_evidence("E", {"x": False})
    status = ledger.status("C")
    assert status.stored_verdict is VerificationVerdict.PASS
    assert status.effective_verdict is VerificationVerdict.UNKNOWN
    assert status.freshness is Freshness.STALE


def test_reverification_restores_trusted_verdict_and_history():
    ledger = ClaimLedger()
    ledger.define(ClaimDefinition("C", "x is true", "v"))
    ledger.put_evidence("E", {"x": True})
    first = ledger.record_verification("C", _report(VerificationVerdict.PASS, ("E",)))
    ledger.put_evidence("E", {"x": False})
    second = ledger.record_verification("C", _report(VerificationVerdict.FAIL, ("E",)))
    assert second.claim_version != first.claim_version
    assert ledger.status("C").effective_verdict is VerificationVerdict.FAIL
    assert [s.verdict for s in ledger.history("C")] == [VerificationVerdict.PASS, VerificationVerdict.FAIL]


def test_missing_evidence_rejected():
    ledger = ClaimLedger()
    ledger.define(ClaimDefinition("C", "x", "v"))
    with pytest.raises(ValueError):
        ledger.record_verification("C", _report(VerificationVerdict.PASS, ("NOPE",)))


def test_wrong_verifier_rejected():
    ledger = ClaimLedger()
    ledger.define(ClaimDefinition("C", "x", "required"))
    with pytest.raises(ValueError):
        ledger.record_verification("C", VerificationReport(VerificationVerdict.PASS, "other"))


def test_claim_dependency_effective_unknown_propagates_after_upstream_evidence_change():
    ledger = ClaimLedger()
    ledger.define(ClaimDefinition("A", "source claim", "v"))
    ledger.define(ClaimDefinition("B", "derived claim", "v"))
    ledger.put_evidence("E", {"x": 1})
    ledger.record_verification("A", _report(VerificationVerdict.PASS, ("E",)))
    ledger.record_verification("B", _report(VerificationVerdict.PASS), claim_dependency_ids=("A",))
    assert ledger.status("B").effective_verdict is VerificationVerdict.PASS
    ledger.put_evidence("E", {"x": 2})
    assert ledger.status("A").effective_verdict is VerificationVerdict.UNKNOWN
    assert ledger.status("B").effective_verdict is VerificationVerdict.UNKNOWN


def test_changed_dependency_set_invalidates_downstream():
    ledger = ClaimLedger()
    for cid in ("A", "B"):
        ledger.define(ClaimDefinition(cid, cid, "v"))
    ledger.put_evidence("E1", {"x": 1})
    ledger.put_evidence("E2", {"y": 2})
    ledger.record_verification("A", _report(VerificationVerdict.PASS, ("E1",)))
    ledger.record_verification("B", _report(VerificationVerdict.PASS), claim_dependency_ids=("A",))
    ledger.record_verification("A", _report(VerificationVerdict.PASS, ("E2",)))
    assert ledger.status("B").effective_verdict is VerificationVerdict.UNKNOWN


def test_explicit_evidence_disagreement_rejected():
    ledger = ClaimLedger()
    ledger.define(ClaimDefinition("C", "x", "v"))
    ledger.put_evidence("E1", {"x": 1})
    ledger.put_evidence("E2", {"x": 2})
    with pytest.raises(ValueError):
        ledger.record_verification("C", _report(VerificationVerdict.PASS, ("E1",)), evidence_ids=("E2",))
