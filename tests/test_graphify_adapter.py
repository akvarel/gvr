from gvr.adapters.graphify import ingest_traversal_result
from gvr import VerificationVerdict


def test_complete_empty_search_can_support_absence():
    ev = ingest_traversal_result({
        "paths": [], "complete_supported_search": True,
        "search_coverage": "COMPLETE_FOR_SUPPORTED_CONSTRUCT",
        "termination_reason": "COMPLETE", "boundary_events": [],
    })
    assert ev.absence_verdict is VerificationVerdict.PASS


def test_partial_empty_search_cannot_prove_absence():
    ev = ingest_traversal_result({
        "paths": [], "complete_supported_search": False,
        "search_coverage": "PARTIAL", "termination_reason": "MAX_DEPTH",
        "boundary_events": [{"boundary_evidence_key": "bnd:1"}],
    })
    assert ev.absence_verdict is VerificationVerdict.UNKNOWN
    assert ev.blocking_boundary_keys == ("bnd:1",)


def test_supporting_evidence_deduplicated_by_key():
    item = {"key": "df:1", "source": "a", "target": "b", "source_file": "A.java"}
    ev = ingest_traversal_result({
        "paths": [{"supporting_evidence": [item]}, {"supporting_evidence": [item]}],
        "complete_supported_search": True,
        "search_coverage": "COMPLETE_FOR_SUPPORTED_CONSTRUCT",
        "termination_reason": "COMPLETE",
    })
    assert [x.id for x in ev.evidence] == ["df:1"]
