import pytest

from gvr import EvidenceConfidence, GraphEvidenceKind, GraphEvidenceModelError
from gvr.adapters.graphify import ingest_traversal_graph

COMPLETE = "COMPLETE_FOR_SUPPORTED_CONSTRUCT"


def _ev(key, source="A", target="B", *, relation="FLOWS_TO", receiver="PROVEN", completeness=COMPLETE):
    return {
        "key": key,
        "relation": relation,
        "source": source,
        "target": target,
        "source_file": "src/Flow.java",
        "source_location": f"{source}->{target}",
        "provenance": "STATIC_AST",
        "confidence_score": 1.0,
        "argument_index": None,
        "receiver_confidence": receiver,
        "analysis_completeness": completeness,
    }


def _path(*items, exactness="EXACT_FOR_RETURNED_PATH", receiver="PROVEN", coverage=COMPLETE):
    return {
        "steps": [{"source": i["source"], "target": i["target"], "relation": i["relation"], "evidence": dict(i)} for i in items],
        "supporting_evidence": [dict(i) for i in items],
        "path_identity": [i["key"] for i in items],
        "path_exactness": exactness,
        "path_receiver_confidence": receiver,
        "path_coverage": coverage,
    }


def _result(paths, **overrides):
    result = {
        "paths": paths,
        "start": "A",
        "target": "C",
        "direction": "FORWARD",
        "visited_count": 3,
        "expanded_count": 2,
        "truncated": False,
        "termination_reason": "COMPLETE",
        "query_bounds": {"effective_allowed_relations": ["FLOWS_TO"]},
        "boundary_events": [],
        "search_coverage": COMPLETE,
        "complete_supported_search": True,
        "start_node_found": True,
        "target_node_found": True,
        "query_validity": True,
        "input_resolution": "RESOLVED",
        "rejected_relations": [],
        "encountered_partial_evidence": False,
        "encountered_unknown_evidence": False,
        "encountered_may_evidence": False,
    }
    result.update(overrides)
    return result


def test_task28_maps_exact_proven_complete_public_traversal_to_canonical_graph_model():
    ab = _ev("df:ab", "A", "B")
    bc = _ev("df:bc", "B", "C")

    model = ingest_traversal_graph(_result([_path(ab, bc)]))

    assert model.provider == "graphify"
    assert [node.id for node in model.nodes] == ["graphify:node:A", "graphify:node:B", "graphify:node:C"]
    assert [edge.id for edge in model.edges] == ["df:ab", "df:bc"]
    assert all(edge.kind is GraphEvidenceKind.REFERENCE for edge in model.edges)
    assert all(edge.confidence is EvidenceConfidence.EXACT for edge in model.edges)
    assert model.edges[0].semantic_identity == {"relation": "FLOWS_TO", "source": "A", "target": "B"}
    assert model.edges[0].exact_identity["key"] == "df:ab"
    assert model.edges[0].native["path_exactness"] == "EXACT_FOR_RETURNED_PATH"
    assert model.absence_verdict("A->C") is not None


def test_task28_deduplicates_and_is_stable_under_path_reordering():
    ab = _ev("df:ab", "A", "B")
    bc = _ev("df:bc", "B", "C")
    direct = _ev("df:ac", "A", "C")

    one = ingest_traversal_graph(_result([_path(ab, bc), _path(direct)]))
    two = ingest_traversal_graph(_result([_path(direct), _path(ab, bc), _path(ab, bc)]))

    assert [edge.id for edge in one.edges] == ["df:ab", "df:ac", "df:bc"]
    assert one.fingerprint == two.fingerprint


def test_task28_rejects_malformed_or_conflicting_df_keys_instead_of_rekeying():
    good = _ev("df:stable", "A", "B")
    with pytest.raises(GraphEvidenceModelError, match="df key"):
        ingest_traversal_graph(_result([_path(dict(good, key="edge-1"))]))

    conflicting = dict(good, target="C")
    with pytest.raises(GraphEvidenceModelError, match="conflicting"):
        ingest_traversal_graph(_result([_path(good), _path(conflicting)]))


def test_task28_may_partial_and_unsupported_never_become_proven_exact_edges():
    may = _ev("df:may", "A", "B", receiver="MAY")
    partial = _ev("df:partial", "B", "C", completeness="PARTIAL")
    unsupported = _ev("df:unsupported", "C", "D", relation="CALLS")

    model = ingest_traversal_graph(_result([
        _path(may, receiver="MAY"),
        _path(partial, coverage="PARTIAL"),
        _path(unsupported),
    ]))

    by_id = {edge.id: edge for edge in model.edges}
    assert by_id["df:may"].confidence is not EvidenceConfidence.EXACT
    assert by_id["df:partial"].confidence is not EvidenceConfidence.EXACT
    assert by_id["df:unsupported"].confidence is not EvidenceConfidence.EXACT
    assert {blocker.id for blocker in model.blockers} >= {"df:may:MAY", "df:partial:PARTIAL", "df:unsupported:UNSUPPORTED_RELATION"}


def test_task28_negative_absence_is_complete_only_for_exact_resolved_complete_search():
    complete = ingest_traversal_graph(_result([]))
    assert complete.absence_subjects == ("graphify:node:A->graphify:node:C",)

    incomplete_cases = [
        {"complete_supported_search": False},
        {"search_coverage": "PARTIAL"},
        {"truncated": True},
        {"query_validity": False},
        {"input_resolution": "TARGET_NODE_NOT_FOUND"},
        {"boundary_events": [{"boundary_evidence_key": "bnd:1", "resolution": "UNSUPPORTED", "canonical_caller_file": "src/Flow.java"}]},
        {"encountered_partial_evidence": True},
        {"encountered_unknown_evidence": True},
    ]
    for override in incomplete_cases:
        model = ingest_traversal_graph(_result([], **override))
        assert model.absence_subjects == ()
