import pytest

from gvr import VerificationVerdict
from gvr.code_graph import EvidenceConfidence, GraphBlocker, GraphEvidence, GraphEvidenceKind, GraphEvidenceModel
from gvr.verifiers.code_graph import CodeGraphClaim, CodeGraphClaimKind, CodeGraphScope, verify_code_graph_claim


def _node(node_id, *, confidence=EvidenceConfidence.EXACT, snapshot="s1"):
    return GraphEvidence(
        id=f"node:{node_id}",
        kind=GraphEvidenceKind.NODE,
        semantic_identity={"qualified_name": node_id},
        exact_identity={"snapshot": snapshot, "qualified_name": node_id},
        confidence=confidence,
    )


def _edge(source, target, relation="CALL", *, edge_id=None, confidence=EvidenceConfidence.EXACT, snapshot="s1"):
    return GraphEvidence(
        id=edge_id or f"edge:{source}:{relation}:{target}",
        kind=GraphEvidenceKind.CALL if relation == "CALL" else GraphEvidenceKind.REFERENCE,
        semantic_identity={"source": source, "target": target, "relation": relation},
        exact_identity={"snapshot": snapshot, "source": source, "target": target, "relation": relation},
        confidence=confidence,
        source=source,
        target=target,
        label=relation,
    )


def _model(nodes, edges=(), *, blockers=(), absence=(), snapshot="s1", provider="any-provider"):
    return GraphEvidenceModel(
        provider=provider,
        nodes=tuple(nodes),
        edges=tuple(edges),
        blockers=tuple(blockers),
        absence_subjects=tuple(absence),
        source_snapshot={"id": snapshot},
    )


def _claim(kind, **kw):
    return CodeGraphClaim(kind=kind, evidence_namespace="ns", scope=CodeGraphScope(snapshot={"id": "s1"}), **kw)


def _codes(report):
    return {issue.code for issue in report.issues}


def test_node_exists_edge_exists_path_exists_no_path_and_absence_truth_table():
    model = _model([_node("A"), _node("B"), _node("C")], [_edge("A", "B"), _edge("B", "C")], absence=("C->A",))

    assert verify_code_graph_claim(_claim(CodeGraphClaimKind.NODE_EXISTS, node="A"), model).verdict is VerificationVerdict.PASS
    assert verify_code_graph_claim(_claim(CodeGraphClaimKind.EDGE_EXISTS, source="A", target="B", relations={"CALL"}), model).verdict is VerificationVerdict.PASS
    assert verify_code_graph_claim(_claim(CodeGraphClaimKind.PATH_EXISTS, source="A", target="C", relations={"CALL"}), model).verdict is VerificationVerdict.PASS
    assert verify_code_graph_claim(_claim(CodeGraphClaimKind.NO_PATH, source="C", target="A", relations={"CALL"}), model).verdict is VerificationVerdict.PASS

    absent = verify_code_graph_claim(_claim(CodeGraphClaimKind.NODE_EXISTS, node="Z"), model)
    assert absent.verdict is VerificationVerdict.UNKNOWN
    assert "ABSENCE_NOT_PROVEN" in _codes(absent)

    absent = verify_code_graph_claim(_claim(CodeGraphClaimKind.NODE_EXISTS, node="Z"), _model([], [], absence=("Z",)))
    assert absent.verdict is VerificationVerdict.FAIL
    assert "NODE_ABSENT" in _codes(absent)

    absent_edge = verify_code_graph_claim(_claim(CodeGraphClaimKind.EDGE_EXISTS, source="A", target="Z"), model)
    assert absent_edge.verdict is VerificationVerdict.UNKNOWN
    assert "ABSENCE_NOT_PROVEN" in _codes(absent_edge)

    absent_edge = verify_code_graph_claim(_claim(CodeGraphClaimKind.EDGE_EXISTS, source="A", target="Z"), _model([], [], absence=("A->Z",)))
    assert absent_edge.verdict is VerificationVerdict.FAIL
    assert "EDGE_ABSENT" in _codes(absent_edge)


def test_unknown_for_heuristic_codeflow_only_complete_absence_and_partial_or_truncated_evidence():
    heuristic = _model([_node("A"), _node("B")], [_edge("A", "B", confidence=EvidenceConfidence.HEURISTIC)], provider="codeflow")
    assert verify_code_graph_claim(_claim(CodeGraphClaimKind.EDGE_EXISTS, source="A", target="B"), heuristic).verdict is VerificationVerdict.UNKNOWN
    assert "EDGE_NOT_EXACT" in _codes(verify_code_graph_claim(_claim(CodeGraphClaimKind.EDGE_EXISTS, source="A", target="B"), heuristic))

    empty = _model([], [], provider="codeflow")
    assert verify_code_graph_claim(_claim(CodeGraphClaimKind.NO_PATH, source="A", target="B"), empty).verdict is VerificationVerdict.UNKNOWN
    assert verify_code_graph_claim(_claim(CodeGraphClaimKind.PATH_EXISTS, source="A", target="B"), empty).verdict is VerificationVerdict.UNKNOWN

    complete_absence = _model([], [], absence=("A->B",))
    absent_path = verify_code_graph_claim(_claim(CodeGraphClaimKind.PATH_EXISTS, source="A", target="B"), complete_absence)
    assert absent_path.verdict is VerificationVerdict.FAIL
    assert "PATH_ABSENT" in _codes(absent_path)

    partial = _model([_node("A"), _node("B")], [_edge("A", "B")], blockers=(GraphBlocker("b:truncated", "truncated", "graph"),))
    report = verify_code_graph_claim(_claim(CodeGraphClaimKind.NO_PATH, source="B", target="A"), partial)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "GRAPH_BLOCKED" in _codes(report)


def test_counterexample_fail_for_no_path_all_paths_and_blast_radius_contains():
    model = _model([_node("A"), _node("B"), _node("C")], [_edge("A", "B"), _edge("B", "C")])

    no_path = verify_code_graph_claim(_claim(CodeGraphClaimKind.NO_PATH, source="A", target="C"), model)
    assert no_path.verdict is VerificationVerdict.FAIL
    assert "COUNTEREXAMPLE_PATH" in _codes(no_path)

    all_paths = verify_code_graph_claim(_claim(CodeGraphClaimKind.ALL_PATHS_PASS_THROUGH, source="A", target="C", through="X"), model)
    assert all_paths.verdict is VerificationVerdict.FAIL
    assert "COUNTEREXAMPLE_PATH" in _codes(all_paths)

    blast = verify_code_graph_claim(_claim(CodeGraphClaimKind.BLAST_RADIUS_CONTAINS, source="A", target="C", max_depth=1), model)
    assert blast.verdict is VerificationVerdict.UNKNOWN
    assert "ABSENCE_NOT_PROVEN" in _codes(blast)

    scoped_absence = _model([_node("A"), _node("C")], [], absence=("A->C:max_depth:1",))
    blast = verify_code_graph_claim(_claim(CodeGraphClaimKind.BLAST_RADIUS_CONTAINS, source="A", target="C", max_depth=1), scoped_absence)
    assert blast.verdict is VerificationVerdict.FAIL
    assert "TARGET_OUTSIDE_BLAST_RADIUS" in _codes(blast)


def test_non_exact_paths_are_not_decisive_negative_counterexamples():
    heuristic = _model(
        [_node("A"), _node("B")],
        [_edge("A", "B", confidence=EvidenceConfidence.INFERRED_HINT)],
        provider="architecture-hints",
    )

    no_path = verify_code_graph_claim(_claim(CodeGraphClaimKind.NO_PATH, source="A", target="B"), heuristic)
    assert no_path.verdict is VerificationVerdict.UNKNOWN
    assert "EDGE_NOT_EXACT" in _codes(no_path)

    all_paths = verify_code_graph_claim(_claim(CodeGraphClaimKind.ALL_PATHS_PASS_THROUGH, source="A", target="B", through="X"), heuristic)
    assert all_paths.verdict is VerificationVerdict.UNKNOWN
    assert "EDGE_NOT_EXACT" in _codes(all_paths)


def test_exact_paths_are_not_masked_by_heuristic_alternatives():
    model = _model(
        [_node("A"), _node("B"), _node("X")],
        [
            _edge("A", "B", confidence=EvidenceConfidence.HEURISTIC),
            _edge("A", "X", edge_id="edge:exact:A:X"),
            _edge("X", "B", edge_id="edge:exact:X:B"),
        ],
        absence=("A->B:bypass:Y",),
    )

    path = verify_code_graph_claim(_claim(CodeGraphClaimKind.PATH_EXISTS, source="A", target="B"), model)
    assert path.verdict is VerificationVerdict.PASS
    assert path.evidence_ids == ("edge:exact:A:X", "edge:exact:X:B")

    no_path = verify_code_graph_claim(_claim(CodeGraphClaimKind.NO_PATH, source="A", target="B"), model)
    assert no_path.verdict is VerificationVerdict.FAIL
    assert "COUNTEREXAMPLE_PATH" in _codes(no_path)

    all_paths = verify_code_graph_claim(_claim(CodeGraphClaimKind.ALL_PATHS_PASS_THROUGH, source="A", target="B", through="Y"), model)
    assert all_paths.verdict is VerificationVerdict.FAIL
    assert "COUNTEREXAMPLE_PATH" in _codes(all_paths)


def test_cycles_duplicates_deterministic_order_invariant_relation_filtering_and_canonical_bfs_path_ids():
    nodes = [_node(x) for x in "ABCD"]
    edges = [_edge("A", "B"), _edge("A", "C", "REF"), _edge("B", "D"), _edge("C", "D", "REF"), _edge("D", "A")]
    one = _model(nodes, edges)
    two = _model(list(reversed(nodes)), list(reversed(edges)) + [edges[0]])

    claim = _claim(CodeGraphClaimKind.PATH_EXISTS, source="A", target="D", relations={"CALL"})
    r1 = verify_code_graph_claim(claim, one)
    r2 = verify_code_graph_claim(claim, two)
    assert r1.verdict is VerificationVerdict.PASS
    assert r1.evidence_ids == ("edge:A:CALL:B", "edge:B:CALL:D")
    assert r1.evidence_ids == r2.evidence_ids
    assert r1.metadata["canonical_path"] == ("A", "B", "D")


def test_graph_model_fingerprint_is_stable_under_nodes_edges_and_blockers_ordering():
    nodes = [_node(x) for x in "ABC"]
    edges = [_edge("A", "B"), _edge("B", "C")]
    blockers = [
        GraphBlocker("b:2", "partial", "C", {"index": 2}),
        GraphBlocker("b:1", "partial", "B", {"index": 1}),
    ]

    first = _model(nodes, edges, blockers=blockers, absence=("Z", "A->Z"))
    second = _model(list(reversed(nodes)), list(reversed(edges)), blockers=tuple(reversed(blockers)), absence=("A->Z", "Z"))

    assert [node.id for node in first.nodes] == [node.id for node in second.nodes]
    assert [edge.id for edge in first.edges] == [edge.id for edge in second.edges]
    assert [blocker.id for blocker in first.blockers] == [blocker.id for blocker in second.blockers]
    assert first.fingerprint == second.fingerprint


def test_snapshot_mismatch_stale_unsupported_and_inferred_blockers_are_unknown_not_provider_branches():
    stale = _model([_node("A")], snapshot="s2", provider="graphify")
    report = verify_code_graph_claim(_claim(CodeGraphClaimKind.NODE_EXISTS, node="A"), stale)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "SNAPSHOT_MISMATCH" in _codes(report)

    blocked = _model([_node("A", confidence=EvidenceConfidence.INFERRED_HINT)], blockers=(GraphBlocker("b:unsupported", "unsupported", "graph"),), provider="graphify")
    report = verify_code_graph_claim(_claim(CodeGraphClaimKind.NODE_EXISTS, node="A"), blocked)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert {"NODE_NOT_EXACT", "GRAPH_BLOCKED"} <= _codes(report)


def test_all_paths_pass_fail_nonvacuous_and_blast_depth():
    model = _model([_node(x) for x in "ABCD"], [_edge("A", "B"), _edge("B", "D"), _edge("A", "C"), _edge("C", "D")], absence=("A->D:bypass:A", "Z->D"))
    assert verify_code_graph_claim(_claim(CodeGraphClaimKind.ALL_PATHS_PASS_THROUGH, source="A", target="D", through="A"), model).verdict is VerificationVerdict.PASS
    assert verify_code_graph_claim(_claim(CodeGraphClaimKind.ALL_PATHS_PASS_THROUGH, source="Z", target="D", through="A"), model).verdict is VerificationVerdict.FAIL
    assert verify_code_graph_claim(_claim(CodeGraphClaimKind.BLAST_RADIUS_CONTAINS, source="A", target="D", max_depth=2), model).verdict is VerificationVerdict.PASS


def test_moderate_thousands_node_structural_performance_is_linear_enough():
    n = 2500
    nodes = [_node(f"N{i}") for i in range(n)]
    edges = [_edge(f"N{i}", f"N{i+1}") for i in range(n - 1)]
    model = _model(nodes, edges)
    report = verify_code_graph_claim(_claim(CodeGraphClaimKind.PATH_EXISTS, source="N0", target=f"N{n-1}"), model)
    assert report.verdict is VerificationVerdict.PASS
    assert len(report.evidence_ids) == n - 1
