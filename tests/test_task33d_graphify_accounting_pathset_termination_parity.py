from __future__ import annotations

from copy import deepcopy

import pytest

from gvr import (
    DataFlowClaim,
    DataFlowClaimKind,
    DataFlowQueryScope,
    SourceRevisionIdentity,
    VerificationVerdict,
    decode_code_graph_observation_evidence,
    encode_graphify_code_graph_observation_evidence,
    verify_data_flow_claim,
)
from gvr.adapters.graphify import ingest_traversal_graph
from gvr.code_graph import EvidenceConfidence, GraphEvidenceModelError
from gvr.graphify_contract import validate_graphify_envelope_authority

from test_code_graph_execution_tasks_27_30_integrated import (
    SNAPSHOT_PATH,
    execution_request,
    graphify_path_snapshot,
    path_claim,
    root_report,
)
from test_task31_authority_remediation import df_edge, path_for, traversal
from test_task33b_graphify_envelope_authority_parity import (
    _surface_authority,
    assert_exact_positive_parity,
    assert_negative_parity,
)


def _unresolved(result: dict[str, object], resolution: str) -> None:
    result.update(
        paths=[],
        input_resolution=resolution,
        termination_reason=resolution,
        truncated=False,
        visited_count=0,
        expanded_count=0,
        search_coverage="UNKNOWN",
        complete_supported_search=False,
        start_node_found=resolution != "START_NODE_NOT_FOUND",
        target_node_found=resolution != "TARGET_NODE_NOT_FOUND",
    )
    result["completeness_certificate"].update(
        termination_reason=resolution,
        search_coverage="UNKNOWN",
        complete_supported_search=False,
    )


def _assert_no_exact_surface(result: dict[str, object]) -> None:
    contract, adapter, typed, verdict, negative = _surface_authority(result)
    assert contract in (frozenset(), "REJECTED")
    assert adapter == "REJECTED" or EvidenceConfidence.EXACT not in adapter
    assert typed == "REJECTED" or EvidenceConfidence.EXACT not in typed
    assert verdict is VerificationVerdict.UNKNOWN
    assert negative is False


def test_task33d_visited_cannot_exceed_expanded_plus_start() -> None:
    result = traversal([path_for(df_edge())])
    result["visited_count"] = 100
    _assert_no_exact_surface(result)


def test_task33d_non_identity_returned_path_count_cannot_exceed_expansions() -> None:
    result = traversal([
        path_for(df_edge(location="parallel-1")),
        path_for(df_edge(location="parallel-2")),
    ])
    result.update(visited_count=2, expanded_count=1)
    _assert_no_exact_surface(result)


def test_task33d_duplicate_returned_path_identity_is_not_authoritative() -> None:
    path = path_for(df_edge())
    result = traversal([path, deepcopy(path)])
    result.update(visited_count=2, expanded_count=2)
    _assert_no_exact_surface(result)


@pytest.mark.parametrize("termination", ["START_NODE_NOT_FOUND", "TARGET_NODE_NOT_FOUND"])
def test_task33d_resolved_input_cannot_use_resolution_failure_termination(termination: str) -> None:
    result = traversal([path_for(df_edge())])
    result["termination_reason"] = termination
    result["completeness_certificate"]["termination_reason"] = termination
    _assert_no_exact_surface(result)


@pytest.mark.parametrize("resolution", ["START_NODE_NOT_FOUND", "TARGET_NODE_NOT_FOUND"])
def test_task33d_unresolved_state_machine_is_exact(resolution: str) -> None:
    valid = traversal([])
    _unresolved(valid, resolution)
    authority = validate_graphify_envelope_authority(valid)
    assert not authority.positive_authorized
    assert not authority.negative_authorized

    mutations = (
        lambda r: r.update(termination_reason="COMPLETE"),
        lambda r: r.update(paths=[path_for(df_edge())]),
        lambda r: r.update(visited_count=1),
        lambda r: r.update(expanded_count=1),
        lambda r: r.update(truncated=True),
    )
    for mutate in mutations:
        malformed = deepcopy(valid)
        mutate(malformed)
        if malformed["termination_reason"] != valid["termination_reason"]:
            malformed["completeness_certificate"]["termination_reason"] = malformed["termination_reason"]
        _assert_no_exact_surface(malformed)


def test_task33d_unknown_path_coverage_is_not_current_native_authority() -> None:
    result = traversal([path_for(df_edge())])
    result["paths"][0]["path_coverage"] = "UNKNOWN"
    _assert_no_exact_surface(result)


def test_task33d_parallel_edges_and_branching_reconvergence_remain_authoritative() -> None:
    parallel = tuple(df_edge(location=f"parallel-{index}") for index in range(3))
    parallel_result = traversal([path_for(edge) for edge in parallel])
    parallel_result.update(visited_count=2, expanded_count=3)
    contract, adapter, typed, verdict, negative = _surface_authority(parallel_result)
    assert contract == frozenset(edge["key"] for edge in parallel)
    assert adapter == (EvidenceConfidence.EXACT,) * 3
    assert typed == (EvidenceConfidence.EXACT,) * 3
    assert verdict is VerificationVerdict.PASS
    assert negative is False

    ax = df_edge("A", "X", location="A-X")
    xb = df_edge("X", "B", location="X-B")
    ay = df_edge("A", "Y", location="A-Y")
    yb = df_edge("Y", "B", location="Y-B")
    branching = traversal([path_for(ax, xb), path_for(ay, yb)])
    branching.update(visited_count=4, expanded_count=4)
    contract, adapter, typed, verdict, negative = _surface_authority(branching)
    assert contract == frozenset(edge["key"] for edge in (ax, xb, ay, yb))
    assert adapter == (EvidenceConfidence.EXACT,) * 4
    assert typed == (EvidenceConfidence.EXACT,) * 4
    assert verdict is VerificationVerdict.PASS
    assert negative is False


def test_task33d_target_stop_truncation_and_complete_negative_regressions() -> None:
    target_stop = traversal([path_for(df_edge())])
    target_stop["query_bounds"]["stop_nodes"] = ["B"]
    assert_exact_positive_parity(target_stop)

    interior = traversal([path_for(df_edge("A", "X"), df_edge("X", "B"))])
    interior.update(visited_count=3, expanded_count=2)
    interior["query_bounds"]["stop_nodes"] = ["X"]
    _assert_no_exact_surface(interior)

    truncated = traversal([path_for(df_edge())])
    truncated.update(
        truncated=True,
        termination_reason="MAX_EXPANSIONS",
        search_coverage="PARTIAL",
        complete_supported_search=False,
    )
    truncated["completeness_certificate"].update(
        termination_reason="MAX_EXPANSIONS",
        search_coverage="PARTIAL",
        complete_supported_search=False,
    )
    assert_exact_positive_parity(truncated)

    negative = traversal([])
    negative["visited_count"] = 1
    assert_negative_parity(negative, authoritative=True)


def test_task33d_zero_step_identity_is_valid_without_fabricated_self_edge() -> None:
    result = traversal([path_for()])
    result.update(start="A", target="A", visited_count=1, expanded_count=0)
    contract = validate_graphify_envelope_authority(result)
    graph = ingest_traversal_graph(result)
    typed = decode_code_graph_observation_evidence(
        encode_graphify_code_graph_observation_evidence(
            result,
            evidence_id="obs.task33d.identity",
            source_revision=SourceRevisionIdentity("fixture-repo", "rev1"),
            claim_fingerprint="task33d-identity",
        )
    ).graph_model
    verdict = verify_data_flow_claim(
        DataFlowClaim(
            DataFlowClaimKind.CAN_FLOW_TO,
            "A",
            "A",
            scope=DataFlowQueryScope(effective_allowed_relations=frozenset(result["query_bounds"]["effective_allowed_relations"])),
        ),
        result,
    ).verdict
    assert contract.positive_authorized
    assert graph.edges == ()
    assert typed.edges == ()
    assert verdict is VerificationVerdict.PASS


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(lambda r: r.update(visited_count=100), id="visited-upper-relation"),
        pytest.param(lambda r: r.update(paths=[r["paths"][0], deepcopy(r["paths"][0])], expanded_count=2), id="duplicate-path-identity"),
        pytest.param(lambda r: r.update(termination_reason="START_NODE_NOT_FOUND"), id="resolved-start-not-found"),
        pytest.param(lambda r: r.update(termination_reason="TARGET_NODE_NOT_FOUND"), id="resolved-target-not-found"),
        pytest.param(lambda r: r["paths"][0].update(path_coverage="UNKNOWN"), id="unknown-path-coverage"),
    ],
)
def test_task33d_adversarial_shared_authority_implies_all_exact_surfaces_and_data_flow_parity(mutation) -> None:
    result = traversal([path_for(df_edge())])
    mutation(result)
    result["completeness_certificate"]["termination_reason"] = result["termination_reason"]
    try:
        authority = validate_graphify_envelope_authority(result)
    except GraphEvidenceModelError:
        authority = None
    contract, adapter, typed, verdict, _ = _surface_authority(result)
    if authority is not None and authority.positive_authorized:
        assert contract != "REJECTED" and contract
        assert adapter != "REJECTED" and set(adapter) == {EvidenceConfidence.EXACT}
        assert typed != "REJECTED" and set(typed) == {EvidenceConfidence.EXACT}
        assert verdict is VerificationVerdict.PASS
    else:
        assert verdict is VerificationVerdict.UNKNOWN


def test_task33d_malformed_graphify_cannot_be_upgraded_by_codeflow_or_sqlite_replay(tmp_path) -> None:
    from gvr import SQLiteStorage, execute_verification_plan
    from test_code_graph_execution_tasks_27_30_integrated import (
        codeflow_path_snapshot,
        encode_codeflow_code_graph_observation_evidence,
        typed_query_scope,
        typed_revision,
    )

    claim = path_claim("task33d-replay")
    malformed = graphify_path_snapshot()
    malformed["visited_count"] = 100
    graphify = encode_graphify_code_graph_observation_evidence(
        malformed,
        evidence_id="obs.graphify.task33d",
        claim=claim,
        source_revision=typed_revision(SNAPSHOT_PATH),
    )
    decoded = decode_code_graph_observation_evidence(graphify)
    assert EvidenceConfidence.EXACT not in tuple(edge.confidence for edge in decoded.graph_model.edges)
    codeflow = encode_codeflow_code_graph_observation_evidence(
        codeflow_path_snapshot(),
        evidence_id="obs.codeflow.task33d",
        claim=claim,
        source_revision=typed_revision(SNAPSHOT_PATH),
        query_scope=typed_query_scope(claim),
    )
    request = execution_request(
        claim,
        {"graphify.snapshot": (graphify, SNAPSHOT_PATH), "codeflow.snapshot": (codeflow, SNAPSHOT_PATH)},
    )
    path = tmp_path / "task33d.sqlite3"
    first = execute_verification_plan(request, storage=SQLiteStorage(path))
    replay = execute_verification_plan(request, storage=SQLiteStorage(path))
    assert root_report(first, claim.claim_id).verdict is VerificationVerdict.UNKNOWN
    assert replay.fingerprint == first.fingerprint
    assert replay.session.fingerprint == first.session.fingerprint
