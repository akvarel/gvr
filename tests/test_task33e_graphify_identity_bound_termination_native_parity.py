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
from gvr.code_graph import EvidenceConfidence
from gvr.graphify_contract import validate_graphify_envelope_authority, validate_graphify_positive_traversal

from test_code_graph_execution_tasks_27_30_integrated import (
    SNAPSHOT_PATH,
    execution_request,
    graphify_path_snapshot,
    path_claim,
    root_report,
)
from test_task31_authority_remediation import FULL_RELATIONS, df_edge, path_for, traversal


def _claim(start: str = "A", target: str = "B") -> DataFlowClaim:
    return DataFlowClaim(
        DataFlowClaimKind.CAN_FLOW_TO,
        start,
        target,
        scope=DataFlowQueryScope(effective_allowed_relations=frozenset(FULL_RELATIONS)),
    )


def _identity(*, with_path: bool) -> dict[str, object]:
    result = traversal([path_for()] if with_path else [])
    result.update(start="A", target="A", visited_count=1, expanded_count=0)
    return result


def _truncate(result: dict[str, object], reason: str) -> None:
    result.update(
        truncated=True,
        termination_reason=reason,
        search_coverage="PARTIAL",
        complete_supported_search=False,
    )
    certificate = result.get("completeness_certificate")
    if certificate is not None:
        certificate.update(
            termination_reason=reason,
            search_coverage="PARTIAL",
            complete_supported_search=False,
        )


def _assert_no_exact_or_absence(result: dict[str, object], *, claim: DataFlowClaim | None = None) -> None:
    authority = validate_graphify_envelope_authority(result)
    assert not authority.positive_authorized
    assert not authority.negative_authorized
    graph = ingest_traversal_graph(result)
    assert EvidenceConfidence.EXACT not in tuple(edge.confidence for edge in graph.edges)
    assert graph.absence_subjects == ()
    typed = decode_code_graph_observation_evidence(
        encode_graphify_code_graph_observation_evidence(
            result,
            evidence_id="obs.task33e",
            source_revision=SourceRevisionIdentity("fixture-repo", "rev1"),
            claim_fingerprint="task33e",
        )
    ).graph_model
    assert EvidenceConfidence.EXACT not in tuple(edge.confidence for edge in typed.edges)
    assert typed.absence_subjects == ()
    assert verify_data_flow_claim(claim or _claim(), result).verdict is VerificationVerdict.UNKNOWN


def _assert_exact(result: dict[str, object]) -> None:
    authority = validate_graphify_envelope_authority(result)
    assert authority.positive_authorized
    assert validate_graphify_positive_traversal(result)
    assert set(edge.confidence for edge in ingest_traversal_graph(result).edges) == {EvidenceConfidence.EXACT}
    claim = DataFlowClaim(
        DataFlowClaimKind.CAN_FLOW_TO,
        str(result["start"]),
        str(result["target"]),
        scope=DataFlowQueryScope(
            effective_allowed_relations=frozenset(FULL_RELATIONS),
            stop_nodes=frozenset(result["query_bounds"]["stop_nodes"]),
        ),
    )
    assert verify_data_flow_claim(claim, result).verdict is VerificationVerdict.PASS


def test_task33e_false_complete_identity_absence_is_impossible_on_all_surfaces() -> None:
    _assert_no_exact_or_absence(_identity(with_path=False), claim=_claim("A", "A"))


def test_task33e_real_zero_step_identity_stays_pass_without_self_edge() -> None:
    result = _identity(with_path=True)
    authority = validate_graphify_envelope_authority(result)
    graph = ingest_traversal_graph(result)
    typed = decode_code_graph_observation_evidence(
        encode_graphify_code_graph_observation_evidence(
            result,
            evidence_id="obs.task33e.identity",
            source_revision=SourceRevisionIdentity("fixture-repo", "rev1"),
            claim_fingerprint="task33e-identity",
        )
    ).graph_model
    assert authority.positive_authorized and not authority.negative_authorized
    assert graph.edges == () and graph.absence_subjects == ()
    assert typed.edges == () and typed.absence_subjects == ()
    assert verify_data_flow_claim(_claim("A", "A"), result).verdict is VerificationVerdict.PASS


@pytest.mark.parametrize(
    ("reason", "limit_name", "limit", "actual"),
    [
        ("MAX_EXPANSIONS", "max_expansions", 2, 1),
        ("MAX_PATHS", "max_paths", 2, 1),
    ],
)
def test_task33e_bound_termination_requires_the_named_bound_to_be_reached(
    reason: str, limit_name: str, limit: int, actual: int
) -> None:
    result = traversal([path_for(df_edge())])
    result["query_bounds"][limit_name] = limit
    if reason == "MAX_EXPANSIONS":
        result["expanded_count"] = actual
    _truncate(result, reason)
    _assert_no_exact_or_absence(result)


@pytest.mark.parametrize("reason", ["MAX_EXPANSIONS", "MAX_PATHS"])
def test_task33e_bound_termination_at_named_cap_preserves_exact_witness(reason: str) -> None:
    result = traversal([path_for(df_edge())])
    if reason == "MAX_EXPANSIONS":
        result["query_bounds"]["max_expansions"] = result["expanded_count"]
    else:
        result["query_bounds"]["max_paths"] = len(result["paths"])
    _truncate(result, reason)
    _assert_exact(result)


def test_task33e_complete_exactly_at_both_bounds_remains_valid() -> None:
    result = traversal([path_for(df_edge())])
    result["query_bounds"].update(max_paths=1, max_expansions=1)
    _assert_exact(result)


def test_task33e_start_stop_is_valid_but_interior_stop_crossing_is_not() -> None:
    start_stop = traversal([path_for(df_edge())])
    start_stop["query_bounds"]["stop_nodes"] = ["A"]
    _assert_exact(start_stop)

    interior = traversal([path_for(df_edge("A", "X"), df_edge("X", "B"))])
    interior.update(visited_count=3, expanded_count=2)
    interior["query_bounds"]["stop_nodes"] = ["X"]
    _assert_no_exact_or_absence(interior)


def test_task33e_missing_target_requires_found_start_and_start_missing_keeps_precedence() -> None:
    target_missing = traversal([])
    target_missing.update(
        input_resolution="TARGET_NODE_NOT_FOUND",
        termination_reason="TARGET_NODE_NOT_FOUND",
        visited_count=0,
        expanded_count=0,
        start_node_found=False,
        target_node_found=False,
        search_coverage="UNKNOWN",
        complete_supported_search=False,
    )
    target_missing["completeness_certificate"].update(
        termination_reason="TARGET_NODE_NOT_FOUND",
        search_coverage="UNKNOWN",
        complete_supported_search=False,
    )
    assert not validate_graphify_envelope_authority(target_missing).current_native

    start_missing = deepcopy(target_missing)
    start_missing.update(input_resolution="START_NODE_NOT_FOUND", termination_reason="START_NODE_NOT_FOUND")
    start_missing["completeness_certificate"]["termination_reason"] = "START_NODE_NOT_FOUND"
    authority = validate_graphify_envelope_authority(start_missing)
    assert authority.current_native
    assert not authority.positive_authorized and not authority.negative_authorized


@pytest.mark.parametrize(
    ("case", "mutation"),
    [
        pytest.param("identity-empty", lambda r: r.update(paths=[]), id="identity-empty"),
        pytest.param("max-expansions-below", lambda r: (r["query_bounds"].update(max_expansions=2), _truncate(r, "MAX_EXPANSIONS")), id="max-expansions-below"),
        pytest.param("max-paths-below", lambda r: (r["query_bounds"].update(max_paths=2), _truncate(r, "MAX_PATHS")), id="max-paths-below"),
        pytest.param("interior-stop", lambda r: r["query_bounds"].update(stop_nodes=["X"]), id="interior-stop"),
    ],
)
def test_task33e_table_mutations_never_expose_exact_or_definitive_absence(case: str, mutation) -> None:
    if case == "identity-empty":
        result = _identity(with_path=True)
        mutation(result)
        _assert_no_exact_or_absence(result, claim=_claim("A", "A"))
        return
    if case == "interior-stop":
        result = traversal([path_for(df_edge("A", "X"), df_edge("X", "B"))])
        result.update(visited_count=3, expanded_count=2)
    else:
        result = traversal([path_for(df_edge())])
    mutation(result)
    _assert_no_exact_or_absence(result)


def test_task33e_codeflow_cannot_rescue_malformed_graphify_and_sqlite_replay_is_stable(tmp_path) -> None:
    from gvr import SQLiteStorage, execute_verification_plan
    from test_code_graph_execution_tasks_27_30_integrated import (
        codeflow_path_snapshot,
        encode_codeflow_code_graph_observation_evidence,
        typed_query_scope,
        typed_revision,
    )

    claim = path_claim("task33e-replay")
    malformed = deepcopy(graphify_path_snapshot())
    malformed["query_bounds"]["max_expansions"] = malformed["expanded_count"] + 1
    _truncate(malformed, "MAX_EXPANSIONS")
    graphify = encode_graphify_code_graph_observation_evidence(
        malformed,
        evidence_id="obs.graphify.task33e",
        claim=claim,
        source_revision=typed_revision(SNAPSHOT_PATH),
    )
    assert EvidenceConfidence.EXACT not in tuple(
        edge.confidence for edge in decode_code_graph_observation_evidence(graphify).graph_model.edges
    )
    codeflow = encode_codeflow_code_graph_observation_evidence(
        codeflow_path_snapshot(),
        evidence_id="obs.codeflow.task33e",
        claim=claim,
        source_revision=typed_revision(SNAPSHOT_PATH),
        query_scope=typed_query_scope(claim),
    )
    request = execution_request(
        claim,
        {"graphify.snapshot": (graphify, SNAPSHOT_PATH), "codeflow.snapshot": (codeflow, SNAPSHOT_PATH)},
    )
    path = tmp_path / "task33e.sqlite3"
    first = execute_verification_plan(request, storage=SQLiteStorage(path))
    replay = execute_verification_plan(request, storage=SQLiteStorage(path))
    assert root_report(first, claim.claim_id).verdict is VerificationVerdict.UNKNOWN
    assert replay.fingerprint == first.fingerprint
    assert replay.session.fingerprint == first.session.fingerprint
