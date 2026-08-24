from __future__ import annotations

from copy import deepcopy

import pytest

from gvr import (
    DataFlowClaim,
    DataFlowClaimKind,
    DataFlowQueryScope,
    SourceRevisionIdentity,
    SQLiteStorage,
    VerificationVerdict,
    decode_code_graph_observation_evidence,
    encode_graphify_code_graph_observation_evidence,
    execute_verification_plan,
    verify_data_flow_claim,
)
from gvr.adapters.graphify import ingest_traversal_graph
from gvr.code_graph import EvidenceConfidence, GraphEvidenceModelError

from test_task31_authority_remediation import FULL_RELATIONS, df_edge, path_for, traversal
from test_task32b_provider_adapter_typed_authority import codeflow_result, codeflow_scope
from test_code_graph_execution_tasks_27_30_integrated import (
    SNAPSHOT_PATH,
    execution_request,
    path_claim as code_graph_path_claim,
    root_report,
)
from gvr import encode_codeflow_code_graph_observation_evidence


def claim(*, revision: str = "rev1", relations=FULL_RELATIONS) -> DataFlowClaim:
    from gvr.verifiers.data_flow import SourceRevision

    return DataFlowClaim(
        kind=DataFlowClaimKind.CAN_FLOW_TO,
        start="A",
        target="B",
        scope=DataFlowQueryScope(effective_allowed_relations=frozenset(relations)),
        evidence_namespace="task33",
        source_revision=SourceRevision(repository="fixture-repo", revision=revision),
    )


def assert_positive_rejected(result: dict[str, object]) -> None:
    report = verify_data_flow_claim(claim(), result)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert {issue.code for issue in report.issues} & {
        "MALFORMED_PATH",
        "CONTRADICTORY_TRAVERSAL",
        "INVALID_EVIDENCE_KEY",
        "EVIDENCE_CONFIDENCE_CONTRADICTION",
    }
    with pytest.raises(GraphEvidenceModelError):
        ingest_traversal_graph(result)
    with pytest.raises(GraphEvidenceModelError):
        encode_graphify_code_graph_observation_evidence(
            result,
            evidence_id="obs.task33.invalid",
            source_revision=SourceRevisionIdentity("fixture-repo", "rev1"),
            claim_fingerprint="task33",
        )


def assert_positive_downgraded(result: dict[str, object]) -> None:
    report = verify_data_flow_claim(claim(), result)
    assert report.verdict is VerificationVerdict.UNKNOWN
    graph = ingest_traversal_graph(result)
    assert graph.edges
    assert all(edge.confidence is EvidenceConfidence.HEURISTIC for edge in graph.edges)
    decoded = decode_code_graph_observation_evidence(
        encode_graphify_code_graph_observation_evidence(
            result,
            evidence_id="obs.task33.downgraded",
            source_revision=SourceRevisionIdentity("fixture-repo", "rev1"),
            claim_fingerprint="task33",
        )
    )
    assert all(edge.confidence is EvidenceConfidence.HEURISTIC for edge in decoded.graph_model.edges)


def test_task33_positive_authority_rejects_disconnected_or_endpoint_rebound_paths_everywhere() -> None:
    ab = df_edge("A", "B")
    disconnected = path_for(ab, df_edge("X", "B", location="X->B"))
    endpoint_rebound = path_for(df_edge("X", "B", location="X->B"))

    assert_positive_rejected(traversal([disconnected]))
    assert_positive_downgraded(traversal([endpoint_rebound]))


def test_task33_positive_authority_rejects_step_evidence_identity_and_query_relation_rebinding_everywhere() -> None:
    ab = df_edge("A", "B")
    result = traversal([path_for(ab)])
    rebound = deepcopy(result)
    rebound["paths"][0]["steps"][0]["target"] = "C"
    assert_positive_rejected(rebound)

    rebound = deepcopy(result)
    rebound["paths"][0]["steps"][0]["evidence"] = df_edge("A", "C", location="A->C")
    assert_positive_rejected(rebound)

    rebound = deepcopy(result)
    rebound["paths"][0]["path_identity"] = [df_edge("A", "C", location="A->C")["key"]]
    assert_positive_rejected(rebound)

    narrowed = traversal([path_for(ab)], allowed_relations=("READ_FROM",))
    assert_positive_downgraded(narrowed)


def test_task33_positive_authority_rejects_confidence_completeness_and_bound_upgrades_everywhere() -> None:
    may = df_edge("A", "B")
    may["receiver_confidence"] = "MAY"
    may["key"] = __import__("gvr.graphify_contract", fromlist=["expected_graphify_df_key"]).expected_graphify_df_key(may)
    may_result = traversal([path_for(may)])
    assert verify_data_flow_claim(claim(), may_result).verdict is VerificationVerdict.UNKNOWN
    assert all(edge.confidence is EvidenceConfidence.HEURISTIC for edge in ingest_traversal_graph(may_result).edges)

    too_deep = traversal([path_for(df_edge("A", "B"))])
    too_deep["query_bounds"]["max_depth"] = 0
    assert_positive_rejected(too_deep)


@pytest.mark.parametrize(
    "overrides",
    [
        {"query_validity": False},
        {"input_resolution": "START_NODE_NOT_FOUND", "start_node_found": False},
        {"input_resolution": "TARGET_NODE_NOT_FOUND", "target_node_found": False},
        {"direction": "BACKWARD"},
        {"truncated": True, "termination_reason": "COMPLETE"},
        {
            "boundary_events": [
                {
                    "boundary_evidence_key": "bnd:task33",
                    "resolution": "UNSUPPORTED",
                    "canonical_caller_file": "src/Flow.java",
                }
            ]
        },
        {"encountered_unknown_evidence": True},
    ],
)
def test_task33_query_level_failures_cannot_authorize_exact_positive_edges(overrides) -> None:
    result = traversal([path_for(df_edge("A", "B"))])
    result.update(overrides)
    assert_positive_downgraded(result)


def test_task33_valid_exact_typed_positive_witness_is_decisive() -> None:
    result = traversal([path_for(df_edge("A", "B"))])
    report = verify_data_flow_claim(claim(), result)
    assert report.verdict is VerificationVerdict.PASS
    graph = ingest_traversal_graph(result)
    assert graph.edges
    assert all(edge.confidence is EvidenceConfidence.EXACT for edge in graph.edges)


def test_task33_negative_authority_preservation_keeps_complete_absence_and_incomplete_unknown() -> None:
    complete = traversal([])
    complete["visited_count"] = 1
    assert verify_data_flow_claim(claim(), complete).verdict is VerificationVerdict.FAIL
    assert ingest_traversal_graph(complete).absence_subjects

    incomplete = traversal([])
    incomplete.update(
        complete_supported_search=False,
        search_coverage="PARTIAL",
        truncated=True,
        termination_reason="MAX_DEPTH",
    )
    assert verify_data_flow_claim(claim(), incomplete).verdict is VerificationVerdict.UNKNOWN
    assert ingest_traversal_graph(incomplete).absence_subjects == ()


def test_task33_positive_typed_authority_keeps_source_advancement_distinct_from_scope() -> None:
    result = traversal([path_for(df_edge("A", "B"))])
    first = decode_code_graph_observation_evidence(
        encode_graphify_code_graph_observation_evidence(
            result,
            evidence_id="obs.task33.rev1",
            source_revision=SourceRevisionIdentity("fixture-repo", "rev1"),
            claim_fingerprint="task33",
        )
    )
    advanced_result = deepcopy(result)
    advanced_result["source_revision"]["revision"] = "rev2"
    second = decode_code_graph_observation_evidence(
        encode_graphify_code_graph_observation_evidence(
            advanced_result,
            evidence_id="obs.task33.rev2",
            source_revision=SourceRevisionIdentity("fixture-repo", "rev2"),
            claim_fingerprint="task33",
        )
    )
    assert first.source_revision != second.source_revision
    assert first.query_scope == second.query_scope

    narrowed = traversal([path_for(df_edge("A", "B"))], allowed_relations=("FLOWS_TO",))
    scoped = decode_code_graph_observation_evidence(
        encode_graphify_code_graph_observation_evidence(
            narrowed,
            evidence_id="obs.task33.scope",
            source_revision=SourceRevisionIdentity("fixture-repo", "rev1"),
            claim_fingerprint="task33",
        )
    )
    assert scoped.source_revision == first.source_revision
    assert scoped.query_scope != first.query_scope


def test_task33_downgraded_positive_authority_runs_real_executor_and_replays_from_sqlite(tmp_path) -> None:
    rebound = traversal([path_for(df_edge("X", "B", location="X->B"))])
    rebound["evidence_namespace"] = "integrated-27-30"
    claim_value = code_graph_path_claim("task33-sqlite")
    observation = encode_graphify_code_graph_observation_evidence(
        rebound,
        evidence_id="obs.task33.sqlite",
        claim=claim_value,
        source_revision=SourceRevisionIdentity("fixture-repo", "rev1"),
    )
    assert all(
        edge.confidence is EvidenceConfidence.HEURISTIC
        for edge in decode_code_graph_observation_evidence(observation).graph_model.edges
    )
    codeflow_observation = encode_codeflow_code_graph_observation_evidence(
        codeflow_result(),
        evidence_id="obs.task33.sqlite.codeflow",
        claim=claim_value,
        source_revision=SourceRevisionIdentity("fixture-repo", "rev-1"),
        query_scope=codeflow_scope(),
    )
    request = execution_request(
        claim_value,
        {
            "graphify.snapshot": (observation, SNAPSHOT_PATH),
            "codeflow.snapshot": (codeflow_observation, SNAPSHOT_PATH),
        },
    )
    database = tmp_path / "task33.sqlite3"

    first = execute_verification_plan(request, storage=SQLiteStorage(database))
    assert root_report(first, claim_value.claim_id).verdict is VerificationVerdict.UNKNOWN
    replay = execute_verification_plan(request, storage=SQLiteStorage(database))
    assert replay.fingerprint == first.fingerprint
    assert root_report(replay, claim_value.claim_id).verdict is VerificationVerdict.UNKNOWN


def test_task33_real_codeflow_typed_path_remains_heuristic_and_cannot_upgrade() -> None:
    decoded = decode_code_graph_observation_evidence(
        encode_codeflow_code_graph_observation_evidence(
            codeflow_result(),
            evidence_id="obs.task33.codeflow",
            source_revision=SourceRevisionIdentity("fixture-repo", "rev-1"),
            query_scope=codeflow_scope(),
            claim_fingerprint="task33",
        )
    )
    assert decoded.graph_model.edges
    assert all(edge.confidence is EvidenceConfidence.HEURISTIC for edge in decoded.graph_model.edges)
