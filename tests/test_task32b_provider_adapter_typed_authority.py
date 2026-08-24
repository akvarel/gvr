from __future__ import annotations

import inspect
from dataclasses import replace
from pathlib import Path

import pytest

from gvr import (
    CoverageCertificate,
    GraphQueryScope,
    SourceRevisionIdentity,
    SQLiteStorage,
    VerificationVerdict,
    decode_code_graph_observation_evidence,
    encode_codeflow_code_graph_observation_evidence,
    encode_graphify_code_graph_observation_evidence,
    execute_verification_plan,
)
from gvr.adapters import codeflow as codeflow_adapter
from gvr.adapters import graphify as graphify_adapter
from gvr.code_graph import EvidenceConfidence, GraphEvidenceModelError

from test_code_graph_execution_tasks_27_30_integrated import (
    SNAPSHOT_PATH,
    execution_request,
    path_claim,
    root_report,
)


REVISION = SourceRevisionIdentity(repository="fixture-repo", revision="rev-1")


def graphify_result(*, reordered: bool = False) -> dict[str, object]:
    requested = ["READ_FROM", "FLOWS_TO"]
    effective = ["FLOWS_TO", "READ_FROM"]
    rejected = ["UNSUPPORTED_B", "UNSUPPORTED_A"]
    stop_nodes = ["Z", "Y"]
    if reordered:
        requested.reverse()
        effective.reverse()
        rejected.reverse()
        stop_nodes.reverse()
    return {
        "start": "A",
        "target": "B",
        "direction": "FORWARD",
        "evidence_namespace": "integrated-27-30",
        "termination_reason": "COMPLETE",
        "search_coverage": "COMPLETE_FOR_SUPPORTED_CONSTRUCT",
        "complete_supported_search": True,
        "query_validity": True,
        "input_resolution": "RESOLVED",
        "start_node_found": True,
        "target_node_found": True,
        "truncated": False,
        "encountered_partial_evidence": False,
        "encountered_may_evidence": False,
        "encountered_unknown_evidence": False,
        "query_bounds": {
            "requested_relations": requested,
            "effective_allowed_relations": effective,
            "rejected_relations": rejected,
            "stop_nodes": stop_nodes,
            "max_depth": 4,
            "max_paths": 8,
            "max_expansions": 64,
        },
        "paths": [],
        "boundary_events": [],
    }


def codeflow_result() -> dict[str, object]:
    return {
        "source_revision": REVISION.to_dict(),
        "query_scope": codeflow_scope().to_dict(),
        "nodes": [
            {
                "id": "A",
                "kind": "node",
                "label": "A",
                "semantic_identity": {"id": "A"},
                "exact_identity": {"id": "A"},
            }
        ],
        "edges": [
            {
                "id": "cf:A:B",
                "kind": "call",
                "source": "A",
                "target": "B",
                "semantic_identity": {"source": "A", "target": "B", "relation": "CALL"},
                "exact_identity": {"source": "A", "target": "B", "relation": "CALL"},
            }
        ],
    }


def codeflow_scope() -> GraphQueryScope:
    return GraphQueryScope(
        start="A",
        target="B",
        direction="FORWARD",
        requested_relations=frozenset({"CALL"}),
        effective_relations=frozenset({"CALL"}),
        rejected_relations=frozenset(),
        max_depth=3,
        max_paths=4,
        max_expansions=40,
        stop_nodes=frozenset(),
        evidence_namespace="codeflow-native",
    )


def test_task32b_graphify_rejects_scope_bearing_legacy_snapshot_and_decodes_native_typed_authority() -> None:
    with pytest.raises(GraphEvidenceModelError, match="scope-bearing legacy source_snapshot"):
        encode_graphify_code_graph_observation_evidence(
            graphify_result(),
            evidence_id="obs.graphify.rebind",
            source_revision=REVISION,
            source_snapshot={**SNAPSHOT_PATH, "start": "B", "target": "C", "query_bounds": {"max_depth": 99}},
        )

    decoded = decode_code_graph_observation_evidence(
        encode_graphify_code_graph_observation_evidence(
            graphify_result(), evidence_id="obs.graphify.typed", source_revision=REVISION
        )
    )
    assert decoded.graph_model._typed_authority is True
    assert decoded.source_revision == REVISION
    assert decoded.query_scope.to_dict() == {
        "start": "graphify:node:A",
        "target": "graphify:node:B",
        "direction": "FORWARD",
        "requested_relations": ("FLOWS_TO", "READ_FROM"),
        "effective_relations": ("FLOWS_TO", "READ_FROM"),
        "rejected_relations": ("UNSUPPORTED_A", "UNSUPPORTED_B"),
        "max_depth": 4,
        "max_paths": 8,
        "max_expansions": 64,
        "stop_nodes": ("graphify:node:Y", "graphify:node:Z"),
        "evidence_namespace": "integrated-27-30",
    }


def test_task32b_graphify_coverage_preserves_native_negative_authority_state() -> None:
    decoded = decode_code_graph_observation_evidence(
        encode_graphify_code_graph_observation_evidence(
            graphify_result(), evidence_id="obs.graphify.coverage", source_revision=REVISION
        )
    )
    assert decoded.coverage == CoverageCertificate(
        coverage="COMPLETE_FOR_SUPPORTED_CONSTRUCT",
        complete_supported_search=True,
        termination_reason="COMPLETE",
        truncated=False,
        details={
            "query_validity": True,
            "input_resolution": "RESOLVED",
            "start_node_found": True,
            "target_node_found": True,
            "encountered_partial_evidence": False,
            "encountered_may_evidence": False,
            "encountered_unknown_evidence": False,
            "blocking_boundary_keys": (),
        },
    )


def test_task32b_codeflow_revision_rebinding_fails_closed_and_output_remains_heuristic_typed_authority() -> None:
    with pytest.raises(GraphEvidenceModelError, match="source revision conflict"):
        encode_codeflow_code_graph_observation_evidence(
            codeflow_result(),
            evidence_id="obs.codeflow.rebind",
            source_revision=replace(REVISION, revision="rev-2"),
            query_scope=codeflow_scope(),
        )

    decoded = decode_code_graph_observation_evidence(
        encode_codeflow_code_graph_observation_evidence(
            codeflow_result(),
            evidence_id="obs.codeflow.typed",
            source_revision=REVISION,
            query_scope=codeflow_scope(),
        )
    )
    assert decoded.graph_model._typed_authority is True
    assert decoded.coverage.proves_complete_search is False
    assert {item.confidence for item in decoded.graph_model.evidence} <= {
        EvidenceConfidence.HEURISTIC,
        EvidenceConfidence.INFERRED_HINT,
    }


def test_task32b_built_in_authoritative_paths_do_not_construct_legacy_authority() -> None:
    assert "_typed_authority=False" not in inspect.getsource(graphify_adapter.encode_graphify_code_graph_observation_evidence)
    assert "_typed_authority=False" not in inspect.getsource(codeflow_adapter.encode_codeflow_code_graph_observation_evidence)


def test_task32b_query_scope_sets_and_bounds_are_distinct_canonical_authorities() -> None:
    base = codeflow_scope()
    assert base.requested_relations != frozenset({"REFERENCE"})
    assert replace(base, requested_relations=frozenset({"REFERENCE"})) != base
    assert replace(base, effective_relations=frozenset({"REFERENCE"})) != base
    assert replace(base, rejected_relations=frozenset({"REFERENCE"})) != base
    assert replace(base, max_paths=5) != base
    assert replace(base, max_expansions=41) != base
    assert replace(base, max_depth=4) != base


def test_task32b_set_reordering_is_fingerprint_invariant_and_scope_revision_changes_are_independent() -> None:
    first = decode_code_graph_observation_evidence(
        encode_graphify_code_graph_observation_evidence(
            graphify_result(), evidence_id="obs.graphify.first", source_revision=REVISION
        )
    ).graph_model
    reordered = decode_code_graph_observation_evidence(
        encode_graphify_code_graph_observation_evidence(
            graphify_result(reordered=True), evidence_id="obs.graphify.reordered", source_revision=REVISION
        )
    ).graph_model
    assert first.fingerprint == reordered.fingerprint
    assert replace(first, query_scope=replace(first.query_scope, max_paths=9)).fingerprint != first.fingerprint
    assert replace(first, source_revision=replace(REVISION, revision="rev-2")).fingerprint != first.fingerprint


def test_task32b_sqlite_execution_enforces_scope_mismatch_unknown_and_replays_exact_typed_observation(tmp_path: Path) -> None:
    native = graphify_result()
    native["query_bounds"] = {
        "requested_relations": ["FLOWS_TO"],
        "effective_allowed_relations": ["FLOWS_TO"],
        "rejected_relations": [],
    }
    claim = path_claim("task32b-sqlite")
    observation = encode_graphify_code_graph_observation_evidence(
        native,
        evidence_id="obs.graphify.sqlite",
        claim=claim,
        source_revision=REVISION,
    )
    decoded_before = decode_code_graph_observation_evidence(observation)
    request = execution_request(claim, {"graphify.snapshot": (observation, SNAPSHOT_PATH)})
    db = tmp_path / "task32b.sqlite3"

    first_storage = SQLiteStorage(db)
    first = execute_verification_plan(request, storage=first_storage)
    assert root_report(first, claim.claim_id).verdict is VerificationVerdict.UNKNOWN
    assert "GRAPH_QUERY_SCOPE_MISMATCH" in {issue.code for issue in root_report(first, claim.claim_id).issues}
    del first_storage

    reopened = SQLiteStorage(db)
    replay = execute_verification_plan(request, storage=reopened)
    assert replay.fingerprint == first.fingerprint
    decoded_after = decode_code_graph_observation_evidence(observation)
    assert decoded_after.graph_model == decoded_before.graph_model
    assert decoded_after.graph_model_fingerprint == decoded_before.graph_model_fingerprint
