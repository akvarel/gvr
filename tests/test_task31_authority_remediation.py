from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from gvr import (
    DataFlowClaim,
    DataFlowClaimKind,
    DataFlowQueryScope,
    VerificationVerdict,
    encode_codeflow_code_graph_observation_evidence,
    encode_graphify_code_graph_observation_evidence,
    ingest_codeflow_graph,
    verify_data_flow_claim,
)
from gvr.code_graph import GraphEvidenceModelError
from gvr.graphify_contract import expected_graphify_df_key, validate_graphify_df_evidence
from gvr.verifiers.corroboration import ProviderVerificationObservation, reconcile_provider_observations
from gvr.model import VerificationIssue, VerificationReport
from gvr.verifiers.data_flow import SourceRevision


FIXTURE = Path(__file__).parent / "fixtures" / "codeflow_262206cb_golden_world.json"
COMPLETE = "COMPLETE_FOR_SUPPORTED_CONSTRUCT"
FULL_RELATIONS = (
    "FLOWS_TO",
    "PASSED_AS_ARGUMENT",
    "READ_FROM",
    "RETURNED_AS",
    "TRANSFORMED_BY",
    "WRITTEN_TO",
)


def df_edge(source="A", target="B", *, relation="FLOWS_TO", location="A->B"):
    item = {
        "relation": relation,
        "source": source,
        "target": target,
        "source_file": "src/Flow.java",
        "source_location": location,
        "provenance": "STATIC_AST",
        "confidence_score": 1.0,
        "argument_index": None,
        "receiver_confidence": "PROVEN",
        "analysis_completeness": COMPLETE,
    }
    item["key"] = expected_graphify_df_key(item)
    return item


def path_for(*items):
    return {
        "steps": [
            {"source": item["source"], "target": item["target"], "relation": item["relation"], "evidence": deepcopy(item)}
            for item in items
        ],
        "supporting_evidence": [deepcopy(item) for item in items],
        "path_identity": [item["key"] for item in items],
        "path_exactness": "EXACT_FOR_RETURNED_PATH",
        "path_receiver_confidence": "PROVEN",
        "path_coverage": COMPLETE,
    }


def traversal(paths, *, source_revision="rev1", allowed_relations=FULL_RELATIONS):
    return {
        "paths": deepcopy(paths),
        "start": "A",
        "target": "B",
        "direction": "FORWARD",
        "visited_count": 2,
        "expanded_count": 1 if paths else 0,
        "truncated": False,
        "termination_reason": "COMPLETE",
        "query_bounds": {
            "direction": "FORWARD",
            "max_depth": 4,
            "max_paths": 50,
            "max_expansions": 2000,
            "requested_allowed_relations": list(allowed_relations),
            "effective_allowed_relations": list(allowed_relations),
            "rejected_relations": [],
            "stop_nodes": [],
        },
        "boundary_events": [],
        "search_coverage": COMPLETE,
        "complete_supported_search": True,
        "completeness_certificate": {
            "schema_version": 1,
            "search_coverage": COMPLETE,
            "complete_supported_search": True,
            "termination_reason": "COMPLETE",
        },
        "source_revision": {"repository": "fixture-repo", "revision": source_revision},
        "start_node_found": True,
        "target_node_found": True,
        "query_validity": True,
        "input_resolution": "RESOLVED",
        "rejected_relations": [],
        "encountered_partial_evidence": False,
        "encountered_unknown_evidence": False,
        "encountered_may_evidence": False,
    }


def provider_report(verdict, code, evidence_ids=()):
    return VerificationReport(
        verdict=verdict,
        verifier="manual",
        issues=(VerificationIssue(code, code, verdict, tuple(evidence_ids)),),
        evidence_ids=tuple(evidence_ids),
    )


def provider_obs(provider, impl, family, verdict, code):
    return ProviderVerificationObservation(
        provider_id=provider,
        implementation_id=impl,
        family_id=family,
        source_snapshot={"rev": "1"},
        claim_fingerprint="claim",
        report=provider_report(verdict, code, (provider,)),
    )


def test_task31_codeflow_ingests_real_pinned_schema_data_snapshot_fixture():
    payload = json.loads(FIXTURE.read_text())
    assert set(payload) == {"schemaVersion", "data", "snapshot"}
    assert payload["schemaVersion"] == 1
    assert payload["data"]["stats"] == {
        **payload["data"]["stats"],
        "files": 6,
        "functions": 7,
        "connections": 6,
    }

    graph = ingest_codeflow_graph(payload)

    assert graph.provider == "codeflow"
    assert graph.source_snapshot["schemaVersion"] == 1
    assert graph.source_snapshot["snapshot"]["files"] == 6
    assert graph.source_snapshot["snapshot"]["functions"] == 7
    assert len(graph.nodes) >= 13
    assert len(graph.edges) >= 6
    assert any(node.id == "codeflow:file:src/app.js" for node in graph.nodes)
    assert any(node.id.startswith("codeflow:function:src/math.js|") for node in graph.nodes)
    assert any(edge.exact_identity.get("functionKey") == "src/math.js|1|add" for edge in graph.edges)


def test_task31_graphify_df_validator_is_shared_and_content_addressed():
    good = df_edge("A", "B")
    assert validate_graphify_df_evidence(good) == good["key"]

    tampered = dict(good, target="C")
    with pytest.raises(GraphEvidenceModelError, match="content-addressed"):
        validate_graphify_df_evidence(tampered)

    result = traversal([path_for(tampered)])
    report = verify_data_flow_claim(
        DataFlowClaim(DataFlowClaimKind.CAN_FLOW_TO, "A", "C"),
        result,
    )
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "INVALID_EVIDENCE_KEY" in {issue.code for issue in report.issues}


def test_task31_data_flow_report_keeps_query_path_revision_scope_and_completeness_authority_separate():
    edge = df_edge("A", "B")
    claim = DataFlowClaim(
        DataFlowClaimKind.CAN_FLOW_TO,
        "A",
        "B",
        scope=DataFlowQueryScope(direction="FORWARD", effective_allowed_relations=frozenset(FULL_RELATIONS)),
        evidence_namespace="authority",
        source_revision=SourceRevision(repository="fixture-repo", revision="rev1"),
    )

    report = verify_data_flow_claim(claim, traversal([path_for(edge)]))

    assert report.verdict is VerificationVerdict.PASS
    assert edge["key"] in report.evidence_ids
    assert report.metadata["query_evidence_id"] in report.evidence_ids
    assert report.metadata["source_revision"] == {"repository": "fixture-repo", "revision": "rev1"}
    assert report.metadata["query_semantic_scope"] == report.metadata["claim_scope"]
    assert report.metadata["completeness_certificate"]["complete_supported_search"] is True
    assert "source_revision" not in report.metadata["query_semantic_scope"]


def test_task31_adapter_sealed_provider_families_cannot_be_rebound_by_callers():
    payload = json.loads(FIXTURE.read_text())
    with pytest.raises(ValueError, match="provider family is adapter-sealed"):
        encode_codeflow_code_graph_observation_evidence(
            payload,
            evidence_id="obs.codeflow.forged-family",
            claim_fingerprint="claim",
            family_id="looks-independent",
        )
    with pytest.raises(ValueError, match="provider family is adapter-sealed"):
        encode_graphify_code_graph_observation_evidence(
            traversal([]),
            evidence_id="obs.graphify.forged-family",
            claim_fingerprint="claim",
            family_id="looks-independent",
        )


def test_task31_same_family_pass_fail_is_family_contradiction_not_independent_conflict():
    report = reconcile_provider_observations([
        provider_obs("wrapper-pass", "graphify-cli", "graphify", VerificationVerdict.PASS, "PROVEN_PATH"),
        provider_obs("wrapper-fail", "graphify-wrapper", "graphify", VerificationVerdict.FAIL, "PROVEN_ABSENCE"),
    ])

    codes = {issue.code for issue in report.issues}
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "PROVIDER_FAMILY_CONTRADICTION" in codes
    assert "PROVIDER_CONFLICT" not in codes
    assert "PROVIDER_CORROBORATED_PASS" not in codes
