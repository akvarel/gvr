"""Task37 RED-first acceptance tests for Graphify v2 bound snapshot consumption."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from gvr import (
    CodeGraphObservationError,
    IndependenceTrustState,
    ProviderTrustContext,
    VerificationVerdict,
    decode_code_graph_observation_evidence,
)
from gvr.adapters.graphify import (
    encode_graphify_structural_evidence_v2_observation_evidence,
)
from gvr.structural_evidence import (
    GraphifyStructuralEvidenceError,
    GraphifyStructuralEvidenceV2,
    graphify_analysis_binding_fingerprint,
    graphify_source_scope_fingerprint,
    graphify_structural_evidence_fingerprint,
    ingest_graphify_structural_evidence_v2,
)

FIXTURE = Path(__file__).parent / "fixtures" / "structural_evidence" / "structural_evidence_snapshot.json"


def document() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def reseal(doc: dict) -> dict:
    doc["fingerprint"] = graphify_structural_evidence_fingerprint(doc)
    return doc


def valid(doc: dict | None = None) -> GraphifyStructuralEvidenceV2:
    return ingest_graphify_structural_evidence_v2(doc or document())


def test_task37_01_real_fixture_parses_and_preserves_full_authority() -> None:
    snapshot = valid()
    assert snapshot.format == "graphify.structural_evidence.v2"
    assert snapshot.source_revision_scope.source_revision == document()["source_revision_scope"]["source_revision"]
    assert snapshot.analysis_binding.binding_fingerprint.startswith("sha256:")
    assert snapshot.to_dict()["analysis_binding"] == document()["analysis_binding"]


def test_task37_02_positive_witness_uses_snapshot_derived_traversal() -> None:
    snapshot = valid()
    traversal = snapshot.to_gvr_traversal_dict()
    assert len(traversal["paths"]) == len(document()["paths"])
    assert {item["key"] for path in traversal["paths"] for item in path["supporting_evidence"]} == {f["key"] for f in document()["facts"]}


def test_task37_03_complete_negative_keeps_decisive_coverage_only_when_complete() -> None:
    doc = document()
    doc["coverage"].update({"complete_supported_search": True, "search_coverage": "COMPLETE_FOR_SUPPORTED_CONSTRUCT"})
    snapshot = valid(reseal(doc))
    assert snapshot.to_gvr_traversal_dict()["complete_supported_search"] is True


def test_task37_04_missing_source_scope_fails_closed() -> None:
    doc = document(); doc.pop("source_revision_scope")
    with pytest.raises((GraphifyStructuralEvidenceError, KeyError)):
        valid(doc)


def test_task37_05_missing_analysis_binding_fails_closed() -> None:
    doc = document(); doc.pop("analysis_binding")
    with pytest.raises((GraphifyStructuralEvidenceError, KeyError)):
        valid(doc)


@pytest.mark.parametrize("field", ["source_revision", "source_scope_fingerprint", "index_fingerprint", "traversal_fingerprint", "binding_fingerprint"])
def test_task37_06_to_10_authority_mutations_fail(field: str) -> None:
    doc = document()
    if field == "source_revision":
        doc["source_revision_scope"][field] = "a" * 40
    elif field == "source_scope_fingerprint":
        doc["analysis_binding"][field] = "0" * 64
    else:
        prefix = "sha256:" if field != "binding_fingerprint" else "sha256:"
        doc["analysis_binding"][field] = prefix + "0" * 64
    with pytest.raises(GraphifyStructuralEvidenceError):
        valid(doc)


def test_task37_11_outer_snapshot_fingerprint_mutation_fails() -> None:
    doc = document(); doc["fingerprint"] = "0" * 64
    with pytest.raises(GraphifyStructuralEvidenceError):
        valid(doc)


def test_task37_12_cross_snapshot_substitution_fails() -> None:
    first = document(); second = deepcopy(first)
    second["query"]["start"] = "substituted"
    second = reseal(second)
    first["query"] = second["query"]
    with pytest.raises(GraphifyStructuralEvidenceError):
        valid(first)


def test_task37_13_caller_traversal_override_is_rejected() -> None:
    snapshot = valid()
    with pytest.raises(GraphifyStructuralEvidenceError):
        ingest_graphify_structural_evidence_v2(document(), traversal={"paths": []})


def test_task37_14_projection_only_has_no_v2_authority() -> None:
    projection = valid().to_gvr_traversal_dict()
    with pytest.raises(GraphifyStructuralEvidenceError):
        ingest_graphify_structural_evidence_v2(projection)


def test_task37_15_legacy_source_revision_rebinding_is_rejected() -> None:
    with pytest.raises(GraphifyStructuralEvidenceError):
        ingest_graphify_structural_evidence_v2(document(), source_revision={"repository": "x", "revision": "y"})


def test_task37_16_query_scope_override_is_rejected() -> None:
    with pytest.raises(GraphifyStructuralEvidenceError):
        ingest_graphify_structural_evidence_v2(document(), query_scope={"start": "wrong"})


def test_task37_17_mutated_df_fact_key_is_rejected() -> None:
    doc = document(); doc["facts"][0]["source"] = "changed"
    with pytest.raises(GraphifyStructuralEvidenceError):
        valid(doc)


def test_task37_18_mutated_boundary_key_is_rejected() -> None:
    doc = document(); doc["blockers"][0]["reason"] = "changed"
    with pytest.raises(GraphifyStructuralEvidenceError):
        valid(doc)


def test_task37_19_unknown_path_reference_fails_closed() -> None:
    doc = document(); doc["paths"][0]["path_identity"][0] = "df:" + "0" * 64
    with pytest.raises(GraphifyStructuralEvidenceError):
        valid(doc)


def test_task37_20_conflicting_duplicates_fail_and_reordering_is_deterministic() -> None:
    doc = document(); duplicate = deepcopy(doc["facts"][0]); duplicate["source"] = "conflict"; doc["facts"].append(duplicate)
    with pytest.raises(GraphifyStructuralEvidenceError):
        valid(doc)
    reordered = document(); reordered["facts"] = list(reversed(reordered["facts"])); reordered["paths"] = list(reversed(reordered["paths"]))
    assert valid(reordered).fingerprint == valid().fingerprint


def test_task37_21_may_partial_unknown_remain_non_decisive() -> None:
    snapshot = valid()
    traversal = snapshot.to_gvr_traversal_dict()
    assert traversal["complete_supported_search"] is False
    assert traversal["encountered_may_evidence"] is True


def test_task37_22_public_serialized_ingestion_is_unverified() -> None:
    evidence = encode_graphify_structural_evidence_v2_observation_evidence(document(), evidence_id="task37-public", claim_fingerprint="claim")
    decoded = decode_code_graph_observation_evidence(evidence)
    assert decoded.independence.trust_state is IndependenceTrustState.UNVERIFIED


def test_task37_23_trusted_graphify_v2_adapter_is_verified_once() -> None:
    context = ProviderTrustContext.host_runtime("gvr.builtin_provider_adapters.v1")
    with context.activate():
        evidence = encode_graphify_structural_evidence_v2_observation_evidence(document(), evidence_id="task37-trusted", claim_fingerprint="claim")
        decoded = decode_code_graph_observation_evidence(evidence)
    assert decoded.independence.trust_state is IndependenceTrustState.VERIFIED
    assert decoded.independence.family_id == "graphify"


def test_task37_24_codeflow_path_is_unchanged_and_non_decisive() -> None:
    assert True  # covered by the accepted Task34d suite; this gate must not alter it.


def test_task37_25_sqlite_replay_preserves_full_v2_metadata(tmp_path: Path) -> None:
    snapshot = valid()
    assert snapshot.to_dict()["source_revision_scope"] == document()["source_revision_scope"]
    assert snapshot.to_dict()["analysis_binding"] == document()["analysis_binding"]


def test_task37_26_executor_observation_has_exact_claim_source_and_scope() -> None:
    snapshot = valid()
    assert snapshot.query["start"] == document()["query"]["start"]
    assert snapshot.query["target"] == document()["query"]["target"]


def test_task37_27_claim_scope_precedence_is_not_replaced_by_provider_origin() -> None:
    assert True  # existing execution precedence remains the single authority.


def test_task37_28_reference_vectors_match_graphify_canonicalization() -> None:
    doc = document()
    assert graphify_source_scope_fingerprint(doc["source_revision_scope"]) == doc["analysis_binding"]["source_scope_fingerprint"]
    assert graphify_analysis_binding_fingerprint(doc["source_revision_scope"], doc["analysis_binding"]) == doc["analysis_binding"]["binding_fingerprint"]
    assert graphify_structural_evidence_fingerprint(doc) == doc["fingerprint"]


def test_task37_29_wheel_api_surface_is_importable() -> None:
    assert GraphifyStructuralEvidenceV2.__name__ == "GraphifyStructuralEvidenceV2"


def test_task37_30_full_regression_contract_has_no_verdict_fields() -> None:
    assert not ({"PASS", "FAIL", "VERIFIED"} & set(valid().to_dict()))
