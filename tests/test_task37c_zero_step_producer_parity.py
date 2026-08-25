"""Task37c RED-first acceptance tests: zero-step producer parity.

Both vectors in ``tests/fixtures/structural_evidence`` are genuine producer
output of the exact Graphify bound pipeline at HEAD
529ade498158a86e607138b1c3e717874553294 (see the committed provenance record).
They are never resealed mutations of another snapshot.

Parser-vs-authority separation under test:

* both producer-valid zero-step identity documents parse;
* the clean identity answer may be decisive positive;
* the boundary-blocked identity answer stays non-decisive (UNKNOWN),
  never malformed;
* mixed zero+nonzero paths, duplicate zeros, and non-identity empty paths
  are rejected.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from gvr.graphify_contract import validate_graphify_envelope_authority
from gvr.structural_evidence import (
    GraphifyStructuralEvidenceError,
    graphify_structural_evidence_fingerprint,
    ingest_graphify_structural_evidence_v2,
)
from gvr.verifiers.data_flow import (
    DataFlowClaim,
    DataFlowClaimKind,
    DataFlowQueryScope,
    SourceRevision,
    verify_data_flow_claim,
)

FIXTURES = Path(__file__).parent / "fixtures" / "structural_evidence"
CLEAN_FIXTURE = FIXTURES / "structural_evidence_v2_zero_step_identity_clean.json"
BOUNDARY_FIXTURE = FIXTURES / "structural_evidence_v2_zero_step_identity_boundary.json"
PROVENANCE = FIXTURES / "provenance" / "task37c_zero_step_identity_provenance.json"
PRODUCER_HEAD = "529ade498158a86e6607138b1c3e717874553294"


def clean_document() -> dict:
    return json.loads(CLEAN_FIXTURE.read_text(encoding="utf-8"))


def boundary_document() -> dict:
    return json.loads(BOUNDARY_FIXTURE.read_text(encoding="utf-8"))


def data_flow_claim(doc: dict, *, claim_id: str = "task37c") -> DataFlowClaim:
    # The data-flow verifier binds claims against the envelope's raw endpoints.
    start = str(doc["query"]["start"])
    bounds = doc["coverage"]["query_bounds"]
    return DataFlowClaim(
        kind=DataFlowClaimKind.CAN_FLOW_TO,
        start=start,
        target=start,
        scope=DataFlowQueryScope(
            direction=doc["query"]["direction"],
            effective_allowed_relations=frozenset(bounds["effective_allowed_relations"]),
            stop_nodes=frozenset(bounds["stop_nodes"]),
        ),
        evidence_namespace="task37c",
    )


# --------------------------------------------------------------------------- #
# Genuine producer provenance
# --------------------------------------------------------------------------- #


def test_task37c_01_provenance_pins_exact_readonly_producer_head() -> None:
    prov = json.loads(PROVENANCE.read_text(encoding="utf-8"))
    assert prov["producer_head"] == PRODUCER_HEAD
    assert prov["producer_head_dirty"] is False
    assert prov["authenticity"].startswith("Documents are direct producer output")
    pipeline = "\n".join(prov["pipeline"])
    assert "build_bound_structural_index" in pipeline
    assert "run_bound_data_flow_query" in pipeline


def test_task37c_02_vectors_carry_full_producer_fingerprints() -> None:
    for loader in (clean_document, boundary_document):
        doc = loader()
        assert doc["format"] == "graphify.structural_evidence.v2"
        assert doc["schema_version"] == 2
        assert doc["analysis_binding"]["binding_fingerprint"].startswith("sha256:")
        assert graphify_structural_evidence_fingerprint(doc) == doc["fingerprint"]
        assert len(doc["paths"]) == 1
        assert doc["paths"][0]["path_identity"] == []
        assert doc["coverage"]["visited_count"] == 1
        assert doc["coverage"]["expanded_count"] == 0


def test_task37c_03_provenance_matches_committed_vector_identities() -> None:
    prov = json.loads(PROVENANCE.read_text(encoding="utf-8"))
    clean = clean_document()
    boundary = boundary_document()
    assert prov["vectors"]["clean"]["fingerprint"] == clean["fingerprint"]
    assert prov["vectors"]["boundary"]["fingerprint"] == boundary["fingerprint"]
    assert prov["vectors"]["clean"]["source_revision"] == clean["source_revision_scope"]["source_revision"]
    assert prov["vectors"]["boundary"]["source_revision"] == boundary["source_revision_scope"]["source_revision"]
    assert prov["vectors"]["boundary"]["boundary_keys"] == [b["key"] for b in boundary["blockers"]]


# --------------------------------------------------------------------------- #
# Clean zero-step identity: parser accepts, authority may decide positive
# --------------------------------------------------------------------------- #


def test_task37c_04_clean_identity_vector_parses_and_projects() -> None:
    snapshot = ingest_graphify_structural_evidence_v2(clean_document())
    traversal = snapshot.to_gvr_traversal_dict()
    assert [path["path_identity"] for path in traversal["paths"]] == [[]]
    assert traversal["complete_supported_search"] is True


def test_task37c_05_clean_identity_is_decisive_positive() -> None:
    doc = clean_document()
    traversal = ingest_graphify_structural_evidence_v2(doc).to_gvr_traversal_dict()
    authority = validate_graphify_envelope_authority(traversal)
    assert authority.positive_authorized is True
    assert authority.negative_authorized is False
    report = verify_data_flow_claim(data_flow_claim(doc), traversal)
    assert report.verdict.name == "PASS"
    assert any(issue.code == "PROVEN_SUPPORTED_PATH" for issue in report.issues)


def test_task37c_06_clean_identity_replay_is_deterministic() -> None:
    first = ingest_graphify_structural_evidence_v2(clean_document())
    second = ingest_graphify_structural_evidence_v2(first.to_dict())
    assert second.fingerprint == first.fingerprint
    assert second.analysis_binding == first.analysis_binding


# --------------------------------------------------------------------------- #
# Boundary-blocked zero-step identity: parses, stays non-decisive UNKNOWN
# --------------------------------------------------------------------------- #


def test_task37c_07_boundary_identity_vector_parses_as_valid_v2_document() -> None:
    """Producer-valid boundary identity must not be treated as malformed."""
    doc = boundary_document()
    assert doc["blockers"], "vector must carry a real blocking boundary"
    snapshot = ingest_graphify_structural_evidence_v2(doc)
    assert len(snapshot.blockers) == len(doc["blockers"])
    assert snapshot.fingerprint == doc["fingerprint"]


def test_task37c_08_boundary_identity_remains_non_decisive_unknown() -> None:
    doc = boundary_document()
    traversal = ingest_graphify_structural_evidence_v2(doc).to_gvr_traversal_dict()
    authority = validate_graphify_envelope_authority(traversal)
    assert authority.positive_authorized is False
    assert authority.negative_authorized is False
    report = verify_data_flow_claim(data_flow_claim(doc), traversal)
    assert report.verdict.name == "UNKNOWN"
    codes = {issue.code for issue in report.issues}
    assert "BLOCKING_BOUNDARY" in codes
    assert "MALFORMED_TRAVERSAL" not in codes
    assert "MALFORMED_PATH" not in codes


def test_task37c_09_boundary_identity_keeps_partial_coverage_semantics() -> None:
    snapshot = ingest_graphify_structural_evidence_v2(boundary_document())
    traversal = snapshot.to_gvr_traversal_dict()
    assert traversal["complete_supported_search"] is False
    assert traversal["search_coverage"] == "PARTIAL"
    assert traversal["termination_reason"] == "COMPLETE"


def test_task37c_10_boundary_identity_replay_is_deterministic() -> None:
    first = ingest_graphify_structural_evidence_v2(boundary_document())
    second = ingest_graphify_structural_evidence_v2(first.to_dict())
    assert second.fingerprint == first.fingerprint


# --------------------------------------------------------------------------- #
# Structural rejection rules (parser level)
# --------------------------------------------------------------------------- #


def test_task37c_11_mixed_zero_and_nonzero_paths_are_rejected() -> None:
    donor = json.loads((FIXTURES / "structural_evidence_snapshot.json").read_text(encoding="utf-8"))
    proven_fact = next(item for item in donor["facts"] if item["receiver_confidence"] == "PROVEN")
    proven_fact["path_identity"] = [[proven_fact["key"]]]
    # Clean producer identity state everywhere else: only the explicit
    # zero/nonzero mixing rule may (and must) reject this document.
    mixed = deepcopy(clean_document())
    mixed["facts"] = [proven_fact]
    mixed["paths"] = [
        {
            "path_identity": [],
            "supporting_evidence_keys": [],
            "exactness": "EXACT_FOR_RETURNED_PATH",
            "receiver_confidence": "PROVEN",
            "coverage": "COMPLETE_FOR_SUPPORTED_CONSTRUCT",
        },
        {
            "path_identity": [proven_fact["key"]],
            "supporting_evidence_keys": [proven_fact["key"]],
            "exactness": "EXACT_FOR_RETURNED_PATH",
            "receiver_confidence": "PROVEN",
            "coverage": "COMPLETE_FOR_SUPPORTED_CONSTRUCT",
        },
    ]
    mixed["fingerprint"] = graphify_structural_evidence_fingerprint(mixed)
    with pytest.raises(GraphifyStructuralEvidenceError, match="mixed"):
        ingest_graphify_structural_evidence_v2(mixed)


def test_task37c_12_duplicate_zero_identity_paths_are_rejected() -> None:
    doc = clean_document()
    doc["paths"].append(deepcopy(doc["paths"][0]))
    doc["fingerprint"] = graphify_structural_evidence_fingerprint(doc)
    with pytest.raises(GraphifyStructuralEvidenceError):
        ingest_graphify_structural_evidence_v2(doc)


@pytest.mark.parametrize("target", ["unreached-distinct-target-node", None])
def test_task37c_13_non_identity_empty_path_is_rejected(target: str | None) -> None:
    doc = clean_document()
    doc["query"]["target"] = target
    doc["fingerprint"] = graphify_structural_evidence_fingerprint(doc)
    with pytest.raises(GraphifyStructuralEvidenceError):
        ingest_graphify_structural_evidence_v2(doc)


# --------------------------------------------------------------------------- #
# Replay / wrong-context / tamper hardening over the new vectors
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("complete_supported_search", True),
        ("search_coverage", "COMPLETE_FOR_SUPPORTED_CONSTRUCT"),
    ],
)
def test_task37c_14_boundary_tamper_with_stale_seal_fails_closed(field: str, value: object) -> None:
    doc = boundary_document()
    doc["coverage"][field] = value
    with pytest.raises(GraphifyStructuralEvidenceError):
        ingest_graphify_structural_evidence_v2(doc)


def test_task37c_15_boundary_blocker_mutation_without_reseal_fails_closed() -> None:
    doc = boundary_document()
    doc["blockers"][0]["reason"] = "tampered"
    with pytest.raises(GraphifyStructuralEvidenceError):
        ingest_graphify_structural_evidence_v2(doc)


def test_task37c_16_wrong_context_revision_stays_unknown_not_decisive() -> None:
    doc = boundary_document()
    traversal = ingest_graphify_structural_evidence_v2(doc).to_gvr_traversal_dict()
    claim = DataFlowClaim(
        kind=DataFlowClaimKind.CAN_FLOW_TO,
        start=traversal["start"],
        target=traversal["start"],
        scope=DataFlowQueryScope(),
        evidence_namespace="task37c-wrong-context",
        source_revision=SourceRevision("graphify", "f" * 40),
    )
    report = verify_data_flow_claim(claim, traversal)
    assert report.verdict.name == "UNKNOWN"
    assert any(issue.code == "SOURCE_REVISION_MISMATCH" for issue in report.issues)
