"""Task37 RED-first acceptance tests for Graphify v2 bound snapshot consumption."""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from gvr import (
    CODE_GRAPH_VERIFIER,
    AtomicClaim,
    CodeGraphObservationError,
    IndependenceTrustState,
    ProviderTrustContext,
    SQLiteStorage,
    SourceRevisionIdentity,
    VerificationExecutionTermination,
    VerificationVerdict,
    decode_code_graph_observation_evidence,
    execute_verification_plan,
)
from gvr.adapters.graphify import (
    encode_graphify_structural_evidence_v2_observation_evidence,
)
from gvr.graphify_contract import validate_graphify_envelope_authority
from gvr.structural_evidence import (
    GraphifySourceRevisionScope,
    GraphifyStructuralAnalysisBinding,
    GraphifyStructuralEvidenceError,
    GraphifyStructuralEvidenceV2,
    graphify_analysis_binding_fingerprint,
    graphify_source_scope_fingerprint,
    graphify_structural_evidence_fingerprint,
    ingest_graphify_structural_evidence_v2,
)
from gvr.verifiers.code_graph import CodeGraphClaimKind

from test_code_graph_execution_tasks_27_30_integrated import (
    SNAPSHOT_PATH,
    codeflow_path_snapshot,
    encode_codeflow_code_graph_observation_evidence,
    execution_request,
    path_claim,
    root_report,
    typed_query_scope,
    typed_revision,
)

FIXTURE = Path(__file__).parent / "fixtures" / "structural_evidence" / "structural_evidence_snapshot.json"
WHEEL_MATRIX_SCRIPT = Path(__file__).parent / "task37b_installed_wheel_matrix.py"


def document() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def reseal(doc: dict) -> dict:
    doc["fingerprint"] = graphify_structural_evidence_fingerprint(doc)
    return doc


def valid(doc: dict | None = None) -> GraphifyStructuralEvidenceV2:
    return ingest_graphify_structural_evidence_v2(doc or document())


def issue_codes(report) -> set[str]:
    return {issue.code for issue in report.issues}


_TARGET_NODE = "src_acme_pipeline_data_value_pipeline_transform_value_return_return"


def targeted_document() -> dict:
    """Fixture snapshot re-bound to a concrete point-to-point question."""
    doc = document()
    doc["query"]["target"] = _TARGET_NODE
    doc["coverage"]["target_node_found"] = True
    return reseal(doc)


def identity_document() -> dict:
    """Producer-valid zero-step identity result: start == target with one empty path."""
    doc = document()
    doc["query"]["target"] = doc["query"]["start"]
    doc["facts"] = []
    doc["blockers"] = []
    doc["paths"] = [{
        "path_identity": [],
        "supporting_evidence_keys": [],
        "exactness": "EXACT_FOR_RETURNED_PATH",
        "receiver_confidence": "PROVEN",
        "coverage": "COMPLETE_FOR_SUPPORTED_CONSTRUCT",
    }]
    doc["coverage"].update({
        "complete_supported_search": True,
        "search_coverage": "COMPLETE_FOR_SUPPORTED_CONSTRUCT",
        "termination_reason": "COMPLETE",
        "truncated": False,
        "input_resolution": "RESOLVED",
        "query_validity": True,
        "start_node_found": True,
        "target_node_found": True,
        "visited_count": 1,
        "expanded_count": 0,
        "encountered_partial_evidence": False,
        "encountered_unknown_evidence": False,
        "encountered_may_evidence": False,
    })
    return reseal(doc)


def unresolved_zero_depth_document() -> dict:
    """Producer-valid max_depth == 0 state: zero-depth never traverses."""
    doc = document()
    doc["query"]["max_depth"] = 0
    doc["query"]["target"] = "unreached-target-node"
    doc["facts"] = []
    doc["paths"] = []
    doc["blockers"] = []
    doc["coverage"].update({
        "complete_supported_search": False,
        "search_coverage": "UNKNOWN",
        "termination_reason": "TARGET_NODE_NOT_FOUND",
        "truncated": False,
        "input_resolution": "TARGET_NODE_NOT_FOUND",
        "query_validity": True,
        "start_node_found": True,
        "target_node_found": False,
        "visited_count": 0,
        "expanded_count": 0,
        "encountered_partial_evidence": False,
        "encountered_unknown_evidence": False,
        "encountered_may_evidence": False,
    })
    return reseal(doc)


def v2_claim(
    claim_id: str = "task37-v2-path",
    *,
    revision: str | None = None,
    relations: list[str] | None = None,
) -> AtomicClaim:
    query = document()["query"]
    bounds = document()["coverage"]["query_bounds"]
    return AtomicClaim(
        claim_id=claim_id,
        claim_kind=CodeGraphClaimKind.PATH_EXISTS.value,
        verifier=CODE_GRAPH_VERIFIER,
        spec={
            "source": f"graphify:node:{query['start']}",
            "target": f"graphify:node:{_TARGET_NODE}",
            "relations": list(relations if relations is not None else bounds["effective_allowed_relations"]),
            "scope": {
                "snapshot": {
                    "repository": "graphify",
                    "revision": revision or document()["source_revision_scope"]["source_revision"],
                },
                "direction": query["direction"],
                "max_depth": bounds["max_depth"],
                "max_paths": bounds["max_paths"],
                "max_expansions": bounds["max_expansions"],
            },
        },
    )


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


def test_task37_24_real_codeflow_observation_stays_non_decisive(tmp_path: Path) -> None:
    """Task27 CodeFlow semantics stay intact: a heuristic CodeFlow observation alone never decides."""
    claim = path_claim("cg-task37-codeflow")
    codeflow = encode_codeflow_code_graph_observation_evidence(
        codeflow_path_snapshot(),
        evidence_id="obs.codeflow.task37",
        claim=claim,
        source_revision=typed_revision(SNAPSHOT_PATH),
        query_scope=typed_query_scope(claim),
    )
    result = execute_verification_plan(
        execution_request(claim, {"codeflow.snapshot": (codeflow, SNAPSHOT_PATH)}),
        storage=SQLiteStorage(tmp_path / "task37-codeflow.sqlite3"),
    )
    report = root_report(result, claim.claim_id)

    assert result.termination is VerificationExecutionTermination.COMPLETE
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert report.evidence_ids == ("obs.codeflow.task37",)
    assert {"EDGE_NOT_EXACT", "PROVIDER_ONLY_HEURISTIC"} <= issue_codes(report)


def test_task37_25_sqlite_close_reopen_preserves_full_v2_authority_metadata(tmp_path: Path) -> None:
    doc = document()
    evidence = encode_graphify_structural_evidence_v2_observation_evidence(
        doc, evidence_id="obs.task37.sqlite", claim_fingerprint="claim"
    )
    before = decode_code_graph_observation_evidence(evidence)

    store_path = tmp_path / "task37.sqlite3"
    store = SQLiteStorage(store_path)
    stored = store.put_evidence(evidence)
    reopened = SQLiteStorage(store_path)
    roundtrip = reopened.get_evidence(stored.fingerprint)

    after = decode_code_graph_observation_evidence(roundtrip.evidence)
    metadata_after = after.graph_model.authority_metadata
    assert metadata_after["format"] == "graphify.structural_evidence.v2"
    assert metadata_after["source_revision_scope"] == doc["source_revision_scope"]
    assert metadata_after["analysis_binding"] == doc["analysis_binding"]
    assert metadata_after["snapshot_fingerprint"] == before.graph_model.authority_metadata["snapshot_fingerprint"]
    # The typed model normalizes lists to tuples in metadata; content must round-trip intact.
    assert json.loads(json.dumps(metadata_after["snapshot"])) == doc
    assert metadata_after["snapshot_fingerprint"] == before.graph_model.authority_metadata["snapshot_fingerprint"]
    assert after.independence.trust_state is IndependenceTrustState.UNVERIFIED


def test_task37_26_integrated_executor_binds_exact_claim_source_and_scope(tmp_path: Path) -> None:
    doc = targeted_document()
    # One trust context seals the origin; the same context must stay active to decode and execute.
    context = ProviderTrustContext.host_runtime("gvr.builtin_provider_adapters.v1")
    with context.activate():
        claim = v2_claim()
        evidence = encode_graphify_structural_evidence_v2_observation_evidence(
            doc, evidence_id="obs.task37.executor", claim=claim
        )
        decoded = decode_code_graph_observation_evidence(evidence)
        assert decoded.independence.trust_state is IndependenceTrustState.VERIFIED
        claim = v2_claim()
        result = execute_verification_plan(
            execution_request(claim, {"graphify.snapshot": (evidence, doc)}),
            storage=SQLiteStorage(tmp_path / "task37-executor.sqlite3"),
        )
        decoded = decode_code_graph_observation_evidence(evidence)
        assert decoded.independence.trust_state is IndependenceTrustState.VERIFIED
        result = execute_verification_plan(
            execution_request(claim, {"graphify.snapshot": (evidence, doc)}),
            storage=SQLiteStorage(tmp_path / "task37-executor.sqlite3"),
        )
    assert decoded.graph_model.source_revision == SourceRevisionIdentity(
        "graphify", doc["source_revision_scope"]["source_revision"]
    )
    assert decoded.graph_model.query_scope.start == f"graphify:node:{doc['query']['start']}"
    assert decoded.graph_model.query_scope.target == f"graphify:node:{doc['query']['target']}"
    report = root_report(result, claim.claim_id)
    assert result.termination is VerificationExecutionTermination.COMPLETE
    codes = issue_codes(report)
    assert "SOURCE_REVISION_MISMATCH" not in codes
    assert "GRAPH_QUERY_SCOPE_MISMATCH" not in codes
    # The fixture carries MAY evidence, so the executor stays non-decisive on content grounds.
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "HEURISTIC_ONLY_SUPPORT" in codes


def test_task37_27_claim_scope_precedence_beats_verified_provider_origin(tmp_path: Path) -> None:
    """VERIFIED provider origin cannot reconcile a claim bound to a different revision or scope."""
    doc = targeted_document()
    context = ProviderTrustContext.host_runtime("gvr.builtin_provider_adapters.v1")
    with context.activate():
        wrong_claim = v2_claim("task37-wrong-revision", revision="f" * 40)
        narrow_claim = v2_claim("task37-narrow-scope", relations=["FLOWS_TO"])
        revision_evidence = encode_graphify_structural_evidence_v2_observation_evidence(
            doc, evidence_id="obs.task37.precedence.revision", claim=wrong_claim
        )
        scope_evidence = encode_graphify_structural_evidence_v2_observation_evidence(
            doc, evidence_id="obs.task37.precedence.scope", claim=narrow_claim
        )
        assert decode_code_graph_observation_evidence(revision_evidence).independence.trust_state is IndependenceTrustState.VERIFIED

        wrong_revision = execute_verification_plan(
            execution_request(wrong_claim, {"graphify.snapshot": (revision_evidence, doc)}),
            storage=SQLiteStorage(tmp_path / "task37-revision.sqlite3"),
        )
        narrower_scope = execute_verification_plan(
            execution_request(narrow_claim, {"graphify.snapshot": (scope_evidence, doc)}),
            storage=SQLiteStorage(tmp_path / "task37-scope.sqlite3"),
        )

    revision_report = root_report(wrong_revision, "task37-wrong-revision")
    assert revision_report.verdict is VerificationVerdict.UNKNOWN
    assert "SOURCE_REVISION_MISMATCH" in issue_codes(revision_report)

    scope_report = root_report(narrower_scope, "task37-narrow-scope")
    assert scope_report.verdict is VerificationVerdict.UNKNOWN
    assert "GRAPH_QUERY_SCOPE_MISMATCH" in issue_codes(scope_report)


def test_task37_28_reference_vectors_match_graphify_canonicalization() -> None:
    doc = document()
    assert graphify_source_scope_fingerprint(doc["source_revision_scope"]) == doc["analysis_binding"]["source_scope_fingerprint"]
    assert graphify_analysis_binding_fingerprint(doc["source_revision_scope"], doc["analysis_binding"]) == doc["analysis_binding"]["binding_fingerprint"]
    assert graphify_structural_evidence_fingerprint(doc) == doc["fingerprint"]


def test_task37_29_installed_wheel_attack_replay_matrix(tmp_path: Path) -> None:
    """Build the wheel, install it into a fresh interpreter, and replay the full attack matrix there."""
    repo_root = Path(__file__).resolve().parents[1]
    wheel_dir = tmp_path / "wheel"
    build = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", "-w", str(wheel_dir), str(repo_root)],
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        pytest.fail("wheel build failed:\n" + (build.stderr or build.stdout)[-2000:])
    wheels = list(wheel_dir.glob("gvr-*.whl"))
    assert len(wheels) == 1, wheels

    venv_dir = tmp_path / "venv"
    created = subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], capture_output=True, text=True)
    assert created.returncode == 0, created.stderr
    venv_python = venv_dir / "bin" / "python"
    installed = subprocess.run(
        [str(venv_python), "-m", "pip", "install", "--no-deps", str(wheels[0])],
        capture_output=True,
        text=True,
    )
    assert installed.returncode == 0, installed.stderr

    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    env["GVR_TASK37B_FIXTURE"] = str(FIXTURE.resolve())
    matrix = subprocess.run(
        [str(venv_python), str(WHEEL_MATRIX_SCRIPT.resolve())],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        env=env,
    )
    assert matrix.returncode == 0, (
        "installed-wheel attack/replay matrix failed\nSTDOUT:\n"
        + matrix.stdout
        + "\nSTDERR:\n"
        + matrix.stderr
    )
    assert "MATRIX OK" in matrix.stdout


def test_task37_30_full_regression_contract_has_no_verdict_fields() -> None:
    assert not ({"PASS", "FAIL", "VERIFIED"} & set(valid().to_dict()))


def test_task37_review_boundary_key_uses_producer_details_fallback() -> None:
    doc = document()
    blocker = doc["blockers"][0]
    blocker["details"].update({
        "repository_fqn": "acme.Repository",
        "entity_fqn": "acme.Entity",
    })
    blocker["key"] = "bnd:5a1213cc82d21143a7389422282539aac2706f5f3a29559bc0f009e633c05771"
    assert valid(reseal(doc)).blockers[0]["key"] == blocker["key"]


def test_task37_review_projection_preserves_native_traversal_accounting() -> None:
    snapshot = valid()
    traversal = snapshot.to_gvr_traversal_dict()
    assert traversal["visited_count"] == snapshot.coverage["visited_count"]
    assert traversal["expanded_count"] == snapshot.coverage["expanded_count"]


def test_task37_review_empty_path_fails_as_contract_error() -> None:
    doc = document()
    doc["paths"][0]["path_identity"] = []
    doc["paths"][0]["supporting_evidence_keys"] = []
    with pytest.raises(GraphifyStructuralEvidenceError):
        valid(reseal(doc))


def test_task37_review_ingestion_is_json_transport_only() -> None:
    doc = document()
    doc["query"]["stop_nodes"] = ("tuple-is-not-json",)
    with pytest.raises(GraphifyStructuralEvidenceError, match="non-JSON"):
        valid(reseal(doc))


def test_task37b_producer_zero_step_identity_path_is_accepted_and_authoritative() -> None:
    snapshot = valid(identity_document())
    traversal = snapshot.to_gvr_traversal_dict()
    assert [path["path_identity"] for path in traversal["paths"]] == [[]]
    assert traversal["complete_supported_search"] is True
    authority = validate_graphify_envelope_authority(traversal)
    assert authority.positive_authorized is True
    assert authority.negative_authorized is False


def test_task37b_identity_snapshot_encodes_without_edges_or_absence() -> None:
    evidence = encode_graphify_structural_evidence_v2_observation_evidence(
        identity_document(), evidence_id="obs.task37b.identity", claim_fingerprint="claim"
    )
    decoded = decode_code_graph_observation_evidence(evidence)
    assert decoded.graph_model.edges == ()
    assert decoded.graph_model.absence_subjects == ()


@pytest.mark.parametrize("target", ["unrelated-target-node", None])
def test_task37b_empty_identity_path_requires_exact_identity_query(target: str | None) -> None:
    doc = identity_document()
    doc["query"]["target"] = target
    with pytest.raises(GraphifyStructuralEvidenceError):
        valid(doc)


def test_task37b_non_empty_identity_rules_are_unchanged() -> None:
    doc = identity_document()
    doc["paths"][0]["supporting_evidence_keys"] = ["df:" + "0" * 64]
    with pytest.raises(GraphifyStructuralEvidenceError):
        valid(doc)


def test_task37b_duplicate_identity_paths_fail_closed() -> None:
    doc = identity_document()
    doc["paths"].append(deepcopy(doc["paths"][0]))
    with pytest.raises(GraphifyStructuralEvidenceError):
        valid(reseal(doc))


@pytest.mark.parametrize(
    ("label", "value"),
    [
        ("exactness", "PARTIAL"),
        ("receiver_confidence", "MAY"),
        ("coverage", "PARTIAL"),
    ],
)
def test_task37b_identity_path_labels_must_be_producer_exact(label: str, value: str) -> None:
    doc = identity_document()
    doc["paths"][0][label] = value
    with pytest.raises(GraphifyStructuralEvidenceError):
        valid(reseal(doc))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("input_resolution", "TARGET_NODE_NOT_FOUND"),
        ("termination_reason", "MAX_DEPTH"),
        ("truncated", True),
        ("complete_supported_search", False),
        ("search_coverage", "PARTIAL"),
        ("target_node_found", False),
        ("query_validity", False),
        ("visited_count", 2),
        ("expanded_count", 1),
        ("encountered_may_evidence", True),
    ],
)
def test_task37b_identity_state_must_be_resolved_and_complete(field: str, value: Any) -> None:
    doc = identity_document()
    doc["coverage"][field] = value
    with pytest.raises(GraphifyStructuralEvidenceError):
        valid(reseal(doc))


def test_task37b_identity_snapshot_with_blockers_fails_closed() -> None:
    doc = identity_document()
    doc["blockers"] = document()["blockers"]
    with pytest.raises(GraphifyStructuralEvidenceError):
        valid(reseal(doc))


@pytest.mark.parametrize("field", ["max_paths", "max_expansions"])
def test_task37b_query_bounds_match_producer_minimums(field: str) -> None:
    doc = document()
    doc["query"][field] = 0
    with pytest.raises(GraphifyStructuralEvidenceError):
        valid(reseal(doc))


def test_task37b_coverage_query_bounds_match_producer_minimums() -> None:
    doc = document()
    doc["coverage"]["query_bounds"]["max_paths"] = 0
    with pytest.raises(GraphifyStructuralEvidenceError):
        valid(reseal(doc))


def test_task37b_max_depth_zero_stays_producer_valid() -> None:
    snapshot = valid(unresolved_zero_depth_document())
    assert snapshot.query["max_depth"] == 0
    assert snapshot.to_gvr_traversal_dict()["paths"] == []


def test_task37b_typed_state_is_deeply_immutable() -> None:
    snapshot = valid()

    def attempt(target: Any, key: str, value: Any) -> None:
        target[key] = value

    for target, key, value in (
        (snapshot.coverage, "complete_supported_search", True),
        (snapshot.query, "max_paths", 1),
        (snapshot.document, "fingerprint", "0" * 64),
        (snapshot.facts[0], "source", "mutated"),
        (snapshot.blockers[0], "reason", "mutated"),
    ):
        with pytest.raises(TypeError):
            attempt(target, key, value)

    # Derived authority surfaces are unchanged by every failed mutation.
    assert snapshot.coverage["complete_supported_search"] is False
    assert snapshot.fingerprint == graphify_structural_evidence_fingerprint(snapshot.to_dict())
    assert snapshot.to_dict() == document()


def test_task37b_direct_construction_gains_no_typed_authority() -> None:
    """A hand-built typed view is inert: every typed-object boundary revalidates."""
    doc = document()
    scope = GraphifySourceRevisionScope(**doc["source_revision_scope"])
    binding = GraphifyStructuralAnalysisBinding(**doc["analysis_binding"])

    def direct_instance(mutated: dict) -> GraphifyStructuralEvidenceV2:
        return GraphifyStructuralEvidenceV2(
            document=mutated,
            source_revision_scope=scope,
            analysis_binding=binding,
            query=mutated["query"],
            coverage=mutated["coverage"],
            facts=tuple(mutated["facts"]),
            paths=tuple(mutated["paths"]),
            blockers=tuple(mutated["blockers"]),
            analyzer_revision=mutated["analyzer_revision"],
        )

    # Forged coverage under a stale fingerprint is rejected at the trusted boundary.
    forged_doc = deepcopy(doc)
    forged_doc["coverage"]["complete_supported_search"] = True
    with pytest.raises(GraphifyStructuralEvidenceError):
        encode_graphify_structural_evidence_v2_observation_evidence(
            direct_instance(forged_doc), evidence_id="obs.task37b.forged", claim_fingerprint="claim"
        )

    # Authority comes from the revalidated canonical content, not from the instance:
    # a directly built view over the true document encodes identically to an ingested one.
    honest = direct_instance(doc)
    honest_evidence = encode_graphify_structural_evidence_v2_observation_evidence(
        honest, evidence_id="obs.task37b.honest", claim_fingerprint="claim"
    )
    ingested_evidence = encode_graphify_structural_evidence_v2_observation_evidence(
        doc, evidence_id="obs.task37b.ingested", claim_fingerprint="claim"
    )
    assert decode_code_graph_observation_evidence(honest_evidence).graph_model.fingerprint == (
        decode_code_graph_observation_evidence(ingested_evidence).graph_model.fingerprint
    )


def test_task37b_trusted_adapter_revalidates_typed_objects() -> None:
    forged = valid()
    forged_doc = forged.to_dict()
    forged_doc["coverage"]["complete_supported_search"] = True
    object.__setattr__(forged, "document", forged_doc)
    with pytest.raises(GraphifyStructuralEvidenceError):
        encode_graphify_structural_evidence_v2_observation_evidence(
            forged, evidence_id="obs.task37b.forged", claim_fingerprint="claim"
        )
