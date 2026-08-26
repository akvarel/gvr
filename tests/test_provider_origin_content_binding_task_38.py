"""Task38 RED-first exploit suite: provider-origin observation content binding.

Drive Task38 requires the first commit to be tests-only and demonstrate, on
exact base ``609750e496510480d2d6b4ce693ac71c0e2ef1ae``, that a copied legitimate
VERIFIED provider-origin assertion behaves as a transferable bearer token: an
attacker can transplant it onto a different observation subject (different claim,
graph model, source revision, query scope/coverage, Graphify-v2 authority
metadata) with all public fingerprints recomputed and still reach VERIFIED.

Each transplanted-observation test asserts fail-closed rejection. On the base
the decode path wrongly accepts the copied seal, so these tests are genuine RED.
Replay/lifetime cases (7-10) and precedence/preservation cases (16-18) pin the
accepted contracts that must survive the remediation.

Threat model: untrusted serialized evidence. Same-process hostile Python is part
of the trusted computing base and is explicitly out of scope.
"""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Callable, Mapping

import pytest

from gvr import (
    AtomicClaim,
    CODE_GRAPH_OBSERVATION_EVIDENCE_KIND,
    CODE_GRAPH_VERIFIER,
    CodeGraphObservationError,
    Evidence,
    GraphEvidenceModel,
    IndependenceTrustState,
    ProviderImplementationIdentity,
    ProviderImplementationRegistration,
    ProviderTrustContext,
    ProviderVerificationObservation,
    SQLiteStorage,
    VerificationVerdict,
    builtin_verifier_capability_registry,
    decode_code_graph_observation_evidence,
    reconcile_provider_observations,
)
from gvr.adapters.codeflow import encode_codeflow_code_graph_observation_evidence
from gvr.adapters.graphify import (
    encode_graphify_code_graph_observation_evidence,
    encode_graphify_structural_evidence_v2_observation_evidence,
)
from gvr.canonical import canonical_fingerprint
from gvr.code_graph import (
    CODE_GRAPH_OBSERVATION_FINGERPRINT_FORMAT,
    EvidenceConfidence,
    GraphEvidence,
    GraphEvidenceKind,
    GraphFacts,
    graph_model_from_dict,
)
from gvr.execution import VerifierExecutionInput, _CodeGraphVerifierRuntime
from gvr.graphify_contract import (
    expected_graphify_df_key,
    validate_graphify_envelope_authority,
)
from gvr.structural_evidence import ingest_graphify_structural_evidence_v2
from gvr.verifiers.code_graph import CodeGraphClaimKind
from gvr.verifiers.data_flow import (
    DataFlowClaim,
    DataFlowClaimKind,
    DataFlowQueryScope,
    verify_data_flow_claim,
)

CONFIG_IDENTITY = "task38-content-binding"
FORGED_CLAIM = "task38.forged.claim.fingerprint"
FIXTURES = Path(__file__).parent / "fixtures" / "structural_evidence"
CLEAN_FIXTURE = FIXTURES / "structural_evidence_v2_zero_step_identity_clean.json"
BOUNDARY_FIXTURE = FIXTURES / "structural_evidence_v2_zero_step_identity_boundary.json"

_CORROBORATION_CODES = {
    "PROVIDER_CORROBORATED_PASS",
    "PROVIDER_CORROBORATED_FAIL",
    "PROVIDER_CONFLICT",
    "PROVIDER_SINGLE_FAMILY_DECISIVE_PASS",
    "PROVIDER_SINGLE_FAMILY_DECISIVE_FAIL",
}


# --------------------------------------------------------------------------- #
# Shared fixtures and builders
# --------------------------------------------------------------------------- #


def clean_document() -> dict:
    return json.loads(CLEAN_FIXTURE.read_text(encoding="utf-8"))


def boundary_document() -> dict:
    return json.loads(BOUNDARY_FIXTURE.read_text(encoding="utf-8"))


def _context(*registrations: ProviderImplementationRegistration) -> ProviderTrustContext:
    return ProviderTrustContext.host_runtime(CONFIG_IDENTITY, registrations=tuple(registrations))


def _path_evidence() -> dict[str, object]:
    evidence = {
        "relation": "FLOWS_TO",
        "source": "A",
        "target": "B",
        "source_file": "src/a.py",
        "source_location": "1:1",
        "provenance": "graphify-canonical-snapshot",
        "receiver_confidence": "PROVEN",
        "analysis_completeness": "COMPLETE_FOR_SUPPORTED_CONSTRUCT",
    }
    evidence["key"] = expected_graphify_df_key(evidence)
    return evidence


def _graphify_path_result() -> dict[str, object]:
    evidence = _path_evidence()
    return {
        "repository": "fixture-repo",
        "revision": "rev-1",
        "start": "A",
        "target": "B",
        "direction": "FORWARD",
        "evidence_namespace": "task38",
        "termination_reason": "EXHAUSTED",
        "search_coverage": "COMPLETE_FOR_SUPPORTED_CONSTRUCT",
        "complete_supported_search": True,
        "query_validity": True,
        "input_resolution": "RESOLVED",
        "start_node_found": True,
        "target_node_found": True,
        "truncated": False,
        "visited_count": 2,
        "expanded_count": 1,
        "boundary_events": [],
        "rejected_relations": [],
        "encountered_partial_evidence": False,
        "encountered_unknown_evidence": False,
        "encountered_may_evidence": False,
        "query_bounds": {
            "requested_relations": ["FLOWS_TO"],
            "effective_allowed_relations": ["FLOWS_TO"],
            "rejected_relations": [],
            "stop_nodes": [],
            "max_depth": 4,
            "max_paths": 8,
            "max_expansions": 64,
        },
        "paths": [
            {
                "path_identity": [evidence["key"]],
                "path_exactness": "EXACT_FOR_RETURNED_PATH",
                "path_receiver_confidence": "PROVEN",
                "path_coverage": "COMPLETE_FOR_SUPPORTED_CONSTRUCT",
                "steps": [
                    {
                        "source": evidence["source"],
                        "target": evidence["target"],
                        "relation": evidence["relation"],
                        "evidence": evidence,
                    }
                ],
                "supporting_evidence": [evidence],
            }
        ],
    }


def _codeflow_result() -> dict[str, object]:
    node = {"id": "codeflow:function:src/a.py|1|a", "kind": "FUNCTION"}
    edge = {
        "id": "codeflow:edge:1",
        "source": node["id"],
        "target": "codeflow:file:src/b.js",
        "relation": "REFERENCES",
        "confidence": "HEURISTIC",
    }
    return {
        "source_revision": {"repository": "fixture-repo", "revision": "rev-1"},
        "query_scope": {
            "start": "codeflow:function:src/a.py|1|a",
            "target": "codeflow:file:src/b.js",
            "direction": "FORWARD",
            "requested_relations": [],
            "effective_relations": [],
            "rejected_relations": [],
            "stop_nodes": [],
            "evidence_namespace": "task38",
        },
        "nodes": [node],
        "edges": [edge],
        "blockers": [],
    }


def _custom_graph() -> GraphEvidenceModel:
    node = GraphEvidence(
        id="display:node:A",
        kind=GraphEvidenceKind.NODE,
        semantic_identity={"handle": "A"},
        exact_identity={"handle": "A", "file": "src/a.py"},
        confidence=EvidenceConfidence.EXACT,
        label="original-label",
    )
    return GraphEvidenceModel(
        provider_identity=ProviderImplementationIdentity(
            "display", "custom-impl", "custom-family", provider_kind="custom-kind"
        ),
        facts=GraphFacts(nodes=(node,)),
    )


def _atomic_claim(claim_id: str = "t38-path") -> AtomicClaim:
    return AtomicClaim(
        claim_id=claim_id,
        claim_kind=CodeGraphClaimKind.PATH_EXISTS.value,
        verifier=CODE_GRAPH_VERIFIER,
        spec={
            "source": "A",
            "target": "B",
            "relations": ["FLOWS_TO"],
            "scope": {
                "snapshot": {"repository": "fixture-repo", "revision": "rev-1"},
                "max_depth": 4,
                "max_paths": 8,
                "max_expansions": 64,
            },
            "evidence_namespace": "task38",
        },
    )


def _trusted_graphify(context: ProviderTrustContext, evidence_id: str, *, claim: Any | None = None) -> Evidence:
    with context.activate():
        return encode_graphify_code_graph_observation_evidence(
            _graphify_path_result(),
            evidence_id=evidence_id,
            claim=claim,
            claim_fingerprint=None if claim is not None else "task38.genuine.claim",
        )


def _trusted_graphify_v2(context: ProviderTrustContext, document: Mapping[str, Any], evidence_id: str) -> Evidence:
    with context.activate():
        return encode_graphify_structural_evidence_v2_observation_evidence(
            document,
            evidence_id=evidence_id,
            claim_fingerprint="task38.genuine.v2.claim",
        )


def _rebuild(evidence_id: str, payload: Mapping[str, Any]) -> Evidence:
    return Evidence(
        id=evidence_id,
        kind=CODE_GRAPH_OBSERVATION_EVIDENCE_KIND,
        payload=payload,
        source=str(payload["provider_id"]),
        fingerprint=canonical_fingerprint(
            payload,
            fingerprint_format=CODE_GRAPH_OBSERVATION_FINGERPRINT_FORMAT,
        ),
    )


def _transplant(
    genuine: Evidence,
    *,
    mutate_model: Callable[[dict], None] | None = None,
    claim_fingerprint: str | None = FORGED_CLAIM,
    new_id: str = "obs.forged",
) -> Evidence:
    """Build a forged observation that reuses the genuine provider-origin seal.

    The graph model is mutated, every public deterministic fingerprint and
    mirrored field is recomputed for internal consistency, but the recorded
    ``provider_origin`` (and its VERIFIED seal) is copied verbatim from the
    genuine observation. This is exactly the Drive Task38 bearer-token attack.
    """

    payload = deepcopy(dict(genuine.payload))
    model_document = deepcopy(payload["graph_model"])
    if mutate_model is not None:
        mutate_model(model_document)
    model = graph_model_from_dict(model_document)
    payload["graph_model"] = model.to_dict()
    payload["graph_model_fingerprint"] = model.fingerprint
    payload["source_snapshot"] = deepcopy(dict(model.source_snapshot))
    payload["authority_metadata"] = deepcopy(dict(model.authority_metadata))
    payload["source_revision"] = model.source_revision.to_dict()
    payload["query_scope"] = model.query_scope.to_dict()
    payload["coverage"] = model.coverage.to_dict()
    if claim_fingerprint is not None:
        payload["claim_fingerprint"] = claim_fingerprint
    return _rebuild(new_id, payload)


def _reorigin(source: Evidence, target: Evidence, *, new_id: str = "obs.reorigin") -> Evidence:
    """Copy only the origin/independence block from ``source`` onto ``target``."""
    payload = deepcopy(dict(target.payload))
    payload["provider_origin"] = deepcopy(source.payload["provider_origin"])
    payload["independence"] = deepcopy(source.payload["independence"])
    return _rebuild(new_id, payload)


def _mutate_node_label(document: dict) -> None:
    document["facts"]["nodes"][0]["label"] = "forged-label"


def _mutate_source_revision(document: dict) -> None:
    document["source_revision"]["revision"] = "forged-revision"


def _mutate_query_scope(document: dict) -> None:
    document["query_scope"]["max_depth"] = 99


def _mutate_coverage(document: dict) -> None:
    document["coverage"]["termination_reason"] = "FORWARDED_FORGERY"


def _mutate_v2_authority_metadata(document: dict) -> None:
    document["authority_metadata"]["snapshot_fingerprint"] = "0" * 64


def _must_reject(context: ProviderTrustContext, forged: Evidence, *, why: str) -> None:
    """Fail-closed requirement: a transplanted origin must never verify.

    On the vulnerable base the decode path accepts the copied seal and returns a
    VERIFIED validated origin, which makes this helper fail and demonstrates the
    exploit end to end.
    """
    with context.activate():
        try:
            decoded = decode_code_graph_observation_evidence(forged)
        except ValueError:
            return
    validated = decoded.validated_origin
    assert (
        validated is None or validated.trust_state is not IndependenceTrustState.VERIFIED
    ), f"content-transplanted observation reached VERIFIED provider origin ({why})"


def _decoded_under(context: ProviderTrustContext, evidence: Evidence):
    with context.activate():
        return decode_code_graph_observation_evidence(evidence)


def _codegraph_runtime() -> tuple[Any, Any]:
    capability = builtin_verifier_capability_registry().lookup(CODE_GRAPH_VERIFIER, "1")
    return _CodeGraphVerifierRuntime(capability), capability


def _issue_codes(report) -> set[str]:
    return {issue.code for issue in report.issues}


def _data_flow_claim(doc: dict, *, claim_id: str = "task38") -> DataFlowClaim:
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
        evidence_namespace="task38",
    )


# --------------------------------------------------------------------------- #
# Cases 1-6: content transplants must be rejected
# --------------------------------------------------------------------------- #


def test_task38_01_claim_fingerprint_transplant_is_rejected() -> None:
    context = _context()
    genuine = _trusted_graphify(context, "obs.e1")
    forged = _transplant(genuine, claim_fingerprint=FORGED_CLAIM)
    assert forged.payload["claim_fingerprint"] == FORGED_CLAIM
    assert forged.payload["provider_origin"] == genuine.payload["provider_origin"]
    assert forged.fingerprint != genuine.fingerprint
    _must_reject(context, forged, why="claim_fingerprint transplant")


def test_task38_02_graph_model_content_transplant_is_rejected() -> None:
    context = _context()
    genuine = _trusted_graphify(context, "obs.e1")
    forged = _transplant(genuine, mutate_model=_mutate_node_label, claim_fingerprint=None)
    assert forged.payload["graph_model_fingerprint"] != genuine.payload["graph_model_fingerprint"]
    _must_reject(context, forged, why="graph-model content transplant")


def test_task38_03_source_revision_transplant_is_rejected() -> None:
    context = _context()
    genuine = _trusted_graphify(context, "obs.e1")
    forged = _transplant(genuine, mutate_model=_mutate_source_revision, claim_fingerprint=None)
    assert forged.payload["source_revision"]["revision"] == "forged-revision"
    _must_reject(context, forged, why="source revision transplant")


@pytest.mark.parametrize("mutation", [_mutate_query_scope, _mutate_coverage])
def test_task38_04_query_and_coverage_transplants_are_rejected(mutation) -> None:
    context = _context()
    genuine = _trusted_graphify(context, "obs.e1")
    forged = _transplant(genuine, mutate_model=mutation, claim_fingerprint=None)
    _must_reject(context, forged, why=f"{mutation.__name__} transplant")


def test_task38_05_graphify_v2_authority_metadata_transplant_is_rejected() -> None:
    context = _context()
    genuine = _trusted_graphify_v2(context, clean_document(), "obs.e1.v2")
    forged = _transplant(
        genuine,
        mutate_model=_mutate_v2_authority_metadata,
        claim_fingerprint=None,
    )
    assert (
        forged.payload["authority_metadata"]["snapshot_fingerprint"]
        != genuine.payload["authority_metadata"]["snapshot_fingerprint"]
    )
    _must_reject(context, forged, why="graphify-v2 authority metadata transplant")


def test_task38_06_origin_cannot_move_to_another_genuine_v2_observation() -> None:
    context = _context()
    first = _trusted_graphify_v2(context, clean_document(), "obs.clean.v2")
    second = _trusted_graphify_v2(context, boundary_document(), "obs.boundary.v2")
    assert second.payload["graph_model_fingerprint"] != first.payload["graph_model_fingerprint"]
    forged = _reorigin(first, second)
    _must_reject(context, forged, why="origin moved to another genuine v2 snapshot")


# --------------------------------------------------------------------------- #
# Cases 7-9: replay and lifetime semantics (must keep working / failing)
# --------------------------------------------------------------------------- #


def test_task38_07_identical_replay_under_same_context_remains_verified() -> None:
    context = _context()
    genuine = _trusted_graphify(context, "obs.e1")
    first = _decoded_under(context, genuine)
    second = _decoded_under(context, genuine)
    assert first.validated_origin is not None
    assert second.validated_origin is not None
    assert first.validated_origin.trust_state is IndependenceTrustState.VERIFIED
    assert second.validated_origin.trust_state is IndependenceTrustState.VERIFIED


def test_task38_08_stored_assertion_without_active_context_stays_unverifiable() -> None:
    context = _context()
    genuine = _trusted_graphify(context, "obs.e1")
    with pytest.raises(CodeGraphObservationError):
        decode_code_graph_observation_evidence(genuine)


def test_task38_09_same_configuration_new_context_rejects_foreign_origin() -> None:
    issuer = _context()
    genuine = _trusted_graphify(issuer, "obs.e1")
    other = ProviderTrustContext.host_runtime(CONFIG_IDENTITY)
    with other.activate(), pytest.raises(CodeGraphObservationError):
        decode_code_graph_observation_evidence(genuine)


# --------------------------------------------------------------------------- #
# Cases 10-11: durable storage replay and tamper
# --------------------------------------------------------------------------- #


def test_task38_10_sqlite_same_context_replay_keeps_trust(tmp_path: Path) -> None:
    context = _context()
    genuine = _trusted_graphify(context, "obs.e1")
    original = _decoded_under(context, genuine)
    assert original.validated_origin is not None

    path = tmp_path / "task38.sqlite3"
    store = SQLiteStorage(path)
    stored = store.put_evidence(genuine)

    reopened = SQLiteStorage(path)
    reloaded = reopened.get_evidence(stored.fingerprint).evidence
    replayed = _decoded_under(context, reloaded)
    assert replayed.validated_origin is not None
    assert replayed.validated_origin.trust_state is IndependenceTrustState.VERIFIED
    assert replayed.origin_assertion.to_dict() == original.origin_assertion.to_dict()


def test_task38_11_sqlite_persisted_content_tamper_is_rejected(tmp_path: Path) -> None:
    context = _context()
    genuine = _trusted_graphify(context, "obs.e1")

    path = tmp_path / "task38.sqlite3"
    store = SQLiteStorage(path)
    stored = store.put_evidence(genuine)
    reloaded = SQLiteStorage(path).get_evidence(stored.fingerprint).evidence

    forged = _transplant(reloaded, mutate_model=_mutate_node_label, claim_fingerprint=None)
    _must_reject(context, forged, why="sqlite-persisted content tamper")


# --------------------------------------------------------------------------- #
# Cases 12-13: CodeFlow and host-registered custom providers
# --------------------------------------------------------------------------- #


def test_task38_12_codeflow_content_transplant_is_rejected() -> None:
    context = _context()
    with context.activate():
        genuine = encode_codeflow_code_graph_observation_evidence(
            _codeflow_result(),
            evidence_id="obs.codeflow.e1",
            claim_fingerprint="task38.genuine.codeflow.claim",
        )
    decoded = _decoded_under(context, genuine)
    assert decoded.validated_origin is not None
    forged = _transplant(genuine, mutate_model=_mutate_node_label, claim_fingerprint=None)
    _must_reject(context, forged, why="codeflow content transplant")


def test_task38_13_host_registered_custom_provider_transplant_is_rejected() -> None:
    context = _context(
        ProviderImplementationRegistration("custom-impl", "custom-kind", "custom-family"),
    )
    with context.activate():
        genuine = context.encode_code_graph_observation_evidence(
            _custom_graph(),
            evidence_id="obs.custom.e1",
            claim_fingerprint="task38.genuine.custom.claim",
        )
    decoded = _decoded_under(context, genuine)
    assert decoded.validated_origin is not None
    assert decoded.validated_origin.trust_state is IndependenceTrustState.VERIFIED
    forged = _transplant(genuine, mutate_model=_mutate_node_label, claim_fingerprint=None)
    _must_reject(context, forged, why="host-registered custom provider transplant")


# --------------------------------------------------------------------------- #
# Cases 14-15: corroboration and integrated executor cannot be manufactured
# --------------------------------------------------------------------------- #


def test_task38_14_two_transplanted_observations_cannot_manufacture_verdicts() -> None:
    context = _context()
    genuine = _trusted_graphify(context, "obs.e1")
    forged_a = _transplant(genuine, mutate_model=_mutate_node_label)
    forged_b = _transplant(
        genuine,
        mutate_model=lambda doc: doc["facts"].__setitem__(
            "absence_subjects", ["forged:absence"]
        ),
    )

    observations: list[object] = []
    for forged in (forged_a, forged_b):
        _must_reject(context, forged, why="manufactured corroboration input")
        observations.append(object())

    reconciled = reconcile_provider_observations(observations)
    codes = _issue_codes(reconciled)
    assert reconciled.verdict is VerificationVerdict.UNKNOWN
    assert codes & _CORROBORATION_CODES == set()
    assert "MALFORMED_GRAPH_EVIDENCE" in codes


def test_task38_15_integrated_executor_rejects_transplanted_observation() -> None:
    context = _context()
    claim = _atomic_claim()
    genuine = _trusted_graphify(context, "obs.e1", claim=claim)
    forged = _transplant(genuine, mutate_model=_mutate_node_label, claim_fingerprint=None)

    runtime, capability = _codegraph_runtime()
    with context.activate():
        report = runtime.verify(
            VerifierExecutionInput(
                claim=claim,
                capability=capability,
                acquisitions=(),
                evidence=(forged,),
                dependencies=(),
            )
        )
    codes = _issue_codes(report)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "MALFORMED_GRAPH_EVIDENCE" in codes
    assert codes & _CORROBORATION_CODES == set()


# --------------------------------------------------------------------------- #
# Case 16: existing mismatch precedence remains unchanged
# --------------------------------------------------------------------------- #


def test_task38_16_source_revision_mirror_mismatch_precedence_unchanged() -> None:
    context = _context()
    genuine = _trusted_graphify(context, "obs.e1")
    payload = deepcopy(dict(genuine.payload))
    payload["source_revision"] = {"repository": "other-repo", "revision": "other-rev"}
    tampered = _rebuild("obs.mirror-tampered", payload)
    with context.activate(), pytest.raises(CodeGraphObservationError, match="source revision mismatch"):
        decode_code_graph_observation_evidence(tampered)


def test_task38_16b_executor_claim_mismatch_precedence_unchanged() -> None:
    context = _context()
    genuine = _trusted_graphify(context, "obs.e1")
    other_claim = _atomic_claim("t38-other-path")

    runtime, capability = _codegraph_runtime()
    with context.activate():
        report = runtime.verify(
            VerifierExecutionInput(
                claim=other_claim,
                capability=capability,
                acquisitions=(),
                evidence=(genuine,),
                dependencies=(),
            )
        )
    codes = _issue_codes(report)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "CLAIM_FINGERPRINT_MISMATCH" in codes


# --------------------------------------------------------------------------- #
# Cases 17-18: Task37c producer vectors remain intact under trusted origin
# --------------------------------------------------------------------------- #


def test_task38_17_task37c_clean_identity_decisive_positive_preserved() -> None:
    context = _context()
    encoded = _trusted_graphify_v2(context, clean_document(), "obs.task37c.clean")
    decoded = _decoded_under(context, encoded)
    assert decoded.validated_origin is not None
    assert decoded.validated_origin.trust_state is IndependenceTrustState.VERIFIED

    document = clean_document()
    traversal = ingest_graphify_structural_evidence_v2(document).to_gvr_traversal_dict()
    authority = validate_graphify_envelope_authority(traversal)
    assert authority.positive_authorized is True
    assert authority.negative_authorized is False
    report = verify_data_flow_claim(_data_flow_claim(document), traversal)
    assert report.verdict.name == "PASS"
    assert any(issue.code == "PROVEN_SUPPORTED_PATH" for issue in report.issues)


def test_task38_18_task37c_boundary_identity_non_decisive_even_when_origin_verified() -> None:
    context = _context()
    encoded = _trusted_graphify_v2(context, boundary_document(), "obs.task37c.boundary")
    decoded = _decoded_under(context, encoded)
    assert decoded.validated_origin is not None
    assert decoded.validated_origin.trust_state is IndependenceTrustState.VERIFIED

    document = boundary_document()
    traversal = ingest_graphify_structural_evidence_v2(document).to_gvr_traversal_dict()
    authority = validate_graphify_envelope_authority(traversal)
    assert authority.positive_authorized is False
    assert authority.negative_authorized is False
    report = verify_data_flow_claim(_data_flow_claim(document), traversal)
    assert report.verdict.name == "UNKNOWN"
    codes = _issue_codes(report)
    assert "BLOCKING_BOUNDARY" in codes
    assert "MALFORMED_TRAVERSAL" not in codes
