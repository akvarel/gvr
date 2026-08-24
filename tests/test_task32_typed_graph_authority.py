from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from gvr import (
    CoverageCertificate,
    GraphFacts,
    GraphQueryScope,
    ProviderImplementationIdentity,
    SourceRevisionIdentity,
)
from gvr.code_graph import (
    CodeGraphObservationError,
    EvidenceConfidence,
    GraphEvidence,
    GraphEvidenceKind,
    GraphEvidenceModel,
    decode_code_graph_observation_evidence,
    encode_code_graph_observation_evidence,
    graph_model_from_dict,
)
from gvr.verifiers.code_graph import (
    CodeGraphClaim,
    CodeGraphClaimKind,
    CodeGraphScope,
    verify_code_graph_observation,
)
from gvr.model import VerificationVerdict


def revision(value: str = "abc123") -> SourceRevisionIdentity:
    return SourceRevisionIdentity(repository="fixture-repo", revision=value)


def query_scope(*, max_depth: int = 4) -> GraphQueryScope:
    return GraphQueryScope(
        start="A",
        target="B",
        direction="FORWARD",
        relations=frozenset({"CALL"}),
        max_depth=max_depth,
        stop_nodes=frozenset(),
        evidence_namespace="task32",
    )


def coverage(*, complete: bool = True) -> CoverageCertificate:
    return CoverageCertificate(
        coverage="COMPLETE_FOR_SUPPORTED_CONSTRUCT" if complete else "PARTIAL",
        complete_supported_search=complete,
        termination_reason="COMPLETE" if complete else "LIMIT_REACHED",
        truncated=not complete,
    )


def edge() -> GraphEvidence:
    return GraphEvidence(
        id="edge:A:B",
        kind=GraphEvidenceKind.CALL,
        semantic_identity={"source": "A", "target": "B", "relation": "CALL"},
        exact_identity={"source": "A", "target": "B", "relation": "CALL", "location": "a.py:1"},
        confidence=EvidenceConfidence.EXACT,
        source="A",
        target="B",
        label="CALL",
    )


def model(*, rev: SourceRevisionIdentity | None = None, scope: GraphQueryScope | None = None) -> GraphEvidenceModel:
    return GraphEvidenceModel(
        provider_identity=ProviderImplementationIdentity(
            provider_id="fixture",
            implementation_id="fixture@1.2.3",
            family_id="fixture",
        ),
        source_revision=rev or revision(),
        query_scope=scope or query_scope(),
        coverage=coverage(),
        facts=GraphFacts(nodes=(), edges=(edge(),)),
    )


def claim(*, rev: SourceRevisionIdentity | None = None, scope: GraphQueryScope | None = None) -> CodeGraphClaim:
    typed_scope = scope or query_scope()
    return CodeGraphClaim(
        kind=CodeGraphClaimKind.EDGE_EXISTS,
        source="A",
        target="B",
        relations=frozenset({"CALL"}),
        scope=CodeGraphScope(
            source_revision=rev or revision(),
            query_scope=typed_scope,
        ),
        evidence_namespace="task32",
    )


def test_task32_typed_authorities_are_frozen_canonical_and_distinct() -> None:
    graph = model()

    with pytest.raises(FrozenInstanceError):
        graph.source_revision.revision = "other"  # type: ignore[misc]

    assert graph.to_dict() == {
        "provider_identity": {
            "provider_id": "fixture",
            "implementation_id": "fixture@1.2.3",
            "family_id": "fixture",
        },
        "source_revision": {"repository": "fixture-repo", "revision": "abc123"},
        "query_scope": {
            "start": "A",
            "target": "B",
            "direction": "FORWARD",
            "relations": ("CALL",),
            "max_depth": 4,
            "stop_nodes": (),
            "evidence_namespace": "task32",
        },
        "coverage": {
            "coverage": "COMPLETE_FOR_SUPPORTED_CONSTRUCT",
            "complete_supported_search": True,
            "termination_reason": "COMPLETE",
            "truncated": False,
            "details": {},
        },
        "facts": {
            "nodes": [],
            "edges": [edge().to_dict()],
            "blockers": [],
            "absence_subjects": (),
        },
    }
    assert "source_revision" not in graph.query_scope.to_dict()
    assert "coverage" not in graph.facts.to_dict()


def test_task32_model_and_observation_fingerprints_are_order_invariant_and_replay_exact() -> None:
    a = model()
    b = replace(a, facts=GraphFacts(nodes=(), edges=tuple(reversed(a.edges))))
    assert a.fingerprint == b.fingerprint

    evidence = encode_code_graph_observation_evidence(a, evidence_id="obs.1", claim_fingerprint="claim")
    replay = decode_code_graph_observation_evidence(evidence)
    assert replay.graph_model == a
    assert replay.graph_model_fingerprint == a.fingerprint
    assert graph_model_from_dict(a.to_dict()) == a

    changed_revision = replace(a, source_revision=revision("def456"))
    changed_scope = replace(a, query_scope=query_scope(max_depth=3))
    changed_coverage = replace(a, coverage=coverage(complete=False))
    changed_provider = replace(
        a,
        provider_identity=ProviderImplementationIdentity("fixture", "fixture@2", "fixture"),
    )
    assert len({a.fingerprint, changed_revision.fingerprint, changed_scope.fingerprint, changed_coverage.fingerprint, changed_provider.fingerprint}) == 5


def test_task32_encoder_uses_typed_provider_identity_and_rejects_authority_overrides() -> None:
    graph = model()
    evidence = encode_code_graph_observation_evidence(
        graph,
        evidence_id="obs.typed",
        claim_fingerprint="claim",
    )
    decoded = decode_code_graph_observation_evidence(evidence)
    assert decoded.provider_identity == graph.provider_identity
    assert decoded.source_revision == graph.source_revision
    assert decoded.query_scope == graph.query_scope
    assert decoded.coverage == graph.coverage

    with pytest.raises(CodeGraphObservationError, match="authority override"):
        encode_code_graph_observation_evidence(
            graph,
            evidence_id="obs.bad",
            claim_fingerprint="claim",
            implementation_id="caller-forged",
        )
    with pytest.raises(CodeGraphObservationError, match="authority override"):
        encode_code_graph_observation_evidence(
            graph,
            evidence_id="obs.bad-snapshot",
            claim_fingerprint="claim",
            source_snapshot={"revision": "caller-forged"},
        )


def test_task32_decoder_rejects_cross_field_authority_tampering() -> None:
    evidence = encode_code_graph_observation_evidence(model(), evidence_id="obs.1", claim_fingerprint="claim")
    tampered_payload = dict(evidence.payload)
    tampered_payload["source_revision"] = {"repository": "fixture-repo", "revision": "other"}
    tampered = replace(evidence, payload=tampered_payload)
    with pytest.raises(CodeGraphObservationError, match="source revision"):
        decode_code_graph_observation_evidence(tampered)


def test_task32_generic_verifier_requires_exact_revision_and_query_scope_binding() -> None:
    exact = verify_code_graph_observation(claim(), model())
    assert exact.verdict is VerificationVerdict.PASS
    assert "PROVEN_EDGE" in {issue.code for issue in exact.issues}

    wrong_revision = verify_code_graph_observation(claim(rev=revision("other")), model())
    assert wrong_revision.verdict is VerificationVerdict.UNKNOWN
    assert "SOURCE_REVISION_MISMATCH" in {issue.code for issue in wrong_revision.issues}

    wrong_scope = verify_code_graph_observation(claim(scope=query_scope(max_depth=3)), model())
    assert wrong_scope.verdict is VerificationVerdict.UNKNOWN
    assert "GRAPH_QUERY_SCOPE_MISMATCH" in {issue.code for issue in wrong_scope.issues}


def test_task32_negative_authority_requires_complete_coverage_certificate() -> None:
    absent_facts = GraphFacts(nodes=(), edges=(), absence_subjects=("A->B",))
    no_path_claim = CodeGraphClaim(
        kind=CodeGraphClaimKind.NO_PATH,
        source="A",
        target="B",
        relations=frozenset({"CALL"}),
        scope=CodeGraphScope(source_revision=revision(), query_scope=query_scope()),
        evidence_namespace="task32",
    )
    complete_model = replace(model(), facts=absent_facts)
    partial_model = replace(complete_model, coverage=coverage(complete=False))

    assert verify_code_graph_observation(no_path_claim, complete_model).verdict is VerificationVerdict.PASS
    partial = verify_code_graph_observation(no_path_claim, partial_model)
    assert partial.verdict is VerificationVerdict.UNKNOWN
    assert "INCOMPLETE_COVERAGE_CERTIFICATE" in {issue.code for issue in partial.issues}


def test_task32_legacy_flat_graph_documents_fail_closed_instead_of_guessing_authority() -> None:
    legacy = {
        "provider": "fixture",
        "source_snapshot": {"repository": "fixture-repo", "revision": "abc123"},
        "nodes": [],
        "edges": [edge().to_dict()],
        "blockers": [],
        "absence_subjects": (),
    }
    with pytest.raises(CodeGraphObservationError, match="typed authority"):
        graph_model_from_dict(legacy)
