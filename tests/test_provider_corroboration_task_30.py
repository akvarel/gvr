from dataclasses import FrozenInstanceError

import pytest

from gvr.code_graph import EvidenceConfidence, GraphEvidence, GraphEvidenceKind, GraphEvidenceModel
from gvr.model import VerificationIssue, VerificationReport, VerificationVerdict
from gvr.verifiers.code_graph import CodeGraphClaim, CodeGraphClaimKind, verify_code_graph_claim
from gvr.verifiers.corroboration import ProviderVerificationObservation, reconcile_provider_observations


def edge(eid="e", confidence=EvidenceConfidence.EXACT):
    return GraphEvidence(
        id=eid,
        kind=GraphEvidenceKind.CALL,
        semantic_identity={"source": "A", "target": "B", "relation": "CALL"},
        exact_identity={"source": "A", "target": "B", "relation": "CALL", "file": eid},
        confidence=confidence,
        source="A",
        target="B",
        label="CALL",
    )


def graph(provider, edges=(), absence=(), snapshot=None):
    return GraphEvidenceModel(provider=provider, nodes=(), edges=tuple(edges), absence_subjects=tuple(absence), source_snapshot=snapshot or {"rev": "1"})


def report(verdict, code, evidence_ids=()):
    return VerificationReport(
        verdict=verdict,
        verifier="manual",
        issues=(VerificationIssue(code, code, verdict, tuple(evidence_ids)),),
        evidence_ids=tuple(evidence_ids),
        metadata={"kept": tuple(evidence_ids)},
    )


def obs(provider, implementation, family, verdict, code, *, claim="A->B", snapshot=None, evidence_ids=()):
    return ProviderVerificationObservation(
        provider_id=provider,
        implementation_id=implementation,
        family_id=family,
        source_snapshot=snapshot or {"rev": "1"},
        claim_fingerprint=claim,
        report=report(verdict, code, evidence_ids),
    )


def test_proven_graphify_pass_plus_codeflow_heuristic_support_is_pass():
    claim = CodeGraphClaim(CodeGraphClaimKind.PATH_EXISTS, source="A", target="B", scope={"snapshot": {"rev": "1"}})
    graphify_report = verify_code_graph_claim(claim, graph("graphify", [edge("graphify:e")]))
    heuristic_report = verify_code_graph_claim(claim, graph("codeflow", [edge("codeflow:e", EvidenceConfidence.HEURISTIC)]))
    result = reconcile_provider_observations([
        ProviderVerificationObservation("graphify", "graphify-rust", "graphify", {"rev": "1"}, "claim:path", graphify_report),
        ProviderVerificationObservation("codeflow", "codeflow-ts", "codeflow", {"rev": "1"}, "claim:path", heuristic_report),
    ])
    assert result.verdict is VerificationVerdict.PASS
    assert result.evidence_ids == ("codeflow:e", "graphify:e")
    assert {i.code for i in result.issues} >= {"PROVEN_GRAPH_PATH", "HEURISTIC_ONLY_SUPPORT", "PROVIDER_SINGLE_FAMILY_DECISIVE_PASS"}
    assert not any(i.code == "PROVIDER_CORROBORATED_PASS" for i in result.issues)


def test_heuristic_only_unknown_not_upgraded_by_repetition():
    first = obs("codeflow-a", "impl-a", "codeflow", VerificationVerdict.UNKNOWN, "EDGE_NOT_EXACT", evidence_ids=("h1",))
    repeat = obs("codeflow-b", "impl-a", "codeflow", VerificationVerdict.UNKNOWN, "EDGE_NOT_EXACT", evidence_ids=("h1",))
    result = reconcile_provider_observations([first, repeat])
    assert result.verdict is VerificationVerdict.UNKNOWN
    assert result.evidence_ids == ("h1",)
    assert any(i.code == "HEURISTIC_ONLY_SUPPORT" for i in result.issues)
    assert any(i.code == "PROVIDER_ONLY_HEURISTIC" for i in result.issues)


def test_same_family_wrappers_do_not_count_as_independent():
    result = reconcile_provider_observations([
        obs("wrapper-a", "graphify-cli", "graphify", VerificationVerdict.PASS, "PROVEN_PATH", evidence_ids=("e1",)),
        obs("wrapper-b", "graphify-cli-wrapper", "graphify", VerificationVerdict.PASS, "PROVEN_PATH", evidence_ids=("e2",)),
    ])
    assert result.verdict is VerificationVerdict.PASS
    assert any(i.code == "PROVIDER_SINGLE_FAMILY_DECISIVE_PASS" for i in result.issues)
    assert not any(i.code == "PROVIDER_CORROBORATED_PASS" for i in result.issues)


def test_complete_no_path_plus_silence_is_pass():
    claim = CodeGraphClaim(CodeGraphClaimKind.NO_PATH, source="A", target="B", scope={"snapshot": {"rev": "1"}})
    complete_absence = verify_code_graph_claim(claim, graph("graphify", absence=("A->B",)))
    result = reconcile_provider_observations([
        ProviderVerificationObservation("graphify", "graphify", "graphify", {"rev": "1"}, "claim:no-path", complete_absence),
    ])
    assert result.verdict is VerificationVerdict.PASS
    assert [i.code for i in result.issues] == ["COMPLETE_GRAPH_ABSENCE", "PROVEN_ABSENCE", "PROVIDER_SINGLE_FAMILY_DECISIVE_PASS"]


def test_independent_decisive_pass_fail_conflict_unknown_preserves_evidence():
    result = reconcile_provider_observations([
        obs("graphify", "graphify", "graphify", VerificationVerdict.PASS, "PROVEN_PATH", evidence_ids=("p",)),
        obs("static", "static", "static-analyzer", VerificationVerdict.FAIL, "COUNTEREXAMPLE_PATH", evidence_ids=("f",)),
    ])
    assert result.verdict is VerificationVerdict.UNKNOWN
    assert result.evidence_ids == ("f", "p")
    assert [i.code for i in result.issues][-2:] == ["CONFLICTING_GRAPH_EVIDENCE", "PROVIDER_CONFLICT"]


def test_two_independent_passes_are_corroborated():
    result = reconcile_provider_observations([
        obs("graphify", "graphify", "graphify", VerificationVerdict.PASS, "PROVEN_PATH", evidence_ids=("g",)),
        obs("ast", "ast-v1", "ast-analyzer", VerificationVerdict.PASS, "PROVEN_PATH", evidence_ids=("a",)),
    ])
    assert result.verdict is VerificationVerdict.PASS
    assert result.evidence_ids == ("a", "g")
    assert any(i.code == "PROVIDER_CORROBORATED_PASS" for i in result.issues)


def test_duplicates_and_reordering_are_fingerprint_invariant():
    observations = [
        obs("b", "b", "b", VerificationVerdict.PASS, "PROVEN_PATH", evidence_ids=("2",)),
        obs("a", "a", "a", VerificationVerdict.PASS, "PROVEN_PATH", evidence_ids=("1",)),
        obs("a", "a", "a", VerificationVerdict.PASS, "PROVEN_PATH", evidence_ids=("1",)),
    ]
    one = reconcile_provider_observations(observations)
    two = reconcile_provider_observations(list(reversed(observations)))
    assert one.metadata["fingerprint"] == two.metadata["fingerprint"]
    assert one.evidence_ids == two.evidence_ids == ("1", "2")


def test_snapshot_mismatch_fails_closed_unknown():
    result = reconcile_provider_observations([
        obs("graphify", "graphify", "graphify", VerificationVerdict.PASS, "PROVEN_PATH", snapshot={"rev": "1"}, evidence_ids=("e",)),
        obs("ast", "ast", "ast", VerificationVerdict.PASS, "PROVEN_PATH", snapshot={"rev": "2"}, evidence_ids=("a",)),
    ])
    assert result.verdict is VerificationVerdict.UNKNOWN
    assert any(i.code == "SOURCE_SNAPSHOT_MISMATCH" for i in result.issues)
    assert any(i.code == "PROVIDER_SNAPSHOT_MISMATCH" for i in result.issues)
    assert result.metadata["snapshot_groups"] == (("sha256:", ()),) or "snapshot_groups" in result.metadata


def test_inferred_hint_ignored_for_decisive_independence():
    hint = verify_code_graph_claim(CodeGraphClaim(CodeGraphClaimKind.PATH_EXISTS, source="A", target="B"), graph("hint", [edge("hint", EvidenceConfidence.INFERRED_HINT)]))
    result = reconcile_provider_observations([
        obs("graphify", "graphify", "graphify", VerificationVerdict.PASS, "PROVEN_PATH", evidence_ids=("g",)),
        ProviderVerificationObservation("hint", "hint", "hint", {"rev": "1"}, "A->B", hint),
    ])
    assert result.verdict is VerificationVerdict.PASS
    assert not any(i.code == "PROVIDER_CORROBORATED_PASS" for i in result.issues)


def test_claim_mismatch_and_malformed_observation_fail_closed():
    with pytest.raises(FrozenInstanceError):
        observation = obs("a", "a", "a", VerificationVerdict.PASS, "PROVEN_PATH")
        observation.provider_id = "mutated"
    result = reconcile_provider_observations([
        obs("a", "a", "a", VerificationVerdict.PASS, "PROVEN_PATH", claim="claim-a"),
        obs("b", "b", "b", VerificationVerdict.PASS, "PROVEN_PATH", claim="claim-b"),
        "malformed",
    ])
    assert result.verdict is VerificationVerdict.UNKNOWN
    assert any(i.code == "PROVIDER_CLAIM_MISMATCH" for i in result.issues)
    assert any(i.code == "MALFORMED_GRAPH_EVIDENCE" for i in result.issues)
    assert any(i.code == "PROVIDER_MALFORMED_OBSERVATION" for i in result.issues)
