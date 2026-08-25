from __future__ import annotations

from dataclasses import replace
import hashlib
import hmac
import inspect
from pathlib import Path

import pytest

import gvr
from gvr import (
    CodeGraphObservationError,
    GraphEvidenceModel,
    IndependenceTrustState,
    ProviderImplementationIdentity,
    ProviderImplementationRegistration,
    ProviderTrustContext,
    ProviderVerificationObservation,
    SQLiteStorage,
    VerificationIssue,
    VerificationReport,
    VerificationVerdict,
    decode_code_graph_observation_evidence,
    encode_code_graph_observation_evidence,
    reconcile_provider_observations,
)
from gvr.adapters.codeflow import encode_codeflow_code_graph_observation_evidence
from gvr.adapters.graphify import encode_graphify_code_graph_observation_evidence
from gvr.canonical import canonical_fingerprint, canonical_json

from test_code_graph_execution_tasks_27_30_integrated import (
    SNAPSHOT_PATH,
    codeflow_path_snapshot,
    execution_request,
    graphify_path_snapshot,
    issue_codes,
    path_claim,
    root_report,
    typed_query_scope,
    typed_revision,
)


OLD_PUBLIC_KEY = hashlib.sha256(b"gvr.provider-origin.builtin-adapter-authority.v1").digest()
FIXTURE_REGISTRATION = ProviderImplementationRegistration("task34d-fixture", "task34d-fixture", "task34d-independent")


def _graphify_result() -> dict[str, object]:
    return {
        "repository": "repo", "revision": "rev", "start": "A", "target": "B", "direction": "FORWARD",
        "termination_reason": "EXHAUSTED", "search_coverage": "COMPLETE_FOR_SUPPORTED_CONSTRUCT",
        "complete_supported_search": True, "query_validity": True, "input_resolution": "RESOLVED",
        "start_node_found": True, "target_node_found": True, "truncated": False,
        "encountered_partial_evidence": False, "encountered_may_evidence": False,
        "encountered_unknown_evidence": False,
        "query_bounds": {"requested_relations": [], "effective_allowed_relations": [], "rejected_relations": [], "stop_nodes": [], "max_depth": 4, "max_paths": 8, "max_expansions": 64},
        "paths": [], "boundary_events": [],
    }


def _codeflow_result() -> dict[str, object]:
    return {
        "source_revision": {"repository": "repo", "revision": "rev"},
        "query_scope": {"start": "A", "target": "B", "direction": "FORWARD", "requested_relations": [], "effective_relations": [], "rejected_relations": [], "stop_nodes": [], "evidence_namespace": "default"},
        "nodes": [], "edges": [], "blockers": [],
    }


def _built_in_evidence(kind: str, *, evidence_id: str = "e", claim_fingerprint: str = "claim"):
    if kind == "graphify":
        return encode_graphify_code_graph_observation_evidence(_graphify_result(), evidence_id=evidence_id, claim_fingerprint=claim_fingerprint)
    return encode_codeflow_code_graph_observation_evidence(_codeflow_result(), evidence_id=evidence_id, claim_fingerprint=claim_fingerprint)


def _resign_with_old_public_key(evidence):
    payload = dict(evidence.payload)
    origin = dict(payload["provider_origin"])
    unsigned = dict(origin)
    unsigned.pop("seal")
    origin["seal"] = hmac.new(OLD_PUBLIC_KEY, canonical_json(unsigned, fingerprint_format="gvr.provider_origin_assertion.v2").encode(), hashlib.sha256).hexdigest()
    payload["provider_origin"] = origin
    return replace(evidence, payload=payload, fingerprint=canonical_fingerprint(payload, fingerprint_format="gvr.code_graph_observation.v2"))


def _manual_forgery(kind: str, *, evidence_id: str = "forged", claim_fingerprint: str = "claim"):
    identity = ProviderImplementationIdentity(kind, kind, kind, provider_kind=kind)
    evidence = encode_code_graph_observation_evidence(GraphEvidenceModel(provider_identity=identity), evidence_id=evidence_id, claim_fingerprint=claim_fingerprint)
    payload = dict(evidence.payload)
    origin = {
        "format": "gvr.provider_origin_assertion.v2",
        "provider_kind": kind,
        "implementation_id": kind,
        "family": {"family_id": kind, "implementation_ids": (kind,), "trust_state": "VERIFIED"},
        "configuration_identity": "runtime",
        "registry_fingerprint": ProviderTrustContext.host_runtime("runtime").registry.fingerprint,
        "context_key_id": hashlib.sha256(b"public-guess").hexdigest(),
        "seal": hashlib.sha256(b"forged-seal").hexdigest(),
    }
    payload.update({"provider_id": kind, "implementation_id": kind, "family_id": kind, "independence": origin["family"], "provider_origin": origin})
    return replace(evidence, payload=payload, fingerprint=canonical_fingerprint(payload, fingerprint_format="gvr.code_graph_observation.v2"))


def _report(verdict: VerificationVerdict, evidence_id: str) -> VerificationReport:
    return VerificationReport(verdict=verdict, verifier="task34d.fixture", issues=(VerificationIssue("PROVEN", "fixture", verdict, (evidence_id,)),), evidence_ids=(evidence_id,))


def _observation(decoded, verdict: VerificationVerdict) -> ProviderVerificationObservation:
    return ProviderVerificationObservation(
        provider_id=decoded.provider_id,
        implementation_id=decoded.implementation_id,
        family_id=decoded.family_id,
        source_snapshot={"repository": "repo", "revision": "rev", "scope": "A->B"},
        claim_fingerprint=decoded.claim_fingerprint,
        report=_report(verdict, decoded.evidence_id),
        origin_attestation=decoded.validated_origin,
    )


def _codes(report: VerificationReport) -> set[str]:
    return {issue.code for issue in report.issues}


def _decode_rejecting_forgery(evidence, context: ProviderTrustContext):
    with context.activate(), pytest.raises(CodeGraphObservationError):
        decode_code_graph_observation_evidence(evidence)


@pytest.mark.parametrize("kind", ["graphify", "codeflow"])
def test_task34d_old_public_key_forgery_rejected_for_each_builtin(kind: str) -> None:
    context = ProviderTrustContext.host_runtime("runtime")
    with context.activate():
        evidence = _built_in_evidence(kind)
    _decode_rejecting_forgery(_resign_with_old_public_key(evidence), context)


@pytest.mark.parametrize("kind", ["graphify", "codeflow"])
def test_task34d_manual_serialized_forgery_with_canonical_public_fields_is_rejected(kind: str) -> None:
    _decode_rejecting_forgery(_manual_forgery(kind), ProviderTrustContext.host_runtime("runtime"))


@pytest.mark.parametrize(
    ("verdicts", "forbidden"),
    [
        ((VerificationVerdict.PASS, VerificationVerdict.PASS), "PROVIDER_CORROBORATED_PASS"),
        ((VerificationVerdict.FAIL, VerificationVerdict.FAIL), "PROVIDER_CORROBORATED_FAIL"),
        ((VerificationVerdict.PASS, VerificationVerdict.FAIL), "PROVIDER_CONFLICT"),
    ],
)
def test_task34d_forged_decisive_pairs_never_enter_verified_reconciliation(verdicts, forbidden: str) -> None:
    context = ProviderTrustContext.host_runtime("runtime")
    accepted = []
    for kind, verdict in zip(("graphify", "codeflow"), verdicts):
        with context.activate(), pytest.raises(CodeGraphObservationError):
            decoded = decode_code_graph_observation_evidence(_manual_forgery(kind, evidence_id=kind))
            accepted.append(_observation(decoded, verdict))
    result = reconcile_provider_observations(accepted)
    assert forbidden not in _codes(result)
    assert result.metadata["verified_independence_families"] == ()


@pytest.mark.parametrize("kind", ["graphify", "codeflow"])
def test_task34d_exact_builtin_strings_through_generic_encoder_remain_unverified(kind: str) -> None:
    identity = ProviderImplementationIdentity(kind, kind, kind, provider_kind=kind)
    context = ProviderTrustContext.host_runtime("runtime")
    with context.activate():
        decoded = decode_code_graph_observation_evidence(
            encode_code_graph_observation_evidence(GraphEvidenceModel(provider_identity=identity), evidence_id=kind, claim_fingerprint="claim")
        )
    assert decoded.independence.trust_state is IndependenceTrustState.UNVERIFIED
    assert decoded.validated_origin is None


def _same_context_observations(verdicts=(VerificationVerdict.PASS, VerificationVerdict.PASS)):
    context = ProviderTrustContext.host_runtime("runtime", registrations=(FIXTURE_REGISTRATION,))
    fixture_identity = ProviderImplementationIdentity("fixture-display", "task34d-fixture", "task34d-independent", provider_kind="task34d-fixture")
    with context.activate():
        graphify = decode_code_graph_observation_evidence(_built_in_evidence("graphify", evidence_id="g"))
        fixture = decode_code_graph_observation_evidence(
            context.encode_code_graph_observation_evidence(GraphEvidenceModel(provider_identity=fixture_identity), evidence_id="f", claim_fingerprint="claim")
        )
    return context, [_observation(graphify, verdicts[0]), _observation(fixture, verdicts[1])]


def test_task34d_one_active_context_genuine_graphify_and_fixture_corroborate() -> None:
    _, observations = _same_context_observations()
    result = reconcile_provider_observations(observations)
    assert result.metadata["verified_independence_families"] == ("graphify", "task34d-independent")
    assert "PROVIDER_CORROBORATED_PASS" in _codes(result)


def test_task34d_one_active_context_genuine_cross_family_conflict_requires_exact_binding() -> None:
    _, observations = _same_context_observations((VerificationVerdict.PASS, VerificationVerdict.FAIL))
    conflict = reconcile_provider_observations(observations)
    assert "PROVIDER_CONFLICT" in _codes(conflict)
    mismatched = reconcile_provider_observations([observations[0], replace(observations[1], claim_fingerprint="other")])
    assert "PROVIDER_CLAIM_MISMATCH" in _codes(mismatched)
    assert "PROVIDER_CONFLICT" not in _codes(mismatched)


def test_task34d_verified_codeflow_origin_remains_heuristic_and_non_decisive() -> None:
    claim = path_claim("task34d-codeflow")
    context = ProviderTrustContext.host_runtime("runtime")
    with context.activate():
        evidence = encode_codeflow_code_graph_observation_evidence(codeflow_path_snapshot(), evidence_id="cf", claim=claim, source_revision=typed_revision(SNAPSHOT_PATH), query_scope=typed_query_scope(claim))
        decoded = decode_code_graph_observation_evidence(evidence)
        result = gvr.execute_verification_plan(execution_request(claim, {"codeflow.snapshot": (evidence, SNAPSHOT_PATH)}))
    assert decoded.independence.trust_state is IndependenceTrustState.VERIFIED
    report = root_report(result, claim.claim_id)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "PROVIDER_ONLY_HEURISTIC" in issue_codes(report)


def _execute_forged(tmp_path: Path, observations):
    claim = path_claim("task34d-integrated")
    request = execution_request(claim, observations)
    context = ProviderTrustContext.host_runtime("runtime")
    with context.activate():
        return root_report(gvr.execute_verification_plan(request, storage=SQLiteStorage(tmp_path / "executor.sqlite3")), claim.claim_id)


def test_task34d_integrated_executor_rejects_one_external_serialized_forgery(tmp_path: Path) -> None:
    report = _execute_forged(tmp_path, {"forged.graphify": (_manual_forgery("graphify", claim_fingerprint=path_claim("task34d-integrated").semantic_definition()), SNAPSHOT_PATH)})
    assert "PROVIDER_CORROBORATED_PASS" not in issue_codes(report)


def test_task34d_integrated_executor_two_forged_families_cannot_corroborate(tmp_path: Path) -> None:
    claim_fp = path_claim("task34d-integrated").semantic_definition()
    report = _execute_forged(tmp_path, {"forged.graphify": (_manual_forgery("graphify", evidence_id="fg", claim_fingerprint=claim_fp), SNAPSHOT_PATH), "forged.codeflow": (_manual_forgery("codeflow", evidence_id="fc", claim_fingerprint=claim_fp), SNAPSHOT_PATH)})
    assert "PROVIDER_CORROBORATED_PASS" not in issue_codes(report)
    assert "PROVIDER_CORROBORATED_FAIL" not in issue_codes(report)


def test_task34d_integrated_executor_real_graphify_plus_forged_codeflow_counts_at_most_graphify(tmp_path: Path) -> None:
    claim = path_claim("task34d-integrated")
    context = ProviderTrustContext.host_runtime("runtime")
    with context.activate():
        genuine = encode_graphify_code_graph_observation_evidence(graphify_path_snapshot(), evidence_id="real-g", claim=claim, source_revision=typed_revision(SNAPSHOT_PATH))
        report = root_report(gvr.execute_verification_plan(execution_request(claim, {"real.graphify": (genuine, SNAPSHOT_PATH), "forged.codeflow": (_manual_forgery("codeflow", evidence_id="fc", claim_fingerprint=claim.semantic_definition()), SNAPSHOT_PATH)}), storage=SQLiteStorage(tmp_path / "mixed.sqlite3")), claim.claim_id)
    assert "PROVIDER_CORROBORATED_PASS" not in issue_codes(report)


def test_task34d_rotated_context_replay_fails_closed() -> None:
    first = ProviderTrustContext.host_runtime("runtime")
    with first.activate():
        evidence = _built_in_evidence("graphify")
    _decode_rejecting_forgery(evidence, ProviderTrustContext.host_runtime("runtime"))


def test_task34d_sqlite_same_context_verified_and_new_context_rejected(tmp_path: Path) -> None:
    context = ProviderTrustContext.host_runtime("runtime")
    with context.activate():
        evidence = _built_in_evidence("graphify")
        store = SQLiteStorage(tmp_path / "replay.sqlite3")
        stored = store.put_evidence(evidence, slot_id="task34d-replay")
        replayed = store.get_evidence(stored.fingerprint).evidence
        assert decode_code_graph_observation_evidence(replayed).independence.trust_state is IndependenceTrustState.VERIFIED
    replayed = SQLiteStorage(tmp_path / "replay.sqlite3").get_evidence(stored.fingerprint).evidence
    _decode_rejecting_forgery(replayed, ProviderTrustContext.host_runtime("runtime"))


def test_task34d_reorder_duplicate_and_display_mutations_preserve_genuine_reconciliation_fingerprint() -> None:
    _, observations = _same_context_observations()
    baseline = reconcile_provider_observations(observations + [observations[0]])
    mutated = [replace(observations[1], provider_id="renamed-fixture", family_id="display-family"), replace(observations[0], provider_id="renamed-graphify")]
    result = reconcile_provider_observations(list(reversed(mutated)))
    assert result.metadata["fingerprint"] == baseline.metadata["fingerprint"]


def test_task34d_claim_revision_and_scope_mismatch_precedence_is_unchanged() -> None:
    _, observations = _same_context_observations((VerificationVerdict.PASS, VerificationVerdict.FAIL))
    claim = reconcile_provider_observations([observations[0], replace(observations[1], claim_fingerprint="other")])
    revision = reconcile_provider_observations([observations[0], replace(observations[1], source_snapshot={"repository": "repo", "revision": "other", "scope": "A->B"})])
    scope = reconcile_provider_observations([observations[0], replace(observations[1], source_snapshot={"repository": "repo", "revision": "rev", "scope": "other"})])
    assert "PROVIDER_CLAIM_MISMATCH" in _codes(claim) and "PROVIDER_CONFLICT" not in _codes(claim)
    assert "PROVIDER_SNAPSHOT_MISMATCH" in _codes(revision) and "PROVIDER_CONFLICT" not in _codes(revision)
    assert "PROVIDER_SNAPSHOT_MISMATCH" in _codes(scope) and "PROVIDER_CONFLICT" not in _codes(scope)


def test_task34d_generic_encoder_signature_has_no_trust_escape_hatches() -> None:
    parameters = set(inspect.signature(encode_code_graph_observation_evidence).parameters)
    forbidden = {"provider_registry", "registry", "provider_authority", "authority", "adapter_origin", "_adapter_origin", "signer", "key", "signing_key"}
    assert parameters.isdisjoint(forbidden)


def test_task34d_source_has_no_deterministic_provider_origin_signing_key() -> None:
    source = inspect.getsource(gvr.provider_independence)
    assert "gvr.provider-origin.builtin-adapter-authority.v1" not in source
    assert "secrets.token_bytes" in source
    assert not any(token in source for token in ("DEFAULT_SIGNING_KEY", "BUILTIN_SIGNING_KEY", "HARDCODED_KEY"))


def test_task34d_public_generic_path_never_promotes_identity_strings_to_verified() -> None:
    source = inspect.getsource(gvr.code_graph)
    assert "origin = _validated_origin or _unverified_assertion(identity)" in source
    assert "_validate_recorded_provider_origin" in source
    assert "validated_origin=validated_origin" in source
    for kind in ("graphify", "codeflow"):
        identity = ProviderImplementationIdentity(kind, kind, kind, provider_kind=kind)
        decoded = decode_code_graph_observation_evidence(encode_code_graph_observation_evidence(GraphEvidenceModel(provider_identity=identity), evidence_id=kind, claim_fingerprint="claim"))
        assert decoded.independence.trust_state is IndependenceTrustState.UNVERIFIED
