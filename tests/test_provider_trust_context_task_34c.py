from __future__ import annotations

from dataclasses import replace
import hashlib
import hmac
import inspect

import pytest

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
    VerifiedIndependenceFamily,
    decode_code_graph_observation_evidence,
    encode_code_graph_observation_evidence,
    reconcile_provider_observations,
)
from gvr.adapters.codeflow import encode_codeflow_code_graph_observation_evidence
from gvr.adapters.graphify import encode_graphify_code_graph_observation_evidence
from gvr.canonical import canonical_json


def _identity(*, implementation: str = "custom-impl", family: str = "custom-family", kind: str = "custom-kind") -> ProviderImplementationIdentity:
    return ProviderImplementationIdentity("display", implementation, family, provider_kind=kind)


def _graph(identity: ProviderImplementationIdentity | None = None) -> GraphEvidenceModel:
    return GraphEvidenceModel(provider_identity=identity or _identity())


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


def _context(configuration: str = "runtime-v1", *, family: str = "custom-family") -> ProviderTrustContext:
    return ProviderTrustContext.host_runtime(
        configuration,
        registrations=(ProviderImplementationRegistration("custom-impl", "custom-kind", family),),
    )


def _report(verdict: VerificationVerdict, evidence_id: str) -> VerificationReport:
    return VerificationReport(
        verdict=verdict,
        verifier="task34c.fixture",
        issues=(VerificationIssue("PROVEN", "fixture", verdict, (evidence_id,)),),
        evidence_ids=(evidence_id,),
    )


def test_task34c_old_public_deterministic_key_cannot_forge_offline() -> None:
    context = ProviderTrustContext.host_runtime("gvr.builtin_provider_adapters.v1")
    with context.activate():
        evidence = encode_graphify_code_graph_observation_evidence(_graphify_result(), evidence_id="g", claim_fingerprint="claim")
    payload = dict(evidence.payload)
    origin = dict(payload["provider_origin"])
    unsigned = dict(origin)
    unsigned.pop("seal")
    old_key = hashlib.sha256(b"gvr.provider-origin.builtin-adapter-authority.v1").digest()
    origin["seal"] = hmac.new(old_key, canonical_json(unsigned, fingerprint_format="gvr.provider_origin_assertion.v2").encode(), hashlib.sha256).hexdigest()
    payload["provider_origin"] = origin
    with context.activate(), pytest.raises(CodeGraphObservationError, match="seal"):
        decode_code_graph_observation_evidence(replace(evidence, payload=payload))


def test_task34c_same_configuration_contexts_have_distinct_runtime_keys() -> None:
    first, second = ProviderTrustContext.host_runtime("same"), ProviderTrustContext.host_runtime("same")
    with first.activate():
        evidence = encode_graphify_code_graph_observation_evidence(_graphify_result(), evidence_id="g", claim_fingerprint="claim")
    with second.activate(), pytest.raises(CodeGraphObservationError):
        decode_code_graph_observation_evidence(evidence)


def test_task34c_generic_encoder_has_no_authority_escape_hatches() -> None:
    parameters = inspect.signature(encode_code_graph_observation_evidence).parameters
    assert not ({"provider_registry", "provider_authority", "_adapter_origin", "key"} & set(parameters))


def test_task34c_generic_encoder_is_unverified_even_inside_active_context() -> None:
    context = _context()
    with context.activate():
        evidence = encode_code_graph_observation_evidence(_graph(), evidence_id="e", claim_fingerprint="claim")
        decoded = decode_code_graph_observation_evidence(evidence)
    assert decoded.independence.trust_state is IndependenceTrustState.UNVERIFIED


def test_task34c_graphify_without_active_context_is_unverified() -> None:
    evidence = encode_graphify_code_graph_observation_evidence(_graphify_result(), evidence_id="g", claim_fingerprint="claim")
    assert decode_code_graph_observation_evidence(evidence).independence.trust_state is IndependenceTrustState.UNVERIFIED


def test_task34c_codeflow_without_active_context_is_unverified() -> None:
    evidence = encode_codeflow_code_graph_observation_evidence(_codeflow_result(), evidence_id="c", claim_fingerprint="claim")
    assert decode_code_graph_observation_evidence(evidence).independence.trust_state is IndependenceTrustState.UNVERIFIED


def test_task34c_real_graphify_adapter_is_verified_under_active_context() -> None:
    context = ProviderTrustContext.host_runtime("runtime")
    with context.activate():
        decoded = decode_code_graph_observation_evidence(encode_graphify_code_graph_observation_evidence(_graphify_result(), evidence_id="g", claim_fingerprint="claim"))
    assert decoded.independence.trust_state is IndependenceTrustState.VERIFIED


def test_task34c_real_codeflow_adapter_is_verified_under_active_context() -> None:
    context = ProviderTrustContext.host_runtime("runtime")
    with context.activate():
        decoded = decode_code_graph_observation_evidence(encode_codeflow_code_graph_observation_evidence(_codeflow_result(), evidence_id="c", claim_fingerprint="claim"))
    assert decoded.independence.trust_state is IndependenceTrustState.VERIFIED


def test_task34c_serialized_verified_assertion_requires_active_context() -> None:
    context = ProviderTrustContext.host_runtime("runtime")
    with context.activate():
        evidence = encode_graphify_code_graph_observation_evidence(_graphify_result(), evidence_id="g", claim_fingerprint="claim")
    with pytest.raises(CodeGraphObservationError, match="active ProviderTrustContext"):
        decode_code_graph_observation_evidence(evidence)


def test_task34c_serialized_assertion_replays_in_same_active_context() -> None:
    context = ProviderTrustContext.host_runtime("runtime")
    with context.activate():
        evidence = encode_graphify_code_graph_observation_evidence(_graphify_result(), evidence_id="g", claim_fingerprint="claim")
        assert decode_code_graph_observation_evidence(evidence).independence.trust_state is IndependenceTrustState.VERIFIED


def test_task34c_context_rotation_fails_closed() -> None:
    first = ProviderTrustContext.host_runtime("runtime")
    with first.activate():
        evidence = encode_graphify_code_graph_observation_evidence(_graphify_result(), evidence_id="g", claim_fingerprint="claim")
    rotated = ProviderTrustContext.host_runtime("runtime")
    with rotated.activate(), pytest.raises(CodeGraphObservationError, match="context key|seal"):
        decode_code_graph_observation_evidence(evidence)


def test_task34c_configuration_mismatch_fails_closed() -> None:
    first = ProviderTrustContext.host_runtime("runtime-v1")
    with first.activate():
        evidence = encode_graphify_code_graph_observation_evidence(_graphify_result(), evidence_id="g", claim_fingerprint="claim")
    with ProviderTrustContext.host_runtime("runtime-v2").activate(), pytest.raises(CodeGraphObservationError, match="configuration"):
        decode_code_graph_observation_evidence(evidence)


def test_task34c_registry_mismatch_fails_closed() -> None:
    first = _context(family="custom-family")
    with first.activate():
        evidence = first.encode_code_graph_observation_evidence(_graph(), evidence_id="e", claim_fingerprint="claim")
    changed = _context(family="changed-family")
    with changed.activate(), pytest.raises(CodeGraphObservationError, match="registry"):
        decode_code_graph_observation_evidence(evidence)


def test_task34c_explicit_key_mismatch_fails_closed() -> None:
    first = _context()
    with first.activate():
        evidence = first.encode_code_graph_observation_evidence(_graph(), evidence_id="e", claim_fingerprint="claim")
    second = _context()
    with second.activate(), pytest.raises(CodeGraphObservationError, match="context key|seal"):
        decode_code_graph_observation_evidence(evidence)


def test_task34c_origin_tampering_fails_closed() -> None:
    context = _context()
    with context.activate():
        evidence = context.encode_code_graph_observation_evidence(_graph(), evidence_id="e", claim_fingerprint="claim")
    payload = dict(evidence.payload)
    payload["provider_origin"] = {**payload["provider_origin"], "implementation_id": "other"}
    with context.activate(), pytest.raises(CodeGraphObservationError):
        decode_code_graph_observation_evidence(replace(evidence, payload=payload))


def test_task34c_context_lifetime_ends_at_context_manager_exit() -> None:
    context = ProviderTrustContext.host_runtime("runtime")
    with context.activate():
        evidence = encode_graphify_code_graph_observation_evidence(_graphify_result(), evidence_id="g", claim_fingerprint="claim")
    with pytest.raises(CodeGraphObservationError, match="active ProviderTrustContext"):
        decode_code_graph_observation_evidence(evidence)


def test_task34c_nested_context_restores_outer_context() -> None:
    outer, inner = ProviderTrustContext.host_runtime("outer"), ProviderTrustContext.host_runtime("inner")
    with outer.activate():
        evidence = encode_graphify_code_graph_observation_evidence(_graphify_result(), evidence_id="g", claim_fingerprint="claim")
        with inner.activate(), pytest.raises(CodeGraphObservationError):
            decode_code_graph_observation_evidence(evidence)
        assert decode_code_graph_observation_evidence(evidence).independence.trust_state is IndependenceTrustState.VERIFIED


def test_task34c_host_context_can_encode_registered_custom_provider() -> None:
    context = _context()
    with context.activate():
        decoded = decode_code_graph_observation_evidence(context.encode_code_graph_observation_evidence(_graph(), evidence_id="e", claim_fingerprint="claim"))
    assert decoded.independence == VerifiedIndependenceFamily("custom-family", ("custom-impl",), IndependenceTrustState.VERIFIED)


def test_task34c_unregistered_custom_provider_stays_unverified() -> None:
    context = ProviderTrustContext.host_runtime("runtime")
    with context.activate():
        decoded = decode_code_graph_observation_evidence(context.encode_code_graph_observation_evidence(_graph(), evidence_id="e", claim_fingerprint="claim"))
    assert decoded.independence.trust_state is IndependenceTrustState.UNVERIFIED


def test_task34c_direct_reconciliation_rejects_unvalidated_origin_assertion() -> None:
    context = _context()
    with context.activate():
        evidence = context.encode_code_graph_observation_evidence(_graph(), evidence_id="e", claim_fingerprint="claim")
    with pytest.raises(ValueError, match="validated origin"):
        ProviderVerificationObservation(
            provider_id="display", implementation_id="custom-impl", family_id="custom-family",
            source_snapshot={"repository": "repo", "revision": "rev"}, claim_fingerprint="claim",
            report=_report(VerificationVerdict.PASS, "e"), origin_attestation=evidence.payload["provider_origin"],
        )


def test_task34c_direct_reconciliation_consumes_validated_origin_only() -> None:
    graphify_context = ProviderTrustContext.host_runtime("runtime")
    with graphify_context.activate():
        graphify = decode_code_graph_observation_evidence(encode_graphify_code_graph_observation_evidence(_graphify_result(), evidence_id="g", claim_fingerprint="claim"))
        codeflow = decode_code_graph_observation_evidence(encode_codeflow_code_graph_observation_evidence(_codeflow_result(), evidence_id="c", claim_fingerprint="claim"))
    observations = (
        ProviderVerificationObservation("graphify", "graphify", "graphify", {"repository": "repo", "revision": "rev"}, "claim", _report(VerificationVerdict.PASS, "g"), origin_attestation=graphify.validated_origin),
        ProviderVerificationObservation("codeflow", "codeflow", "codeflow", {"repository": "repo", "revision": "rev"}, "claim", _report(VerificationVerdict.PASS, "c"), origin_attestation=codeflow.validated_origin),
    )
    assert reconcile_provider_observations(observations).verdict is VerificationVerdict.PASS


def test_task34c_sqlite_replay_succeeds_with_same_context(tmp_path) -> None:
    context = _context()
    with context.activate():
        evidence = context.encode_code_graph_observation_evidence(_graph(), evidence_id="e", claim_fingerprint="claim")
    storage = SQLiteStorage(tmp_path / "gvr.sqlite")
    stored = storage.put_evidence(evidence)
    replayed = storage.get_evidence(stored.fingerprint).evidence
    with context.activate():
        assert decode_code_graph_observation_evidence(replayed).independence.trust_state is IndependenceTrustState.VERIFIED


def test_task34c_sqlite_replay_fails_with_wrong_context(tmp_path) -> None:
    context = _context()
    with context.activate():
        evidence = context.encode_code_graph_observation_evidence(_graph(), evidence_id="e", claim_fingerprint="claim")
    storage = SQLiteStorage(tmp_path / "gvr.sqlite")
    stored = storage.put_evidence(evidence)
    replayed = storage.get_evidence(stored.fingerprint).evidence
    with _context().activate(), pytest.raises(CodeGraphObservationError):
        decode_code_graph_observation_evidence(replayed)


def test_task34c_public_surface_exposes_context_not_authority_or_builtin_secret() -> None:
    import gvr
    import gvr.provider_independence as implementation

    assert gvr.ProviderTrustContext is ProviderTrustContext
    assert not hasattr(gvr, "ProviderOriginAuthority")
    assert not hasattr(implementation, "_BUILTIN_SECRET")
