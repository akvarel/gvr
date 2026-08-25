from __future__ import annotations

from dataclasses import replace

import pytest

from gvr import (
    CodeGraphObservationError,
    GraphEvidenceModel,
    IndependenceTrustState,
    ProviderImplementationIdentity,
    ProviderImplementationRegistration,
    ProviderImplementationRegistry,
    ProviderTrustContext,
    ProviderVerificationObservation,
    VerificationIssue,
    VerificationReport,
    VerificationVerdict,
    VerifiedIndependenceFamily,
    builtin_provider_implementation_registry,
    decode_code_graph_observation_evidence,
    encode_code_graph_observation_evidence,
    reconcile_provider_observations,
)
from gvr.adapters.codeflow import encode_codeflow_code_graph_observation_evidence
from gvr.adapters.graphify import encode_graphify_code_graph_observation_evidence


def _identity(*, provider: str = "display", implementation: str = "impl", family: str = "family", kind: str = "low-level") -> ProviderImplementationIdentity:
    return ProviderImplementationIdentity(provider, implementation, family, provider_kind=kind)


def _report(verdict: VerificationVerdict, evidence_id: str) -> VerificationReport:
    return VerificationReport(
        verdict=verdict,
        verifier="task34b.fixture",
        issues=(VerificationIssue("PROVEN", "fixture", verdict, (evidence_id,)),),
        evidence_ids=(evidence_id,),
    )


def _observation(*, identity: ProviderImplementationIdentity, verdict: VerificationVerdict, evidence_id: str, attestation=None) -> ProviderVerificationObservation:
    return ProviderVerificationObservation(
        provider_id=identity.provider_id,
        implementation_id=identity.implementation_id,
        family_id=identity.family_id,
        source_snapshot={"repository": "repo", "revision": "rev", "scope": "A->B"},
        claim_fingerprint="claim",
        report=_report(verdict, evidence_id),
        origin_attestation=attestation,
    )


def _host_registry(configuration_identity: str = "runtime-config-v1"):
    context = ProviderTrustContext.host_runtime(
        configuration_identity,
        registrations=(ProviderImplementationRegistration("custom-impl", "custom-kind", "custom-family"),),
    )
    return context, context.registry


def _trusted_custom(context: ProviderTrustContext, *, evidence_id: str = "custom"):
    with context.activate():
        evidence = context.encode_code_graph_observation_evidence(
            _graph(_identity(implementation="custom-impl", family="caller", kind="custom-kind")),
            evidence_id=evidence_id,
            claim_fingerprint="claim",
        )
        return evidence, decode_code_graph_observation_evidence(evidence)


def _graph(identity: ProviderImplementationIdentity) -> GraphEvidenceModel:
    return GraphEvidenceModel(provider_identity=identity)


def _graphify_result() -> dict[str, object]:
    return {
        "repository": "repo",
        "revision": "rev",
        "start": "A",
        "target": "B",
        "direction": "FORWARD",
        "termination_reason": "EXHAUSTED",
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
        "query_bounds": {"requested_relations": [], "effective_allowed_relations": [], "rejected_relations": [], "stop_nodes": [], "max_depth": 4, "max_paths": 8, "max_expansions": 64},
        "paths": [],
        "boundary_events": [],
    }


def _codeflow_result() -> dict[str, object]:
    return {
        "source_revision": {"repository": "repo", "revision": "rev"},
        "query_scope": {"start": "A", "target": "B", "direction": "FORWARD", "requested_relations": [], "effective_relations": [], "rejected_relations": [], "stop_nodes": [], "evidence_namespace": "default"},
        "nodes": [],
        "edges": [],
        "blockers": [],
    }


def test_task34b_public_graphify_kind_string_cannot_resolve_verified() -> None:
    resolution = builtin_provider_implementation_registry().resolve(_identity(implementation="graphify", family="graphify", kind="graphify"))
    assert resolution.trust_state is IndependenceTrustState.UNVERIFIED


def test_task34b_public_codeflow_kind_string_cannot_resolve_verified() -> None:
    resolution = builtin_provider_implementation_registry().resolve(_identity(implementation="codeflow", family="codeflow", kind="codeflow"))
    assert resolution.trust_state is IndependenceTrustState.UNVERIFIED


def test_task34b_public_provider_and_family_labels_never_upgrade() -> None:
    resolution = builtin_provider_implementation_registry().resolve(_identity(provider="graphify", implementation="wrapper", family="codeflow"))
    assert resolution.trust_state is IndependenceTrustState.UNVERIFIED


def test_task34b_caller_built_verified_family_cannot_upgrade_direct_reconciliation() -> None:
    forged = VerifiedIndependenceFamily("forged", ("impl",), IndependenceTrustState.VERIFIED)
    with pytest.raises(ValueError, match="origin attestation"):
        ProviderVerificationObservation(
            provider_id="display", implementation_id="impl", family_id="forged",
            source_snapshot={"repository": "repo", "revision": "rev"}, claim_fingerprint="claim",
            report=_report(VerificationVerdict.PASS, "e"), independence=forged,
        )


def test_task34b_custom_per_observation_registry_cannot_upgrade() -> None:
    forged = ProviderImplementationRegistry().with_registration(
        implementation_id="impl", provider_kind="low-level", family_id="forged"
    )
    assert forged.resolve(_identity()).trust_state is IndependenceTrustState.UNVERIFIED


def test_task34b_builtin_graphify_adapter_origin_is_verified() -> None:
    context = ProviderTrustContext.host_runtime("runtime")
    with context.activate():
        evidence = encode_graphify_code_graph_observation_evidence(_graphify_result(), evidence_id="g", claim_fingerprint="claim")
        decoded = decode_code_graph_observation_evidence(evidence)
    assert decoded.independence == VerifiedIndependenceFamily("graphify", ("graphify",), IndependenceTrustState.VERIFIED)


def test_task34b_builtin_codeflow_adapter_origin_is_verified() -> None:
    context = ProviderTrustContext.host_runtime("runtime")
    with context.activate():
        evidence = encode_codeflow_code_graph_observation_evidence(_codeflow_result(), evidence_id="c", claim_fingerprint="claim")
        decoded = decode_code_graph_observation_evidence(evidence)
    assert decoded.independence == VerifiedIndependenceFamily("codeflow", ("codeflow",), IndependenceTrustState.VERIFIED)


def test_task34b_low_level_encoder_cannot_claim_builtin_graphify_origin() -> None:
    evidence = encode_code_graph_observation_evidence(_graph(_identity(implementation="graphify", family="graphify", kind="graphify")), evidence_id="x", claim_fingerprint="claim")
    assert decode_code_graph_observation_evidence(evidence).independence.trust_state is IndependenceTrustState.UNVERIFIED


def test_task34b_low_level_encoder_cannot_claim_builtin_codeflow_origin() -> None:
    evidence = encode_code_graph_observation_evidence(_graph(_identity(implementation="codeflow", family="codeflow", kind="codeflow")), evidence_id="x", claim_fingerprint="claim")
    assert decode_code_graph_observation_evidence(evidence).independence.trust_state is IndependenceTrustState.UNVERIFIED


def test_task34b_host_authorized_custom_provider_resolves_verified() -> None:
    context, _ = _host_registry()
    _, decoded = _trusted_custom(context)
    assert decoded.independence.trust_state is IndependenceTrustState.VERIFIED
    assert decoded.independence.family_id == "custom-family"


def test_task34b_wrong_host_authority_cannot_register_custom_provider() -> None:
    context, _ = _host_registry()
    other = ProviderTrustContext.host_runtime("other-config")
    with context.activate():
        evidence = context.encode_code_graph_observation_evidence(_graph(_identity(implementation="custom-impl", family="caller", kind="custom-kind")), evidence_id="custom", claim_fingerprint="claim")
    with other.activate(), pytest.raises(CodeGraphObservationError):
        decode_code_graph_observation_evidence(evidence)


def test_task34b_custom_registry_configuration_identity_is_serialized() -> None:
    context, registry = _host_registry()
    evidence, _ = _trusted_custom(context)
    assert evidence.payload["provider_origin"]["configuration_identity"] == "runtime-config-v1"
    assert evidence.payload["provider_origin"]["registry_fingerprint"] == registry.fingerprint


def test_task34b_custom_registry_decode_requires_same_runtime_configuration() -> None:
    context, _ = _host_registry()
    evidence, _ = _trusted_custom(context)
    other, _ = _host_registry("runtime-config-v2")
    with other.activate(), pytest.raises(CodeGraphObservationError, match="configuration identity"):
        decode_code_graph_observation_evidence(evidence)


def test_task34b_custom_registry_decode_requires_registry_fingerprint_match() -> None:
    context, _ = _host_registry()
    evidence, _ = _trusted_custom(context)
    changed = ProviderTrustContext.host_runtime("runtime-config-v1", registrations=(
        ProviderImplementationRegistration("custom-impl", "custom-kind", "custom-family"),
        ProviderImplementationRegistration("second", "custom-kind", "second-family"),
    ))
    with changed.activate(), pytest.raises(CodeGraphObservationError, match="registry fingerprint"):
        decode_code_graph_observation_evidence(evidence)


def test_task34b_custom_registry_replay_with_exact_configuration_succeeds() -> None:
    context, registry = _host_registry()
    evidence, decoded = _trusted_custom(context)
    assert decoded.independence.family_id == "custom-family"
    assert decoded.origin_assertion.registry_fingerprint == registry.fingerprint


def test_task34b_recorded_origin_tampering_fails_decode() -> None:
    context, _ = _host_registry()
    evidence, _ = _trusted_custom(context)
    payload = dict(evidence.payload)
    payload["provider_origin"] = {**payload["provider_origin"], "configuration_identity": "forged"}
    with context.activate(), pytest.raises(CodeGraphObservationError):
        decode_code_graph_observation_evidence(replace(evidence, payload=payload))


def test_task34b_direct_reconciliation_fail_closed_without_attestation() -> None:
    first = _observation(identity=_identity(provider="a", implementation="a", family="one"), verdict=VerificationVerdict.PASS, evidence_id="a")
    second = _observation(identity=_identity(provider="b", implementation="b", family="two"), verdict=VerificationVerdict.PASS, evidence_id="b")
    result = reconcile_provider_observations((first, second))
    assert result.metadata["verified_independence_families"] == ()
    assert "PROVIDER_CORROBORATED_PASS" not in {issue.code for issue in result.issues}


def test_task34b_direct_reconciliation_accepts_host_attested_custom_origin() -> None:
    context, _ = _host_registry()
    custom_identity = _identity(implementation="custom-impl", family="caller", kind="custom-kind")
    with context.activate():
        custom_evidence = context.encode_code_graph_observation_evidence(_graph(custom_identity), evidence_id="c", claim_fingerprint="claim")
        custom = decode_code_graph_observation_evidence(custom_evidence).validated_origin
        builtin_evidence = encode_graphify_code_graph_observation_evidence(_graphify_result(), evidence_id="g", claim_fingerprint="claim")
        builtin = decode_code_graph_observation_evidence(builtin_evidence).validated_origin
    result = reconcile_provider_observations((
        _observation(identity=ProviderImplementationIdentity("graphify", "graphify", "graphify", provider_kind="graphify"), verdict=VerificationVerdict.PASS, evidence_id="g", attestation=builtin),
        _observation(identity=custom_identity, verdict=VerificationVerdict.PASS, evidence_id="c", attestation=custom),
    ))
    assert "PROVIDER_CORROBORATED_PASS" in {issue.code for issue in result.issues}


def test_task34b_truth_authority_remains_orthogonal_to_unverified_origin() -> None:
    decisive = _observation(identity=_identity(), verdict=VerificationVerdict.FAIL, evidence_id="f")
    result = reconcile_provider_observations((decisive,))
    assert result.verdict is VerificationVerdict.FAIL
    assert result.metadata["verified_independence_families"] == ()


def test_task34b_verified_origin_does_not_upgrade_heuristic_truth() -> None:
    context = ProviderTrustContext.host_runtime("runtime")
    with context.activate():
        evidence = encode_codeflow_code_graph_observation_evidence(_codeflow_result(), evidence_id="c", claim_fingerprint="claim")
        decoded = decode_code_graph_observation_evidence(evidence)
    heuristic = _observation(identity=decoded.provider_identity, verdict=VerificationVerdict.UNKNOWN, evidence_id="c", attestation=decoded.validated_origin)
    result = reconcile_provider_observations((heuristic,))
    assert result.verdict is VerificationVerdict.UNKNOWN
    assert "PROVIDER_CORROBORATED_PASS" not in {issue.code for issue in result.issues}
