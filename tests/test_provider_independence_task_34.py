from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from gvr import (
    IndependenceTrustState,
    ProviderImplementationIdentity,
    ProviderImplementationRegistration,
    ProviderImplementationRegistry,
    ProviderTrustContext,
    SQLiteStorage,
    VerifiedIndependenceFamily,
    builtin_provider_implementation_registry,
    decode_code_graph_observation_evidence,
    encode_code_graph_observation_evidence,
)
from gvr.code_graph import GraphEvidenceModel
from gvr.provider_independence import _attest_active_builtin_provider_origin, observation_subject_for
from gvr.model import VerificationIssue, VerificationReport, VerificationVerdict
from gvr.verifiers.corroboration import ProviderVerificationObservation, reconcile_provider_observations


def report(verdict: VerificationVerdict, evidence_id: str) -> VerificationReport:
    return VerificationReport(
        verdict=verdict,
        verifier="task34.fixture",
        issues=(VerificationIssue("PROVEN_PATH", "fixture", verdict, (evidence_id,)),),
        evidence_ids=(evidence_id,),
    )


def fixture_registry() -> tuple[ProviderTrustContext, ProviderImplementationRegistry]:
    context = ProviderTrustContext.host_runtime(
        "task34-test-runtime",
        registrations=(ProviderImplementationRegistration(
            "task34-deterministic-provider", "task34-test", "task34-independent"
        ),),
    )
    return context, context.registry


def identity(provider_id: str, implementation_id: str, family_id: str, *, kind: str = "low-level") -> ProviderImplementationIdentity:
    return ProviderImplementationIdentity(
        provider_id=provider_id,
        implementation_id=implementation_id,
        family_id=family_id,
        provider_kind=kind,
        implementation_revision="1",
    )


def observation(
    provider_id: str,
    implementation_id: str,
    family_id: str,
    verdict: VerificationVerdict,
    evidence_id: str,
    *,
    registry: ProviderImplementationRegistry | None = None,
    revision: str = "rev1",
    kind: str = "low-level",
    authority: ProviderTrustContext | None = None,
) -> ProviderVerificationObservation:
    provider_identity = identity(provider_id, implementation_id, family_id, kind=kind)
    origin = None
    if kind in {"graphify", "codeflow"} or authority is not None:
        context = authority or ProviderTrustContext.host_runtime("task34-builtins")
        graph = GraphEvidenceModel(provider_identity=provider_identity)
        subject = observation_subject_for(graph, "claim")
        with context.activate():
            if kind in {"graphify", "codeflow"}:
                assertion = _attest_active_builtin_provider_origin(
                    provider_identity,
                    adapter_kind=kind,
                    observation_subject_fingerprint=subject.fingerprint,
                )
                origin = context.validate(
                    provider_identity,
                    assertion.to_dict(),
                    observation_subject_fingerprint=subject.fingerprint,
                )
            else:
                encoded = context.encode_code_graph_observation_evidence(
                    graph, evidence_id=evidence_id, claim_fingerprint="claim"
                )
                origin = decode_code_graph_observation_evidence(encoded).validated_origin
    return ProviderVerificationObservation(
        provider_id=provider_id,
        implementation_id=implementation_id,
        family_id=family_id,
        source_snapshot={"repository": "repo", "revision": revision, "scope": "A->B"},
        claim_fingerprint="claim",
        report=report(verdict, evidence_id),
        origin_attestation=origin,
    )


def codes(result: VerificationReport) -> set[str]:
    return {issue.code for issue in result.issues}


def test_task34_same_graphify_implementation_relabeling_counts_once() -> None:
    registry = builtin_provider_implementation_registry()
    result = reconcile_provider_observations([
        observation("graphify-wrapper-a", "graphify", "family-a", VerificationVerdict.PASS, "g1", registry=registry, kind="graphify"),
        observation("graphify-wrapper-b", "graphify", "family-b", VerificationVerdict.PASS, "g2", registry=registry, kind="graphify"),
    ])
    assert result.verdict is VerificationVerdict.PASS
    assert result.metadata["verified_independence_families"] == ("graphify",)
    assert "PROVIDER_SINGLE_FAMILY_DECISIVE_PASS" in codes(result)
    assert "PROVIDER_CORROBORATED_PASS" not in codes(result)


def test_task34_low_level_graphify_family_strings_are_unverified() -> None:
    result = reconcile_provider_observations([
        observation("graphify", "caller-wrapper-a", "family-a", VerificationVerdict.PASS, "a"),
        observation("graphify", "caller-wrapper-b", "family-b", VerificationVerdict.PASS, "b"),
    ])
    assert result.verdict is VerificationVerdict.PASS
    assert result.metadata["verified_independence_families"] == ()
    assert result.metadata["unverified_provider_labels"] == ("family-a", "family-b")
    assert "PROVIDER_CORROBORATED_PASS" not in codes(result)


def test_task34_same_codeflow_implementation_relabeling_counts_once() -> None:
    registry = builtin_provider_implementation_registry()
    result = reconcile_provider_observations([
        observation("codeflow-a", "codeflow", "x", VerificationVerdict.PASS, "c1", registry=registry, kind="codeflow"),
        observation("codeflow-b", "codeflow", "y", VerificationVerdict.PASS, "c2", registry=registry, kind="codeflow"),
    ])
    assert result.metadata["verified_independence_families"] == ("codeflow",)
    assert "PROVIDER_CORROBORATED_PASS" not in codes(result)


def test_task34_unregistered_distinct_family_strings_never_corroborate() -> None:
    result = reconcile_provider_observations([
        observation("one", "one", "claimed-one", VerificationVerdict.PASS, "1"),
        observation("two", "two", "claimed-two", VerificationVerdict.PASS, "2"),
    ])
    assert result.verdict is VerificationVerdict.PASS
    assert "PROVIDER_CORROBORATED_PASS" not in codes(result)
    assert result.metadata["verified_independence_families"] == ()


def test_task34_genuinely_registered_graphify_and_fixture_provider_corroborate() -> None:
    authority, registry = fixture_registry()
    result = reconcile_provider_observations([
        observation("graphify-display", "graphify", "forged", VerificationVerdict.PASS, "g", registry=registry, kind="graphify"),
        observation("fixture-display", "task34-deterministic-provider", "forged-too", VerificationVerdict.PASS, "f", registry=registry, kind="task34-test", authority=authority),
    ])
    assert result.verdict is VerificationVerdict.PASS
    assert result.metadata["verified_independence_families"] == ("graphify", "task34-independent")
    assert "PROVIDER_CORROBORATED_PASS" in codes(result)


def test_task34_same_verified_family_pass_fail_is_intra_family_unknown() -> None:
    registry = builtin_provider_implementation_registry()
    result = reconcile_provider_observations([
        observation("g-pass", "graphify", "a", VerificationVerdict.PASS, "p", registry=registry, kind="graphify"),
        observation("g-fail", "graphify", "b", VerificationVerdict.FAIL, "f", registry=registry, kind="graphify"),
    ])
    assert result.verdict is VerificationVerdict.UNKNOWN
    assert "PROVIDER_FAMILY_CONTRADICTION" in codes(result)
    assert "PROVIDER_CONFLICT" not in codes(result)


def test_task34_distinct_verified_families_pass_fail_is_cross_provider_unknown() -> None:
    authority, registry = fixture_registry()
    result = reconcile_provider_observations([
        observation("g", "graphify", "a", VerificationVerdict.PASS, "p", registry=registry, kind="graphify"),
        observation("f", "task34-deterministic-provider", "b", VerificationVerdict.FAIL, "f", registry=registry, kind="task34-test", authority=authority),
    ])
    assert result.verdict is VerificationVerdict.UNKNOWN
    assert "PROVIDER_CONFLICT" in codes(result)
    assert "PROVIDER_FAMILY_CONTRADICTION" not in codes(result)


def test_task34_revision_mismatch_precedes_cross_provider_conflict() -> None:
    authority, registry = fixture_registry()
    result = reconcile_provider_observations([
        observation("g", "graphify", "a", VerificationVerdict.PASS, "p", registry=registry, kind="graphify", revision="rev1"),
        observation("f", "task34-deterministic-provider", "b", VerificationVerdict.FAIL, "f", registry=registry, kind="task34-test", revision="rev2", authority=authority),
    ])
    assert result.verdict is VerificationVerdict.UNKNOWN
    assert "PROVIDER_SNAPSHOT_MISMATCH" in codes(result)
    assert "PROVIDER_CONFLICT" not in codes(result)


def test_task34_reorder_duplicates_and_transport_labels_do_not_change_fingerprint() -> None:
    authority, registry = fixture_registry()
    observations = [
        observation("display-g", "graphify", "caller-a", VerificationVerdict.PASS, "g", registry=registry, kind="graphify"),
        observation("display-f", "task34-deterministic-provider", "caller-b", VerificationVerdict.PASS, "f", registry=registry, kind="task34-test", authority=authority),
    ]
    first = reconcile_provider_observations(observations + [observations[0]])
    relabeled = [replace(observations[0], provider_id="other-display", family_id="other-label"), observations[1]]
    second = reconcile_provider_observations(list(reversed(relabeled)))
    assert first.metadata["fingerprint"] == second.metadata["fingerprint"]
    assert first.metadata["verified_independence_families"] == second.metadata["verified_independence_families"]


def test_task34_sqlite_reopen_preserves_verified_resolution(tmp_path: Path) -> None:
    authority, registry = fixture_registry()
    graph = GraphEvidenceModel(provider_identity=identity("fixture-display", "task34-deterministic-provider", "caller-label", kind="task34-test"))
    with authority.activate():
        evidence = authority.encode_code_graph_observation_evidence(
            graph, evidence_id="task34.sqlite", claim_fingerprint="claim"
        )
        decoded = decode_code_graph_observation_evidence(evidence)
    assert decoded.independence.trust_state is IndependenceTrustState.VERIFIED
    assert decoded.independence.family_id == "task34-independent"

    path = tmp_path / "task34.sqlite3"
    stored = SQLiteStorage(path).put_evidence(evidence, slot_id="task34-slot")
    replayed = SQLiteStorage(path).get_evidence(stored.fingerprint).evidence
    with authority.activate():
        decoded_replay = decode_code_graph_observation_evidence(replayed)
    assert decoded_replay.independence == decoded.independence
    assert replayed.fingerprint == evidence.fingerprint
