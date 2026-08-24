from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import pytest

from gvr import (
    AtomicClaim,
    AtomicClaimBinding,
    ClaimGraph,
    CODE_GRAPH_OBSERVATION_EVIDENCE_KIND,
    CODE_GRAPH_VERIFIER,
    Evidence,
    EvidenceAcquisitionStatus,
    EvidenceCompleteness,
    EvidenceCoverage,
    EvidenceProviderCapability,
    EvidenceProviderCapabilityRegistry,
    EvidenceProviderResult,
    EvidenceProviderRuntimeRegistry,
    EvidenceRequest,
    SQLiteStorage,
    VerificationExecutionRequest,
    VerificationExecutionTermination,
    VerificationPlanStepKind,
    VerificationPlanningRequest,
    VerificationVerdict,
    VerifierCapabilityRegistry,
    VerifierCost,
    VerifierDeterminism,
    builtin_verifier_capability_registry,
    builtin_verifier_runtime_registry,
    compile_verification_plan,
    execute_verification_plan,
    encode_code_graph_observation_evidence,
    encode_codeflow_code_graph_observation_evidence,
    encode_graphify_code_graph_observation_evidence,
)
from gvr.code_graph import EvidenceConfidence, GraphEvidence, GraphEvidenceKind, GraphEvidenceModel
from gvr.verifiers.code_graph import CodeGraphClaimKind


REQUEST_KIND = "LOAD_PRECOMPUTED_CODE_GRAPH_OBSERVATION"
SNAPSHOT_PATH = {
    "repository": "fixture-repo",
    "revision": "rev-1",
    "start": "A",
    "target": "B",
    "direction": "FORWARD",
    "termination_reason": "COMPLETE",
    "search_coverage": "COMPLETE_FOR_SUPPORTED_CONSTRUCT",
    "complete_supported_search": True,
    "query_bounds": {"relations": ["FLOWS_TO"]},
}
SNAPSHOT_ADVANCED = {**SNAPSHOT_PATH, "revision": "rev-2"}


@dataclass
class ProviderRuntime:
    capability: EvidenceProviderCapability
    evidence: Evidence
    snapshot: Mapping[str, Any]
    calls: list[EvidenceRequest]

    @property
    def provider_id(self) -> str:
        return self.capability.provider_id

    @property
    def version(self) -> str:
        return self.capability.version

    def acquire(self, request: EvidenceRequest) -> EvidenceProviderResult:
        self.calls.append(request)
        return EvidenceProviderResult(
            request_id=request.request_id,
            request_fingerprint=request.fingerprint,
            provider_id=request.provider_id,
            provider_version=request.provider_version,
            status=EvidenceAcquisitionStatus.COMPLETE,
            coverage=EvidenceCoverage(
                completeness=EvidenceCompleteness.COMPLETE,
                covered_evidence_kinds=request.requested_evidence_kinds,
                declared_scope=request.semantic_scope,
                observed_scope=request.semantic_scope,
                declared_bounds=request.bounds,
                consumed={"records": 1},
                termination={"reason": "PRECOMPUTED_SNAPSHOT"},
                termination_reason="PRECOMPUTED_SNAPSHOT",
                source_identity=request.source_context,
                snapshot_identity=request.snapshot_context,
            ),
            evidence=(self.evidence,),
            capability_fingerprint=self.capability.fingerprint,
            evidence_slot_identities=(
                request.evidence_slot_identity(
                    self.evidence.id,
                    source_identity=request.source_context,
                ),
            ),
        )


def provider_capability(provider_id: str) -> EvidenceProviderCapability:
    return EvidenceProviderCapability(
        provider_id=provider_id,
        version="1",
        request_kinds=(REQUEST_KIND,),
        produced_evidence_kinds=(CODE_GRAPH_OBSERVATION_EVIDENCE_KIND,),
        source_classes=("repository",),
        snapshot_classes=("revision",),
        input_schema={"type": "precomputed"},
        output_schema={"type": "gvr.EvidenceProviderResult"},
        determinism=VerifierDeterminism.O1,
        side_effect_free=True,
        cost=VerifierCost.EXTERNAL,
        bounds={"source": "external_precomputed_snapshot"},
        coverage={"mode": "DECLARED_SCOPE"},
    )


def path_claim(claim_id: str = "cg-path", *, snapshot: Mapping[str, Any] = SNAPSHOT_PATH) -> AtomicClaim:
    return AtomicClaim(
        claim_id=claim_id,
        claim_kind=CodeGraphClaimKind.PATH_EXISTS.value,
        verifier=CODE_GRAPH_VERIFIER,
        spec={
            "source": "graphify:node:A",
            "target": "graphify:node:B",
            "relations": ["FLOWS_TO"],
            "scope": {"snapshot": snapshot},
            "evidence_namespace": "integrated-27-30",
        },
    )


def no_path_claim(claim_id: str = "cg-no-path", *, snapshot: Mapping[str, Any] = SNAPSHOT_PATH) -> AtomicClaim:
    return AtomicClaim(
        claim_id=claim_id,
        claim_kind=CodeGraphClaimKind.NO_PATH.value,
        verifier=CODE_GRAPH_VERIFIER,
        spec={
            "source": "A",
            "target": "B",
            "relations": ["FLOWS_TO"],
            "scope": {"snapshot": snapshot},
            "evidence_namespace": "integrated-27-30",
        },
    )


def graphify_path_snapshot(snapshot: Mapping[str, Any] = SNAPSHOT_PATH) -> Mapping[str, Any]:
    return {
        "start": "A",
        "target": "B",
        "direction": "FORWARD",
        "termination_reason": snapshot["termination_reason"],
        "search_coverage": snapshot["search_coverage"],
        "complete_supported_search": snapshot["complete_supported_search"],
        "query_bounds": snapshot["query_bounds"],
        "query_validity": True,
        "input_resolution": "RESOLVED",
        "truncated": False,
        "paths": [
            {
                "path_identity": ["df:graphify:path:A:B"],
                "path_exactness": "EXACT_FOR_RETURNED_PATH",
                "path_receiver_confidence": "PROVEN",
                "path_coverage": "COMPLETE_FOR_SUPPORTED_CONSTRUCT",
                "supporting_evidence": [
                    {
                        "key": "df:graphify:path:A:B",
                        "relation": "FLOWS_TO",
                        "source": "A",
                        "target": "B",
                        "source_file": "src/a.py",
                        "source_location": "1:1",
                        "provenance": "graphify-canonical-snapshot",
                        "receiver_confidence": "PROVEN",
                        "analysis_completeness": "COMPLETE_FOR_SUPPORTED_CONSTRUCT",
                    }
                ],
            }
        ],
    }


def graphify_no_path_snapshot(snapshot: Mapping[str, Any] = SNAPSHOT_PATH) -> Mapping[str, Any]:
    return {
        "start": "A",
        "target": "B",
        "direction": "FORWARD",
        "termination_reason": snapshot["termination_reason"],
        "search_coverage": snapshot["search_coverage"],
        "complete_supported_search": snapshot["complete_supported_search"],
        "query_bounds": snapshot["query_bounds"],
        "query_validity": True,
        "input_resolution": "RESOLVED",
        "truncated": False,
        "paths": [],
        "boundary_events": [],
        "encountered_partial_evidence": False,
        "encountered_unknown_evidence": False,
    }


def codeflow_path_snapshot(snapshot: Mapping[str, Any] = SNAPSHOT_PATH) -> Mapping[str, Any]:
    return {
        "source_snapshot": dict(snapshot),
        "edges": [
            {
                "id": "cf:heuristic:path:A:B",
                "kind": "call",
                "source": "graphify:node:A",
                "target": "graphify:node:B",
                "semantic_identity": {
                    "source": "graphify:node:A",
                    "target": "graphify:node:B",
                    "relation": "FLOWS_TO",
                },
                "exact_identity": {
                    "source": "graphify:node:A",
                    "target": "graphify:node:B",
                    "relation": "FLOWS_TO",
                    "snapshot": snapshot["revision"],
                },
            }
        ],
    }


def codeflow_silence_snapshot(snapshot: Mapping[str, Any] = SNAPSHOT_PATH) -> Mapping[str, Any]:
    return {"source_snapshot": dict(snapshot), "nodes": [], "edges": []}


def exact_model(provider: str, edge_id: str, *, snapshot: Mapping[str, Any] = SNAPSHOT_PATH) -> GraphEvidenceModel:
    return GraphEvidenceModel(
        provider=provider,
        nodes=(),
        edges=(
            GraphEvidence(
                id=edge_id,
                kind=GraphEvidenceKind.CALL,
                semantic_identity={
                    "source": "graphify:node:A",
                    "target": "graphify:node:B",
                    "relation": "FLOWS_TO",
                },
                exact_identity={
                    "source": "graphify:node:A",
                    "target": "graphify:node:B",
                    "relation": "FLOWS_TO",
                    "snapshot": snapshot["revision"],
                },
                confidence=EvidenceConfidence.EXACT,
                source="graphify:node:A",
                target="graphify:node:B",
                label="FLOWS_TO",
            ),
        ),
        source_snapshot=snapshot,
    )


def request_for(provider_id: str, claim: AtomicClaim, snapshot: Mapping[str, Any]) -> EvidenceRequest:
    return EvidenceRequest(
        request_id=f"request.{claim.claim_id}.{provider_id}",
        provider_id=provider_id,
        provider_version="1",
        request_kind=REQUEST_KIND,
        requested_evidence_kinds=(CODE_GRAPH_OBSERVATION_EVIDENCE_KIND,),
        subject={"claim_id": claim.claim_id},
        spec={"claim_fingerprint": claim.semantic_definition(), "provider_id": provider_id},
        semantic_scope={"repository": "fixture-repo", "claim_id": claim.claim_id},
        source_context={"repository": "fixture-repo", "provider_id": provider_id},
        snapshot_context=snapshot,
        bounds={"max_records": 1},
        source_class="repository",
        snapshot_class="revision",
    )


def execution_request(claim: AtomicClaim, observations: Mapping[str, tuple[Evidence, Mapping[str, Any]]]):
    graph = ClaimGraph(nodes=(claim,))
    verifier_cap = builtin_verifier_capability_registry().lookup(CODE_GRAPH_VERIFIER, "1")
    verifier_caps = VerifierCapabilityRegistry((verifier_cap,))
    provider_caps = EvidenceProviderCapabilityRegistry(tuple(provider_capability(pid) for pid in observations))
    requests = {pid: request_for(pid, claim, snapshot) for pid, (_, snapshot) in observations.items()}
    planning = VerificationPlanningRequest(
        claim_graph=graph,
        bindings=(
            AtomicClaimBinding(
                claim_id=claim.claim_id,
                verifier_id=CODE_GRAPH_VERIFIER,
                verifier_version="1",
                verifier_capability_fingerprint=verifier_cap.fingerprint,
                evidence_requests=tuple(requests[pid] for pid in sorted(requests)),
            ),
        ),
        verifier_capability_registry=verifier_caps,
        verifier_capability_registry_fingerprint=verifier_caps.fingerprint,
        evidence_provider_capability_registry=provider_caps,
        evidence_provider_capability_registry_fingerprint=provider_caps.fingerprint,
    )
    plan = compile_verification_plan(planning)
    provider_runtimes = {
        (pid, "1"): ProviderRuntime(provider_capability(pid), evidence, snapshot, [])
        for pid, (evidence, snapshot) in observations.items()
    }
    provider_registry = EvidenceProviderRuntimeRegistry(provider_caps, provider_runtimes)
    return VerificationExecutionRequest(
        plan=plan,
        plan_fingerprint=plan.fingerprint,
        claim_graph=graph,
        claim_graph_fingerprint=graph.fingerprint,
        roots=(claim.claim_id,),
        verifier_runtime_registry=builtin_verifier_runtime_registry(verifier_caps),
        verifier_capability_registry_fingerprint=verifier_caps.fingerprint,
        evidence_provider_runtime_registry=provider_registry,
        evidence_provider_capability_registry_fingerprint=provider_caps.fingerprint,
        evidence_requests={(item.request_id, item.fingerprint): item for item in requests.values()},
    )


def root_report(result, claim_id: str):
    return result.bundles[claim_id].report


def issue_codes(report) -> set[str]:
    return {issue.code for issue in report.issues}


def test_i_graphify_proven_plus_codeflow_heuristic_passes_with_both_exact_acquisitions(tmp_path: Path) -> None:
    claim = path_claim()
    graphify = encode_graphify_code_graph_observation_evidence(
        graphify_path_snapshot(),
        evidence_id="obs.graphify.path",
        claim=claim,
        source_snapshot=SNAPSHOT_PATH,
    )
    codeflow = encode_codeflow_code_graph_observation_evidence(
        codeflow_path_snapshot(),
        evidence_id="obs.codeflow.path",
        claim=claim,
    )
    request = execution_request(
        claim,
        {"graphify.snapshot": (graphify, SNAPSHOT_PATH), "codeflow.snapshot": (codeflow, SNAPSHOT_PATH)},
    )

    storage = SQLiteStorage(tmp_path / "gvr.sqlite3")
    result = execute_verification_plan(request, storage=storage)
    report = root_report(result, claim.claim_id)

    assert result.termination is VerificationExecutionTermination.COMPLETE
    assert result.consumption.acquisitions == 2
    assert result.session.root_verdicts == {claim.claim_id: VerificationVerdict.PASS}
    assert report.verdict is VerificationVerdict.PASS
    assert report.evidence_ids == ("obs.codeflow.path", "obs.graphify.path")
    assert {"PROVEN_PATH", "EDGE_NOT_EXACT", "PROVIDER_SINGLE_FAMILY_DECISIVE_PASS"} <= issue_codes(report)
    assert "PROVIDER_CORROBORATED_PASS" not in issue_codes(report)
    assert storage.claim_status(claim.claim_id).stored_verdict is VerificationVerdict.PASS
    assert {step.kind for step in result.steps} >= {
        VerificationPlanStepKind.ACQUIRE_EVIDENCE,
        VerificationPlanStepKind.VERIFY_ATOMIC_CLAIM,
    }


def test_ii_codeflow_only_heuristic_remains_unknown(tmp_path: Path) -> None:
    claim = path_claim("cg-codeflow-only")
    codeflow = encode_codeflow_code_graph_observation_evidence(
        codeflow_path_snapshot(),
        evidence_id="obs.codeflow.only",
        claim=claim,
    )
    result = execute_verification_plan(
        execution_request(claim, {"codeflow.snapshot": (codeflow, SNAPSHOT_PATH)}),
        storage=SQLiteStorage(tmp_path / "gvr.sqlite3"),
    )
    report = root_report(result, claim.claim_id)

    assert result.termination is VerificationExecutionTermination.COMPLETE
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert report.evidence_ids == ("obs.codeflow.only",)
    assert {"EDGE_NOT_EXACT", "PROVIDER_ONLY_HEURISTIC"} <= issue_codes(report)


def test_iii_graphify_complete_no_path_passes_without_codeflow_silence(tmp_path: Path) -> None:
    claim = no_path_claim()
    graphify = encode_graphify_code_graph_observation_evidence(
        graphify_no_path_snapshot(),
        evidence_id="obs.graphify.no-path",
        claim=claim,
        source_snapshot=SNAPSHOT_PATH,
    )
    codeflow = encode_codeflow_code_graph_observation_evidence(
        codeflow_silence_snapshot(),
        evidence_id="obs.codeflow.silence",
        claim=claim,
    )
    result = execute_verification_plan(
        execution_request(
            claim,
            {"graphify.snapshot": (graphify, SNAPSHOT_PATH), "codeflow.snapshot": (codeflow, SNAPSHOT_PATH)},
        ),
        storage=SQLiteStorage(tmp_path / "gvr.sqlite3"),
    )
    report = root_report(result, claim.claim_id)

    assert report.verdict is VerificationVerdict.PASS
    assert report.evidence_ids == ("obs.graphify.no-path",)
    assert {"PROVEN_ABSENCE", "ABSENCE_NOT_PROVEN", "PROVIDER_SINGLE_FAMILY_DECISIVE_PASS"} <= issue_codes(report)


def test_iv_independent_decisive_pass_fail_conflict_is_unknown(tmp_path: Path) -> None:
    claim = path_claim("cg-conflict")
    passing = encode_code_graph_observation_evidence(
        exact_model("exact-pass", "exact:pass"),
        evidence_id="obs.exact.pass",
        claim=claim,
        implementation_id="exact-pass-v1",
        family_id="exact-pass-family",
    )
    failing = encode_code_graph_observation_evidence(
        GraphEvidenceModel(provider="exact-fail", nodes=(), edges=(), source_snapshot=SNAPSHOT_PATH),
        evidence_id="obs.exact.fail",
        claim=claim,
        implementation_id="exact-fail-v1",
        family_id="exact-fail-family",
    )
    result = execute_verification_plan(
        execution_request(
            claim,
            {"exact.pass": (passing, SNAPSHOT_PATH), "exact.fail": (failing, SNAPSHOT_PATH)},
        ),
        storage=SQLiteStorage(tmp_path / "gvr.sqlite3"),
    )
    report = root_report(result, claim.claim_id)

    assert report.verdict is VerificationVerdict.UNKNOWN
    assert report.evidence_ids == ("obs.exact.fail", "obs.exact.pass")
    assert {"PATH_ABSENT", "PROVEN_PATH", "PROVIDER_CONFLICT"} <= issue_codes(report)


def test_v_close_reopen_replay_idempotency_then_one_provider_snapshot_advance_isolated_invalidation(tmp_path: Path) -> None:
    path = tmp_path / "gvr.sqlite3"
    claim = path_claim()
    graphify = encode_graphify_code_graph_observation_evidence(
        graphify_path_snapshot(),
        evidence_id="obs.graphify.replay",
        claim=claim,
        source_snapshot=SNAPSHOT_PATH,
    )
    codeflow_v1 = encode_codeflow_code_graph_observation_evidence(
        codeflow_path_snapshot(),
        evidence_id="obs.codeflow.replay",
        claim=claim,
    )
    first_request = execution_request(
        claim,
        {"graphify.snapshot": (graphify, SNAPSHOT_PATH), "codeflow.snapshot": (codeflow_v1, SNAPSHOT_PATH)},
    )
    first_store = SQLiteStorage(path)
    first = execute_verification_plan(first_request, storage=first_store)
    del first_store

    reopened = SQLiteStorage(path)
    replay = execute_verification_plan(first_request, storage=reopened)
    assert replay.fingerprint == first.fingerprint
    assert replay.session.fingerprint == first.session.fingerprint

    advanced_claim = path_claim(snapshot=SNAPSHOT_ADVANCED)
    codeflow_v2 = encode_codeflow_code_graph_observation_evidence(
        codeflow_path_snapshot(SNAPSHOT_ADVANCED),
        evidence_id="obs.codeflow.replay",
        claim=advanced_claim,
    )
    advanced = execute_verification_plan(
        execution_request(
            advanced_claim,
            {"graphify.snapshot": (graphify, SNAPSHOT_PATH), "codeflow.snapshot": (codeflow_v2, SNAPSHOT_ADVANCED)},
        ),
        storage=reopened,
    )

    graphify_slot = first_request.evidence_requests[
        ("request.cg-path.graphify.snapshot", next(r.fingerprint for r in first_request.evidence_requests.values() if r.provider_id == "graphify.snapshot"))
    ].evidence_slot_identity("obs.graphify.replay", source_identity={"repository": "fixture-repo", "provider_id": "graphify.snapshot"}).slot_id
    codeflow_slot = first_request.evidence_requests[
        ("request.cg-path.codeflow.snapshot", next(r.fingerprint for r in first_request.evidence_requests.values() if r.provider_id == "codeflow.snapshot"))
    ].evidence_slot_identity("obs.codeflow.replay", source_identity={"repository": "fixture-repo", "provider_id": "codeflow.snapshot"}).slot_id

    assert advanced.fingerprint != first.fingerprint
    assert len(reopened.slot_history(codeflow_slot)) == 2
    assert len(reopened.slot_history(graphify_slot)) == 1
    assert not reopened.get_session(first.session.fingerprint).current
    assert reopened.get_session(advanced.session.fingerprint).current
    assert all("obs.graphify.replay" not in event.cause_object for event in reopened.invalidation_events())


def test_vi_contamination_mix_claim_mismatch_never_upgrades_truth(tmp_path: Path) -> None:
    claim = path_claim("cg-clean")
    contaminant_claim = path_claim("cg-contaminant")
    clean = encode_graphify_code_graph_observation_evidence(
        graphify_path_snapshot(),
        evidence_id="obs.clean.graphify",
        claim=claim,
        source_snapshot=SNAPSHOT_PATH,
    )
    contaminant = encode_code_graph_observation_evidence(
        exact_model("contaminant", "exact:contaminant"),
        evidence_id="obs.contaminant",
        claim=contaminant_claim,
        implementation_id="contaminant-v1",
        family_id="contaminant-family",
    )
    result = execute_verification_plan(
        execution_request(
            claim,
            {"graphify.snapshot": (clean, SNAPSHOT_PATH), "contaminant.snapshot": (contaminant, SNAPSHOT_PATH)},
        ),
        storage=SQLiteStorage(tmp_path / "gvr.sqlite3"),
    )
    report = root_report(result, claim.claim_id)

    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "PROVIDER_CLAIM_MISMATCH" in issue_codes(report)
    assert "PROVIDER_CORROBORATED_PASS" not in issue_codes(report)
