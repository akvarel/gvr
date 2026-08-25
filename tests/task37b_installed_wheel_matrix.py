"""Task37b installed-wheel attack/replay matrix.

Runs against the *installed* gvr package (site-packages of a fresh virtual
environment created from the built wheel) with the repository source tree
absent from ``sys.path``. Every attack must fail closed; the benign replay
must round-trip with a stable fingerprint. Exit code 0 only when all checks
pass.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f" :: {detail}"))
    if not cond:
        failures.append(name)


def expect_raises(exc: type[BaseException], fn, name: str) -> None:
    try:
        fn()
    except exc:
        check(name, True)
    except Exception as exc:  # noqa: BLE001 - report the wrong failure mode
        check(name, False, f"raised {exc!r}")
    else:
        check(name, False, "no error raised")


def main() -> int:
    import gvr

    print("installed from wheel:", gvr.__file__)
    check("import-from-site-packages", "site-packages" in Path(gvr.__file__).as_posix(), gvr.__file__)

    from gvr.adapters.graphify import encode_graphify_structural_evidence_v2_observation_evidence
    from gvr.structural_evidence import (
        GraphifyStructuralEvidenceError,
        GraphifyStructuralEvidenceV2,
        graphify_structural_evidence_fingerprint,
        ingest_graphify_structural_evidence_v2,
    )

    fixture = Path(os.environ["GVR_TASK37B_FIXTURE"])

    def document() -> dict:
        return json.loads(fixture.read_text(encoding="utf-8"))

    def reseal(doc: dict) -> dict:
        doc["fingerprint"] = graphify_structural_evidence_fingerprint(doc)
        return doc

    # Benign replay: ingest, serialize, re-ingest keeps one stable fingerprint.
    snapshot = ingest_graphify_structural_evidence_v2(document())
    replay = ingest_graphify_structural_evidence_v2(snapshot.to_dict())
    check("benign-replay-fingerprint-stable", replay.fingerprint == snapshot.fingerprint)
    check("benign-replay-binding-stable", replay.analysis_binding == snapshot.analysis_binding)

    # Attack 1: mutated authority content under a stale seal.
    mutated = document()
    mutated["coverage"]["complete_supported_search"] = True
    expect_raises(
        GraphifyStructuralEvidenceError,
        lambda: ingest_graphify_structural_evidence_v2(mutated),
        "attack-mutated-coverage-rejected",
    )

    # Attack 2: caller-supplied traversal override.
    override = document()
    expect_raises(
        GraphifyStructuralEvidenceError,
        lambda: ingest_graphify_structural_evidence_v2(override, traversal={"paths": []}),
        "attack-caller-traversal-override-rejected",
    )

    # Attack 3: producer-invalid query bounds (max_paths/max_expansions >= 1 parity).
    zero_paths = document()
    zero_paths["query"]["max_paths"] = 0
    expect_raises(
        GraphifyStructuralEvidenceError,
        lambda: ingest_graphify_structural_evidence_v2(reseal(zero_paths)),
        "attack-zero-max-paths-rejected",
    )
    zero_expansions = document()
    zero_expansions["query"]["max_expansions"] = 0
    expect_raises(
        GraphifyStructuralEvidenceError,
        lambda: ingest_graphify_structural_evidence_v2(reseal(zero_expansions)),
        "attack-zero-max-expansions-rejected",
    )

    # Attack 4: post-ingest typed-state mutation must be impossible and ineffective.
    def mutate_typed() -> None:
        snapshot.coverage["complete_supported_search"] = True

    expect_raises(TypeError, mutate_typed, "typed-state-mutation-blocked")
    check(
        "typed-projection-unchanged-after-attempt",
        snapshot.to_gvr_traversal_dict()["complete_supported_search"] is False,
    )

    # Attack 5: direct construction of a typed view grants no authority.
    def direct_instance(mutated: dict):
        return GraphifyStructuralEvidenceV2(
            document=mutated,
            source_revision_scope=None,
            analysis_binding=None,
            query=mutated["query"],
            coverage=mutated["coverage"],
            facts=tuple(mutated["facts"]),
            paths=tuple(mutated["paths"]),
            blockers=tuple(mutated["blockers"]),
            analyzer_revision=mutated["analyzer_revision"],
        )

    forged_view_doc = document()
    forged_view_doc["coverage"]["complete_supported_search"] = True
    expect_raises(
        GraphifyStructuralEvidenceError,
        lambda: encode_graphify_structural_evidence_v2_observation_evidence(
            direct_instance(forged_view_doc), evidence_id="attack.direct", claim_fingerprint="claim"
        ),
        "direct-typed-construction-gains-no-authority",
    )

    # Attack 6: forged typed object handed to the trusted adapter.
    forged = ingest_graphify_structural_evidence_v2(document())
    forged_doc = forged.to_dict()
    forged_doc["coverage"]["complete_supported_search"] = True
    object.__setattr__(forged, "document", forged_doc)
    expect_raises(
        GraphifyStructuralEvidenceError,
        lambda: encode_graphify_structural_evidence_v2_observation_evidence(
            forged, evidence_id="attack.forged", claim_fingerprint="claim"
        ),
        "adapter-revalidates-typed-object",
    )

    # Replay trust semantics: public serialized use stays UNVERIFIED.
    evidence = encode_graphify_structural_evidence_v2_observation_evidence(
        document(), evidence_id="public.replay", claim_fingerprint="claim"
    )
    decoded = gvr.decode_code_graph_observation_evidence(evidence)
    check(
        "serialized-public-use-unverified",
        decoded.independence.trust_state is gvr.IndependenceTrustState.UNVERIFIED,
    )

    # ---- Producer-valid acceptance surfaces (Task37b section 6) ----

    def complete_identity_doc() -> dict:
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

    from gvr.graphify_contract import validate_graphify_envelope_authority

    # Producer-valid zero-step identity is accepted and positively authorized.
    identity_snapshot = ingest_graphify_structural_evidence_v2(complete_identity_doc())
    identity_traversal = identity_snapshot.to_gvr_traversal_dict()
    identity_authority = validate_graphify_envelope_authority(identity_traversal)
    check("identity-path-accepted", [p["path_identity"] for p in identity_traversal["paths"]] == [[]])
    check("identity-positive-not-negative-authority",
          identity_authority.positive_authorized is True and identity_authority.negative_authorized is False)

    # Producer-valid positive witness: single PROVEN/COMPLETE fact bound to its df path.
    base_doc = document()
    proven_fact = next(fact for fact in base_doc["facts"] if fact["receiver_confidence"] == "PROVEN")
    positive_doc = document()
    target_node = str(proven_fact["target"])
    positive_doc["query"]["target"] = target_node
    proven_fact["path_identity"] = [[proven_fact["key"]]]
    positive_doc["facts"] = [proven_fact]
    positive_doc["paths"] = [{
        "path_identity": [proven_fact["key"]],
        "supporting_evidence_keys": [proven_fact["key"]],
        "exactness": "EXACT_FOR_RETURNED_PATH",
        "receiver_confidence": "PROVEN",
        "coverage": "COMPLETE_FOR_SUPPORTED_CONSTRUCT",
    }]
    positive_doc["blockers"] = []
    positive_doc["coverage"].update({
        "complete_supported_search": True,
        "search_coverage": "COMPLETE_FOR_SUPPORTED_CONSTRUCT",
        "termination_reason": "COMPLETE",
        "truncated": False,
        "input_resolution": "RESOLVED",
        "query_validity": True,
        "start_node_found": True,
        "target_node_found": True,
        "visited_count": 2,
        "expanded_count": 1,
        "encountered_partial_evidence": False,
        "encountered_unknown_evidence": False,
        "encountered_may_evidence": False,
    })
    positive_snapshot = ingest_graphify_structural_evidence_v2(reseal(positive_doc))
    positive_traversal = positive_snapshot.to_gvr_traversal_dict()
    check("positive-witness-authorized", validate_graphify_envelope_authority(positive_traversal).positive_authorized is True)

    # Complete negative: resolved start != target with zero paths stays negatively authorized.
    negative_doc = document()
    negative_doc["query"]["target"] = "unreached-distinct-target-node"
    negative_doc["facts"] = []
    negative_doc["paths"] = []
    negative_doc["blockers"] = []
    negative_doc["coverage"].update({
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
    negative_traversal = ingest_graphify_structural_evidence_v2(reseal(negative_doc)).to_gvr_traversal_dict()
    negative_authority = validate_graphify_envelope_authority(negative_traversal)
    check("complete-negative-authorized",
          negative_authority.negative_authorized is True and negative_authority.positive_authorized is False)

    # Trusted adapter origin: VERIFIED only under the active trust context.
    context = gvr.ProviderTrustContext.host_runtime("gvr.builtin_provider_adapters.v1")
    with context.activate():
        trusted_evidence = encode_graphify_structural_evidence_v2_observation_evidence(
            positive_doc, evidence_id="trusted.replay", claim_fingerprint="claim"
        )
        trusted_decoded = gvr.decode_code_graph_observation_evidence(trusted_evidence)
    check("trusted-context-verified-origin",
          trusted_decoded.independence.trust_state is gvr.IndependenceTrustState.VERIFIED)

    # Projection-only rejection: the derived traversal view is not ingestible.
    expect_raises(
        GraphifyStructuralEvidenceError,
        lambda: ingest_graphify_structural_evidence_v2(snapshot.to_gvr_traversal_dict()),
        "projection-only-rejected",
    )

    # Binding/fingerprint mutation rejection.
    binding_mutated = document()
    binding_mutated["analysis_binding"]["index_fingerprint"] = "sha256:" + "1" * 64
    expect_raises(
        GraphifyStructuralEvidenceError,
        lambda: ingest_graphify_structural_evidence_v2(binding_mutated),
        "binding-fingerprint-mutation-rejected",
    )

    # Cross-snapshot substitution rejection.
    first = document()
    second = json.loads(json.dumps(first))
    second["query"]["start"] = "substituted-start-node"
    second = reseal(second)
    first["query"] = second["query"]
    expect_raises(
        GraphifyStructuralEvidenceError,
        lambda: ingest_graphify_structural_evidence_v2(first),
        "cross-snapshot-substitution-rejected",
    )

    # SQLite close/reopen replay preserves the full v2 authority metadata.
    stored_evidence = encode_graphify_structural_evidence_v2_observation_evidence(
        document(), evidence_id="sqlite.replay", claim_fingerprint="claim"
    )
    storage_path = Path(os.environ.get("GVR_TASK37B_SQLITE", "task37b-matrix.sqlite3"))
    store = gvr.SQLiteStorage(storage_path)
    stored = store.put_evidence(stored_evidence)
    reopened = gvr.SQLiteStorage(storage_path)
    roundtrip = reopened.get_evidence(stored.fingerprint)
    replayed = gvr.decode_code_graph_observation_evidence(roundtrip.evidence)
    metadata = replayed.graph_model.authority_metadata
    check("sqlite-replay-preserves-binding", metadata["analysis_binding"] == document()["analysis_binding"])
    check("sqlite-replay-preserves-scope", metadata["source_revision_scope"] == document()["source_revision_scope"])
    check("sqlite-replay-stays-unverified",
          replayed.independence.trust_state is gvr.IndependenceTrustState.UNVERIFIED)

    # Mismatch precedence at the verifier boundary under the installed wheel.
    from gvr.code_graph import GraphQueryScope, SourceRevisionIdentity
    from gvr.verifiers.code_graph import CodeGraphClaim, CodeGraphClaimKind, verify_code_graph_observation

    graph_model = trusted_decoded.graph_model
    wrong_revision_claim = CodeGraphClaim(
        kind=CodeGraphClaimKind.PATH_EXISTS,
        source=graph_model.query_scope.start,
        target=graph_model.query_scope.target,
        scope={
            "source_revision": SourceRevisionIdentity("graphify", "f" * 40),
            "query_scope": graph_model.query_scope,
        },
    )
    revision_report = verify_code_graph_observation(wrong_revision_claim, graph_model)
    check("mismatch-precedence-source-revision",
          revision_report.verdict is gvr.VerificationVerdict.UNKNOWN
          and any(issue.code == "SOURCE_REVISION_MISMATCH" for issue in revision_report.issues))

    if failures:
        print("MATRIX FAILED:", failures)
        return 1
    print("MATRIX OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
