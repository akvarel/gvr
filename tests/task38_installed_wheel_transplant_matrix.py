"""Task38 installed-wheel provider-origin content-transplant matrix.

Runs against the *installed* gvr package (site-packages of a fresh virtual
environment created from the built wheel) with the repository source tree
absent from ``sys.path``. Repeats the Drive Task38 attack surface under the
same active trust context: every observation-content transplant must fail
closed, benign same-context replay must stay VERIFIED with a stable origin
document. Exit code 0 only when all checks pass.
"""
from __future__ import annotations

from copy import deepcopy
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


def graphify_path_result() -> dict:
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
    from gvr.graphify_contract import expected_graphify_df_key

    evidence["key"] = expected_graphify_df_key(evidence)

    return {
        "repository": "fixture-repo",
        "revision": "rev-1",
        "start": "A",
        "target": "B",
        "direction": "FORWARD",
        "evidence_namespace": "task38-wheel",
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
                    {"source": evidence["source"], "target": evidence["target"], "relation": evidence["relation"], "evidence": evidence}
                ],
                "supporting_evidence": [evidence],
            }
        ],
    }


def codeflow_result() -> dict:
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
            "evidence_namespace": "task38-wheel",
        },
        "nodes": [{"id": "codeflow:function:src/a.py|1|a", "kind": "FUNCTION"}],
        "edges": [],
        "blockers": [],
    }


def main() -> int:
    import gvr

    print("installed from wheel:", gvr.__file__)
    check("import-from-site-packages", "site-packages" in Path(gvr.__file__).as_posix(), gvr.__file__)

    from gvr.adapters.codeflow import encode_codeflow_code_graph_observation_evidence
    from gvr.adapters.graphify import encode_graphify_code_graph_observation_evidence
    from gvr.canonical import canonical_fingerprint
    from gvr.code_graph import (
        CODE_GRAPH_OBSERVATION_FINGERPRINT_FORMAT,
        EvidenceConfidence,
        GraphEvidence,
        GraphEvidenceKind,
        GraphFacts,
        GraphEvidenceModel,
        ProviderImplementationIdentity,
        graph_model_from_dict,
    )

    context = gvr.ProviderTrustContext.host_runtime("gvr.task38.wheel.matrix")

    def trusted_graphify(evidence_id: str) -> gvr.Evidence:
        with context.activate():
            return encode_graphify_code_graph_observation_evidence(
                graphify_path_result(), evidence_id=evidence_id, claim_fingerprint="wheel.claim"
            )

    genuine = trusted_graphify("obs.genuine")
    decoded = None
    with context.activate():
        decoded = gvr.decode_code_graph_observation_evidence(genuine)
    check("genuine-origin-verified", decoded.validated_origin is not None and decoded.validated_origin.trust_state is gvr.IndependenceTrustState.VERIFIED)
    check("v3-format-with-subject-binding", decoded.origin_assertion.to_dict()["format"] == "gvr.provider_origin_assertion.v3" and bool(decoded.origin_assertion.observation_subject_fingerprint))

    # Identical replay under the same context stays VERIFIED.
    replayed_decode = None
    with context.activate():
        replayed_decode = gvr.decode_code_graph_observation_evidence(genuine)
    check("identical-replay-verified", replayed_decode.validated_origin is not None)

    def transplant(genuine_evidence: gvr.Evidence, *, mutate=None, claim="wheel.forged") -> gvr.Evidence:
        payload = deepcopy(dict(genuine_evidence.payload))
        model_document = deepcopy(payload["graph_model"])
        if mutate is not None:
            mutate(model_document)
        model = graph_model_from_dict(model_document)
        payload["graph_model"] = model.to_dict()
        payload["graph_model_fingerprint"] = model.fingerprint
        payload["source_snapshot"] = deepcopy(dict(model.source_snapshot))
        payload["authority_metadata"] = deepcopy(dict(model.authority_metadata))
        payload["source_revision"] = model.source_revision.to_dict()
        payload["query_scope"] = model.query_scope.to_dict()
        payload["coverage"] = model.coverage.to_dict()
        if claim is not None:
            payload["claim_fingerprint"] = claim
        return gvr.Evidence(
            id="obs.wheel.forged",
            kind=payload["kind"],
            payload=payload,
            source=str(payload["provider_id"]),
            fingerprint=canonical_fingerprint(payload, fingerprint_format=CODE_GRAPH_OBSERVATION_FINGERPRINT_FORMAT),
        )

    def must_reject(forged: gvr.Evidence, name: str) -> None:
        try:
            with context.activate():
                forged_decoded = gvr.decode_code_graph_observation_evidence(forged)
        except ValueError:
            check(name, True)
            return
        validated = forged_decoded.validated_origin
        ok = validated is None or validated.trust_state is not gvr.IndependenceTrustState.VERIFIED
        check(name, ok, "transplanted origin reached VERIFIED")

    # 1. Claim fingerprint transplant under the same context.
    must_reject(transplant(genuine), "claim-transplant-rejected")
    # 2. Graph-model content transplant.
    must_reject(
        transplant(genuine, mutate=lambda doc: doc["facts"]["nodes"][0].__setitem__("label", "forged"), claim=None),
        "graph-model-transplant-rejected",
    )
    # 3. Source revision transplant.
    must_reject(
        transplant(genuine, mutate=lambda doc: doc["source_revision"].__setitem__("revision", "forged-rev"), claim=None),
        "source-revision-transplant-rejected",
    )
    # 4. Query scope and coverage transplants.
    must_reject(
        transplant(genuine, mutate=lambda doc: doc["query_scope"].__setitem__("max_depth", 99), claim=None),
        "query-scope-transplant-rejected",
    )
    must_reject(
        transplant(genuine, mutate=lambda doc: doc["coverage"]["details"].__setitem__("forged", True), claim=None),
        "coverage-transplant-rejected",
    )
    # 5. Authority metadata transplant on a natively authority-tagged model.
    with context.activate():
        authority_genuine = encode_graphify_code_graph_observation_evidence(
            graphify_path_result(),
            evidence_id="obs.authority",
            claim_fingerprint="wheel.authority.claim",
            authority_metadata={"format": "wheel.v2", "snapshot_fingerprint": "a" * 64},
        )
    must_reject(
        transplant(authority_genuine, mutate=lambda doc: doc["authority_metadata"].__setitem__("snapshot_fingerprint", "0" * 64), claim=None),
        "v2-authority-metadata-transplant-rejected",
    )
    # 6. CodeFlow content transplant.
    with context.activate():
        codeflow_genuine = encode_codeflow_code_graph_observation_evidence(
            codeflow_result(), evidence_id="obs.codeflow", claim_fingerprint="wheel.codeflow.claim"
        )
    must_reject(
        transplant(codeflow_genuine, mutate=lambda doc: doc["facts"]["nodes"][0].__setitem__("id", "forged:id"), claim=None),
        "codeflow-transplant-rejected",
    )
    # 7. Host-registered custom provider content transplant.
    custom_context = gvr.ProviderTrustContext.host_runtime(
        "gvr.task38.wheel.matrix.custom",
        registrations=(gvr.ProviderImplementationRegistration("custom-impl", "custom-kind", "custom-family"),),
    )
    node = GraphEvidence(
        id="display:node:A",
        kind=GraphEvidenceKind.NODE,
        semantic_identity={"handle": "A"},
        exact_identity={"handle": "A", "file": "src/a.py"},
        confidence=EvidenceConfidence.EXACT,
        label="original-label",
    )
    with custom_context.activate():
        custom_genuine = custom_context.encode_code_graph_observation_evidence(
            GraphEvidenceModel(
                provider_identity=ProviderImplementationIdentity("display", "custom-impl", "custom-family", provider_kind="custom-kind"),
                facts=GraphFacts(nodes=(node,)),
            ),
            evidence_id="obs.custom",
            claim_fingerprint="wheel.custom.claim",
        )
    custom_payload = deepcopy(dict(custom_genuine.payload))
    custom_payload["graph_model"]["facts"]["nodes"][0]["label"] = "forged-label"
    custom_model = graph_model_from_dict(custom_payload["graph_model"])
    custom_payload["graph_model"] = custom_model.to_dict()
    custom_payload["graph_model_fingerprint"] = custom_model.fingerprint
    custom_forged = gvr.Evidence(
        id="obs.custom.forged",
        kind=custom_payload["kind"],
        payload=custom_payload,
        source=str(custom_payload["provider_id"]),
        fingerprint=canonical_fingerprint(custom_payload, fingerprint_format=CODE_GRAPH_OBSERVATION_FINGERPRINT_FORMAT),
    )
    must_reject(custom_forged, "custom-provider-transplant-rejected")

    # 8. No active context and foreign context of the same configuration.
    expect_raises(gvr.CodeGraphObservationError, lambda: gvr.decode_code_graph_observation_evidence(genuine), "no-active-context-rejected")
    other = gvr.ProviderTrustContext.host_runtime("gvr.task38.wheel.matrix")

    def decode_under_foreign_context():
        with other.activate():
            return gvr.decode_code_graph_observation_evidence(genuine)

    expect_raises(gvr.CodeGraphObservationError, decode_under_foreign_context, "new-context-rejected")

    # 9. SQLite same-context replay keeps trust; tampered reload fails closed.
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        store = gvr.SQLiteStorage(Path(tmp) / "matrix.sqlite3")
        stored = store.put_evidence(genuine)
        reloaded = gvr.SQLiteStorage(Path(tmp) / "matrix.sqlite3").get_evidence(stored.fingerprint).evidence
        sqlite_replay = None
        with context.activate():
            sqlite_replay = gvr.decode_code_graph_observation_evidence(reloaded)
        check(
            "sqlite-same-context-replay-verified",
            sqlite_replay.validated_origin is not None
            and sqlite_replay.origin_assertion.to_dict() == decoded.origin_assertion.to_dict(),
        )
        must_reject(
            transplant(reloaded, mutate=lambda doc: doc["facts"]["nodes"][0].__setitem__("label", "forged"), claim=None),
            "sqlite-tamper-rejected",
        )

    # 10. Public generic encoding remains UNVERIFIED even inside an active context.
    identity = ProviderImplementationIdentity("generic", "generic", "generic")
    with context.activate():
        generic = gvr.encode_code_graph_observation_evidence(
            GraphEvidenceModel(provider_identity=identity), evidence_id="obs.generic", claim_fingerprint="claim"
        )
        generic_decoded = gvr.decode_code_graph_observation_evidence(generic)
    check(
        "public-generic-stays-unverified",
        generic_decoded.independence.trust_state is gvr.IndependenceTrustState.UNVERIFIED and generic_decoded.validated_origin is None,
    )

    print()
    if failures:
        print(f"{len(failures)} FAILURES")
        return 1
    print("ALL CHECKS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
