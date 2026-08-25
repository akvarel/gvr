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

    if failures:
        print("MATRIX FAILED:", failures)
        return 1
    print("MATRIX OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
