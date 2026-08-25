"""Generate genuine producer-derived Graphify v2 zero-step identity vectors.

Runs the exact bound pipeline of the Graphify producer at HEAD 529ade498158a86e607138b1c3e717874553294:
  derive_git_source_authority -> build_bound_structural_index -> run_bound_data_flow_query
  -> build_structural_evidence_snapshot -> snapshot.to_dict()
No document is hand-mutated or resealed: every emitted byte comes from the producer.
"""
import json, os, subprocess, sys
from pathlib import Path

GRAPHIFY_ROOT = Path(os.environ.get("GRAPHIFY_CHECKOUT", "/sharedssd/git/graphify"))
sys.path.insert(0, str(GRAPHIFY_ROOT))

from graphify.structural_evidence import (
    build_bound_structural_index,
    build_structural_evidence_snapshot,
    derive_git_source_authority,
)

GVR_ROOT = Path(__file__).resolve().parents[3]
OUT = GVR_ROOT / "tests" / "fixtures" / "structural_evidence"
SCRATCH = Path(os.environ.get("TASK37C_SCRATCH", Path.home() / ".jcode/scratch/task37c-sources"))

GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "Task37c Fixture",
    "GIT_AUTHOR_EMAIL": "task37c@example.com",
    "GIT_COMMITTER_NAME": "Task37c Fixture",
    "GIT_COMMITTER_EMAIL": "task37c@example.com",
    "GIT_AUTHOR_DATE": "2026-08-25T00:00:00+00:00",
    "GIT_COMMITTER_DATE": "2026-08-25T00:00:00+00:00",
}

CLEAN_SOURCE = (
    "package acme;\n"
    "class Pipeline {\n"
    "    Value run(Value in) { return transform(in); }\n"
    "    Value transform(Value v) { return v; }\n"
    "}\n"
    "class Value {}\n"
)

BOUNDARY_SOURCE = (
    "package acme;\n"
    "class Pipeline {\n"
    "    Value run(Value in) { Result r = new Result(in); return r.value(); }\n"
    "    Value fallback(Value v) { return v; }\n"
    "}\n"
    "class Value {}\n"
)


def make_repo(name: str, source: str) -> Path:
    repo = SCRATCH / name
    if repo.exists():
        subprocess.run(["rm", "-rf", str(repo)], check=True)
    src = repo / "src" / "acme"
    src.mkdir(parents=True)
    (src / "Pipeline.java").write_text(source, encoding="utf-8")
    for args in (["git", "init", "-q"], ["git", "add", "-A"], ["git", "commit", "-q", "-m", "source"]):
        subprocess.run(args, cwd=repo, check=True, env=GIT_ENV)
    return repo


def identity_snapshot(repo: Path, cache: Path) -> tuple[dict, dict]:
    authority = derive_git_source_authority(repo)
    index = build_bound_structural_index(authority, sorted(repo.rglob("*.java")), cache_root=cache)
    # Pick a deterministic start: the run() parameter data value node.
    start = next(
        node["id"]
        for node in index.nodes
        if node.get("type") == "data_value"
        and (node.get("metadata") or {}).get("kind") == "PARAMETER"
        and (node.get("metadata") or {}).get("name") == "in"
    )
    from graphify.data_flow_query import DataFlowQuery
    query = DataFlowQuery(start=start, target=start, max_depth=6)
    from graphify.structural_evidence import run_bound_data_flow_query
    analysis = run_bound_data_flow_query(index, query)
    result = analysis.result
    print(f"[{repo.name}] start={start}")
    print(f"  paths={len(result.paths)} boundary_events={len(result.boundary_events)} "
          f"coverage={result.search_coverage} complete={result.complete_supported_search} "
          f"termination={result.termination_reason} visited={result.visited_count} expanded={result.expanded_count}")
    snapshot = build_structural_evidence_snapshot(analysis)
    doc = snapshot.to_dict()
    return doc, {"start_node": start, "source_revision": authority.source_revision}


def main() -> None:
    SCRATCH.mkdir(parents=True, exist_ok=True)
    clean_repo = make_repo("clean-identity", CLEAN_SOURCE)
    boundary_repo = make_repo("boundary-identity", BOUNDARY_SOURCE)
    clean_doc, clean_meta = identity_snapshot(clean_repo, SCRATCH / "cache-clean")
    boundary_doc, boundary_meta = identity_snapshot(boundary_repo, SCRATCH / "cache-boundary")

    assert len(clean_doc["paths"]) == 1 and clean_doc["paths"][0]["path_identity"] == []
    assert not clean_doc["blockers"] and clean_doc["coverage"]["complete_supported_search"] is True
    assert len(boundary_doc["paths"]) == 1 and boundary_doc["paths"][0]["path_identity"] == []
    assert boundary_doc["blockers"], "boundary vector must carry a real blocking boundary"

    OUT.mkdir(parents=True, exist_ok=True)
    clean_path = OUT / "structural_evidence_v2_zero_step_identity_clean.json"
    boundary_path = OUT / "structural_evidence_v2_zero_step_identity_boundary.json"
    clean_path.write_text(json.dumps(clean_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    boundary_path.write_text(json.dumps(boundary_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    provenance = {
        "generator": "gen_vectors.py (this directory)",
        "producer_repository": "git@github.com:akvarel/graphify.git",
        "producer_checkout": "/sharedssd/git/graphify",
        "producer_head": subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=GRAPHIFY_ROOT, capture_output=True, text=True
        ).stdout.strip(),
        "producer_head_dirty": bool(subprocess.run(
            ["git", "status", "--porcelain"], cwd=GRAPHIFY_ROOT, capture_output=True, text=True
        ).stdout.strip()),
        "pipeline": [
            "derive_git_source_authority(repo)",
            "build_bound_structural_index(authority, rglob('*.java'), cache_root)",
            "run_bound_data_flow_query(index, DataFlowQuery(start=s, target=s, max_depth=6))",
            "build_structural_evidence_snapshot(analysis)",
            "StructuralEvidenceSnapshot.to_dict()",
        ],
        "analyzer_revision": clean_doc["analyzer_revision"],
        "vectors": {
            "clean": {
                "file": clean_path.name,
                "fingerprint": clean_doc["fingerprint"],
                "source_revision": clean_doc["source_revision_scope"]["source_revision"],
                "query_start_node": clean_meta["start_node"],
                "fixture_source_sha256": __import__("hashlib").sha256(CLEAN_SOURCE.encode()).hexdigest(),
            },
            "boundary": {
                "file": boundary_path.name,
                "fingerprint": boundary_doc["fingerprint"],
                "source_revision": boundary_doc["source_revision_scope"]["source_revision"],
                "query_start_node": boundary_meta["start_node"],
                "boundary_keys": [b["key"] for b in boundary_doc["blockers"]],
                "fixture_source_sha256": __import__("hashlib").sha256(BOUNDARY_SOURCE.encode()).hexdigest(),
            },
        },
        "authenticity": "Documents are direct producer output; no field was mutated or resealed.",
    }
    prov_path = OUT / "provenance" / "task37c_zero_step_identity_provenance.json"
    prov_path.parent.mkdir(parents=True, exist_ok=True)
    prov_path.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("wrote", clean_path)
    print("wrote", boundary_path)
    print("wrote", prov_path)


if __name__ == "__main__":
    main()
