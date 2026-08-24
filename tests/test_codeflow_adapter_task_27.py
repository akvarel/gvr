import json
from pathlib import Path

import pytest

from gvr import VerificationVerdict
from gvr.code_graph import EvidenceConfidence, GraphEvidenceKind, GraphEvidenceModelError
from gvr.adapters.codeflow import ingest_codeflow_graph

FIXTURE = Path(__file__).parent / "fixtures" / "codeflow_task27_graph.json"


def load_fixture(**overrides):
    data = json.loads(FIXTURE.read_text())
    data.update(overrides)
    return data


def test_codeflow_adapter_normalizes_to_provider_independent_canonical_model():
    graph = ingest_codeflow_graph(load_fixture())

    assert graph.provider == "codeflow"
    assert graph.nodes[0].kind is GraphEvidenceKind.NODE
    assert graph.edges[0].kind is GraphEvidenceKind.CALL
    assert graph.fingerprint == ingest_codeflow_graph(load_fixture()).fingerprint

    assert graph.nodes[1].semantic_identity == {"qualified_name": "app.handler"}
    assert graph.nodes[1].exact_identity == {
        "path": "src/app.py",
        "span": (1, 5),
        "sha256": "222",
    }
    assert graph.nodes[1].semantic_fingerprint != graph.nodes[1].exact_fingerprint


def test_codeflow_epistemic_semantics_are_conservative():
    graph = ingest_codeflow_graph(load_fixture())
    by_id = {e.id: e for e in graph.evidence}

    assert by_id["edge:call:handler-save"].confidence is EvidenceConfidence.HEURISTIC
    assert by_id["edge:ref:app-db"].confidence is EvidenceConfidence.HEURISTIC
    assert by_id["edge:arch:web-db"].confidence is EvidenceConfidence.INFERRED_HINT

    assert graph.absence_verdict("db.delete_all") is VerificationVerdict.UNKNOWN
    assert graph.blockers[0].id == "blocker:unsupported-language"
    assert graph.blockers[0].reason == "unsupported_language"


def test_codeflow_adapter_is_deterministic_and_side_effect_free():
    raw = load_fixture()
    before = json.loads(json.dumps(raw, sort_keys=True))

    first = ingest_codeflow_graph(raw)
    second = ingest_codeflow_graph(raw)

    assert raw == before
    assert first.to_dict() == second.to_dict()
    assert first.fingerprint == second.fingerprint


def test_conflicting_native_duplicate_ids_fail_closed():
    duplicate = {
        "id": "edge:call:handler-save",
        "kind": "call",
        "source": "symbol:src/app.py#handler",
        "target": "symbol:src/db.py#save",
        "semantic_identity": {"caller": "app.handler", "callee": "db.save_v2"},
        "exact_identity": {"file": "src/app.py", "line": 4},
    }
    raw = load_fixture()
    raw["edges"] = raw["edges"] + [duplicate]

    with pytest.raises(GraphEvidenceModelError, match="conflicting duplicate"):
        ingest_codeflow_graph(raw)
