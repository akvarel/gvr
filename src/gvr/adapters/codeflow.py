from __future__ import annotations

from typing import Any, Mapping

from ..code_graph import (
    EvidenceConfidence,
    GraphBlocker,
    GraphEvidence,
    GraphEvidenceKind,
    GraphEvidenceModel,
    GraphEvidenceModelError,
    encode_code_graph_observation_evidence,
)
from ..model import Evidence


def _items(value: Any) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item for item in value if isinstance(item, Mapping))


def _identity(item: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = item.get(key)
    return dict(value) if isinstance(value, Mapping) else {}


def _node(item: Mapping[str, Any]) -> GraphEvidence:
    evidence_id = str(item.get("id") or "")
    if not evidence_id:
        raise GraphEvidenceModelError("node evidence requires id")
    return GraphEvidence(
        id=evidence_id,
        kind=GraphEvidenceKind.NODE,
        semantic_identity=_identity(item, "semantic_identity"),
        exact_identity=_identity(item, "exact_identity"),
        confidence=EvidenceConfidence.EXACT,
        label=str(item.get("label") or ""),
        native={"kind": str(item.get("kind") or "")},
    )


def _edge(item: Mapping[str, Any]) -> GraphEvidence:
    evidence_id = str(item.get("id") or "")
    if not evidence_id:
        raise GraphEvidenceModelError("edge evidence requires id")
    native_kind = str(item.get("kind") or "").lower()
    if native_kind == "call":
        kind = GraphEvidenceKind.CALL
        confidence = EvidenceConfidence.HEURISTIC
    elif native_kind == "reference":
        kind = GraphEvidenceKind.REFERENCE
        confidence = EvidenceConfidence.HEURISTIC
    elif native_kind == "architecture":
        kind = GraphEvidenceKind.ARCHITECTURE
        confidence = EvidenceConfidence.INFERRED_HINT
    else:
        kind = GraphEvidenceKind.REFERENCE
        confidence = EvidenceConfidence.HEURISTIC
    return GraphEvidence(
        id=evidence_id,
        kind=kind,
        semantic_identity=_identity(item, "semantic_identity"),
        exact_identity=_identity(item, "exact_identity"),
        confidence=confidence,
        source=str(item.get("source") or ""),
        target=str(item.get("target") or ""),
        native={"kind": native_kind},
    )


def _dedupe(items: tuple[GraphEvidence, ...]) -> tuple[GraphEvidence, ...]:
    by_id: dict[str, GraphEvidence] = {}
    for item in items:
        existing = by_id.get(item.id)
        if existing is not None and existing != item:
            raise GraphEvidenceModelError(f"conflicting duplicate native graph evidence id: {item.id}")
        by_id[item.id] = item
    return tuple(by_id.values())


def ingest_codeflow_graph(result: Mapping[str, Any]) -> GraphEvidenceModel:
    """Convert a pinned CodeFlow graph-like payload into canonical GVR evidence.

    The adapter is intentionally pure: it never executes CodeFlow, reparses source,
    opens files, uses Node, performs network access, or installs dependencies. It
    only normalizes the supplied public mapping into provider-independent evidence.
    """

    nodes = _dedupe(tuple(_node(item) for item in _items(result.get("nodes"))))
    edges = _dedupe(tuple(_edge(item) for item in _items(result.get("edges"))))
    blockers = tuple(
        GraphBlocker(
            id=str(item.get("id") or ""),
            reason=str(item.get("reason") or "unknown"),
            scope=str(item.get("scope") or ""),
            details=dict(item.get("details") or {}) if isinstance(item.get("details"), Mapping) else {},
        )
        for item in _items(result.get("blockers"))
        if str(item.get("id") or "")
    )
    snapshot = result.get("source_snapshot")
    return GraphEvidenceModel(
        provider="codeflow",
        nodes=nodes,
        edges=edges,
        blockers=blockers,
        absence_subjects=(),
        source_snapshot=dict(snapshot) if isinstance(snapshot, Mapping) else {},
    )


def encode_codeflow_code_graph_observation_evidence(
    result: Mapping[str, Any],
    *,
    evidence_id: str,
    claim: Any | None = None,
    claim_fingerprint: str | None = None,
    implementation_id: str = "codeflow",
    family_id: str = "codeflow",
    source_snapshot: Mapping[str, Any] | None = None,
) -> Evidence:
    """Encode a precomputed CodeFlow canonical graph snapshot for execution.

    This adapter is the only place that understands CodeFlow's public snapshot
    shape. The verifier runtime receives only canonical observation evidence.
    """

    return encode_code_graph_observation_evidence(
        ingest_codeflow_graph(result),
        evidence_id=evidence_id,
        claim=claim,
        claim_fingerprint=claim_fingerprint,
        implementation_id=implementation_id,
        family_id=family_id,
        source_snapshot=source_snapshot,
    )
