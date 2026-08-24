from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from ..code_graph import (
    EvidenceConfidence,
    GraphBlocker,
    GraphEvidence,
    GraphEvidenceKind,
    GraphEvidenceModel,
    GraphEvidenceModelError,
)
from ..model import Evidence, VerificationVerdict


_COMPLETE = "COMPLETE_FOR_SUPPORTED_CONSTRUCT"
_EXACT_PATH = "EXACT_FOR_RETURNED_PATH"
_SUPPORTED_DATA_FLOW_RELATIONS = frozenset({
    "FLOWS_TO",
    "PASSED_AS_ARGUMENT",
    "READ_FROM",
    "RETURNED_AS",
    "TRANSFORMED_BY",
    "WRITTEN_TO",
})


@dataclass(frozen=True)
class GraphifyTraversalEvidence:
    """Evidence and audit metadata ingested from Graphify's public result contract."""

    evidence: tuple[Evidence, ...]
    complete_supported_search: bool
    search_coverage: str
    termination_reason: str
    blocking_boundary_keys: tuple[str, ...]
    boundary_evidence: tuple[Evidence, ...] = ()
    conflicting_evidence_ids: tuple[str, ...] = ()
    start: str = ""
    target: str | None = None
    direction: str = "UNKNOWN"
    truncated: bool = False
    input_resolution: str = "UNKNOWN"
    query_validity: bool = False
    start_node_found: bool = False
    target_node_found: bool | None = None
    query_bounds: Mapping[str, Any] = field(default_factory=dict)

    @property
    def absence_verdict(self) -> VerificationVerdict:
        """Whether an empty-path result may support an absence claim."""
        if self.complete_supported_search and self.search_coverage == "COMPLETE_FOR_SUPPORTED_CONSTRUCT":
            return VerificationVerdict.PASS
        return VerificationVerdict.UNKNOWN


def _mapping_items(value: Any) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item for item in value if isinstance(item, Mapping))


def ingest_traversal_result(result: Mapping[str, Any]) -> GraphifyTraversalEvidence:
    """Ingest only Graphify's public traversal-result mapping.

    This adapter does not reparse source or reconstruct a graph. It exposes the
    exact direct and boundary evidence records so a verifier report can be
    recorded in :class:`gvr.ledger.ClaimLedger` without custom dependency logic.
    Validation of whether the payload proves a claim remains the verifier's job.
    """

    direct_by_key: dict[str, Evidence] = {}
    conflicting_evidence_ids: set[str] = set()
    for path in _mapping_items(result.get("paths")):
        for item in _mapping_items(path.get("supporting_evidence")):
            key = str(item.get("key") or "")
            if not key:
                continue
            candidate = Evidence(
                id=key,
                kind="graphify.data_flow_edge",
                payload=dict(item),
                source=str(item.get("source_file") or "") or None,
                fingerprint=key,
            )
            existing = direct_by_key.get(key)
            if existing is not None and existing != candidate:
                conflicting_evidence_ids.add(key)
            else:
                direct_by_key.setdefault(key, candidate)

    boundary_by_key: dict[str, Evidence] = {}
    for event in _mapping_items(result.get("boundary_events")):
        key = str(
            event.get("boundary_evidence_key")
            or event.get("diagnostic_evidence_key")
            or ""
        )
        if not key:
            continue
        candidate = Evidence(
            id=key,
            kind="graphify.data_flow_boundary",
            payload=dict(event),
            source=str(event.get("canonical_caller_file") or "") or None,
            fingerprint=key,
        )
        existing = boundary_by_key.get(key)
        if existing is not None and existing != candidate:
            conflicting_evidence_ids.add(key)
        else:
            boundary_by_key.setdefault(key, candidate)

    conflicting_evidence_ids.update(set(direct_by_key) & set(boundary_by_key))
    boundary_keys = tuple(sorted(boundary_by_key))
    all_evidence = {**direct_by_key, **boundary_by_key}
    return GraphifyTraversalEvidence(
        evidence=tuple(all_evidence[key] for key in sorted(all_evidence)),
        complete_supported_search=bool(result.get("complete_supported_search", False)),
        search_coverage=str(result.get("search_coverage") or "UNKNOWN"),
        termination_reason=str(result.get("termination_reason") or "UNKNOWN"),
        blocking_boundary_keys=boundary_keys,
        boundary_evidence=tuple(boundary_by_key[key] for key in boundary_keys),
        conflicting_evidence_ids=tuple(sorted(conflicting_evidence_ids)),
        start=str(result.get("start") or ""),
        target=(None if result.get("target") is None else str(result.get("target"))),
        direction=str(result.get("direction") or "UNKNOWN"),
        truncated=bool(result.get("truncated", False)),
        input_resolution=str(result.get("input_resolution") or "UNKNOWN"),
        query_validity=result.get("query_validity") is True,
        start_node_found=result.get("start_node_found") is True,
        target_node_found=(
            None
            if result.get("target_node_found") is None
            else result.get("target_node_found") is True
        ),
        query_bounds=(
            dict(result.get("query_bounds", {}))
            if isinstance(result.get("query_bounds", {}), Mapping)
            else {}
        ),
    )


def _require_df_key(item: Mapping[str, Any]) -> str:
    key = str(item.get("key") or "")
    if not key.startswith("df:") or len(key) <= 3:
        raise GraphEvidenceModelError("Graphify traversal evidence requires a public df key")
    return key


def _node_id(value: str) -> str:
    if not value:
        raise GraphEvidenceModelError("Graphify traversal node id must be non-empty")
    return f"graphify:node:{value}"


def _edge_identity(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "key": str(item.get("key") or ""),
        "relation": str(item.get("relation") or ""),
        "source": str(item.get("source") or ""),
        "target": str(item.get("target") or ""),
        "source_file": str(item.get("source_file") or ""),
        "source_location": str(item.get("source_location") or ""),
        "provenance": str(item.get("provenance") or ""),
        "argument_index": item.get("argument_index"),
    }


def _path_by_evidence(paths: tuple[Mapping[str, Any], ...]) -> dict[str, tuple[Mapping[str, Any], Mapping[str, Any]]]:
    owners: dict[str, tuple[Mapping[str, Any], Mapping[str, Any]]] = {}
    identities: dict[str, Mapping[str, Any]] = {}
    for index, path in enumerate(paths):
        identity = path.get("path_identity")
        supporting = _mapping_items(path.get("supporting_evidence"))
        if identity is not None:
            if not isinstance(identity, (list, tuple)):
                raise GraphEvidenceModelError("Graphify path_identity must be ordered public df keys")
            keys = tuple(str(key) for key in identity)
            if keys != tuple(str(item.get("key") or "") for item in supporting):
                raise GraphEvidenceModelError("Graphify path_identity must exactly match supporting_evidence order")
            for key in keys:
                if not key.startswith("df:"):
                    raise GraphEvidenceModelError("Graphify path_identity contains a non-df key")
        for item in supporting:
            key = _require_df_key(item)
            identity = _edge_identity(item)
            existing_identity = identities.get(key)
            if existing_identity is not None and existing_identity != identity:
                raise GraphEvidenceModelError(f"conflicting duplicate graphify df key: {key}")
            identities[key] = identity
            owners.setdefault(key, (item, path))
    return owners


def _edge_confidence(item: Mapping[str, Any], path: Mapping[str, Any] | None) -> EvidenceConfidence:
    relation = str(item.get("relation") or "")
    if relation not in _SUPPORTED_DATA_FLOW_RELATIONS:
        return EvidenceConfidence.HEURISTIC
    if str(item.get("receiver_confidence") or "") != "PROVEN":
        return EvidenceConfidence.HEURISTIC
    if str(item.get("analysis_completeness") or "") != _COMPLETE:
        return EvidenceConfidence.HEURISTIC
    if path is None:
        return EvidenceConfidence.HEURISTIC
    if str(path.get("path_exactness") or "") != _EXACT_PATH:
        return EvidenceConfidence.HEURISTIC
    if str(path.get("path_receiver_confidence") or "") != "PROVEN":
        return EvidenceConfidence.HEURISTIC
    if str(path.get("path_coverage") or "") != _COMPLETE:
        return EvidenceConfidence.HEURISTIC
    return EvidenceConfidence.EXACT


def _edge_blockers(item: Mapping[str, Any]) -> tuple[GraphBlocker, ...]:
    key = str(item.get("key") or "")
    blockers: list[GraphBlocker] = []
    relation = str(item.get("relation") or "")
    if relation not in _SUPPORTED_DATA_FLOW_RELATIONS:
        blockers.append(GraphBlocker(f"{key}:UNSUPPORTED_RELATION", "UNSUPPORTED_RELATION", key, {"relation": relation}))
    receiver = str(item.get("receiver_confidence") or "")
    if receiver != "PROVEN":
        blockers.append(GraphBlocker(f"{key}:MAY", "MAY", key, {"receiver_confidence": receiver or "UNKNOWN"}))
    completeness = str(item.get("analysis_completeness") or "")
    if completeness != _COMPLETE:
        blockers.append(GraphBlocker(f"{key}:PARTIAL", "PARTIAL", key, {"analysis_completeness": completeness or "UNKNOWN"}))
    return tuple(blockers)


def ingest_traversal_graph(result: Mapping[str, Any]) -> GraphEvidenceModel:
    """Map a Graphify public traversal result into Task 27 graph evidence.

    The adapter consumes only the already-returned public traversal mapping. It
    never imports Graphify, calls traversal APIs, reparses source, fabricates
    missing evidence keys, or upgrades MAY/PARTIAL/unsupported evidence to exact.
    """

    paths = _mapping_items(result.get("paths"))
    path_owners = _path_by_evidence(paths)

    nodes_by_id: dict[str, GraphEvidence] = {}
    edges_by_id: dict[str, GraphEvidence] = {}
    blockers: list[GraphBlocker] = []

    def add_node(raw_id: str) -> None:
        node_id = _node_id(raw_id)
        nodes_by_id.setdefault(
            node_id,
            GraphEvidence(
                id=node_id,
                kind=GraphEvidenceKind.NODE,
                semantic_identity={"id": raw_id},
                exact_identity={"id": raw_id},
                confidence=EvidenceConfidence.EXACT,
                label=raw_id,
                native={"provider": "graphify"},
            ),
        )

    for key in sorted(path_owners):
        item, path = path_owners[key]
        identity = _edge_identity(item)
        source = str(item.get("source") or "")
        target = str(item.get("target") or "")
        add_node(source)
        add_node(target)
        edge = GraphEvidence(
            id=key,
            kind=GraphEvidenceKind.REFERENCE,
            semantic_identity={"relation": identity["relation"], "source": source, "target": target},
            exact_identity=identity,
            confidence=_edge_confidence(item, path),
            source=_node_id(source),
            target=_node_id(target),
            label=identity["relation"],
            native={
                "provider": "graphify",
                "path_exactness": str(path.get("path_exactness") or ""),
                "path_receiver_confidence": str(path.get("path_receiver_confidence") or ""),
                "path_coverage": str(path.get("path_coverage") or ""),
                "evidence": dict(item),
            },
        )
        existing = edges_by_id.get(key)
        if existing is not None and existing != edge:
            raise GraphEvidenceModelError(f"conflicting duplicate graphify df key: {key}")
        edges_by_id[key] = edge
        blockers.extend(_edge_blockers(item))

    for event in _mapping_items(result.get("boundary_events")):
        key = str(event.get("boundary_evidence_key") or event.get("diagnostic_evidence_key") or "")
        if not key:
            continue
        blockers.append(GraphBlocker(key, str(event.get("resolution") or "BOUNDARY"), str(event.get("canonical_caller_file") or ""), dict(event)))

    complete_absence = (
        result.get("complete_supported_search") is True
        and str(result.get("search_coverage") or "") == _COMPLETE
        and result.get("truncated") is not True
        and result.get("query_validity") is True
        and str(result.get("input_resolution") or "") == "RESOLVED"
        and not _mapping_items(result.get("boundary_events"))
        and result.get("encountered_partial_evidence") is not True
        and result.get("encountered_unknown_evidence") is not True
    )
    absence_subjects: tuple[str, ...] = ()
    start = str(result.get("start") or "")
    target = result.get("target")
    if complete_absence and not edges_by_id and start and target is not None:
        absence_subjects = (f"{start}->{target}",)

    return GraphEvidenceModel(
        provider="graphify",
        nodes=tuple(nodes_by_id[key] for key in sorted(nodes_by_id)),
        edges=tuple(edges_by_id[key] for key in sorted(edges_by_id)),
        blockers=tuple(blockers),
        absence_subjects=absence_subjects,
        source_snapshot={
            "start": start,
            "target": None if target is None else str(target),
            "direction": str(result.get("direction") or "UNKNOWN"),
            "termination_reason": str(result.get("termination_reason") or "UNKNOWN"),
            "search_coverage": str(result.get("search_coverage") or "UNKNOWN"),
            "complete_supported_search": result.get("complete_supported_search") is True,
            "query_bounds": dict(result.get("query_bounds") or {}) if isinstance(result.get("query_bounds"), Mapping) else {},
        },
    )
