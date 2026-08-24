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
    CoverageCertificate,
    GraphFacts,
    GraphQueryScope,
    ProviderImplementationIdentity,
    SourceRevisionIdentity,
    encode_code_graph_observation_evidence,
)
from ..graphify_contract import validate_graphify_df_evidence
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
_ADAPTER_FAMILY_ID = "graphify"


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
    return validate_graphify_df_evidence(item)


def _require_adapter_family(family_id: str) -> None:
    if family_id != _ADAPTER_FAMILY_ID:
        raise ValueError("Graphify provider family is adapter-sealed")


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
        absence_subjects = (f"{_node_id(start)}->{_node_id(str(target))}",)

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


def encode_graphify_code_graph_observation_evidence(
    result: Mapping[str, Any],
    *,
    evidence_id: str,
    claim: Any | None = None,
    claim_fingerprint: str | None = None,
    implementation_id: str = "graphify",
    family_id: str = "graphify",
    source_revision: SourceRevisionIdentity | None = None,
    source_snapshot: Mapping[str, Any] | None = None,
) -> Evidence:
    """Encode a precomputed Graphify traversal snapshot for execution.

    Graphify-specific parsing and exactness classification stays in this adapter.
    The execution runtime only decodes canonical provider observation evidence.
    """

    _require_adapter_family(family_id)
    graph = ingest_traversal_graph(result)
    revision = _authoritative_source_revision(result, source_revision, source_snapshot)
    query_scope = _graphify_query_scope(result)
    coverage = _graphify_coverage(result)
    graph = GraphEvidenceModel(
        provider_identity=ProviderImplementationIdentity("graphify", implementation_id, "graphify"),
        source_revision=revision,
        query_scope=query_scope,
        coverage=coverage,
        facts=GraphFacts(
            nodes=graph.nodes,
            edges=graph.edges,
            blockers=graph.blockers,
            absence_subjects=graph.absence_subjects,
        ),
    )
    return encode_code_graph_observation_evidence(
        graph,
        evidence_id=evidence_id,
        claim=claim,
        claim_fingerprint=claim_fingerprint,
    )


def _authoritative_source_revision(
    result: Mapping[str, Any],
    supplied: SourceRevisionIdentity | None,
    legacy: Mapping[str, Any] | None,
) -> SourceRevisionIdentity:
    native = _revision_mapping(result.get("source_revision"))
    if native is None:
        repository = result.get("repository") or result.get("repo")
        revision = result.get("revision") or result.get("commit") or result.get("sha")
        if repository is not None or revision is not None:
            if not repository or not revision:
                raise GraphEvidenceModelError("Graphify native revision requires repository and revision")
            native = SourceRevisionIdentity(str(repository), str(revision))
    compatibility = _revision_only_legacy_snapshot(legacy)
    candidates = tuple(item for item in (native, supplied, compatibility) if item is not None)
    if not candidates:
        raise GraphEvidenceModelError("Graphify authoritative observations require a typed source revision")
    if any(item != candidates[0] for item in candidates[1:]):
        raise GraphEvidenceModelError("Graphify source revision conflict")
    return candidates[0]


def _revision_mapping(value: Any) -> SourceRevisionIdentity | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise GraphEvidenceModelError("provider source_revision must be a mapping")
    try:
        return SourceRevisionIdentity(str(value["repository"]), str(value["revision"]))
    except KeyError as exc:
        raise GraphEvidenceModelError("provider source_revision requires repository and revision") from exc


def _revision_only_legacy_snapshot(value: Mapping[str, Any] | None) -> SourceRevisionIdentity | None:
    if value is None:
        return None
    allowed = {"repository", "repo", "revision", "commit", "sha", "source_revision"}
    if set(value) - allowed:
        raise GraphEvidenceModelError("scope-bearing legacy source_snapshot is forbidden on provider authority paths")
    nested = value.get("source_revision")
    if nested is not None:
        return _revision_mapping(nested)
    repository = value.get("repository") or value.get("repo")
    revision = value.get("revision") or value.get("commit") or value.get("sha")
    if not repository or not revision:
        raise GraphEvidenceModelError("revision-only source_snapshot requires repository and revision")
    return SourceRevisionIdentity(str(repository), str(revision))


def _native_set(value: Any, name: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple, set, frozenset)):
        raise GraphEvidenceModelError(f"Graphify {name} must be a sequence")
    return frozenset(str(item) for item in value)


def _native_bound(bounds: Mapping[str, Any], name: str) -> int | None:
    value = bounds.get(name)
    if value is None:
        return None
    if type(value) is not int or value < 0:
        raise GraphEvidenceModelError(f"Graphify {name} must be a non-negative integer")
    return value


def _native_bound_alias(bounds: Mapping[str, Any], *names: str) -> int | None:
    present = tuple(name for name in names if bounds.get(name) is not None)
    if not present:
        return None
    values = tuple(_native_bound(bounds, name) for name in present)
    if any(value != values[0] for value in values[1:]):
        raise GraphEvidenceModelError(f"Graphify conflicting bound aliases: {', '.join(present)}")
    return values[0]


def _graphify_query_scope(result: Mapping[str, Any]) -> GraphQueryScope:
    bounds = result.get("query_bounds", {})
    if not isinstance(bounds, Mapping):
        raise GraphEvidenceModelError("Graphify query_bounds must be a mapping")
    start = str(result.get("start") or "")
    target = result.get("target")
    if not start:
        raise GraphEvidenceModelError("Graphify authoritative query requires start")
    requested = _native_set(bounds.get("requested_relations", bounds.get("relations", ())), "requested_relations")
    effective = _native_set(bounds.get("effective_allowed_relations", bounds.get("effective_relations", bounds.get("relations", ()))), "effective_relations")
    return GraphQueryScope(
        start=_node_id(start),
        target=None if target is None else _node_id(str(target)),
        direction=str(result.get("direction") or bounds.get("direction") or "FORWARD"),
        requested_relations=requested,
        effective_relations=effective,
        rejected_relations=_native_set(bounds.get("rejected_relations", ()), "rejected_relations"),
        max_depth=_native_bound(bounds, "max_depth"),
        max_paths=_native_bound(bounds, "max_paths"),
        max_expansions=_native_bound_alias(bounds, "max_expansions", "max_visited_expansions", "visited_expansion_bound"),
        stop_nodes=frozenset(_node_id(item) for item in _native_set(bounds.get("stop_nodes", ()), "stop_nodes")),
        evidence_namespace=str(result.get("evidence_namespace") or "default"),
    )


def _graphify_coverage(result: Mapping[str, Any]) -> CoverageCertificate:
    boundary_keys = tuple(sorted(
        str(item.get("boundary_evidence_key") or item.get("diagnostic_evidence_key") or "")
        for item in _mapping_items(result.get("boundary_events"))
        if str(item.get("boundary_evidence_key") or item.get("diagnostic_evidence_key") or "")
    ))
    return CoverageCertificate(
        coverage=str(result.get("search_coverage") or "UNKNOWN"),
        complete_supported_search=result.get("complete_supported_search") is True,
        termination_reason=str(result.get("termination_reason") or "UNKNOWN"),
        truncated=result.get("truncated") is True,
        details={
            "query_validity": result.get("query_validity") is True,
            "input_resolution": str(result.get("input_resolution") or "UNKNOWN"),
            "start_node_found": result.get("start_node_found") is True,
            "target_node_found": None if result.get("target_node_found") is None else result.get("target_node_found") is True,
            "encountered_partial_evidence": result.get("encountered_partial_evidence") is True,
            "encountered_may_evidence": result.get("encountered_may_evidence") is True,
            "encountered_unknown_evidence": result.get("encountered_unknown_evidence") is True,
            "blocking_boundary_keys": boundary_keys,
        },
    )
