from __future__ import annotations

from typing import Any, Mapping

from ..canonical import canonical_fingerprint

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
from ..model import Evidence


_ADAPTER_FAMILY_ID = "codeflow"


def _items(value: Any) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item for item in value if isinstance(item, Mapping))


def _identity(item: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = item.get(key)
    return dict(value) if isinstance(value, Mapping) else {}


def _require_adapter_family(family_id: str) -> None:
    if family_id != _ADAPTER_FAMILY_ID:
        raise ValueError("CodeFlow provider family is adapter-sealed")


def _codeflow_envelope(result: Mapping[str, Any]) -> Mapping[str, Any] | None:
    if set(result) >= {"schemaVersion", "data", "snapshot"}:
        if result.get("schemaVersion") != 1:
            raise GraphEvidenceModelError("unsupported CodeFlow schemaVersion")
        data = result.get("data")
        snapshot = result.get("snapshot")
        if not isinstance(data, Mapping) or not isinstance(snapshot, Mapping):
            raise GraphEvidenceModelError("CodeFlow envelope requires data and snapshot mappings")
        return data
    return None


def _file_node(item: Mapping[str, Any]) -> GraphEvidence:
    path = str(item.get("path") or "")
    if not path:
        raise GraphEvidenceModelError("CodeFlow file node requires path")
    return GraphEvidence(
        id=f"codeflow:file:{path}",
        kind=GraphEvidenceKind.NODE,
        semantic_identity={
            "path": path,
            "name": str(item.get("name") or ""),
            "folder": str(item.get("folder") or ""),
            "layer": str(item.get("layer") or ""),
            "is_code": item.get("isCode") is True,
        },
        exact_identity={
            "path": path,
            "lines": item.get("lines"),
            "parser_provenance": str(item.get("parserProvenance") or ""),
        },
        confidence=EvidenceConfidence.HEURISTIC,
        label=path,
        native={"kind": "file", "provider": "codeflow"},
    )


def _function_node(item: Mapping[str, Any]) -> GraphEvidence:
    key = str(item.get("key") or "")
    if not key:
        raise GraphEvidenceModelError("CodeFlow function node requires key")
    file_path = str(item.get("file") or "")
    name = str(item.get("name") or "")
    return GraphEvidence(
        id=f"codeflow:function:{key}",
        kind=GraphEvidenceKind.NODE,
        semantic_identity={
            "name": name,
            "file": file_path,
            "type": str(item.get("type") or ""),
            "layer": str(item.get("layer") or ""),
        },
        exact_identity={
            "key": key,
            "file": file_path,
            "line": item.get("line"),
            "is_exported": item.get("isExported"),
            "is_top_level": item.get("isTopLevel"),
            "is_class_method": item.get("isClassMethod"),
        },
        confidence=EvidenceConfidence.HEURISTIC,
        source=f"codeflow:file:{file_path}" if file_path else "",
        label=name or key,
        native={"kind": "function", "provider": "codeflow"},
    )


def _connection_edge(item: Mapping[str, Any]) -> GraphEvidence:
    source_file = str(item.get("source") or "")
    target_file = str(item.get("target") or "")
    function_key = str(item.get("functionKey") or "")
    if not source_file or not target_file:
        raise GraphEvidenceModelError("CodeFlow connection edge requires source and target")
    identity = {
        "source": source_file,
        "target": target_file,
        "function": str(item.get("fn") or ""),
        "functionKey": function_key,
        "count": item.get("count"),
    }
    edge_id = "codeflow:connection:" + canonical_fingerprint(identity, fingerprint_format="codeflow.connection.v1")
    return GraphEvidence(
        id=edge_id,
        kind=GraphEvidenceKind.REFERENCE,
        semantic_identity={
            "source": source_file,
            "target": target_file,
            "function": str(item.get("fn") or ""),
        },
        exact_identity=identity,
        confidence=EvidenceConfidence.HEURISTIC,
        source=f"codeflow:function:{function_key}" if function_key else f"codeflow:file:{source_file}",
        target=f"codeflow:file:{target_file}",
        label=str(item.get("fn") or "uses"),
        native={"kind": "connection", "provider": "codeflow"},
    )


def _layer_violation_blockers(data: Mapping[str, Any]) -> tuple[GraphBlocker, ...]:
    blockers: list[GraphBlocker] = []
    for index, item in enumerate(_items(data.get("layerViolations"))):
        file_path = str(item.get("file") or "")
        to_file = str(item.get("toFile") or "")
        blockers.append(GraphBlocker(
            id=f"codeflow:layer_violation:{index}:{file_path}->{to_file}",
            reason="layer_violation",
            scope=file_path,
            details=dict(item),
        ))
    return tuple(blockers)


def _ingest_codeflow_envelope(result: Mapping[str, Any], data: Mapping[str, Any]) -> GraphEvidenceModel:
    nodes = _dedupe(
        tuple(_file_node(item) for item in _items(data.get("files")))
        + tuple(_function_node(item) for item in _items(data.get("functions")))
    )
    edges = _dedupe(tuple(_connection_edge(item) for item in _items(data.get("connections"))))
    snapshot = result.get("snapshot")
    return GraphEvidenceModel(
        provider="codeflow",
        nodes=nodes,
        edges=edges,
        blockers=_layer_violation_blockers(data),
        absence_subjects=(),
        source_snapshot={
            "schemaVersion": result.get("schemaVersion"),
            "snapshot": dict(snapshot) if isinstance(snapshot, Mapping) else {},
            "stats": dict(data.get("stats")) if isinstance(data.get("stats"), Mapping) else {},
            "excludePatterns": tuple(str(item) for item in data.get("excludePatterns", ()) if isinstance(item, str)),
        },
    )


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

    envelope = _codeflow_envelope(result)
    if envelope is not None:
        return _ingest_codeflow_envelope(result, envelope)

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
    source_revision: SourceRevisionIdentity | None = None,
    query_scope: GraphQueryScope | None = None,
    source_snapshot: Mapping[str, Any] | None = None,
) -> Evidence:
    """Encode a precomputed CodeFlow canonical graph snapshot for execution.

    This adapter is the only place that understands CodeFlow's public snapshot
    shape. The verifier runtime receives only canonical observation evidence.
    """

    _require_adapter_family(family_id)
    graph = ingest_codeflow_graph(result)
    native_revision = _native_codeflow_revision(result)
    compatibility_revision = _revision_only_snapshot(source_snapshot)
    revisions = tuple(item for item in (native_revision, source_revision, compatibility_revision) if item is not None)
    if not revisions:
        raise GraphEvidenceModelError("CodeFlow authoritative observations require a typed source revision")
    if any(item != revisions[0] for item in revisions[1:]):
        raise GraphEvidenceModelError("CodeFlow source revision conflict")
    native_scope = _typed_query_scope(result.get("query_scope"))
    scopes = tuple(item for item in (native_scope, query_scope) if item is not None)
    if not scopes:
        raise GraphEvidenceModelError("CodeFlow authoritative observations require a typed query scope")
    if any(item != scopes[0] for item in scopes[1:]):
        raise GraphEvidenceModelError("CodeFlow query scope conflict")
    graph = GraphEvidenceModel(
        provider_identity=ProviderImplementationIdentity("codeflow", implementation_id, "codeflow"),
        source_revision=revisions[0],
        query_scope=scopes[0],
        coverage=CoverageCertificate(
            coverage="HEURISTIC_INDEX",
            complete_supported_search=False,
            termination_reason="CODEFLOW_HEURISTIC_ANALYSIS",
            truncated=False,
            details={"negative_authority": False},
        ),
        facts=GraphFacts(
            nodes=tuple(_as_heuristic(item) for item in graph.nodes),
            edges=tuple(_as_heuristic(item) for item in graph.edges),
            blockers=graph.blockers,
            absence_subjects=(),
        ),
    )
    return encode_code_graph_observation_evidence(
        graph,
        evidence_id=evidence_id,
        claim=claim,
        claim_fingerprint=claim_fingerprint,
    )


def _typed_revision(value: Any) -> SourceRevisionIdentity | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise GraphEvidenceModelError("CodeFlow source_revision must be a mapping")
    try:
        return SourceRevisionIdentity(str(value["repository"]), str(value["revision"]))
    except KeyError as exc:
        raise GraphEvidenceModelError("CodeFlow source_revision requires repository and revision") from exc


def _native_codeflow_revision(result: Mapping[str, Any]) -> SourceRevisionIdentity | None:
    native = _typed_revision(result.get("source_revision"))
    snapshot = result.get("snapshot")
    if not isinstance(snapshot, Mapping):
        return native
    revision = snapshot.get("revision") or snapshot.get("commit") or snapshot.get("sha")
    if revision is None:
        return native
    repository = snapshot.get("repository") or snapshot.get("repo") or result.get("repository") or result.get("repo")
    if not repository:
        raise GraphEvidenceModelError("CodeFlow native snapshot revision requires repository identity")
    snapshot_revision = SourceRevisionIdentity(str(repository), str(revision))
    if native is not None and native != snapshot_revision:
        raise GraphEvidenceModelError("CodeFlow source revision conflict")
    return snapshot_revision


def _revision_only_snapshot(value: Mapping[str, Any] | None) -> SourceRevisionIdentity | None:
    if value is None:
        return None
    allowed = {"repository", "repo", "revision", "commit", "sha", "source_revision"}
    if set(value) - allowed:
        raise GraphEvidenceModelError("scope-bearing legacy source_snapshot is forbidden on provider authority paths")
    nested = value.get("source_revision")
    if nested is not None:
        return _typed_revision(nested)
    repository = value.get("repository") or value.get("repo")
    revision = value.get("revision") or value.get("commit") or value.get("sha")
    if not repository or not revision:
        raise GraphEvidenceModelError("revision-only source_snapshot requires repository and revision")
    return SourceRevisionIdentity(str(repository), str(revision))


def _typed_query_scope(value: Any) -> GraphQueryScope | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise GraphEvidenceModelError("CodeFlow query_scope must be a mapping")
    return GraphQueryScope(
        start=str(value.get("start") or ""),
        target=None if value.get("target") is None else str(value.get("target")),
        direction=str(value.get("direction") or "FORWARD"),
        requested_relations=frozenset(str(item) for item in value.get("requested_relations", value.get("relations", ()))),
        effective_relations=frozenset(str(item) for item in value.get("effective_relations", value.get("relations", ()))),
        rejected_relations=frozenset(str(item) for item in value.get("rejected_relations", ())),
        max_depth=None if value.get("max_depth") is None else int(value["max_depth"]),
        max_paths=None if value.get("max_paths") is None else int(value["max_paths"]),
        max_expansions=None if value.get("max_expansions") is None else int(value["max_expansions"]),
        stop_nodes=frozenset(str(item) for item in value.get("stop_nodes", ())),
        evidence_namespace=str(value.get("evidence_namespace") or "default"),
    )


def _as_heuristic(item: GraphEvidence) -> GraphEvidence:
    if item.confidence in {EvidenceConfidence.HEURISTIC, EvidenceConfidence.INFERRED_HINT}:
        return item
    return GraphEvidence(
        id=item.id,
        kind=item.kind,
        semantic_identity=item.semantic_identity,
        exact_identity=item.exact_identity,
        confidence=EvidenceConfidence.HEURISTIC,
        source=item.source,
        target=item.target,
        label=item.label,
        native=item.native,
    )
