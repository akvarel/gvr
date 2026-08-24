from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from ..code_graph import (
    EvidenceConfidence,
    GraphEvidence,
    GraphEvidenceModel,
    GraphQueryScope,
    SourceRevisionIdentity,
)
from ..model import VerificationIssue, VerificationReport, VerificationVerdict

CODE_GRAPH_VERIFIER = "gvr.code_graph.v1"


class CodeGraphClaimKind(str, Enum):
    NODE_EXISTS = "NODE_EXISTS"
    EDGE_EXISTS = "EDGE_EXISTS"
    PATH_EXISTS = "PATH_EXISTS"
    NO_PATH = "NO_PATH"
    ALL_PATHS_PASS_THROUGH = "ALL_PATHS_PASS_THROUGH"
    BLAST_RADIUS_CONTAINS = "BLAST_RADIUS_CONTAINS"


@dataclass(frozen=True)
class CodeGraphScope:
    snapshot: Mapping[str, Any] = field(default_factory=dict)
    relations: frozenset[str] = field(default_factory=frozenset)
    direction: str = "FORWARD"
    evidence_namespace: str = "default"
    max_depth: int | None = None
    stop_nodes: frozenset[str] = field(default_factory=frozenset)
    source_revision: SourceRevisionIdentity | None = None
    query_scope: GraphQueryScope | None = None

    def __post_init__(self) -> None:
        if self.query_scope is not None:
            if not isinstance(self.query_scope, GraphQueryScope):
                raise ValueError("code-graph query_scope must be a GraphQueryScope")
            typed = self.query_scope
            object.__setattr__(self, "relations", typed.relations)
            object.__setattr__(self, "direction", typed.direction)
            object.__setattr__(self, "evidence_namespace", typed.evidence_namespace)
            object.__setattr__(self, "max_depth", typed.max_depth)
            object.__setattr__(self, "stop_nodes", typed.stop_nodes)
        if self.source_revision is not None and not isinstance(self.source_revision, SourceRevisionIdentity):
            raise ValueError("code-graph source_revision must be a SourceRevisionIdentity")
        object.__setattr__(self, "snapshot", _stable(self.snapshot))
        object.__setattr__(self, "relations", frozenset(str(r) for r in self.relations))
        direction = str(self.direction or "FORWARD").upper()
        if direction not in {"FORWARD", "BACKWARD"}:
            raise ValueError(f"invalid code-graph scope direction: {direction!r}")
        object.__setattr__(self, "direction", direction)
        if not self.evidence_namespace:
            raise ValueError("code-graph scope requires a non-empty evidence namespace")
        object.__setattr__(self, "evidence_namespace", str(self.evidence_namespace))
        if self.max_depth is not None:
            max_depth = int(self.max_depth)
            if max_depth < 0:
                raise ValueError("code-graph scope max_depth must be non-negative")
            object.__setattr__(self, "max_depth", max_depth)
        object.__setattr__(self, "stop_nodes", frozenset(str(node) for node in self.stop_nodes))


@dataclass(frozen=True)
class CodeGraphClaim:
    kind: CodeGraphClaimKind
    node: str | None = None
    source: str | None = None
    target: str | None = None
    through: str | None = None
    max_depth: int | None = None
    relations: frozenset[str] = field(default_factory=frozenset)
    scope: CodeGraphScope = field(default_factory=CodeGraphScope)
    evidence_namespace: str = "default"

    def __post_init__(self) -> None:
        if not isinstance(self.kind, CodeGraphClaimKind):
            object.__setattr__(self, "kind", CodeGraphClaimKind(str(self.kind)))
        if not isinstance(self.scope, CodeGraphScope):
            if not isinstance(self.scope, Mapping):
                raise ValueError("code-graph claim scope must be a CodeGraphScope")
            object.__setattr__(self, "scope", CodeGraphScope(**dict(self.scope)))
        claim_relations = frozenset(str(r) for r in self.relations)
        if claim_relations and self.scope.relations and claim_relations != self.scope.relations:
            raise ValueError("code-graph claim relations conflict with scope relations")
        object.__setattr__(self, "relations", claim_relations or self.scope.relations)
        if self.evidence_namespace and self.scope.evidence_namespace != "default" and self.evidence_namespace != "default" and self.evidence_namespace != self.scope.evidence_namespace:
            raise ValueError("code-graph claim evidence_namespace conflicts with scope evidence_namespace")
        evidence_namespace = self.scope.evidence_namespace if self.evidence_namespace == "default" else self.evidence_namespace
        if not evidence_namespace:
            raise ValueError("code-graph claim requires a non-empty evidence namespace")
        object.__setattr__(self, "evidence_namespace", evidence_namespace)
        if self.max_depth is not None:
            max_depth = int(self.max_depth)
            if max_depth < 0:
                raise ValueError("code-graph claim max_depth must be non-negative")
            if self.scope.max_depth is not None and max_depth != self.scope.max_depth:
                raise ValueError("code-graph claim max_depth conflicts with scope max_depth")
            object.__setattr__(self, "max_depth", max_depth)
        elif self.scope.max_depth is not None:
            object.__setattr__(self, "max_depth", self.scope.max_depth)


_MESSAGES = {
    "PROVEN_NODE": "An exact canonical node proves the node-existence claim.",
    "PROVEN_EDGE": "An exact canonical edge proves the edge-existence claim.",
    "PROVEN_GRAPH_EDGE": "An exact canonical graph edge proves the edge-existence claim.",
    "PROVEN_PATH": "An exact canonical BFS path proves the path-existence claim.",
    "PROVEN_GRAPH_PATH": "An exact canonical graph path proves the path-existence claim.",
    "PROVEN_ABSENCE": "The canonical graph contains a scoped complete absence observation.",
    "COMPLETE_GRAPH_ABSENCE": "The canonical graph contains a scoped complete absence observation.",
    "NODE_ABSENT": "The requested node is absent from the canonical graph.",
    "EDGE_ABSENT": "No matching canonical edge is present.",
    "PATH_ABSENT": "No matching canonical path is present.",
    "ABSENCE_NOT_PROVEN": "The canonical observations do not prove path absence.",
    "INCOMPLETE_GRAPH_SEARCH": "The canonical graph search is incomplete for this scoped claim.",
    "BYPASS_ABSENCE_NOT_PROVEN": "The canonical observations do not prove complete absence of paths bypassing the required node.",
    "COUNTEREXAMPLE_PATH": "A canonical path counterexample disproves the claim.",
    "NONVACUOUS_PATH_REQUIRED": "All-paths claims require at least one path to quantify over.",
    "ALL_PATHS_PASS_THROUGH": "Every canonical path passes through the required node.",
    "BLAST_RADIUS_CONTAINS": "The target is reachable within the requested blast depth.",
    "TARGET_OUTSIDE_BLAST_RADIUS": "The target is not reachable within the requested blast depth.",
    "NODE_NOT_EXACT": "The matching node is heuristic, inferred, or otherwise non-exact.",
    "EDGE_NOT_EXACT": "The matching edge or path contains heuristic, inferred, or otherwise non-exact evidence.",
    "HEURISTIC_ONLY_SUPPORT": "The matching graph support is heuristic, inferred, or otherwise non-exact.",
    "GRAPH_BLOCKED": "Graph blockers make this canonical observation set incomplete for the claim.",
    "SNAPSHOT_MISMATCH": "The claim scope snapshot does not match the graph evidence snapshot.",
    "SOURCE_SNAPSHOT_MISMATCH": "The claim scope snapshot does not match the graph evidence source snapshot.",
    "UNSUPPORTED_RELATION": "The graph evidence records an unsupported relation for this claim.",
    "CONFLICTING_GRAPH_EVIDENCE": "The graph evidence contains conflicting observations for this claim.",
    "MALFORMED_GRAPH_EVIDENCE": "The graph evidence is malformed and was treated as fail-closed UNKNOWN.",
    "SOURCE_REVISION_MISMATCH": "The claim and graph observation are bound to different source revisions.",
    "GRAPH_QUERY_SCOPE_MISMATCH": "The claim and graph observation are bound to different query scopes.",
    "INCOMPLETE_COVERAGE_CERTIFICATE": "The typed coverage certificate cannot prove a complete negative search.",
}

_LEGACY_ISSUE_ALIASES = {
    "PROVEN_GRAPH_EDGE": ("PROVEN_EDGE",),
    "PROVEN_GRAPH_PATH": ("PROVEN_PATH",),
    "COMPLETE_GRAPH_ABSENCE": ("PROVEN_ABSENCE",),
    "HEURISTIC_ONLY_SUPPORT": ("EDGE_NOT_EXACT",),
    "INCOMPLETE_GRAPH_SEARCH": ("ABSENCE_NOT_PROVEN",),
    "SOURCE_SNAPSHOT_MISMATCH": ("SNAPSHOT_MISMATCH",),
}


def verify_code_graph_claim(claim: CodeGraphClaim, graph: GraphEvidenceModel) -> VerificationReport:
    if not isinstance(claim, CodeGraphClaim):
        raise ValueError("claim must be a CodeGraphClaim")
    issues: list[VerificationIssue] = []
    if claim.scope.snapshot and _stable(graph.source_snapshot) != claim.scope.snapshot:
        issues.extend(_issues("SOURCE_SNAPSHOT_MISMATCH", VerificationVerdict.UNKNOWN))
        return _report(VerificationVerdict.UNKNOWN, issues)

    blocker_issues = _blocker_issues(graph)
    nodes = _node_index(graph)
    edges = _dedupe_edges(graph.edges)
    relations = claim.relations or claim.scope.relations
    direction = claim.scope.direction
    max_depth = claim.max_depth
    stop_nodes = claim.scope.stop_nodes

    if claim.kind is CodeGraphClaimKind.NODE_EXISTS:
        matches = nodes.get(str(claim.node), ())
        return _positive_item(
            matches,
            "PROVEN_NODE",
            "NODE_NOT_EXACT",
            "NODE_ABSENT",
            _complete_absence_for_node(graph, claim.node, blocker_issues),
            blocker_issues,
        )

    if claim.kind is CodeGraphClaimKind.EDGE_EXISTS:
        matches = [e for e in edges if e.source == claim.source and e.target == claim.target and _relation_ok(e, relations)]
        return _positive_item(
            matches,
            "PROVEN_GRAPH_EDGE",
            "HEURISTIC_ONLY_SUPPORT",
            "EDGE_ABSENT",
            _complete_absence_for_pair(graph, claim.source, claim.target, blocker_issues),
            blocker_issues,
        )

    if claim.kind is CodeGraphClaimKind.PATH_EXISTS:
        exact_path = _bfs_exact(edges, str(claim.source), str(claim.target), relations, direction=direction, max_depth=max_depth, stop_nodes=stop_nodes)
        if exact_path is not None:
            return _report(VerificationVerdict.UNKNOWN if blocker_issues else VerificationVerdict.PASS, blocker_issues or _issues("PROVEN_GRAPH_PATH", VerificationVerdict.PASS, tuple(e.id for e in exact_path)), exact_path, direction=direction)
        path = _bfs(edges, str(claim.source), str(claim.target), relations, direction=direction, max_depth=max_depth, stop_nodes=stop_nodes)
        if path is not None:
            return _report(VerificationVerdict.UNKNOWN, _issues("HEURISTIC_ONLY_SUPPORT", VerificationVerdict.UNKNOWN, tuple(e.id for e in path)) + blocker_issues, path, direction=direction)
        else:
            if _complete_absence_for_pair(graph, claim.source, claim.target, blocker_issues):
                return _report(VerificationVerdict.FAIL, [_issue("PATH_ABSENT", VerificationVerdict.FAIL)])
            return _report(VerificationVerdict.UNKNOWN, blocker_issues or _incomplete_issues(claim))

    if claim.kind is CodeGraphClaimKind.NO_PATH:
        exact_path = _bfs_exact(edges, str(claim.source), str(claim.target), relations, direction=direction, max_depth=max_depth, stop_nodes=stop_nodes)
        if exact_path is not None:
            return _report(VerificationVerdict.FAIL, [_issue("COUNTEREXAMPLE_PATH", VerificationVerdict.FAIL, tuple(e.id for e in exact_path))], exact_path, direction=direction)
        path = _bfs(edges, str(claim.source), str(claim.target), relations, direction=direction, max_depth=max_depth, stop_nodes=stop_nodes)
        if path is not None:
            return _report(VerificationVerdict.UNKNOWN, _issues("HEURISTIC_ONLY_SUPPORT", VerificationVerdict.UNKNOWN, tuple(e.id for e in path)) + blocker_issues, path, direction=direction)
        if _complete_absence_for_pair(graph, claim.source, claim.target, blocker_issues):
            return _report(VerificationVerdict.PASS, _issues("COMPLETE_GRAPH_ABSENCE", VerificationVerdict.PASS))
        return _report(VerificationVerdict.UNKNOWN, blocker_issues or _incomplete_issues(claim))

    if claim.kind is CodeGraphClaimKind.ALL_PATHS_PASS_THROUGH:
        paths = list(_all_simple_paths(edges, str(claim.source), str(claim.target), relations, direction=direction, max_depth=max_depth, stop_nodes=stop_nodes))
        if not paths:
            if _complete_absence_for_pair(graph, claim.source, claim.target, blocker_issues):
                return _report(VerificationVerdict.FAIL, [_issue("NONVACUOUS_PATH_REQUIRED", VerificationVerdict.FAIL)])
            return _report(VerificationVerdict.UNKNOWN, blocker_issues or _incomplete_issues(claim))
        non_exact_path: list[GraphEvidence] | None = None
        for path in paths:
            route = _path_nodes(str(claim.source), path, direction)
            if _path_exact(path) and claim.through not in route:
                return _report(VerificationVerdict.FAIL, [_issue("COUNTEREXAMPLE_PATH", VerificationVerdict.FAIL, tuple(e.id for e in path))], path, direction=direction)
            if not _path_exact(path) and non_exact_path is None:
                non_exact_path = path
        if non_exact_path is not None:
            return _report(VerificationVerdict.UNKNOWN, _issues("HEURISTIC_ONLY_SUPPORT", VerificationVerdict.UNKNOWN, tuple(e.id for e in non_exact_path)) + blocker_issues, non_exact_path, direction=direction)
        if not _complete_absence_for_bypass(graph, claim.source, claim.target, claim.through, blocker_issues):
            return _report(VerificationVerdict.UNKNOWN, blocker_issues or [_issue("BYPASS_ABSENCE_NOT_PROVEN", VerificationVerdict.UNKNOWN)])
        return _report(VerificationVerdict.UNKNOWN if blocker_issues else VerificationVerdict.PASS, blocker_issues or [_issue("ALL_PATHS_PASS_THROUGH", VerificationVerdict.PASS)])

    if claim.kind is CodeGraphClaimKind.BLAST_RADIUS_CONTAINS:
        exact_path = _bfs_exact(edges, str(claim.source), str(claim.target), relations, direction=direction, max_depth=max_depth, stop_nodes=stop_nodes)
        if exact_path is not None:
            return _report(VerificationVerdict.UNKNOWN if blocker_issues else VerificationVerdict.PASS, blocker_issues or [_issue("BLAST_RADIUS_CONTAINS", VerificationVerdict.PASS, tuple(e.id for e in exact_path))], exact_path, direction=direction)
        path = _bfs(edges, str(claim.source), str(claim.target), relations, direction=direction, max_depth=max_depth, stop_nodes=stop_nodes)
        if path is not None:
            return _report(VerificationVerdict.UNKNOWN, _issues("HEURISTIC_ONLY_SUPPORT", VerificationVerdict.UNKNOWN, tuple(e.id for e in path)) + blocker_issues, path, direction=direction)
        else:
            if _complete_absence_for_blast(graph, claim.source, claim.target, max_depth, blocker_issues) or _complete_absence_for_pair(graph, claim.source, claim.target, blocker_issues):
                return _report(VerificationVerdict.FAIL, [_issue("TARGET_OUTSIDE_BLAST_RADIUS", VerificationVerdict.FAIL)])
            return _report(VerificationVerdict.UNKNOWN, blocker_issues or _incomplete_issues(claim))

    raise ValueError(f"unsupported code graph claim kind: {claim.kind}")


def verify_code_graph_observation(claim: CodeGraphClaim, graph: GraphEvidenceModel) -> VerificationReport:
    """Verify one canonical observation only after exact typed authority binding."""

    if not graph._typed_authority:
        return verify_code_graph_claim(claim, graph)
    if claim.scope.source_revision is None or claim.scope.query_scope is None:
        return _report(VerificationVerdict.UNKNOWN, [_issue("MALFORMED_GRAPH_EVIDENCE", VerificationVerdict.UNKNOWN)], ())
    if claim.scope.source_revision != graph.source_revision:
        return _report(VerificationVerdict.UNKNOWN, [_issue("SOURCE_REVISION_MISMATCH", VerificationVerdict.UNKNOWN)], ())
    if claim.scope.query_scope != graph.query_scope:
        return _report(VerificationVerdict.UNKNOWN, [_issue("GRAPH_QUERY_SCOPE_MISMATCH", VerificationVerdict.UNKNOWN)], ())
    if claim.kind in {CodeGraphClaimKind.NO_PATH, CodeGraphClaimKind.ALL_PATHS_PASS_THROUGH} and not graph.coverage.proves_complete_search:
        return _report(VerificationVerdict.UNKNOWN, [_issue("INCOMPLETE_COVERAGE_CERTIFICATE", VerificationVerdict.UNKNOWN)], ())
    return verify_code_graph_claim(claim, graph)


def _positive_item(
    matches: list[GraphEvidence] | tuple[GraphEvidence, ...],
    pass_code: str,
    unknown_code: str,
    fail_code: str,
    complete_absence: bool,
    blocker_issues: list[VerificationIssue],
) -> VerificationReport:
    if not matches:
        if complete_absence:
            return _report(VerificationVerdict.FAIL, [_issue(fail_code, VerificationVerdict.FAIL)])
        return _report(VerificationVerdict.UNKNOWN, blocker_issues or _issues("INCOMPLETE_GRAPH_SEARCH", VerificationVerdict.UNKNOWN))
    exact = [m for m in matches if m.confidence is EvidenceConfidence.EXACT]
    if exact and not blocker_issues:
        return _report(VerificationVerdict.PASS, _issues(pass_code, VerificationVerdict.PASS, (exact[0].id,)), evidence_ids=(exact[0].id,))
    return _report(VerificationVerdict.UNKNOWN, _issues(unknown_code, VerificationVerdict.UNKNOWN, tuple(m.id for m in matches)) + blocker_issues, evidence_ids=tuple(m.id for m in matches))


def _report(
    verdict: VerificationVerdict,
    issues: list[VerificationIssue],
    path: list[GraphEvidence] | None = None,
    evidence_ids: tuple[str, ...] | None = None,
    *,
    direction: str = "FORWARD",
) -> VerificationReport:
    ids = evidence_ids if evidence_ids is not None else tuple(e.id for e in (path or ()))
    metadata = {"canonical_path": _path_nodes(_path_start(path, direction), path, direction)} if path else {}
    return VerificationReport(verdict=verdict, verifier=CODE_GRAPH_VERIFIER, issues=tuple(issues), evidence_ids=ids, metadata=metadata)


def _issue(code: str, verdict: VerificationVerdict, evidence_ids: tuple[str, ...] = ()) -> VerificationIssue:
    return VerificationIssue(code=code, message=_MESSAGES[code], verdict=verdict, evidence_ids=evidence_ids)


def _issues(code: str, verdict: VerificationVerdict, evidence_ids: tuple[str, ...] = ()) -> list[VerificationIssue]:
    return [_issue(code, verdict, evidence_ids)] + [
        _issue(alias, verdict, evidence_ids) for alias in _LEGACY_ISSUE_ALIASES.get(code, ())
    ]


def _incomplete_issues(claim: CodeGraphClaim) -> list[VerificationIssue]:
    return _issues(
        "INCOMPLETE_GRAPH_SEARCH",
        VerificationVerdict.UNKNOWN,
        tuple(sorted(_scope_evidence_ids(claim))),
    )


def _scope_evidence_ids(claim: CodeGraphClaim) -> tuple[str, ...]:
    ids: list[str] = []
    if claim.scope.max_depth is not None:
        ids.append(f"scope:max_depth:{claim.scope.max_depth}")
    if claim.scope.stop_nodes:
        ids.extend(f"scope:stop_node:{node}" for node in sorted(claim.scope.stop_nodes))
    if claim.scope.direction != "FORWARD":
        ids.append(f"scope:direction:{claim.scope.direction}")
    return tuple(ids)


def _blocker_issues(graph: GraphEvidenceModel) -> list[VerificationIssue]:
    if not graph.blockers:
        return []
    ids = tuple(b.id for b in graph.blockers)
    issues = [_issue("GRAPH_BLOCKED", VerificationVerdict.UNKNOWN, ids)]
    reasons = {str(b.reason).upper() for b in graph.blockers}
    if any("UNSUPPORTED_RELATION" in reason or "UNSUPPORTED" in reason for reason in reasons):
        issues.append(_issue("UNSUPPORTED_RELATION", VerificationVerdict.UNKNOWN, ids))
    if any("CONFLICT" in reason for reason in reasons):
        issues.append(_issue("CONFLICTING_GRAPH_EVIDENCE", VerificationVerdict.UNKNOWN, ids))
    if any("MALFORMED" in reason for reason in reasons):
        issues.append(_issue("MALFORMED_GRAPH_EVIDENCE", VerificationVerdict.UNKNOWN, ids))
    return issues


def _node_index(graph: GraphEvidenceModel) -> dict[str, tuple[GraphEvidence, ...]]:
    out: dict[str, list[GraphEvidence]] = defaultdict(list)
    for n in sorted(graph.nodes, key=lambda e: e.id):
        keys = {n.id, str(n.semantic_identity.get("qualified_name", "")), str(n.exact_identity.get("qualified_name", ""))}
        for key in keys - {""}:
            out[key].append(n)
    return {k: tuple(v) for k, v in out.items()}


def _dedupe_edges(edges: tuple[GraphEvidence, ...]) -> tuple[GraphEvidence, ...]:
    return tuple({e.id: e for e in sorted(edges, key=lambda e: (e.source, e.target, e.label, e.id))}.values())


def _relation_ok(edge: GraphEvidence, relations: frozenset[str]) -> bool:
    if not relations:
        return True
    relation = edge.label or str(edge.semantic_identity.get("relation", "")) or edge.kind.value
    return relation in relations or edge.kind.value in relations


def _adjacency(edges: tuple[GraphEvidence, ...], relations: frozenset[str], direction: str = "FORWARD") -> dict[str, tuple[GraphEvidence, ...]]:
    out: dict[str, list[GraphEvidence]] = defaultdict(list)
    for edge in edges:
        if edge.source and edge.target and _relation_ok(edge, relations):
            out[_edge_from(edge, direction)].append(edge)
    return {node: tuple(sorted(items, key=lambda e: (_edge_to(e, direction), e.id))) for node, items in out.items()}


def _bfs(
    edges: tuple[GraphEvidence, ...],
    source: str,
    target: str,
    relations: frozenset[str],
    *,
    direction: str = "FORWARD",
    max_depth: int | None = None,
    stop_nodes: frozenset[str] = frozenset(),
) -> list[GraphEvidence] | None:
    if source == target:
        return []
    adj = _adjacency(edges, relations, direction)
    queue = deque([(source, [])])
    visited = {source}
    while queue:
        node, path = queue.popleft()
        if max_depth is not None and len(path) >= max_depth:
            continue
        if node in stop_nodes:
            continue
        for edge in adj.get(node, ()):
            next_node = _edge_to(edge, direction)
            if next_node in visited:
                continue
            next_path = path + [edge]
            if next_node == target:
                return next_path
            visited.add(next_node)
            queue.append((next_node, next_path))
    return None


def _bfs_exact(
    edges: tuple[GraphEvidence, ...],
    source: str,
    target: str,
    relations: frozenset[str],
    *,
    direction: str = "FORWARD",
    max_depth: int | None = None,
    stop_nodes: frozenset[str] = frozenset(),
) -> list[GraphEvidence] | None:
    return _bfs(
        tuple(edge for edge in edges if edge.confidence is EvidenceConfidence.EXACT),
        source,
        target,
        relations,
        direction=direction,
        max_depth=max_depth,
        stop_nodes=stop_nodes,
    )


def _all_simple_paths(
    edges: tuple[GraphEvidence, ...],
    source: str,
    target: str,
    relations: frozenset[str],
    *,
    direction: str = "FORWARD",
    max_depth: int | None = None,
    stop_nodes: frozenset[str] = frozenset(),
) -> tuple[list[GraphEvidence], ...]:
    adj = _adjacency(edges, relations, direction)
    found: list[list[GraphEvidence]] = []
    stack: list[tuple[str, list[GraphEvidence], frozenset[str]]] = [(source, [], frozenset({source}))]
    while stack:
        node, path, seen = stack.pop()
        if max_depth is not None and len(path) >= max_depth:
            continue
        if node in stop_nodes:
            continue
        for edge in reversed(adj.get(node, ())) :
            next_node = _edge_to(edge, direction)
            if next_node in seen:
                continue
            next_path = path + [edge]
            if next_node == target:
                found.append(next_path)
            else:
                stack.append((next_node, next_path, seen | {next_node}))
    return tuple(sorted(found, key=lambda p: tuple(e.id for e in p)))


def _path_exact(path: list[GraphEvidence]) -> bool:
    return all(edge.confidence is EvidenceConfidence.EXACT for edge in path)


def _path_nodes(source: str, path: list[GraphEvidence], direction: str = "FORWARD") -> tuple[str, ...]:
    return tuple([source] + [_edge_to(edge, direction) for edge in path])


def _path_start(path: list[GraphEvidence], direction: str) -> str:
    if not path:
        return ""
    return _edge_from(path[0], direction)


def _edge_from(edge: GraphEvidence, direction: str) -> str:
    return edge.target if direction == "BACKWARD" else edge.source


def _edge_to(edge: GraphEvidence, direction: str) -> str:
    return edge.source if direction == "BACKWARD" else edge.target


def _absence_key(source: object, target: object) -> str:
    return f"{source}->{target}"


def _bypass_absence_key(source: object, target: object, through: object) -> str:
    return f"{source}->{target}:bypass:{through}"


def _blast_absence_key(source: object, target: object, max_depth: object) -> str:
    return f"{source}->{target}:max_depth:{max_depth}"


def _complete_absence_for_node(graph: GraphEvidenceModel, node: object, blocker_issues: list[VerificationIssue]) -> bool:
    return not blocker_issues and graph.absence_verdict(str(node)) is VerificationVerdict.PASS


def _complete_absence_for_pair(graph: GraphEvidenceModel, source: object, target: object, blocker_issues: list[VerificationIssue]) -> bool:
    return not blocker_issues and graph.absence_verdict(_absence_key(source, target)) is VerificationVerdict.PASS


def _complete_absence_for_bypass(graph: GraphEvidenceModel, source: object, target: object, through: object, blocker_issues: list[VerificationIssue]) -> bool:
    return not blocker_issues and graph.absence_verdict(_bypass_absence_key(source, target, through)) is VerificationVerdict.PASS


def _complete_absence_for_blast(graph: GraphEvidenceModel, source: object, target: object, max_depth: object, blocker_issues: list[VerificationIssue]) -> bool:
    return not blocker_issues and graph.absence_verdict(_blast_absence_key(source, target, max_depth)) is VerificationVerdict.PASS


def _stable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _stable(value[k]) for k in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return tuple(_stable(v) for v in value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)
