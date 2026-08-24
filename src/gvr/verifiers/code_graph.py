from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from ..code_graph import EvidenceConfidence, GraphEvidence, GraphEvidenceModel
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

    def __post_init__(self) -> None:
        object.__setattr__(self, "snapshot", _stable(self.snapshot))
        object.__setattr__(self, "relations", frozenset(str(r) for r in self.relations))


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
        object.__setattr__(self, "relations", frozenset(str(r) for r in self.relations))
        if not self.evidence_namespace:
            raise ValueError("code-graph claim requires a non-empty evidence namespace")


_MESSAGES = {
    "PROVEN_NODE": "An exact canonical node proves the node-existence claim.",
    "PROVEN_EDGE": "An exact canonical edge proves the edge-existence claim.",
    "PROVEN_PATH": "An exact canonical BFS path proves the path-existence claim.",
    "PROVEN_ABSENCE": "The canonical graph contains a scoped complete absence observation.",
    "NODE_ABSENT": "The requested node is absent from the canonical graph.",
    "EDGE_ABSENT": "No matching canonical edge is present.",
    "PATH_ABSENT": "No matching canonical path is present.",
    "ABSENCE_NOT_PROVEN": "The canonical observations do not prove path absence.",
    "BYPASS_ABSENCE_NOT_PROVEN": "The canonical observations do not prove complete absence of paths bypassing the required node.",
    "COUNTEREXAMPLE_PATH": "A canonical path counterexample disproves the claim.",
    "NONVACUOUS_PATH_REQUIRED": "All-paths claims require at least one path to quantify over.",
    "ALL_PATHS_PASS_THROUGH": "Every canonical path passes through the required node.",
    "BLAST_RADIUS_CONTAINS": "The target is reachable within the requested blast depth.",
    "TARGET_OUTSIDE_BLAST_RADIUS": "The target is not reachable within the requested blast depth.",
    "NODE_NOT_EXACT": "The matching node is heuristic, inferred, or otherwise non-exact.",
    "EDGE_NOT_EXACT": "The matching edge or path contains heuristic, inferred, or otherwise non-exact evidence.",
    "GRAPH_BLOCKED": "Graph blockers make this canonical observation set incomplete for the claim.",
    "SNAPSHOT_MISMATCH": "The claim scope snapshot does not match the graph evidence snapshot.",
}


def verify_code_graph_claim(claim: CodeGraphClaim, graph: GraphEvidenceModel) -> VerificationReport:
    if not isinstance(claim, CodeGraphClaim):
        raise ValueError("claim must be a CodeGraphClaim")
    issues: list[VerificationIssue] = []
    if claim.scope.snapshot and _stable(graph.source_snapshot) != claim.scope.snapshot:
        issues.append(_issue("SNAPSHOT_MISMATCH", VerificationVerdict.UNKNOWN))
        return _report(VerificationVerdict.UNKNOWN, issues)

    blocker_issues = [_issue("GRAPH_BLOCKED", VerificationVerdict.UNKNOWN, tuple(b.id for b in graph.blockers))] if graph.blockers else []
    nodes = _node_index(graph)
    edges = _dedupe_edges(graph.edges)
    relations = claim.relations or claim.scope.relations

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
            "PROVEN_EDGE",
            "EDGE_NOT_EXACT",
            "EDGE_ABSENT",
            _complete_absence_for_pair(graph, claim.source, claim.target, blocker_issues),
            blocker_issues,
        )

    if claim.kind is CodeGraphClaimKind.PATH_EXISTS:
        exact_path = _bfs_exact(edges, str(claim.source), str(claim.target), relations)
        if exact_path is not None:
            return _report(VerificationVerdict.UNKNOWN if blocker_issues else VerificationVerdict.PASS, blocker_issues or [_issue("PROVEN_PATH", VerificationVerdict.PASS, tuple(e.id for e in exact_path))], exact_path)
        path = _bfs(edges, str(claim.source), str(claim.target), relations)
        if path is not None:
            return _report(VerificationVerdict.UNKNOWN, [_issue("EDGE_NOT_EXACT", VerificationVerdict.UNKNOWN, tuple(e.id for e in path))] + blocker_issues, path)
        else:
            if _complete_absence_for_pair(graph, claim.source, claim.target, blocker_issues):
                return _report(VerificationVerdict.FAIL, [_issue("PATH_ABSENT", VerificationVerdict.FAIL)])
            return _report(VerificationVerdict.UNKNOWN, blocker_issues or [_issue("ABSENCE_NOT_PROVEN", VerificationVerdict.UNKNOWN)])

    if claim.kind is CodeGraphClaimKind.NO_PATH:
        exact_path = _bfs_exact(edges, str(claim.source), str(claim.target), relations)
        if exact_path is not None:
            return _report(VerificationVerdict.FAIL, [_issue("COUNTEREXAMPLE_PATH", VerificationVerdict.FAIL, tuple(e.id for e in exact_path))], exact_path)
        path = _bfs(edges, str(claim.source), str(claim.target), relations)
        if path is not None:
            return _report(VerificationVerdict.UNKNOWN, [_issue("EDGE_NOT_EXACT", VerificationVerdict.UNKNOWN, tuple(e.id for e in path))] + blocker_issues, path)
        if _complete_absence_for_pair(graph, claim.source, claim.target, blocker_issues):
            return _report(VerificationVerdict.PASS, [_issue("PROVEN_ABSENCE", VerificationVerdict.PASS)])
        return _report(VerificationVerdict.UNKNOWN, blocker_issues or [_issue("ABSENCE_NOT_PROVEN", VerificationVerdict.UNKNOWN)])

    if claim.kind is CodeGraphClaimKind.ALL_PATHS_PASS_THROUGH:
        paths = list(_all_simple_paths(edges, str(claim.source), str(claim.target), relations))
        if not paths:
            if _complete_absence_for_pair(graph, claim.source, claim.target, blocker_issues):
                return _report(VerificationVerdict.FAIL, [_issue("NONVACUOUS_PATH_REQUIRED", VerificationVerdict.FAIL)])
            return _report(VerificationVerdict.UNKNOWN, blocker_issues or [_issue("ABSENCE_NOT_PROVEN", VerificationVerdict.UNKNOWN)])
        non_exact_path: list[GraphEvidence] | None = None
        for path in paths:
            route = _path_nodes(str(claim.source), path)
            if _path_exact(path) and claim.through not in route:
                return _report(VerificationVerdict.FAIL, [_issue("COUNTEREXAMPLE_PATH", VerificationVerdict.FAIL, tuple(e.id for e in path))], path)
            if not _path_exact(path) and non_exact_path is None:
                non_exact_path = path
        if non_exact_path is not None:
            return _report(VerificationVerdict.UNKNOWN, [_issue("EDGE_NOT_EXACT", VerificationVerdict.UNKNOWN, tuple(e.id for e in non_exact_path))] + blocker_issues, non_exact_path)
        if not _complete_absence_for_bypass(graph, claim.source, claim.target, claim.through, blocker_issues):
            return _report(VerificationVerdict.UNKNOWN, blocker_issues or [_issue("BYPASS_ABSENCE_NOT_PROVEN", VerificationVerdict.UNKNOWN)])
        return _report(VerificationVerdict.UNKNOWN if blocker_issues else VerificationVerdict.PASS, blocker_issues or [_issue("ALL_PATHS_PASS_THROUGH", VerificationVerdict.PASS)])

    if claim.kind is CodeGraphClaimKind.BLAST_RADIUS_CONTAINS:
        exact_path = _bfs_exact(edges, str(claim.source), str(claim.target), relations, max_depth=claim.max_depth)
        if exact_path is not None:
            return _report(VerificationVerdict.UNKNOWN if blocker_issues else VerificationVerdict.PASS, blocker_issues or [_issue("BLAST_RADIUS_CONTAINS", VerificationVerdict.PASS, tuple(e.id for e in exact_path))], exact_path)
        path = _bfs(edges, str(claim.source), str(claim.target), relations, max_depth=claim.max_depth)
        if path is not None:
            return _report(VerificationVerdict.UNKNOWN, [_issue("EDGE_NOT_EXACT", VerificationVerdict.UNKNOWN, tuple(e.id for e in path))] + blocker_issues, path)
        else:
            if _complete_absence_for_blast(graph, claim.source, claim.target, claim.max_depth, blocker_issues) or _complete_absence_for_pair(graph, claim.source, claim.target, blocker_issues):
                return _report(VerificationVerdict.FAIL, [_issue("TARGET_OUTSIDE_BLAST_RADIUS", VerificationVerdict.FAIL)])
            return _report(VerificationVerdict.UNKNOWN, blocker_issues or [_issue("ABSENCE_NOT_PROVEN", VerificationVerdict.UNKNOWN)])

    raise ValueError(f"unsupported code graph claim kind: {claim.kind}")


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
        return _report(VerificationVerdict.UNKNOWN, blocker_issues or [_issue("ABSENCE_NOT_PROVEN", VerificationVerdict.UNKNOWN)])
    exact = [m for m in matches if m.confidence is EvidenceConfidence.EXACT]
    if exact and not blocker_issues:
        return _report(VerificationVerdict.PASS, [_issue(pass_code, VerificationVerdict.PASS, (exact[0].id,))], evidence_ids=(exact[0].id,))
    return _report(VerificationVerdict.UNKNOWN, [_issue(unknown_code, VerificationVerdict.UNKNOWN, tuple(m.id for m in matches))] + blocker_issues, evidence_ids=tuple(m.id for m in matches))


def _report(verdict: VerificationVerdict, issues: list[VerificationIssue], path: list[GraphEvidence] | None = None, evidence_ids: tuple[str, ...] | None = None) -> VerificationReport:
    ids = evidence_ids if evidence_ids is not None else tuple(e.id for e in (path or ()))
    metadata = {"canonical_path": _path_nodes(path[0].source, path)} if path else {}
    return VerificationReport(verdict=verdict, verifier=CODE_GRAPH_VERIFIER, issues=tuple(issues), evidence_ids=ids, metadata=metadata)


def _issue(code: str, verdict: VerificationVerdict, evidence_ids: tuple[str, ...] = ()) -> VerificationIssue:
    return VerificationIssue(code=code, message=_MESSAGES[code], verdict=verdict, evidence_ids=evidence_ids)


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


def _adjacency(edges: tuple[GraphEvidence, ...], relations: frozenset[str]) -> dict[str, tuple[GraphEvidence, ...]]:
    out: dict[str, list[GraphEvidence]] = defaultdict(list)
    for edge in edges:
        if edge.source and edge.target and _relation_ok(edge, relations):
            out[edge.source].append(edge)
    return {node: tuple(sorted(items, key=lambda e: (e.target, e.id))) for node, items in out.items()}


def _bfs(edges: tuple[GraphEvidence, ...], source: str, target: str, relations: frozenset[str], max_depth: int | None = None) -> list[GraphEvidence] | None:
    if source == target:
        return []
    adj = _adjacency(edges, relations)
    queue = deque([(source, [])])
    visited = {source}
    while queue:
        node, path = queue.popleft()
        if max_depth is not None and len(path) >= max_depth:
            continue
        for edge in adj.get(node, ()):
            if edge.target in visited:
                continue
            next_path = path + [edge]
            if edge.target == target:
                return next_path
            visited.add(edge.target)
            queue.append((edge.target, next_path))
    return None


def _bfs_exact(edges: tuple[GraphEvidence, ...], source: str, target: str, relations: frozenset[str], max_depth: int | None = None) -> list[GraphEvidence] | None:
    return _bfs(tuple(edge for edge in edges if edge.confidence is EvidenceConfidence.EXACT), source, target, relations, max_depth=max_depth)


def _all_simple_paths(edges: tuple[GraphEvidence, ...], source: str, target: str, relations: frozenset[str]) -> tuple[list[GraphEvidence], ...]:
    adj = _adjacency(edges, relations)
    found: list[list[GraphEvidence]] = []
    stack: list[tuple[str, list[GraphEvidence], frozenset[str]]] = [(source, [], frozenset({source}))]
    while stack:
        node, path, seen = stack.pop()
        for edge in reversed(adj.get(node, ())) :
            if edge.target in seen:
                continue
            next_path = path + [edge]
            if edge.target == target:
                found.append(next_path)
            else:
                stack.append((edge.target, next_path, seen | {edge.target}))
    return tuple(sorted(found, key=lambda p: tuple(e.id for e in p)))


def _path_exact(path: list[GraphEvidence]) -> bool:
    return all(edge.confidence is EvidenceConfidence.EXACT for edge in path)


def _path_nodes(source: str, path: list[GraphEvidence]) -> tuple[str, ...]:
    return tuple([source] + [edge.target for edge in path])


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
