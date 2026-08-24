from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from ..adapters.graphify import ingest_traversal_result
from ..bundle import (
    BundleValidationError,
    VerificationBundle,
    build_verification_bundle,
)
from ..code_graph import GraphEvidenceModelError
from ..model import Evidence, VerificationIssue, VerificationReport, VerificationVerdict
from ..graphify_contract import (
    expected_graphify_df_key,
    validate_graphify_df_evidence,
    validate_graphify_envelope_authority,
    validate_graphify_positive_traversal,
)


DATA_FLOW_VERIFIER = "gvr.graphify.data_flow.v1"
COMPLETE_COVERAGE = "COMPLETE_FOR_SUPPORTED_CONSTRUCT"
SUPPORTED_DATA_FLOW_RELATIONS = frozenset({
    "FLOWS_TO",
    "PASSED_AS_ARGUMENT",
    "RETURNED_AS",
    "READ_FROM",
    "WRITTEN_TO",
    "TRANSFORMED_BY",
})
BLOCKING_RESOLUTIONS = frozenset({"AMBIGUOUS", "UNRESOLVED", "UNSUPPORTED"})
_TRUNCATION_REASONS = frozenset({"MAX_DEPTH", "MAX_PATHS", "MAX_EXPANSIONS"})
class DataFlowClaimKind(str, Enum):
    CAN_FLOW_TO = "CAN_FLOW_TO"
    NO_SUPPORTED_PATH = "NO_SUPPORTED_PATH"


@dataclass(frozen=True)
class DataFlowQueryScope:
    """Immutable semantic scope that gives an absence claim its exact meaning."""

    direction: str = "FORWARD"
    effective_allowed_relations: frozenset[str] = field(
        default_factory=lambda: frozenset(SUPPORTED_DATA_FLOW_RELATIONS)
    )
    stop_nodes: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        direction = str(self.direction).upper()
        relations = frozenset(str(item) for item in self.effective_allowed_relations)
        stop_nodes = frozenset(str(item) for item in self.stop_nodes)
        if direction not in {"FORWARD", "BACKWARD"}:
            raise ValueError(f"invalid data-flow scope direction: {direction!r}")
        if not relations <= SUPPORTED_DATA_FLOW_RELATIONS:
            raise ValueError("data-flow claim scope contains unsupported relations")
        if any(not item for item in stop_nodes):
            raise ValueError("data-flow claim scope contains an empty stop node")
        object.__setattr__(self, "direction", direction)
        object.__setattr__(self, "effective_allowed_relations", relations)
        object.__setattr__(self, "stop_nodes", stop_nodes)


@dataclass(frozen=True)
class SourceRevision:
    """Typed source revision authority, deliberately separate from query scope."""

    repository: str
    revision: str

    def __post_init__(self) -> None:
        repository = str(self.repository)
        revision = str(self.revision)
        if not repository or not revision:
            raise ValueError("source revision requires repository and revision")
        object.__setattr__(self, "repository", repository)
        object.__setattr__(self, "revision", revision)

    def to_dict(self) -> dict[str, str]:
        return {"repository": self.repository, "revision": self.revision}


@dataclass(frozen=True)
class CompletenessCertificate:
    """Typed search-completeness authority separated from query scope."""

    search_coverage: str
    complete_supported_search: bool
    termination_reason: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "search_coverage", str(self.search_coverage))
        object.__setattr__(self, "complete_supported_search", bool(self.complete_supported_search))
        object.__setattr__(self, "termination_reason", str(self.termination_reason))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "search_coverage": self.search_coverage,
            "complete_supported_search": self.complete_supported_search,
            "termination_reason": self.termination_reason,
        }


@dataclass(frozen=True)
class DataFlowClaim:
    kind: DataFlowClaimKind
    start: str
    target: str
    scope: DataFlowQueryScope = field(default_factory=DataFlowQueryScope)
    evidence_namespace: str = "default"
    source_context: str | None = None
    source_revision: SourceRevision | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, DataFlowClaimKind):
            object.__setattr__(self, "kind", DataFlowClaimKind(str(self.kind)))
        if not isinstance(self.scope, DataFlowQueryScope):
            if not isinstance(self.scope, Mapping):
                raise ValueError("data-flow claim scope must be a DataFlowQueryScope")
            object.__setattr__(self, "scope", DataFlowQueryScope(**dict(self.scope)))
        if not self.start or not self.target:
            raise ValueError("data-flow claim requires non-empty start and target")
        namespace = str(self.evidence_namespace)
        if not namespace:
            raise ValueError("data-flow claim requires a non-empty evidence namespace")
        object.__setattr__(self, "evidence_namespace", namespace)
        if self.source_revision is not None and not isinstance(self.source_revision, SourceRevision):
            if not isinstance(self.source_revision, Mapping):
                raise ValueError("source_revision must be a SourceRevision")
            object.__setattr__(self, "source_revision", SourceRevision(**dict(self.source_revision)))
        if self.source_context is not None:
            object.__setattr__(self, "source_context", str(self.source_context))

    @property
    def source_revision_identity(self) -> Mapping[str, str] | None:
        if self.source_revision is not None:
            return self.source_revision.to_dict()
        return None


@dataclass(frozen=True)
class _PathAnalysis:
    identity: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    qualifying: bool
    issue_codes: tuple[str, ...]


_ISSUE_MESSAGES = {
    "PROVEN_SUPPORTED_PATH": "A fully exact supported data-flow path proves the claim decision.",
    "NO_SUPPORTED_PATH": "The complete supported search returned no path.",
    "INCOMPLETE_SUPPORTED_SEARCH": "The supported search is incomplete, so absence is not proven.",
    "MAY_PATH": "A returned path has MAY receiver confidence.",
    "MAY_SEARCH_EVIDENCE": "The explored search region contains MAY evidence.",
    "PARTIAL_PATH": "A returned path has partial supported-construct coverage.",
    "START_NODE_NOT_FOUND": "Graphify did not resolve the traversal start node.",
    "TARGET_NODE_NOT_FOUND": "Graphify did not resolve the traversal target node.",
    "BLOCKING_BOUNDARY": "A blocking Graphify boundary prevents an absence conclusion.",
    "UNSUPPORTED_PATH_RELATION": "A returned path contains a relation outside the value-flow vocabulary.",
    "INVALID_EVIDENCE_KEY": "A path has a missing, duplicate, malformed, or content-mismatched evidence key.",
    "CONTRADICTORY_TRAVERSAL": "The traversal payload contains contradictory epistemic or termination state.",
    "EVIDENCE_CONFIDENCE_CONTRADICTION": "Path confidence upgrades MAY direct evidence to PROVEN.",
    "EVIDENCE_COMPLETENESS_CONTRADICTION": "Path coverage upgrades PARTIAL direct evidence to complete.",
    "MALFORMED_TRAVERSAL": "The traversal payload does not satisfy the public Graphify result contract.",
    "MALFORMED_PATH": "A returned path is structurally inconsistent with its supporting evidence.",
    "CLAIM_QUERY_MISMATCH": "The claim endpoints do not match the traversal query direction.",
    "CLAIM_SCOPE_MISMATCH": "The traversal query scope does not match the immutable claim scope.",
    "SOURCE_REVISION_MISMATCH": "The traversal source revision does not match the typed claim source revision.",
    "INVALID_QUERY": "Graphify reports an invalid traversal query.",
}


def _stable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _stable(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [_stable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _mapping_sequence(value: Any) -> tuple[Mapping[str, Any], ...] | None:
    if not isinstance(value, (list, tuple)):
        return None
    if not all(isinstance(item, Mapping) for item in value):
        return None
    return tuple(value)


def _scope_metadata(scope: DataFlowQueryScope) -> dict[str, Any]:
    return {
        "direction": scope.direction,
        "effective_allowed_relations": sorted(scope.effective_allowed_relations),
        "stop_nodes": sorted(scope.stop_nodes),
    }


def _source_revision_metadata(claim: DataFlowClaim) -> Mapping[str, str] | None:
    identity = claim.source_revision_identity
    return None if identity is None else dict(identity)


def _completeness_certificate(result: Mapping[str, Any]) -> dict[str, Any]:
    raw = result.get("completeness_certificate")
    if isinstance(raw, Mapping):
        certificate = dict(_stable(raw))
        certificate.setdefault("schema_version", 1)
        certificate.setdefault("search_coverage", str(result.get("search_coverage") or ""))
        certificate.setdefault("complete_supported_search", result.get("complete_supported_search"))
        certificate.setdefault("termination_reason", str(result.get("termination_reason") or ""))
        return certificate
    return CompletenessCertificate(
        search_coverage=str(result.get("search_coverage") or ""),
        complete_supported_search=result.get("complete_supported_search") is True,
        termination_reason=str(result.get("termination_reason") or ""),
    ).to_dict()


def _canonical_query_result(result: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize the public result facts used as a replaceable ledger basis."""

    raw_paths = _mapping_sequence(result.get("paths")) or ()
    paths: list[dict[str, Any]] = []
    for path in raw_paths:
        refs = _mapping_sequence(path.get("supporting_evidence")) or ()
        steps = _mapping_sequence(path.get("steps")) or ()
        paths.append({
            "path_identity": [str(item) for item in (path.get("path_identity") or ())],
            "path_exactness": str(path.get("path_exactness") or ""),
            "path_receiver_confidence": str(path.get("path_receiver_confidence") or ""),
            "path_coverage": str(path.get("path_coverage") or ""),
            "evidence_ids": [str(ref.get("key") or "") for ref in refs],
            "steps": [
                {
                    "source": str(step.get("source") or ""),
                    "target": str(step.get("target") or ""),
                    "relation": str(step.get("relation") or ""),
                }
                for step in steps
            ],
        })
    paths.sort(key=lambda path: json.dumps(path, sort_keys=True, separators=(",", ":")))

    raw_boundaries = _mapping_sequence(result.get("boundary_events")) or ()
    boundaries = [dict(_stable(event)) for event in raw_boundaries]
    boundaries.sort(key=lambda event: json.dumps(event, sort_keys=True, separators=(",", ":")))

    raw_bounds = result.get("query_bounds")
    bounds = dict(raw_bounds) if isinstance(raw_bounds, Mapping) else {}
    normalized_bounds = {
        "direction": str(bounds.get("direction") or ""),
        "max_depth": bounds.get("max_depth"),
        "max_paths": bounds.get("max_paths"),
        "max_expansions": bounds.get("max_expansions"),
        "requested_allowed_relations": sorted(str(item) for item in (bounds.get("requested_allowed_relations") or ())),
        "effective_allowed_relations": sorted(str(item) for item in (bounds.get("effective_allowed_relations") or ())),
        "rejected_relations": sorted(str(item) for item in (bounds.get("rejected_relations") or ())),
        "stop_nodes": sorted(str(item) for item in (bounds.get("stop_nodes") or ())),
    }
    return {
        "query_start": str(result.get("start") or ""),
        "query_target": None if result.get("target") is None else str(result.get("target")),
        "direction": str(result.get("direction") or ""),
        "visited_count": result.get("visited_count"),
        "expanded_count": result.get("expanded_count"),
        "truncated": result.get("truncated"),
        "termination_reason": str(result.get("termination_reason") or ""),
        "query_bounds": normalized_bounds,
        "completeness_certificate": _completeness_certificate(result),
        "boundary_events": boundaries,
        "search_coverage": str(result.get("search_coverage") or ""),
        "complete_supported_search": result.get("complete_supported_search"),
        "start_node_found": result.get("start_node_found"),
        "target_node_found": result.get("target_node_found"),
        "query_validity": result.get("query_validity"),
        "input_resolution": str(result.get("input_resolution") or ""),
        "rejected_relations": sorted(str(item) for item in (result.get("rejected_relations") or ())),
        "encountered_partial_evidence": result.get("encountered_partial_evidence"),
        "encountered_unknown_evidence": result.get("encountered_unknown_evidence"),
        "encountered_may_evidence": result.get("encountered_may_evidence"),
        "paths": paths,
    }


def build_query_result_evidence(
    claim: DataFlowClaim,
    traversal_result: Mapping[str, Any],
) -> Evidence:
    """Build the stable query-evidence slot whose payload changes invalidate a claim.

    The ID names the semantic query slot, not one result version. Updating the
    normalized payload for the same ID therefore makes ClaimLedger dependents
    stale. ``source_context`` is deliberately payload state rather than part of
    the ID so a revision change invalidates the existing verification basis.
    """

    identity = {
        "schema_version": 1,
        "verifier": DATA_FLOW_VERIFIER,
        "evidence_namespace": claim.evidence_namespace,
        "start": claim.start,
        "target": claim.target,
        "scope": _scope_metadata(claim.scope),
    }
    canonical_identity = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    evidence_id = "gvrq:" + hashlib.sha256(canonical_identity.encode("utf-8")).hexdigest()
    payload = {
        "schema_version": 1,
        "kind": "graphify.data_flow_query_result",
        "evidence_namespace": claim.evidence_namespace,
        "source_context": claim.source_context,
        "source_revision": _source_revision_metadata(claim),
        "query_semantic_scope": identity["scope"],
        "completeness_certificate": _completeness_certificate(traversal_result),
        "query_identity": identity,
        "result": _canonical_query_result(traversal_result),
    }
    canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return Evidence(
        id=evidence_id,
        kind="graphify.data_flow_query_result",
        payload=payload,
        source=claim.source_context,
        fingerprint=hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest(),
    )


def _expected_evidence_key(item: Mapping[str, Any]) -> str:
    return expected_graphify_df_key(item)


def _same_evidence(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return _stable(left) == _stable(right)


def _path_analysis(
    path: Mapping[str, Any],
    *,
    flow_start: str,
    flow_target: str,
    effective_allowed_relations: frozenset[str],
    seen_evidence: dict[str, Any],
) -> _PathAnalysis:
    issues: set[str] = set()
    steps = _mapping_sequence(path.get("steps"))
    refs = _mapping_sequence(path.get("supporting_evidence"))
    identity_value = path.get("path_identity")
    if steps is None or refs is None or not isinstance(identity_value, (list, tuple)):
        return _PathAnalysis((), (), False, ("MALFORMED_PATH",))

    identity = tuple(str(key or "") for key in identity_value)
    if len(steps) != len(refs) or len(identity) != len(refs):
        issues.add("MALFORMED_PATH")

    usable_ids: list[str] = []
    keys: list[str] = []
    for index, ref in enumerate(refs):
        key = str(ref.get("key") or "")
        keys.append(key)
        key_valid = True
        try:
            validate_graphify_df_evidence(ref)
        except GraphEvidenceModelError:
            issues.add("INVALID_EVIDENCE_KEY")
            key_valid = False
        if key_valid and key in keys[:-1]:
            issues.add("INVALID_EVIDENCE_KEY")
            key_valid = False
        if key_valid:
            canonical = _stable(ref)
            previous = seen_evidence.get(key)
            if previous is not None and previous != canonical:
                issues.add("INVALID_EVIDENCE_KEY")
            else:
                seen_evidence[key] = canonical
                usable_ids.append(key)

        relation = str(ref.get("relation") or "")
        if relation not in SUPPORTED_DATA_FLOW_RELATIONS:
            issues.add("UNSUPPORTED_PATH_RELATION")
        elif relation not in effective_allowed_relations:
            issues.add("CONTRADICTORY_TRAVERSAL")
        if not all(str(ref.get(field) or "") for field in ("source", "target", "source_file", "source_location")):
            issues.add("MALFORMED_PATH")

        if index < len(steps):
            step = steps[index]
            step_evidence = step.get("evidence")
            if not isinstance(step_evidence, Mapping):
                issues.add("MALFORMED_PATH")
            elif not _same_evidence(step_evidence, ref):
                issues.add("MALFORMED_PATH")
            if (
                str(step.get("source") or "") != str(ref.get("source") or "")
                or str(step.get("target") or "") != str(ref.get("target") or "")
                or str(step.get("relation") or "") != relation
            ):
                issues.add("MALFORMED_PATH")

    if identity != tuple(keys):
        issues.add("MALFORMED_PATH")
    if len(set(identity)) != len(identity):
        issues.add("INVALID_EVIDENCE_KEY")

    if steps:
        if str(steps[0].get("source") or "") != flow_start:
            issues.add("MALFORMED_PATH")
        if str(steps[-1].get("target") or "") != flow_target:
            issues.add("MALFORMED_PATH")
        for left, right in zip(steps, steps[1:]):
            if str(left.get("target") or "") != str(right.get("source") or ""):
                issues.add("MALFORMED_PATH")
    elif flow_start != flow_target:
        issues.add("MALFORMED_PATH")

    exactness = str(path.get("path_exactness") or "")
    receiver = str(path.get("path_receiver_confidence") or "")
    coverage = str(path.get("path_coverage") or "")
    if exactness != "EXACT_FOR_RETURNED_PATH":
        issues.add("MALFORMED_PATH")
    if receiver not in {"PROVEN", "MAY"}:
        issues.add("MALFORMED_PATH")
    if coverage not in {COMPLETE_COVERAGE, "PARTIAL"}:
        issues.add("MALFORMED_PATH")

    direct_receiver = tuple(str(ref.get("receiver_confidence") or "UNKNOWN") for ref in refs)
    direct_coverage = tuple(str(ref.get("analysis_completeness") or "UNKNOWN") for ref in refs)
    if receiver == "PROVEN" and any(value != "PROVEN" for value in direct_receiver):
        issues.add("EVIDENCE_CONFIDENCE_CONTRADICTION")
    if coverage == COMPLETE_COVERAGE and any(value != COMPLETE_COVERAGE for value in direct_coverage):
        issues.add("EVIDENCE_COMPLETENESS_CONTRADICTION")
    if receiver == "MAY":
        issues.add("MAY_PATH")
    if coverage == "PARTIAL":
        issues.add("PARTIAL_PATH")

    invalidating = issues - {"MAY_PATH", "PARTIAL_PATH"}
    qualifying = (
        not invalidating
        and receiver == "PROVEN"
        and coverage == COMPLETE_COVERAGE
        and exactness == "EXACT_FOR_RETURNED_PATH"
    )
    return _PathAnalysis(
        identity=identity,
        evidence_ids=tuple(sorted(set(usable_ids))),
        qualifying=qualifying,
        issue_codes=tuple(sorted(issues)),
    )


def _boundary_events(result: Mapping[str, Any]) -> tuple[dict[str, Any], ...] | None:
    raw = _mapping_sequence(result.get("boundary_events"))
    if raw is None:
        return None
    events: list[dict[str, Any]] = []
    for event in raw:
        key = str(event.get("boundary_evidence_key") or "")
        resolution = str(event.get("resolution") or "")
        normalized = dict(_stable(event))
        normalized["evidence_key"] = key
        normalized["resolution"] = resolution
        events.append(normalized)
    events.sort(key=lambda event: (
        str(event.get("evidence_key") or ""),
        str(event.get("resolution") or ""),
        json.dumps(event, sort_keys=True, separators=(",", ":")),
    ))
    return tuple(events)


def _global_issues(
    claim: DataFlowClaim,
    result: Mapping[str, Any],
    paths: Sequence[Mapping[str, Any]],
    boundaries: Sequence[Mapping[str, Any]],
) -> tuple[set[str], str, str, frozenset[str]]:
    issues: set[str] = set()
    try:
        envelope_authority = validate_graphify_envelope_authority(result)
    except GraphEvidenceModelError:
        envelope_authority = None
        issues.add("MALFORMED_TRAVERSAL")
    else:
        if paths and not envelope_authority.positive_authorized:
            issues.add("CONTRADICTORY_TRAVERSAL")
        if not paths and result.get("complete_supported_search") is True and not envelope_authority.negative_authorized:
            issues.add("CONTRADICTORY_TRAVERSAL")
    direction = str(result.get("direction") or "")
    query_start = str(result.get("start") or "")
    raw_target = result.get("target")
    query_target = "" if raw_target is None else str(raw_target)

    if direction == "FORWARD":
        flow_start, flow_target = query_start, query_target
    elif direction == "BACKWARD":
        flow_start, flow_target = query_target, query_start
    else:
        issues.add("MALFORMED_TRAVERSAL")
        flow_start, flow_target = query_start, query_target

    if not query_start or raw_target is None or not query_target:
        issues.add("MALFORMED_TRAVERSAL")
    if claim.start != flow_start or claim.target != flow_target:
        issues.add("CLAIM_QUERY_MISMATCH")
    if result.get("query_validity") is not True:
        issues.add("INVALID_QUERY")

    query_bounds = result.get("query_bounds")
    effective_allowed_relations: frozenset[str] = frozenset()
    actual_stop_nodes: frozenset[str] = frozenset()
    query_limits: dict[str, int] = {}
    if not isinstance(query_bounds, Mapping):
        issues.add("MALFORMED_TRAVERSAL")
    else:
        requested = query_bounds.get("requested_allowed_relations")
        effective = query_bounds.get("effective_allowed_relations")
        bounds_rejected = query_bounds.get("rejected_relations")
        stop_nodes = query_bounds.get("stop_nodes")
        string_arrays = (requested, effective, bounds_rejected, stop_nodes)
        if any(
            not isinstance(items, (list, tuple))
            or not all(isinstance(item, str) for item in items)
            for items in string_arrays
        ):
            issues.add("MALFORMED_TRAVERSAL")
        else:
            requested_relations = frozenset(requested)
            effective_allowed_relations = frozenset(effective)
            # Graphify treats the point-to-point target as terminal before it
            # consults stop_nodes. Listing that same target is therefore a
            # canonical no-op, not a different claim scope.
            actual_stop_nodes = frozenset(stop_nodes) - {query_target}
            expected_effective = requested_relations & SUPPORTED_DATA_FLOW_RELATIONS
            expected_rejected = requested_relations - SUPPORTED_DATA_FLOW_RELATIONS
            if effective_allowed_relations != expected_effective:
                issues.add("CONTRADICTORY_TRAVERSAL")
            if frozenset(bounds_rejected) != expected_rejected:
                issues.add("CONTRADICTORY_TRAVERSAL")
        if str(query_bounds.get("direction") or "") != direction:
            issues.add("CONTRADICTORY_TRAVERSAL")
        for name, minimum in (("max_depth", 0), ("max_paths", 1), ("max_expansions", 1)):
            value = query_bounds.get(name)
            if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
                issues.add("MALFORMED_TRAVERSAL")
            else:
                query_limits[name] = value

    if (
        claim.scope.direction != direction
        or claim.scope.effective_allowed_relations != effective_allowed_relations
        or claim.scope.stop_nodes != actual_stop_nodes
    ):
        issues.add("CLAIM_SCOPE_MISMATCH")

    claimed_revision = _source_revision_metadata(claim)
    result_revision = result.get("source_revision")
    if claimed_revision is not None:
        if not isinstance(result_revision, Mapping) or dict(_stable(result_revision)) != dict(_stable(claimed_revision)):
            issues.add("SOURCE_REVISION_MISMATCH")

    rejected_relations = result.get("rejected_relations")
    if not isinstance(rejected_relations, (list, tuple)) or not all(
        isinstance(item, str) for item in rejected_relations
    ):
        issues.add("MALFORMED_TRAVERSAL")
    elif isinstance(query_bounds, Mapping) and isinstance(
        query_bounds.get("rejected_relations"), (list, tuple)
    ) and tuple(sorted(rejected_relations)) != tuple(sorted(query_bounds["rejected_relations"])):
        issues.add("CONTRADICTORY_TRAVERSAL")

    counts: dict[str, int] = {}
    for count_field in ("visited_count", "expanded_count"):
        count = result.get(count_field)
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            issues.add("MALFORMED_TRAVERSAL")
        else:
            counts[count_field] = count

    epistemic_flags = (
        "encountered_partial_evidence",
        "encountered_unknown_evidence",
        "encountered_may_evidence",
    )
    if any(not isinstance(result.get(field), bool) for field in epistemic_flags):
        issues.add("MALFORMED_TRAVERSAL")
    if result.get("encountered_may_evidence") is True:
        issues.add("MAY_SEARCH_EVIDENCE")

    complete = result.get("complete_supported_search")
    truncated = result.get("truncated")
    start_found = result.get("start_node_found")
    target_found = result.get("target_node_found")
    if not isinstance(complete, bool) or not isinstance(truncated, bool):
        issues.add("MALFORMED_TRAVERSAL")
    if not isinstance(start_found, bool) or not isinstance(target_found, bool):
        issues.add("MALFORMED_TRAVERSAL")

    termination = str(result.get("termination_reason") or "")
    coverage = str(result.get("search_coverage") or "")
    resolution = str(result.get("input_resolution") or "")
    if coverage not in {COMPLETE_COVERAGE, "PARTIAL", "UNKNOWN"}:
        issues.add("MALFORMED_TRAVERSAL")
    if resolution not in {"RESOLVED", "START_NODE_NOT_FOUND", "TARGET_NODE_NOT_FOUND"}:
        issues.add("MALFORMED_TRAVERSAL")
    if termination not in {"COMPLETE", *_TRUNCATION_REASONS, "START_NODE_NOT_FOUND", "TARGET_NODE_NOT_FOUND"}:
        issues.add("MALFORMED_TRAVERSAL")

    blocking = False
    for event in boundaries:
        key = str(event.get("evidence_key") or "")
        boundary_resolution = str(event.get("resolution") or "")
        if not key:
            issues.add("MALFORMED_TRAVERSAL")
        if boundary_resolution not in BLOCKING_RESOLUTIONS:
            issues.add("MALFORMED_TRAVERSAL")
        else:
            blocking = True

    if blocking:
        issues.add("BLOCKING_BOUNDARY")
    if resolution == "START_NODE_NOT_FOUND":
        issues.add("START_NODE_NOT_FOUND")
        if start_found is not False or termination != resolution or paths:
            issues.add("CONTRADICTORY_TRAVERSAL")
    elif resolution == "TARGET_NODE_NOT_FOUND":
        issues.add("TARGET_NODE_NOT_FOUND")
        if target_found is not False or termination != resolution or paths:
            issues.add("CONTRADICTORY_TRAVERSAL")
    elif resolution == "RESOLVED" and (start_found is not True or target_found is not True):
        issues.add("CONTRADICTORY_TRAVERSAL")

    if resolution == "RESOLVED" and counts.get("visited_count", 0) < 1:
        issues.add("CONTRADICTORY_TRAVERSAL")
    if resolution == "START_NODE_NOT_FOUND" and counts.get("visited_count") not in {None, 0}:
        issues.add("CONTRADICTORY_TRAVERSAL")

    required_expansions = 0
    required_visited = 1 if paths else 0
    returned_path_nodes: set[str] = set()
    for path in paths:
        path_steps = _mapping_sequence(path.get("steps"))
        if path_steps is None:
            continue
        if len(path_steps) > query_limits.get("max_depth", len(path_steps)):
            issues.add("CONTRADICTORY_TRAVERSAL")
        required_expansions = max(required_expansions, len(path_steps))
        path_nodes = {
            str(step.get(field) or "")
            for step in path_steps
            for field in ("source", "target")
            if str(step.get(field) or "")
        }
        returned_path_nodes.update(path_nodes)
    required_visited = max(required_visited, len(returned_path_nodes))
    if counts.get("expanded_count", required_expansions) < required_expansions:
        issues.add("CONTRADICTORY_TRAVERSAL")
    if counts.get("visited_count", required_visited) < required_visited:
        issues.add("CONTRADICTORY_TRAVERSAL")
    if counts.get("expanded_count", 0) > 0 and counts.get("visited_count", 0) < 2:
        issues.add("CONTRADICTORY_TRAVERSAL")
    if resolution == "RESOLVED" and counts.get("visited_count", 0) > counts.get("expanded_count", 0) + 1:
        issues.add("CONTRADICTORY_TRAVERSAL")
    if resolution != "RESOLVED" and any(counts.get(name, 0) != 0 for name in ("visited_count", "expanded_count")):
        issues.add("CONTRADICTORY_TRAVERSAL")
    non_identity_path_count = sum(
        1
        for path in paths
        if (_mapping_sequence(path.get("steps")) or ())
    )
    if non_identity_path_count > counts.get("expanded_count", non_identity_path_count):
        issues.add("CONTRADICTORY_TRAVERSAL")
    if len(paths) > query_limits.get("max_paths", len(paths)):
        issues.add("CONTRADICTORY_TRAVERSAL")
    if counts.get("expanded_count", 0) > query_limits.get(
        "max_expansions", counts.get("expanded_count", 0)
    ):
        issues.add("CONTRADICTORY_TRAVERSAL")

    if truncated is True and termination not in _TRUNCATION_REASONS:
        issues.add("CONTRADICTORY_TRAVERSAL")
    if truncated is False and termination in _TRUNCATION_REASONS:
        issues.add("CONTRADICTORY_TRAVERSAL")
    if resolution != "RESOLVED":
        expected_coverage = "UNKNOWN"
    elif (
        truncated is True
        or blocking
        or result.get("encountered_partial_evidence") is True
        or result.get("encountered_unknown_evidence") is True
    ):
        expected_coverage = "PARTIAL"
    else:
        expected_coverage = COMPLETE_COVERAGE
    if coverage != expected_coverage:
        issues.add("CONTRADICTORY_TRAVERSAL")

    expected_complete = (
        resolution == "RESOLVED"
        and result.get("query_validity") is True
        and truncated is False
        and not blocking
        and result.get("encountered_partial_evidence") is False
        and result.get("encountered_unknown_evidence") is False
        and coverage == COMPLETE_COVERAGE
        and start_found is True
        and target_found is True
    )
    if isinstance(complete, bool) and complete is not expected_complete:
        issues.add("CONTRADICTORY_TRAVERSAL")
    if complete is False and not paths:
        issues.add("INCOMPLETE_SUPPORTED_SEARCH")

    return issues, flow_start, flow_target, effective_allowed_relations


def _issues(
    codes: Sequence[str],
    verdict: VerificationVerdict,
    evidence_ids: tuple[str, ...],
) -> tuple[VerificationIssue, ...]:
    return tuple(
        VerificationIssue(
            code=code,
            message=_ISSUE_MESSAGES[code],
            verdict=verdict,
            evidence_ids=evidence_ids,
        )
        for code in sorted(set(codes))
    )


def verify_data_flow_claim(
    claim: DataFlowClaim,
    traversal_result: Mapping[str, Any],
) -> VerificationReport:
    """Verify one explicit data-flow claim from a Graphify traversal result.

    The verifier consumes only Graphify's public query-time result. It never
    reparses source, builds another graph, crosses blocking boundaries, upgrades
    MAY/PARTIAL state, or treats truncated search absence as proof.
    """

    positive_validation_error = False
    try:
        validate_graphify_positive_traversal(traversal_result)
    except GraphEvidenceModelError:
        positive_validation_error = True
    try:
        ingested = ingest_traversal_result(traversal_result)
    except GraphEvidenceModelError:
        # Preserve verifier fail-closed reporting while adapters and typed
        # observation encoders reject the same malformed positive authority.
        ingested = ingest_traversal_result({**dict(traversal_result), "paths": []})
    query_evidence = build_query_result_evidence(claim, traversal_result)
    raw_paths = _mapping_sequence(traversal_result.get("paths"))
    boundaries = _boundary_events(traversal_result)
    structural_issue = raw_paths is None or boundaries is None
    paths = () if raw_paths is None else raw_paths
    normalized_boundaries = () if boundaries is None else boundaries

    global_codes, flow_start, flow_target, effective_allowed_relations = _global_issues(
        claim, traversal_result, paths, normalized_boundaries
    )
    if structural_issue:
        global_codes.add("MALFORMED_TRAVERSAL")
    if positive_validation_error:
        global_codes.add("MALFORMED_PATH")

    seen_evidence: dict[str, Any] = {}
    analyses = tuple(
        _path_analysis(
            path,
            flow_start=flow_start,
            flow_target=flow_target,
            effective_allowed_relations=effective_allowed_relations,
            seen_evidence=seen_evidence,
        )
        for path in paths
    )
    identities = [analysis.identity for analysis in analyses]
    if len(set(identities)) != len(identities):
        global_codes.add("MALFORMED_TRAVERSAL")

    path_codes = {code for analysis in analyses for code in analysis.issue_codes}
    hard_path_codes = path_codes - {"MAY_PATH", "PARTIAL_PATH"}
    qualifying = sorted(
        (analysis for analysis in analyses if analysis.qualifying),
        key=lambda analysis: analysis.identity,
    )
    valid_evidence_ids = tuple(sorted({
        evidence_id
        for analysis in analyses
        for evidence_id in analysis.evidence_ids
    }))
    boundary_ids = tuple(sorted(ingested.blocking_boundary_keys))

    selected: _PathAnalysis | None = None
    verdict: VerificationVerdict
    decision_code: str | None = None
    evidence_ids: tuple[str, ...]
    fail_closed = bool(global_codes & {
        "MALFORMED_TRAVERSAL",
        "CONTRADICTORY_TRAVERSAL",
        "CLAIM_QUERY_MISMATCH",
        "CLAIM_SCOPE_MISMATCH",
        "SOURCE_REVISION_MISMATCH",
        "INVALID_QUERY",
    }) or bool(hard_path_codes)

    if fail_closed:
        verdict = VerificationVerdict.UNKNOWN
        evidence_ids = tuple(sorted(set(valid_evidence_ids) | set(boundary_ids) | {query_evidence.id}))
    elif qualifying:
        selected = qualifying[0]
        verdict = (
            VerificationVerdict.PASS
            if claim.kind is DataFlowClaimKind.CAN_FLOW_TO
            else VerificationVerdict.FAIL
        )
        decision_code = "PROVEN_SUPPORTED_PATH"
        evidence_ids = tuple(sorted(set(selected.evidence_ids) | {query_evidence.id}))
    elif analyses:
        verdict = VerificationVerdict.UNKNOWN
        evidence_ids = tuple(sorted(set(valid_evidence_ids) | set(boundary_ids) | {query_evidence.id}))
    elif (
        traversal_result.get("complete_supported_search") is True
        and "MAY_SEARCH_EVIDENCE" not in global_codes
    ):
        verdict = (
            VerificationVerdict.FAIL
            if claim.kind is DataFlowClaimKind.CAN_FLOW_TO
            else VerificationVerdict.PASS
        )
        decision_code = "NO_SUPPORTED_PATH"
        evidence_ids = (query_evidence.id,)
    else:
        verdict = VerificationVerdict.UNKNOWN
        evidence_ids = tuple(sorted(set(boundary_ids) | {query_evidence.id}))

    if verdict is VerificationVerdict.UNKNOWN:
        issue_codes = set(global_codes) | path_codes
        if not issue_codes:
            issue_codes.add("INCOMPLETE_SUPPORTED_SEARCH")
    else:
        issue_codes = {decision_code} if decision_code is not None else set()

    graphify_metadata = {
        "query_start": ingested.start,
        "query_target": ingested.target,
        "direction": ingested.direction,
        "visited_count": traversal_result.get("visited_count"),
        "expanded_count": traversal_result.get("expanded_count"),
        "truncated": ingested.truncated,
        "termination_reason": ingested.termination_reason,
        "search_coverage": ingested.search_coverage,
        "complete_supported_search": ingested.complete_supported_search,
        "input_resolution": ingested.input_resolution,
        "query_validity": ingested.query_validity,
        "start_node_found": ingested.start_node_found,
        "target_node_found": ingested.target_node_found,
        "query_bounds": _stable(ingested.query_bounds),
        "rejected_relations": sorted(str(item) for item in (traversal_result.get("rejected_relations") or ())),
        "encountered_partial_evidence": traversal_result.get("encountered_partial_evidence") is True,
        "encountered_unknown_evidence": traversal_result.get("encountered_unknown_evidence") is True,
        "encountered_may_evidence": traversal_result.get("encountered_may_evidence") is True,
        "boundary_events": list(normalized_boundaries),
    }
    metadata = {
        "claim_kind": claim.kind.value,
        "start": claim.start,
        "target": claim.target,
        "claim_scope": _scope_metadata(claim.scope),
        "query_semantic_scope": _scope_metadata(claim.scope),
        "source_revision": _source_revision_metadata(claim),
        "completeness_certificate": _completeness_certificate(traversal_result),
        "evidence_namespace": claim.evidence_namespace,
        "source_context": claim.source_context,
        "query_evidence_id": query_evidence.id,
        "returned_path_count": len(analyses),
        "qualifying_path_count": len(qualifying),
        "selected_path_identity": (
            None if selected is None else list(selected.identity)
        ),
        "graphify": graphify_metadata,
    }
    return VerificationReport(
        verdict=verdict,
        verifier=DATA_FLOW_VERIFIER,
        issues=_issues(tuple(issue_codes), verdict, evidence_ids),
        evidence_ids=evidence_ids,
        metadata=metadata,
    )


def verify_data_flow_claim_bundle(
    claim: DataFlowClaim,
    traversal_result: Mapping[str, Any],
) -> VerificationBundle:
    """Verify a data-flow claim and package exactly its recordable evidence."""

    report = verify_data_flow_claim(claim, traversal_result)
    ingested = ingest_traversal_result(traversal_result)
    if ingested.conflicting_evidence_ids:
        raise BundleValidationError(
            "conflicting Graphify evidence records share IDs: "
            + ", ".join(ingested.conflicting_evidence_ids)
        )
    query_evidence = build_query_result_evidence(claim, traversal_result)
    available = {
        evidence.id: evidence
        for evidence in (*ingested.evidence, query_evidence)
    }
    selected = tuple(
        available[evidence_id]
        for evidence_id in report.evidence_ids
        if evidence_id in available
    )
    return build_verification_bundle(report, selected)
