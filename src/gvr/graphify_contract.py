from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .code_graph import GraphEvidenceModelError

GRAPHIFY_DF_KEY_RE = re.compile(r"^df:[0-9a-f]{64}$")
_GRAPHIFY_DF_KEY_FORMAT = "graphify.data_flow.evidence_key.v1"
_GRAPHIFY_DF_KEY_FIELDS = (
    "relation",
    "source",
    "target",
    "source_file",
    "source_location",
    "provenance",
)
_SUPPORTED_RELATIONS = frozenset({
    "FLOWS_TO",
    "PASSED_AS_ARGUMENT",
    "READ_FROM",
    "RETURNED_AS",
    "TRANSFORMED_BY",
    "WRITTEN_TO",
})
_TRUNCATION_REASONS = frozenset({"MAX_DEPTH", "MAX_PATHS", "MAX_EXPANSIONS"})
_BLOCKING_BOUNDARY_RESOLUTIONS = frozenset({"AMBIGUOUS", "UNRESOLVED", "UNSUPPORTED"})
_SEARCH_COVERAGE = frozenset({"COMPLETE_FOR_SUPPORTED_CONSTRUCT", "PARTIAL", "UNKNOWN"})
_INPUT_RESOLUTIONS = frozenset({
    "RESOLVED", "START_NODE_NOT_FOUND", "TARGET_NODE_NOT_FOUND",
    "AMBIGUOUS_START", "AMBIGUOUS_TARGET",
})
_TERMINATION_REASONS = frozenset({
    "COMPLETE", *_TRUNCATION_REASONS, "START_NODE_NOT_FOUND", "TARGET_NODE_NOT_FOUND",
})


@dataclass(frozen=True)
class GraphifyEnvelopeAuthority:
    """Shared authority decision for one public Graphify traversal envelope."""

    positive_authorized: bool
    negative_authorized: bool


def _field_pairs(item: Mapping[str, Any]) -> list[tuple[str, str]]:
    fields: list[tuple[str, str]] = [
        ("r", str(item.get("relation") or "")),
        ("s", str(item.get("source") or "")),
        ("t", str(item.get("target") or "")),
        ("f", str(item.get("source_file") or "")),
        ("l", str(item.get("source_location") or "")),
        ("p", str(item.get("provenance") or "")),
    ]
    argument_index = item.get("argument_index")
    if argument_index is not None:
        fields.append(("ai", str(argument_index)))
    return fields


def expected_graphify_df_key(item: Mapping[str, Any]) -> str:
    """Return the public content-addressed Graphify df evidence key."""

    canonical = json.dumps(sorted(_field_pairs(item)), sort_keys=True, separators=(",", ":"))
    return "df:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_graphify_df_evidence(item: Mapping[str, Any]) -> str:
    """Validate Graphify's public df key against the evidence content.

    Both the Graphify adapter and data-flow verifier use this one validator so
    path evidence cannot be re-keyed, rebound to different content, or accepted
    with a syntactically plausible but non-content-addressed id.
    """

    if not isinstance(item, Mapping):
        raise GraphEvidenceModelError("Graphify df evidence must be a mapping")
    key = str(item.get("key") or "")
    if not GRAPHIFY_DF_KEY_RE.fullmatch(key):
        raise GraphEvidenceModelError("Graphify df key must be df:<64 lowercase sha256 hex>")
    missing = [field for field in _GRAPHIFY_DF_KEY_FIELDS if not str(item.get(field) or "")]
    if missing:
        raise GraphEvidenceModelError("Graphify df evidence is missing content-addressed fields: " + ", ".join(missing))
    expected = expected_graphify_df_key(item)
    if key != expected:
        raise GraphEvidenceModelError("Graphify df evidence key is not content-addressed to its public content")
    return key


def graphify_df_key_is_valid(item: Mapping[str, Any]) -> bool:
    try:
        validate_graphify_df_evidence(item)
        return True
    except GraphEvidenceModelError:
        return False


def _mapping_sequence(value: Any, name: str) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, (list, tuple)) or not all(isinstance(item, Mapping) for item in value):
        raise GraphEvidenceModelError(f"Graphify {name} must be a sequence of mappings")
    return tuple(value)


def _stable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _stable(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [_stable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _string_set(value: Any, name: str) -> frozenset[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple, set, frozenset)):
        raise GraphEvidenceModelError(f"Graphify {name} must be a sequence")
    if not all(isinstance(item, str) and item for item in value):
        raise GraphEvidenceModelError(f"Graphify {name} must contain non-empty strings")
    return frozenset(value)


def _real_count(result: Mapping[str, Any], name: str) -> int:
    value = result.get(name)
    if type(value) is not int or value < 0:
        raise GraphEvidenceModelError(f"Graphify {name} must be a non-negative integer")
    return value


def validate_graphify_envelope_authority(result: Mapping[str, Any]) -> GraphifyEnvelopeAuthority:
    """Validate public query metadata once for positive and negative consumers.

    Positive authority is existential, so a valid exact returned witness may
    remain authoritative after a bounded truncation. Negative authority is
    universal and therefore requires a strictly complete, unblocked envelope.
    """

    if not isinstance(result, Mapping):
        raise GraphEvidenceModelError("Graphify traversal result must be a mapping")
    paths = _mapping_sequence(result.get("paths"), "paths")
    direction = str(result.get("direction") or "")
    if direction not in {"FORWARD", "BACKWARD"}:
        raise GraphEvidenceModelError("Graphify direction must be FORWARD or BACKWARD")
    start = str(result.get("start") or "")
    target = "" if result.get("target") is None else str(result.get("target"))
    if not start or not target:
        raise GraphEvidenceModelError("Graphify traversal requires non-empty query endpoints")

    bounds = result.get("query_bounds")
    if not isinstance(bounds, Mapping):
        raise GraphEvidenceModelError("Graphify traversal requires query_bounds")
    direction_valid = bounds.get("direction") is None or str(bounds.get("direction") or "") == direction
    canonical_relation_partition = bounds.get("requested_allowed_relations") is not None
    requested_raw = bounds.get("requested_allowed_relations", bounds.get("requested_relations", bounds.get("relations", ())))
    effective_raw = bounds.get("effective_allowed_relations", bounds.get("effective_relations", bounds.get("relations", ())))
    requested = _string_set(requested_raw, "requested relations")
    effective = _string_set(effective_raw, "effective relations")
    rejected = _string_set(bounds.get("rejected_relations"), "rejected relations") if bounds.get("rejected_relations") else frozenset()
    stop_nodes = _string_set(bounds.get("stop_nodes"), "stop_nodes") if bounds.get("stop_nodes") else frozenset()
    partition_valid = effective == requested & _SUPPORTED_RELATIONS and not effective - _SUPPORTED_RELATIONS
    if canonical_relation_partition:
        partition_valid = partition_valid and rejected == requested - _SUPPORTED_RELATIONS
    top_rejected_raw = result.get("rejected_relations")
    top_rejected = _string_set(top_rejected_raw, "top-level rejected relations") if top_rejected_raw else rejected
    partition_valid = partition_valid and top_rejected == rejected

    limits: dict[str, int] = {}
    for name, minimum in (("max_depth", 0), ("max_paths", 1), ("max_expansions", 1)):
        value = bounds.get(name)
        if value is None:
            limits[name] = 2**63 - 1
            continue
        if type(value) is not int or value < minimum:
            raise GraphEvidenceModelError(f"Graphify {name} must be an integer >= {minimum}")
        limits[name] = value
    visited = _real_count(result, "visited_count") if "visited_count" in result else None
    expanded = _real_count(result, "expanded_count") if "expanded_count" in result else None

    required_boolean_fields = (
        "truncated", "query_validity", "start_node_found", "target_node_found", "complete_supported_search",
    )
    optional_boolean_fields = (
        "encountered_may_evidence", "encountered_partial_evidence", "encountered_unknown_evidence",
    )
    if any(type(result.get(name)) is not bool for name in required_boolean_fields) or any(
        name in result and type(result.get(name)) is not bool for name in optional_boolean_fields
    ):
        raise GraphEvidenceModelError("Graphify authority flags must be booleans")
    epistemic = {name: result.get(name, False) for name in optional_boolean_fields}
    truncated = result["truncated"]
    coverage = str(result.get("search_coverage") or "")
    resolution = str(result.get("input_resolution") or "")
    termination = str(result.get("termination_reason") or "")
    if coverage not in _SEARCH_COVERAGE or resolution not in _INPUT_RESOLUTIONS or termination not in _TERMINATION_REASONS:
        raise GraphEvidenceModelError("Graphify envelope contains an unknown authority vocabulary value")

    certificate = result.get("completeness_certificate")
    certificate_valid = certificate is None or (
        isinstance(certificate, Mapping)
        and certificate.get("schema_version") == 1
        and certificate.get("search_coverage") == coverage
        and certificate.get("complete_supported_search") is result.get("complete_supported_search")
        and certificate.get("termination_reason") == termination
    )
    boundaries = _mapping_sequence(result.get("boundary_events", ()), "boundary_events")
    blocking = any(str(event.get("resolution") or "") in _BLOCKING_BOUNDARY_RESOLUTIONS for event in boundaries)
    returned_nodes: set[str] = set()
    required_expansions = 0
    path_bounds_valid = True
    for path in paths:
        steps = _mapping_sequence(path.get("steps"), "path steps")
        required_expansions = max(required_expansions, len(steps))
        if len(steps) > limits["max_depth"]:
            path_bounds_valid = False
        returned_nodes.update(
            str(step.get(field) or "")
            for step in steps
            for field in ("source", "target")
            if str(step.get(field) or "")
        )
    if expanded is None:
        expanded = required_expansions
    if visited is None:
        visited = max(1, len(returned_nodes))
    counts_valid = (
        path_bounds_valid
        and expanded <= visited
        and expanded <= limits["max_expansions"]
        and len(paths) <= limits["max_paths"]
    )
    counts_valid = counts_valid and expanded >= required_expansions and visited >= max(1, len(returned_nodes))
    if expanded > 0 and visited < 2:
        counts_valid = False

    truncation_valid = truncated is (termination in _TRUNCATION_REASONS)
    resolved = resolution == "RESOLVED" and result["start_node_found"] is True and result["target_node_found"] is True
    expected_coverage = (
        "UNKNOWN" if resolution != "RESOLVED"
        else "PARTIAL" if truncated or blocking or epistemic["encountered_partial_evidence"] or epistemic["encountered_unknown_evidence"]
        else "COMPLETE_FOR_SUPPORTED_CONSTRUCT"
    )
    coverage_valid = coverage == expected_coverage
    expected_complete = (
        resolved and result["query_validity"] is True and not truncated and not blocking
        and not epistemic["encountered_partial_evidence"] and not epistemic["encountered_unknown_evidence"]
        and coverage == "COMPLETE_FOR_SUPPORTED_CONSTRUCT"
    )
    completeness_valid = result["complete_supported_search"] is expected_complete
    common = direction_valid and partition_valid and certificate_valid and counts_valid and truncation_valid and coverage_valid and completeness_valid
    positive = (
        common and bool(paths) and resolved and result["query_validity"] is True
        and not blocking and not epistemic["encountered_may_evidence"]
        and not epistemic["encountered_partial_evidence"] and not epistemic["encountered_unknown_evidence"]
        and not (stop_nodes & returned_nodes)
    )
    negative = common and not paths and expected_complete and not epistemic["encountered_may_evidence"]
    return GraphifyEnvelopeAuthority(positive_authorized=positive, negative_authorized=negative)


def validate_graphify_positive_traversal(result: Mapping[str, Any]) -> frozenset[str]:
    """Validate the authority of every returned positive Graphify path.

    Empty-path results are deliberately outside this validator so negative
    authority remains governed by the separate completeness certificate.  A
    returned path, however, must be an ordered, content-addressed replay of the
    exact public query from its authoritative start to target.  This function is
    shared by the adapter, data-flow verifier, and typed observation path.
    """

    if not isinstance(result, Mapping):
        raise GraphEvidenceModelError("Graphify traversal result must be a mapping")
    envelope = validate_graphify_envelope_authority(result)
    paths = _mapping_sequence(result.get("paths"), "paths")
    if not paths:
        return frozenset()

    direction = str(result.get("direction") or "")
    start = str(result.get("start") or "")
    raw_target = result.get("target")
    target = "" if raw_target is None else str(raw_target)
    if direction == "FORWARD":
        flow_start, flow_target = start, target
    elif direction == "BACKWARD":
        flow_start, flow_target = target, start
    else:
        raise GraphEvidenceModelError("Graphify positive traversal requires FORWARD or BACKWARD direction")
    if not flow_start or not flow_target:
        raise GraphEvidenceModelError("Graphify positive traversal requires non-empty query endpoints")

    bounds = result.get("query_bounds")
    if not isinstance(bounds, Mapping):
        raise GraphEvidenceModelError("Graphify positive traversal requires query_bounds")
    def relation_set(value: Any, name: str) -> frozenset[str]:
        if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple, set, frozenset)):
            raise GraphEvidenceModelError(f"Graphify {name} must be a sequence")
        return frozenset(str(item) for item in value)

    requested_raw = bounds.get(
        "requested_allowed_relations",
        bounds.get("requested_relations", bounds.get("relations", ())),
    )
    effective_raw = bounds.get(
        "effective_allowed_relations",
        bounds.get("effective_relations", bounds.get("relations", ())),
    )
    rejected_raw = bounds.get("rejected_relations", ())
    requested = relation_set(requested_raw, "requested relations")
    effective = relation_set(effective_raw, "effective relations")
    rejected = relation_set(rejected_raw, "rejected relations")
    stop_nodes = relation_set(bounds.get("stop_nodes", ()), "stop_nodes")
    query_authority = envelope.positive_authorized and (
        result.get("query_validity") is True
        and str(result.get("input_resolution") or "") == "RESOLVED"
        and result.get("start_node_found") is True
        and result.get("target_node_found") is True
        and effective == requested & _SUPPORTED_RELATIONS
        and rejected == requested - _SUPPORTED_RELATIONS
        and not effective - _SUPPORTED_RELATIONS
    )
    if bounds.get("direction") is not None and str(bounds.get("direction") or "") != direction:
        query_authority = False
    top_rejected = result.get("rejected_relations")
    if top_rejected is not None:
        query_authority = query_authority and relation_set(top_rejected, "top-level rejected relations") == rejected
    max_depth = bounds.get("max_depth")
    max_paths = bounds.get("max_paths")
    max_expansions = bounds.get(
        "max_expansions",
        bounds.get("max_visited_expansions", bounds.get("visited_expansion_bound")),
    )
    if max_depth is not None and (type(max_depth) is not int or max_depth < 0):
        raise GraphEvidenceModelError("Graphify max_depth must be a non-negative integer")
    if max_paths is not None and (type(max_paths) is not int or max_paths < 0):
        raise GraphEvidenceModelError("Graphify max_paths must be a non-negative integer")
    if max_expansions is not None and (type(max_expansions) is not int or max_expansions < 0):
        raise GraphEvidenceModelError("Graphify max_expansions must be a non-negative integer")
    if max_paths is not None and len(paths) > max_paths:
        raise GraphEvidenceModelError("Graphify returned paths exceed max_paths")
    truncated = result.get("truncated")
    termination = str(result.get("termination_reason") or "")
    if not isinstance(truncated, bool):
        query_authority = False
    elif truncated is not (termination in _TRUNCATION_REASONS):
        query_authority = False
    boundaries = _mapping_sequence(result.get("boundary_events", ()), "boundary_events")
    if any(
        str(event.get("resolution") or "") in _BLOCKING_BOUNDARY_RESOLUTIONS
        for event in boundaries
    ):
        query_authority = False
    if any(
        result.get(flag) is True
        for flag in (
            "encountered_may_evidence",
            "encountered_partial_evidence",
            "encountered_unknown_evidence",
        )
    ):
        query_authority = False

    seen_evidence: dict[str, Any] = {}
    authoritative_keys: set[str] = set()
    for path in paths:
        steps = _mapping_sequence(path.get("steps"), "path steps")
        evidence = _mapping_sequence(path.get("supporting_evidence"), "path supporting_evidence")
        identity_raw = path.get("path_identity")
        if not isinstance(identity_raw, (list, tuple)):
            raise GraphEvidenceModelError("Graphify path_identity must be ordered public df keys")
        identity = tuple(str(key or "") for key in identity_raw)
        if not steps or len(steps) != len(evidence) or len(identity) != len(evidence):
            raise GraphEvidenceModelError("Graphify positive path steps, evidence, and identity must align")
        if max_depth is not None and len(steps) > max_depth:
            raise GraphEvidenceModelError("Graphify positive path exceeds max_depth")
        authoritative = (
            query_authority
            and str(path.get("path_exactness") or "") == "EXACT_FOR_RETURNED_PATH"
            and str(path.get("path_receiver_confidence") or "") == "PROVEN"
            and str(path.get("path_coverage") or "") == "COMPLETE_FOR_SUPPORTED_CONSTRUCT"
            and all(str(item.get("receiver_confidence") or "") == "PROVEN" for item in evidence)
            and all(str(item.get("analysis_completeness") or "") == "COMPLETE_FOR_SUPPORTED_CONSTRUCT" for item in evidence)
        )

        keys: list[str] = []
        for index, (step, item) in enumerate(zip(steps, evidence)):
            key = validate_graphify_df_evidence(item)
            keys.append(key)
            canonical = _stable(item)
            previous = seen_evidence.get(key)
            if previous is not None and previous != canonical:
                raise GraphEvidenceModelError(f"conflicting duplicate graphify df key: {key}")
            seen_evidence[key] = canonical
            if _stable(step.get("evidence")) != canonical:
                raise GraphEvidenceModelError("Graphify path step evidence must exactly match supporting_evidence")
            relation = str(item.get("relation") or "")
            if relation not in _SUPPORTED_RELATIONS or (effective and relation not in effective):
                authoritative = False
            if any(str(step.get(field) or "") != str(item.get(field) or "") for field in ("source", "target", "relation")):
                raise GraphEvidenceModelError("Graphify path step must exactly match supporting evidence endpoints and relation")
            if index and str(steps[index - 1].get("target") or "") != str(step.get("source") or ""):
                raise GraphEvidenceModelError("Graphify positive path is disconnected")
        if identity != tuple(keys):
            raise GraphEvidenceModelError("Graphify path_identity must exactly match supporting_evidence order")
        if len(set(identity)) != len(identity):
            raise GraphEvidenceModelError("Graphify positive path repeats a df evidence key")
        if (
            str(steps[0].get("source") or "") != flow_start
            or str(steps[-1].get("target") or "") != flow_target
        ):
            authoritative = False
        interior_nodes = {
            str(step.get("target") or "")
            for step in steps[:-1]
        }
        if interior_nodes & stop_nodes:
            authoritative = False
        if authoritative:
            authoritative_keys.update(keys)
    return frozenset(authoritative_keys)
