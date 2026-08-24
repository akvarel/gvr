from __future__ import annotations

import hashlib
import json
import re
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
    query_authority = (
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
