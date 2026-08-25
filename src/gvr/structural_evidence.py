"""Strict consumer for Graphify's full ``graphify.structural_evidence.v2`` contract.

This module deliberately mirrors only the producer's public canonicalization and
validation rules. It never authenticates a remote producer. Provider-origin trust
is granted only by the trusted adapter path in :mod:`gvr.adapters.graphify`.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import math
import re
from types import MappingProxyType
from typing import Any, Mapping

from .graphify_contract import validate_graphify_df_evidence

SCHEMA_VERSION = 2
FORMAT = "graphify.structural_evidence.v2"
SNAPSHOT_FINGERPRINT_FORMAT = "graphify.structural_evidence.fingerprint.v2"
BINDING_FINGERPRINT_FORMAT = "graphify.structural_analysis.binding.v1"
INDEX_FINGERPRINT_FORMAT = "graphify.structural_index.fingerprint.v1"
TRAVERSAL_FINGERPRINT_FORMAT = "graphify.structural_traversal.fingerprint.v1"
SOURCE_CLASS = "git.commit"
PROVIDER_ID = "graphify"
_SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")
_HASH_RE = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")
_DF_RE = re.compile(r"^df:[0-9a-f]{64}$")
_BND_RE = re.compile(r"^bnd:[0-9a-f]{64}$")
_DIAG_RE = re.compile(r"^diag:.+$")
# Producer parity: the only resolutions under which a boundary event blocks
# (and therefore degrades a zero-step identity answer to PARTIAL coverage).
_BLOCKING_BOUNDARY_RESOLUTIONS = frozenset({"AMBIGUOUS", "UNRESOLVED", "UNSUPPORTED"})

def _freeze(value: Any) -> Any:
    """Recursively seal a validated JSON-transport value tree.

    Sequences become tuples and mappings become read-only proxies, so no
    reachable mutation path (including ``list.__setitem__`` style escapes)
    can alter sealed state.
    """
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    """Rebuild plain mutable JSON values from sealed state."""
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw(item) for item in value]
    return value


class GraphifyStructuralEvidenceError(ValueError):
    """Raised when a full Graphify v2 document cannot be trusted as bound evidence."""


def _canonical_value(value: Any) -> Any:
    """Build Graphify's JSON-transport canonical value tree.

    The producer's fingerprint contract is defined over JSON-transportable
    values.  ``ingest_graphify_structural_evidence_v2`` therefore rejects
    Python-only values before calling this compatibility implementation.  The
    coercive branches remain here so the public fingerprint helpers preserve
    the producer's reference-vector behavior for typed values.
    """
    if isinstance(value, Mapping):
        items = [[str(key), _canonical_value(value[key])] for key in value]
        items.sort(key=lambda pair: pair[0].encode("utf-8"))
        return {"$map": items}
    if isinstance(value, (list, tuple)):
        return {"$list": [_canonical_value(item) for item in value]}
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        if isinstance(value, float) and (not math.isfinite(value)):
            raise GraphifyStructuralEvidenceError("non-finite float in structural evidence")
        return value
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _canonical_value(value.to_dict())
    return str(value)


def _canonical_json(value: Any, fingerprint_format: str) -> str:
    return json.dumps(
        {"content": _canonical_value(value), "format": fingerprint_format},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _digest(value: Any, fingerprint_format: str) -> str:
    return hashlib.sha256(_canonical_json(value, fingerprint_format).encode("utf-8")).hexdigest()


def graphify_structural_evidence_fingerprint(document: Mapping[str, Any]) -> str:
    """Recompute the producer v2 fingerprint, excluding only the carried digest."""
    if not isinstance(document, Mapping):
        raise GraphifyStructuralEvidenceError("snapshot document must be a mapping")
    content = {str(key): deepcopy(value) for key, value in document.items() if key != "fingerprint"}
    # StructuralEvidenceSnapshot normalizes identity-bearing collections before
    # computing its fingerprint. This makes producer-semantic reordering stable.
    for name, identity in (("facts", "key"), ("blockers", "key")):
        if isinstance(content.get(name), list):
            content[name] = sorted(content[name], key=lambda item: str(item.get(identity, "")))
    if isinstance(content.get("paths"), list):
        content["paths"] = sorted(
            content["paths"],
            key=lambda item: tuple(str(value) for value in item.get("path_identity", ())),
        )
    return _digest(content, SNAPSHOT_FINGERPRINT_FORMAT)


def graphify_source_scope_fingerprint(scope: Mapping[str, Any]) -> str:
    if not isinstance(scope, Mapping):
        raise GraphifyStructuralEvidenceError("source_revision_scope must be a mapping")
    return _digest(
        {
            "provider_id": scope.get("provider_id"),
            "source_class": scope.get("source_class"),
            "source_revision": scope.get("source_revision"),
        },
        SNAPSHOT_FINGERPRINT_FORMAT,
    )


def graphify_analysis_binding_fingerprint(scope: Mapping[str, Any], binding: Mapping[str, Any]) -> str:
    expected_scope = graphify_source_scope_fingerprint(scope)
    return "sha256:" + _digest(
        {
            "source_revision_scope": {
                "provider_id": scope.get("provider_id"),
                "source_class": scope.get("source_class"),
                "source_revision": scope.get("source_revision"),
            },
            "source_scope_fingerprint": expected_scope,
            "index_fingerprint": binding.get("index_fingerprint"),
            "traversal_fingerprint": binding.get("traversal_fingerprint"),
        },
        BINDING_FINGERPRINT_FORMAT,
    )


def _require_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GraphifyStructuralEvidenceError(f"{name} must be a mapping")
    return value


def _require_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise GraphifyStructuralEvidenceError(f"{name} must be a non-empty string")
    return value


def _sequence(value: Any, name: str) -> list[Any]:
    if not isinstance(value, (list, tuple)):
        raise GraphifyStructuralEvidenceError(f"{name} must be a sequence")
    return list(value)


def _validate_hash(value: Any, name: str) -> str:
    text = _require_string(value, name)
    if not _HASH_RE.fullmatch(text):
        raise GraphifyStructuralEvidenceError(f"invalid {name}")
    return text


def _boundary_key(blocker: Mapping[str, Any]) -> str:
    details = blocker.get("details")
    details = details if isinstance(details, Mapping) else {}

    def public_value(*names: str) -> Any:
        for name in names:
            value = blocker.get(name)
            if value not in (None, ""):
                return value
        for name in names:
            value = details.get(name)
            if value not in (None, ""):
                return value
        return ""

    fields = [
        ("sf", public_value("canonical_caller_file")),
        ("loc", public_value("caller_location", "callerLocation")),
        ("kind", public_value("diagnostic_kind", "diagnosticKind", "kind")),
        ("cap", public_value("capability")),
        ("framework", public_value("framework")),
        ("res", public_value("resolution")),
        ("method", public_value("method")),
        ("arity", str(public_value("arity") or 0)),
        ("rfqn", public_value("receiver_fqn", "receiverFqn")),
        ("repo", public_value("repository_fqn", "repositoryFqn")),
        ("entity", public_value("entity_fqn", "entityFqn")),
        ("reason", public_value("reason")),
    ]
    canonical = json.dumps(sorted((str(k), str(v)) for k, v in fields), sort_keys=True, separators=(",", ":"))
    return "bnd:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class GraphifySourceRevisionScope:
    provider_id: str
    source_class: str
    source_revision: str

    def __post_init__(self) -> None:
        if self.provider_id != PROVIDER_ID:
            raise GraphifyStructuralEvidenceError("source provider_id must be graphify")
        if self.source_class != SOURCE_CLASS:
            raise GraphifyStructuralEvidenceError("source_class must be git.commit")
        if not _SHA_RE.fullmatch(self.source_revision):
            raise GraphifyStructuralEvidenceError("source_revision must be a lowercase Git object SHA")

    @property
    def fingerprint(self) -> str:
        return graphify_source_scope_fingerprint(self.to_dict())

    def to_dict(self) -> dict[str, str]:
        return {"provider_id": self.provider_id, "source_class": self.source_class, "source_revision": self.source_revision}


@dataclass(frozen=True)
class GraphifyStructuralAnalysisBinding:
    source_scope_fingerprint: str
    index_fingerprint: str
    traversal_fingerprint: str
    binding_fingerprint: str

    def __post_init__(self) -> None:
        for name in ("source_scope_fingerprint", "index_fingerprint", "traversal_fingerprint", "binding_fingerprint"):
            _validate_hash(getattr(self, name), name)

    def validate(self, scope: GraphifySourceRevisionScope) -> None:
        if self.source_scope_fingerprint != scope.fingerprint:
            raise GraphifyStructuralEvidenceError("analysis binding source scope fingerprint mismatch")
        expected = graphify_analysis_binding_fingerprint(scope.to_dict(), self.to_dict())
        if self.binding_fingerprint != expected:
            raise GraphifyStructuralEvidenceError("analysis binding fingerprint mismatch")

    def to_dict(self) -> dict[str, str]:
        return {
            "source_scope_fingerprint": self.source_scope_fingerprint,
            "index_fingerprint": self.index_fingerprint,
            "traversal_fingerprint": self.traversal_fingerprint,
            "binding_fingerprint": self.binding_fingerprint,
        }


def _native_boundary_event(blocker: Mapping[str, Any]) -> dict[str, Any]:
    """Project one sealed v2 blocker into the producer's public native shape.

    Mirrors ``StructuralEvidenceBlocker.to_gvr_boundary_event`` of the producer,
    restored to the full native envelope vocabulary by joining the sealed
    top-level fields with the carried diagnostic ``details`` so authority
    consumers see the same boundary events the producer emits.
    """
    details = blocker.get("details")
    details = details if isinstance(details, Mapping) else {}

    def native(*names: str) -> Any:
        for name in names:
            value = blocker.get(name)
            if value not in (None, ""):
                return value
        for name in names:
            if isinstance(value := details.get(name), (str, int, float)) and value not in ("",):
                return value
        return ""

    return {
        "type": "boundary_event",
        "diagnostic_kind": str(native("diagnostic_kind", "diagnosticKind", "kind")),
        "capability": str(native("capability")),
        "framework": str(native("framework")),
        "boundary_evidence_key": str(blocker["key"]),
        "diagnostic_node_id": str(native("diagnostic_node_id", "diagnosticNodeId")),
        "diagnostic_evidence_key": str(blocker["diagnostic_key"]),
        "canonical_caller_file": str(native("canonical_caller_file")),
        "caller_location": str(native("caller_location", "callerLocation")),
        "resolution": str(blocker["resolution"]),
        "reason": str(blocker["reason"]),
        "receiver": str(native("receiver", "receiver_fqn")),
        "receiver_fqn": str(native("receiver_fqn", "receiverFqn")),
        "receiver_confidence": str(native("receiver_confidence", "receiverConfidence")),
        "method": str(native("method")),
        "arity": int(native("arity") or 0),
        "import_context": str(native("import_context", "importContext")),
        "candidate_count": int(native("candidate_count", "candidateCount") or 0),
        "repository_fqn": str(native("repository_fqn", "repositoryFqn")),
        "entity_fqn": str(native("entity_fqn", "entityFqn")),
        "mapping_target": str(native("mapping_target", "mappingTarget")),
    }


@dataclass(frozen=True)
class GraphifyStructuralEvidenceV2:
    """Typed GVR view of one validated full Graphify v2 snapshot.

    The instance itself is an inert, deeply immutable container and grants no
    authority on its own: every typed-object boundary must revalidate the
    canonical document (see the trusted adapter). Sealed state cannot be
    mutated through any reachable path.
    """

    document: Mapping[str, Any]
    source_revision_scope: GraphifySourceRevisionScope
    analysis_binding: GraphifyStructuralAnalysisBinding
    query: Mapping[str, Any]
    coverage: Mapping[str, Any]
    facts: tuple[Mapping[str, Any], ...]
    paths: tuple[Mapping[str, Any], ...]
    blockers: tuple[Mapping[str, Any], ...]
    analyzer_revision: str

    @property
    def format(self) -> str:
        return FORMAT

    @property
    def fingerprint(self) -> str:
        return str(self.document["fingerprint"])

    @property
    def source_revision(self) -> dict[str, str]:
        return {"repository": PROVIDER_ID, "revision": self.source_revision_scope.source_revision}

    def to_dict(self) -> dict[str, Any]:
        return _thaw(self.document)

    def to_gvr_traversal_dict(self) -> dict[str, Any]:
        fact_by_key = {str(fact["key"]): fact for fact in self.facts}
        paths: list[dict[str, Any]] = []
        for path in self.paths:
            keys = [str(key) for key in path["supporting_evidence_keys"]]
            supporting = [_thaw(fact_by_key[key]) for key in keys]
            steps = [
                {
                    "source": item["source"],
                    "target": item["target"],
                    "relation": item["relation"],
                    "evidence": _thaw(fact_by_key[key]),
                }
                for key, item in zip(keys, supporting)
            ]
            paths.append({
                "path_identity": list(path["path_identity"]),
                "supporting_evidence": supporting,
                "steps": steps,
                "path_exactness": path["exactness"],
                "path_receiver_confidence": path["receiver_confidence"],
                "path_coverage": path["coverage"],
            })
        query = _thaw(self.query)
        coverage = _thaw(self.coverage)
        bounds = dict(coverage.get("query_bounds") or query)
        return {
            "paths": paths,
            "boundary_events": [_thaw(_native_boundary_event(blocker)) for blocker in self.blockers],
            "complete_supported_search": coverage["complete_supported_search"],
            "search_coverage": coverage["search_coverage"],
            "termination_reason": coverage["termination_reason"],
            "start": query.get("start", ""),
            "target": query.get("target"),
            "direction": query.get("direction", "UNKNOWN"),
            "truncated": coverage["truncated"],
            "input_resolution": coverage["input_resolution"],
            "query_validity": coverage["query_validity"],
            "start_node_found": coverage["start_node_found"],
            "target_node_found": coverage["target_node_found"],
            "visited_count": coverage["visited_count"],
            "expanded_count": coverage["expanded_count"],
            "query_bounds": bounds,
            "rejected_relations": list(coverage["rejected_relations"]),
            "encountered_partial_evidence": coverage["encountered_partial_evidence"],
            "encountered_unknown_evidence": coverage["encountered_unknown_evidence"],
            "encountered_may_evidence": coverage["encountered_may_evidence"],
            "source_revision": self.source_revision,
        }


def _validate_fact(fact: Mapping[str, Any], path_ids: set[tuple[str, ...]]) -> dict[str, Any]:
    required = {"key", "relation", "source", "target", "source_file", "source_location", "provenance", "analysis_completeness", "receiver_confidence"}
    if not required <= set(fact):
        raise GraphifyStructuralEvidenceError("structural fact is missing required fields")
    candidate = dict(fact)
    try:
        validate_graphify_df_evidence(candidate)
    except ValueError as exc:
        raise GraphifyStructuralEvidenceError(str(exc)) from exc
    if candidate["provenance"] not in {"STATIC_AST", "CROSS_FILE", "FRAMEWORK_CONTRACT"}:
        raise GraphifyStructuralEvidenceError("invalid structural fact provenance")
    if candidate["analysis_completeness"] not in {"COMPLETE_FOR_SUPPORTED_CONSTRUCT", "PARTIAL", "UNKNOWN"}:
        raise GraphifyStructuralEvidenceError("invalid structural fact coverage")
    if candidate["receiver_confidence"] not in {"PROVEN", "MAY"}:
        raise GraphifyStructuralEvidenceError("invalid structural fact receiver confidence")
    path_identity = tuple(tuple(str(key) for key in path) for path in _sequence(candidate.get("path_identity", []), "fact.path_identity"))
    if any(path not in path_ids for path in path_identity):
        raise GraphifyStructuralEvidenceError("fact references unknown path identity")
    candidate["path_identity"] = [list(path) for path in path_identity]
    return candidate


def _validate_blocker(blocker: Mapping[str, Any]) -> dict[str, Any]:
    candidate = dict(blocker)
    key = _require_string(candidate.get("key"), "blocker.key")
    if not _BND_RE.fullmatch(key):
        raise GraphifyStructuralEvidenceError("blocker key must be bnd:<64 lowercase sha256 hex>")
    if _boundary_key(candidate) != key:
        raise GraphifyStructuralEvidenceError("blocker key is not content-addressed to its public content")
    diagnostic = _require_string(candidate.get("diagnostic_key"), "blocker.diagnostic_key")
    if not _DIAG_RE.fullmatch(diagnostic):
        raise GraphifyStructuralEvidenceError("invalid blocker diagnostic key")
    return candidate


def _validate_query(query: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(query))
    _require_string(result.get("start"), "query.start")
    if result.get("target") is not None:
        _require_string(result["target"], "query.target")
    if result.get("direction") not in {"FORWARD", "BACKWARD"}:
        raise GraphifyStructuralEvidenceError("query.direction must be FORWARD or BACKWARD")
    for key in ("requested_allowed_relations", "effective_allowed_relations", "rejected_relations", "stop_nodes"):
        _sequence(result.get(key), f"query.{key}")
    for key, minimum in (("max_depth", 0), ("max_paths", 1), ("max_expansions", 1)):
        if type(result.get(key)) is not int or result[key] < minimum:
            raise GraphifyStructuralEvidenceError(f"query.{key} must be an integer >= {minimum}")
    return result


def _assert_json_transport(value: Any, name: str = "snapshot") -> None:
    """Reject values that cannot occur in a JSON snapshot transport."""
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise GraphifyStructuralEvidenceError(f"{name} contains a non-finite JSON number")
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise GraphifyStructuralEvidenceError(f"{name} contains a non-string JSON object key")
            _assert_json_transport(child, f"{name}.{key}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _assert_json_transport(child, f"{name}[{index}]")
        return
    raise GraphifyStructuralEvidenceError(f"{name} contains a non-JSON value")


def _validate_coverage(coverage: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(coverage))
    for key in ("complete_supported_search", "truncated", "query_validity", "start_node_found", "encountered_partial_evidence", "encountered_unknown_evidence", "encountered_may_evidence"):
        if type(result.get(key)) is not bool:
            raise GraphifyStructuralEvidenceError(f"coverage.{key} must be boolean")
    if result.get("target_node_found") is not None and type(result["target_node_found"]) is not bool:
        raise GraphifyStructuralEvidenceError("coverage.target_node_found must be boolean or null")
    if result.get("search_coverage") not in {"COMPLETE_FOR_SUPPORTED_CONSTRUCT", "PARTIAL", "UNKNOWN"}:
        raise GraphifyStructuralEvidenceError("invalid coverage.search_coverage")
    if not _require_string(result.get("termination_reason"), "coverage.termination_reason"):
        raise GraphifyStructuralEvidenceError("invalid coverage termination")
    _require_string(result.get("input_resolution"), "coverage.input_resolution")
    _sequence(result.get("rejected_relations"), "coverage.rejected_relations")
    if type(result.get("visited_count")) is not int or type(result.get("expanded_count")) is not int:
        raise GraphifyStructuralEvidenceError("coverage counts must be integers")
    _require_mapping(result.get("query_bounds"), "coverage.query_bounds")
    # Producer parity: run_data_flow_query rejects max_paths/max_expansions below 1.
    for name, minimum in (("max_depth", 0), ("max_paths", 1), ("max_expansions", 1)):
        value = result["query_bounds"].get(name)
        if type(value) is not int or value < minimum:
            raise GraphifyStructuralEvidenceError(
                f"coverage.query_bounds.{name} must be an integer >= {minimum}"
            )
    return result


def ingest_graphify_structural_evidence_v2(
    document: Mapping[str, Any],
    *,
    source_revision: Any | None = None,
    source_snapshot: Any | None = None,
    query_scope: Any | None = None,
    traversal: Any | None = None,
) -> GraphifyStructuralEvidenceV2:
    """Parse one complete v2 document; all authority-bearing inputs stay bound."""
    if not isinstance(document, Mapping):
        raise GraphifyStructuralEvidenceError("snapshot document must be a mapping")
    _assert_json_transport(document)
    if any(value is not None for value in (source_revision, source_snapshot, query_scope, traversal)):
        raise GraphifyStructuralEvidenceError("caller authority or traversal overrides are forbidden for v2 snapshots")
    required = {"schema_version", "format", "provider_id", "analyzer_revision", "source_revision_scope", "analysis_binding", "query", "coverage", "facts", "paths", "blockers", "fingerprint"}
    if set(document) != required:
        raise GraphifyStructuralEvidenceError("full v2 snapshot fields are required and extensions are forbidden")
    if document["schema_version"] != SCHEMA_VERSION or document["format"] != FORMAT or document["provider_id"] != PROVIDER_ID:
        raise GraphifyStructuralEvidenceError("snapshot schema, format, or provider mismatch")
    scope_doc = _require_mapping(document["source_revision_scope"], "source_revision_scope")
    if set(scope_doc) != {"provider_id", "source_class", "source_revision"}:
        raise GraphifyStructuralEvidenceError("source_revision_scope is incomplete")
    scope = GraphifySourceRevisionScope(**{key: str(scope_doc[key]) for key in scope_doc})
    binding_doc = _require_mapping(document["analysis_binding"], "analysis_binding")
    if set(binding_doc) != {"source_scope_fingerprint", "index_fingerprint", "traversal_fingerprint", "binding_fingerprint"}:
        raise GraphifyStructuralEvidenceError("analysis_binding is incomplete")
    binding = GraphifyStructuralAnalysisBinding(**{key: str(binding_doc[key]) for key in binding_doc})
    binding.validate(scope)
    if _require_string(document["analyzer_revision"], "analyzer_revision").find("/") < 1:
        raise GraphifyStructuralEvidenceError("analyzer_revision must be namespaced")
    query = _validate_query(_require_mapping(document["query"], "query"))
    coverage = _validate_coverage(_require_mapping(document["coverage"], "coverage"))
    raw_paths = _sequence(document["paths"], "paths")
    identity_target = query.get("target")
    is_identity_query = (
        identity_target is not None
        and str(identity_target) == str(query.get("start"))
    )
    path_ids: list[tuple[str, ...]] = []
    for path in raw_paths:
        item = _require_mapping(path, "path")
        identity = tuple(str(key) for key in _sequence(item.get("path_identity"), "path.path_identity"))
        supporting = tuple(str(key) for key in _sequence(item.get("supporting_evidence_keys"), "path.supporting_evidence_keys"))
        if not identity:
            # Producer-valid zero-step identity: the only empty path identity
            # allowed is the point-to-point answer of a bound start == target
            # query, carrying the producer's exact identity labels.
            if not is_identity_query or supporting:
                raise GraphifyStructuralEvidenceError(
                    "empty path identity is only valid as the producer zero-step identity path of a start == target query"
                )
            for label, expected in (
                ("exactness", "EXACT_FOR_RETURNED_PATH"),
                ("receiver_confidence", "PROVEN"),
                ("coverage", "COMPLETE_FOR_SUPPORTED_CONSTRUCT"),
            ):
                if item.get(label) != expected:
                    raise GraphifyStructuralEvidenceError(
                        f"zero-step identity path {label} must be {expected}"
                    )
        elif identity != supporting or any(not _DF_RE.fullmatch(key) for key in identity):
            raise GraphifyStructuralEvidenceError("path identity must exactly match ordered df evidence keys")
        for key in ("exactness", "receiver_confidence", "coverage"):
            _require_string(item.get(key), f"path.{key}")
        path_ids.append(identity)
    if sum(1 for identity in path_ids if not identity) > 1:
        raise GraphifyStructuralEvidenceError("at most one producer zero-step identity path is allowed")
    if any(not identity for identity in path_ids):
        if len(path_ids) != 1:
            # The producer emits the zero-step identity answer only as a single
            # standalone path; mixing it with non-empty evidence paths is a
            # contract violation even when every other field looks valid.
            raise GraphifyStructuralEvidenceError(
                "producer zero-step identity path cannot be mixed with non-empty evidence paths"
            )
        # Parser-vs-authority separation: both producer-valid zero-step identity
        # states parse. Decisiveness is decided later by the authority surface.
        common_identity_state = (
            coverage.get("input_resolution") == "RESOLVED"
            and coverage.get("query_validity") is True
            and coverage.get("start_node_found") is True
            and coverage.get("target_node_found") is True
            and coverage.get("truncated") is False
            and coverage.get("termination_reason") == "COMPLETE"
            and coverage.get("visited_count") == 1
            and coverage.get("expanded_count") == 0
            and coverage.get("encountered_partial_evidence") is False
            and coverage.get("encountered_unknown_evidence") is False
            and coverage.get("encountered_may_evidence") is False
        )
        blockers = _sequence(document["blockers"], "blockers")
        clean_identity_state = (
            common_identity_state
            and coverage.get("complete_supported_search") is True
            and coverage.get("search_coverage") == "COMPLETE_FOR_SUPPORTED_CONSTRUCT"
            and not blockers
        )
        boundary_identity_state = (
            common_identity_state
            and coverage.get("complete_supported_search") is False
            and coverage.get("search_coverage") == "PARTIAL"
            and bool(blockers)
            and all(
                str(blocker.get("resolution") or "") in _BLOCKING_BOUNDARY_RESOLUTIONS
                for blocker in blockers
            )
        )
        if not clean_identity_state and not boundary_identity_state:
            raise GraphifyStructuralEvidenceError(
                "zero-step identity path requires the producer's resolved clean or blocking-boundary identity state"
            )
    path_id_set = set(path_ids)
    facts = tuple(_validate_fact(_require_mapping(item, "fact"), path_id_set) for item in _sequence(document["facts"], "facts"))
    fact_keys = {str(fact["key"]) for fact in facts}
    seen_facts: dict[str, Mapping[str, Any]] = {}
    for fact in facts:
        prior = seen_facts.get(str(fact["key"]))
        if prior is not None and prior != fact:
            raise GraphifyStructuralEvidenceError("conflicting duplicate structural fact")
        seen_facts[str(fact["key"])] = fact
    paths: list[dict[str, Any]] = []
    seen_paths: dict[tuple[str, ...], Mapping[str, Any]] = {}
    for raw, identity in zip(raw_paths, path_ids):
        path = dict(_require_mapping(raw, "path")); path["path_identity"] = list(identity); path["supporting_evidence_keys"] = list(identity)
        if any(key not in fact_keys for key in identity):
            raise GraphifyStructuralEvidenceError("path references unknown fact")
        prior = seen_paths.get(identity)
        if prior is not None and prior != path:
            raise GraphifyStructuralEvidenceError("conflicting duplicate structural path")
        seen_paths[identity] = path
        paths.append(path)
    blockers = tuple(_validate_blocker(_require_mapping(item, "blocker")) for item in _sequence(document["blockers"], "blockers"))
    seen_blockers: dict[str, Mapping[str, Any]] = {}
    for blocker in blockers:
        prior = seen_blockers.get(str(blocker["key"]))
        if prior is not None and prior != blocker:
            raise GraphifyStructuralEvidenceError("conflicting duplicate structural blocker")
        seen_blockers[str(blocker["key"])] = blocker
    expected_fingerprint = graphify_structural_evidence_fingerprint(document)
    if document["fingerprint"] != expected_fingerprint:
        raise GraphifyStructuralEvidenceError("snapshot fingerprint mismatch")
    return GraphifyStructuralEvidenceV2(
        document=_freeze(dict(document)),
        source_revision_scope=scope,
        analysis_binding=binding,
        query=_freeze(query),
        coverage=_freeze(coverage),
        facts=tuple(_freeze(seen_facts[key]) for key in sorted(seen_facts)),
        paths=tuple(_freeze(seen_paths[key]) for key in sorted(seen_paths)),
        blockers=tuple(_freeze(seen_blockers[key]) for key in sorted(seen_blockers)),
        analyzer_revision=str(document["analyzer_revision"]),
    )


# Friendly aliases for callers that prefer the contract noun.
parse_graphify_structural_evidence_v2 = ingest_graphify_structural_evidence_v2
validate_graphify_structural_evidence_v2 = ingest_graphify_structural_evidence_v2

__all__ = [
    "GraphifyStructuralEvidenceError",
    "GraphifySourceRevisionScope",
    "GraphifyStructuralAnalysisBinding",
    "GraphifyStructuralEvidenceV2",
    "graphify_structural_evidence_fingerprint",
    "graphify_source_scope_fingerprint",
    "graphify_analysis_binding_fingerprint",
    "ingest_graphify_structural_evidence_v2",
    "parse_graphify_structural_evidence_v2",
    "validate_graphify_structural_evidence_v2",
]
