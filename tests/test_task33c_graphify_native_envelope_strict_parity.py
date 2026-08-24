from __future__ import annotations

import hashlib
import json

import pytest

from gvr import VerificationVerdict
from gvr.code_graph import EvidenceConfidence

from test_task31_authority_remediation import df_edge, path_for, traversal
from test_task33b_graphify_envelope_authority_parity import (
    _surface_authority,
    assert_exact_positive_parity,
    assert_negative_parity,
    assert_non_authoritative_parity,
)


_REQUIRED_NATIVE_FIELDS = (
    "paths",
    "start",
    "target",
    "direction",
    "visited_count",
    "expanded_count",
    "truncated",
    "termination_reason",
    "query_bounds",
    "boundary_events",
    "search_coverage",
    "complete_supported_search",
    "start_node_found",
    "target_node_found",
    "query_validity",
    "input_resolution",
    "rejected_relations",
    "encountered_partial_evidence",
    "encountered_unknown_evidence",
    "encountered_may_evidence",
)

_REQUIRED_NATIVE_BOUNDS = (
    "direction",
    "max_depth",
    "max_paths",
    "max_expansions",
    "requested_allowed_relations",
    "effective_allowed_relations",
    "rejected_relations",
    "stop_nodes",
)

_REQUIRED_NATIVE_PATH_FIELDS = (
    "steps",
    "supporting_evidence",
    "path_identity",
    "path_exactness",
    "path_receiver_confidence",
    "path_coverage",
)


@pytest.mark.parametrize("field", _REQUIRED_NATIVE_FIELDS)
def test_task33c_deleting_any_native_top_level_field_removes_authority(field: str) -> None:
    result = traversal([path_for(df_edge())])
    del result[field]
    assert_non_authoritative_parity(result)


@pytest.mark.parametrize("field", _REQUIRED_NATIVE_BOUNDS)
def test_task33c_deleting_any_native_query_bound_removes_authority(field: str) -> None:
    result = traversal([path_for(df_edge())])
    del result["query_bounds"][field]
    assert_non_authoritative_parity(result)


@pytest.mark.parametrize("field", _REQUIRED_NATIVE_PATH_FIELDS)
def test_task33c_deleting_any_native_path_field_removes_authority(field: str) -> None:
    result = traversal([path_for(df_edge())])
    del result["paths"][0][field]
    assert_non_authoritative_parity(result)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("start", 7),
        ("target", 7),
        ("termination_reason", 7),
        ("search_coverage", 7),
        ("input_resolution", 7),
        ("rejected_relations", "FLOWS_TO"),
        ("boundary_events", {}),
    ],
)
def test_task33c_native_field_types_are_not_string_coerced(field: str, value: object) -> None:
    result = traversal([path_for(df_edge())])
    result[field] = value
    assert_non_authoritative_parity(result)


def test_task33c_expanded_count_may_exceed_unique_visited_count() -> None:
    edges = tuple(df_edge(location=f"A->B:{index}") for index in range(3))
    result = traversal([path_for(edge) for edge in edges])
    result["visited_count"] = 2
    result["expanded_count"] = 3
    contract, adapter, typed, verdict, negative = _surface_authority(result)
    assert contract == frozenset(edge["key"] for edge in edges)
    assert adapter == (EvidenceConfidence.EXACT,) * 3
    assert typed == (EvidenceConfidence.EXACT,) * 3
    assert verdict is VerificationVerdict.PASS
    assert negative is False


def test_task33c_target_is_a_valid_terminal_stop_node() -> None:
    result = traversal([path_for(df_edge())])
    result["query_bounds"]["stop_nodes"] = ["B"]
    assert_exact_positive_parity(result)


def test_task33c_non_target_returned_stop_node_is_non_authoritative() -> None:
    first = df_edge("A", "X", location="A->X")
    second = df_edge("X", "B", location="X->B")
    result = traversal([path_for(first, second)])
    result["visited_count"] = 3
    result["expanded_count"] = 2
    result["query_bounds"]["stop_nodes"] = ["X"]
    contract, adapter, typed, verdict, negative = _surface_authority(result)
    assert contract in (frozenset(), "REJECTED")
    assert adapter == (EvidenceConfidence.HEURISTIC, EvidenceConfidence.HEURISTIC)
    assert typed == (EvidenceConfidence.HEURISTIC, EvidenceConfidence.HEURISTIC)
    assert verdict is VerificationVerdict.UNKNOWN
    assert negative is False


def test_task33c_legacy_relation_aliases_are_non_authoritative() -> None:
    result = traversal([path_for(df_edge())])
    bounds = result["query_bounds"]
    bounds["relations"] = bounds.pop("requested_allowed_relations")
    bounds["effective_relations"] = bounds.pop("effective_allowed_relations")
    assert_non_authoritative_parity(result)


@pytest.mark.parametrize("resolution", ["AMBIGUOUS_START", "AMBIGUOUS_TARGET"])
def test_task33c_invented_input_resolution_is_not_native_authority(resolution: str) -> None:
    result = traversal([path_for(df_edge())])
    result["input_resolution"] = resolution
    assert_non_authoritative_parity(result)


def test_task33c_truncated_exact_positive_and_complete_negative_semantics_remain_distinct() -> None:
    positive = traversal([path_for(df_edge())])
    positive.update(
        truncated=True,
        termination_reason="MAX_EXPANSIONS",
        search_coverage="PARTIAL",
        complete_supported_search=False,
    )
    positive["completeness_certificate"].update(
        termination_reason="MAX_EXPANSIONS",
        search_coverage="PARTIAL",
        complete_supported_search=False,
    )
    assert_exact_positive_parity(positive)

    negative = traversal([])
    negative["visited_count"] = 1
    assert_negative_parity(negative, authoritative=True)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda event: event.pop("boundary_evidence_key"),
        lambda event: event.update(diagnostic_evidence_key="diag:other"),
        lambda event: event.update(resolution="BOGUS"),
        lambda event: event.pop("diagnostic_node_id"),
    ],
)
def test_task33c_boundary_identity_and_blocking_resolution_are_strict(mutation) -> None:
    result = traversal([path_for(df_edge())])
    event = {
        "type": "boundary_event",
        "diagnostic_kind": "cross_file_resolution",
        "capability": "call_resolution",
        "framework": "",
        "boundary_evidence_key": "",
        "diagnostic_node_id": "diag-node-1",
        "diagnostic_evidence_key": "diag:diag-node-1",
        "canonical_caller_file": "src/Flow.java",
        "caller_location": "1:1",
        "resolution": "UNRESOLVED",
        "reason": "unresolved",
        "receiver": "service",
        "receiver_fqn": "pkg.Service",
        "receiver_confidence": "MAY",
        "method": "run",
        "arity": 0,
        "import_context": "unknown",
        "candidate_count": 0,
        "repository_fqn": "",
        "entity_fqn": "",
        "mapping_target": "",
    }
    fields = [
        ("sf", event["canonical_caller_file"]),
        ("loc", event["caller_location"]),
        ("kind", event["diagnostic_kind"]),
        ("cap", event["capability"]),
        ("framework", event["framework"]),
        ("res", event["resolution"]),
        ("method", event["method"]),
        ("arity", str(event["arity"])),
        ("rfqn", event["receiver_fqn"]),
        ("repo", event["repository_fqn"]),
        ("entity", event["entity_fqn"]),
        ("reason", event["reason"]),
    ]
    canonical = json.dumps(sorted(fields), sort_keys=True, separators=(",", ":"))
    event["boundary_evidence_key"] = "bnd:" + hashlib.sha256(canonical.encode()).hexdigest()
    mutation(event)
    result["boundary_events"] = [event]
    result.update(search_coverage="PARTIAL", complete_supported_search=False)
    result["completeness_certificate"].update(
        search_coverage="PARTIAL", complete_supported_search=False
    )
    assert_non_authoritative_parity(result)


def test_task33c_codeflow_confidence_is_not_upgraded_by_graphify_parser() -> None:
    malformed = traversal([path_for(df_edge())])
    del malformed["visited_count"]
    contract, adapter, typed, verdict, negative = _surface_authority(malformed)
    assert contract in (frozenset(), "REJECTED")
    assert adapter in ((EvidenceConfidence.HEURISTIC,), "REJECTED")
    assert typed in ((EvidenceConfidence.HEURISTIC,), "REJECTED")
    assert verdict is VerificationVerdict.UNKNOWN
    assert negative is False
