from __future__ import annotations

from copy import deepcopy

import pytest

from gvr import (
    DataFlowClaim,
    DataFlowClaimKind,
    DataFlowQueryScope,
    SourceRevisionIdentity,
    VerificationVerdict,
    decode_code_graph_observation_evidence,
    encode_graphify_code_graph_observation_evidence,
    verify_data_flow_claim,
)
from gvr.adapters.graphify import ingest_traversal_graph
from gvr.code_graph import EvidenceConfidence, GraphEvidenceModelError
from gvr.graphify_contract import validate_graphify_positive_traversal

from test_task31_authority_remediation import FULL_RELATIONS, df_edge, path_for, traversal


def _claim() -> DataFlowClaim:
    from gvr.verifiers.data_flow import SourceRevision

    return DataFlowClaim(
        kind=DataFlowClaimKind.CAN_FLOW_TO,
        start="A",
        target="B",
        scope=DataFlowQueryScope(effective_allowed_relations=frozenset(FULL_RELATIONS)),
        evidence_namespace="task33b",
        source_revision=SourceRevision(repository="fixture-repo", revision="rev1"),
    )


def _surface_authority(result: dict[str, object]) -> tuple[object, ...]:
    """Return the authority decision from the contract, adapter, typed path, and verifier."""

    try:
        contract = validate_graphify_positive_traversal(result)
    except GraphEvidenceModelError:
        contract = "REJECTED"
    try:
        graph = ingest_traversal_graph(result)
        adapter = tuple(edge.confidence for edge in graph.edges)
        negative = bool(graph.absence_subjects)
    except GraphEvidenceModelError:
        adapter = "REJECTED"
        negative = False
    try:
        decoded = decode_code_graph_observation_evidence(
            encode_graphify_code_graph_observation_evidence(
                result,
                evidence_id="obs.task33b.parity",
                source_revision=SourceRevisionIdentity("fixture-repo", "rev1"),
                claim_fingerprint="task33b",
            )
        )
        typed = tuple(edge.confidence for edge in decoded.graph_model.edges)
    except GraphEvidenceModelError:
        typed = "REJECTED"
    report = verify_data_flow_claim(_claim(), result)
    return contract, adapter, typed, report.verdict, negative


def assert_exact_positive_parity(result: dict[str, object]) -> None:
    contract, adapter, typed, verdict, negative = _surface_authority(result)
    assert contract == frozenset({result["paths"][0]["path_identity"][0]})
    assert adapter == (EvidenceConfidence.EXACT,)
    assert typed == (EvidenceConfidence.EXACT,)
    assert verdict is VerificationVerdict.PASS
    assert negative is False


def assert_non_authoritative_parity(result: dict[str, object]) -> None:
    contract, adapter, typed, verdict, negative = _surface_authority(result)
    assert contract in (frozenset(), "REJECTED")
    assert adapter in ((EvidenceConfidence.HEURISTIC,), "REJECTED")
    assert typed in ((EvidenceConfidence.HEURISTIC,), "REJECTED")
    assert verdict is VerificationVerdict.UNKNOWN
    assert negative is False


def assert_negative_parity(result: dict[str, object], *, authoritative: bool) -> None:
    contract, adapter, typed, verdict, negative = _surface_authority(result)
    assert contract == frozenset()
    assert adapter == ()
    assert typed == ()
    assert negative is authoritative
    assert verdict is (VerificationVerdict.FAIL if authoritative else VerificationVerdict.UNKNOWN)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("direction", "SIDEWAYS"),
        ("search_coverage", "COMPLETE"),
        ("termination_reason", "DONE"),
        ("input_resolution", "OK"),
        ("query_validity", 1),
        ("start_node_found", 1),
        ("target_node_found", 1),
        ("complete_supported_search", 1),
        ("encountered_may_evidence", 0),
        ("encountered_partial_evidence", None),
        ("encountered_unknown_evidence", "false"),
    ],
)
def test_task33b_real_envelope_vocabularies_and_boolean_types_are_shared(field, value) -> None:
    result = traversal([path_for(df_edge())])
    result[field] = value
    assert_non_authoritative_parity(result)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("visited_count", True),
        ("visited_count", -1),
        ("visited_count", 1),
        ("expanded_count", True),
        ("expanded_count", -1),
        ("expanded_count", 3),
    ],
)
def test_task33b_counts_must_be_real_bounded_integers_covering_returned_paths(field, value) -> None:
    result = traversal([path_for(df_edge())])
    result[field] = value
    assert_non_authoritative_parity(result)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_depth", True),
        ("max_depth", -1),
        ("max_paths", True),
        ("max_paths", 0),
        ("max_expansions", True),
        ("max_expansions", 0),
    ],
)
def test_task33b_query_bounds_are_finite_real_integers_and_enforced(field, value) -> None:
    result = traversal([path_for(df_edge())])
    result["query_bounds"][field] = value
    assert_non_authoritative_parity(result)


def test_task33b_relation_vocabulary_partition_and_stop_node_vocabulary_are_strict() -> None:
    for mutate in (
        lambda r: r["query_bounds"].update(requested_allowed_relations=[*FULL_RELATIONS, ""], effective_allowed_relations=[*FULL_RELATIONS, ""]),
        lambda r: r["query_bounds"].update(requested_allowed_relations=[*FULL_RELATIONS, "MAGIC"], rejected_relations=[]),
        lambda r: r["query_bounds"].update(effective_allowed_relations=[*FULL_RELATIONS, "MAGIC"]),
        lambda r: r["query_bounds"].update(stop_nodes=[""]),
        lambda r: r.update(rejected_relations=["MAGIC"]),
    ):
        result = traversal([path_for(df_edge())])
        mutate(result)
        assert_non_authoritative_parity(result)


def test_task33b_completeness_certificate_must_exactly_cover_top_level_coverage_and_termination() -> None:
    for field, value in (
        ("schema_version", 2),
        ("search_coverage", "PARTIAL"),
        ("complete_supported_search", False),
        ("termination_reason", "MAX_DEPTH"),
    ):
        result = traversal([path_for(df_edge())])
        result["completeness_certificate"][field] = value
        assert_non_authoritative_parity(result)


def test_task33b_termination_and_coverage_state_machine_rejects_impossible_combinations() -> None:
    cases = (
        {"truncated": False, "termination_reason": "MAX_DEPTH"},
        {"truncated": True, "termination_reason": "COMPLETE"},
        {"complete_supported_search": True, "search_coverage": "PARTIAL"},
        {"complete_supported_search": False, "search_coverage": "COMPLETE_FOR_SUPPORTED_CONSTRUCT"},
    )
    for values in cases:
        result = traversal([path_for(df_edge())])
        result.update(values)
        result["completeness_certificate"].update(
            search_coverage=result["search_coverage"],
            complete_supported_search=result["complete_supported_search"],
            termination_reason=result["termination_reason"],
        )
        assert_non_authoritative_parity(result)


def test_task33b_truncated_exact_positive_witness_preserves_existential_authority() -> None:
    result = traversal([path_for(df_edge())])
    result.update(
        truncated=True,
        termination_reason="MAX_PATHS",
        complete_supported_search=False,
        search_coverage="PARTIAL",
    )
    result["completeness_certificate"].update(
        termination_reason="MAX_PATHS",
        complete_supported_search=False,
        search_coverage="PARTIAL",
    )
    assert_exact_positive_parity(result)


def test_task33b_negative_authority_requires_strict_complete_envelope_and_count_coverage() -> None:
    complete = traversal([])
    complete["visited_count"] = 1
    assert_negative_parity(complete, authoritative=True)

    mutations = (
        lambda r: r.update(visited_count=True),
        lambda r: r.update(expanded_count=1, visited_count=0),
        lambda r: r.update(termination_reason="DONE"),
        lambda r: r.update(search_coverage="COMPLETE"),
        lambda r: r["completeness_certificate"].update(termination_reason="MAX_DEPTH"),
        lambda r: r.update(encountered_may_evidence=True),
        lambda r: r.update(rejected_relations=["MAGIC"]),
    )
    for mutate in mutations:
        result = deepcopy(complete)
        mutate(result)
        assert_negative_parity(result, authoritative=False)
