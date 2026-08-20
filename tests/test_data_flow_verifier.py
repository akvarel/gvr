from __future__ import annotations

import hashlib
import json
from copy import deepcopy

from gvr import (
    DATA_FLOW_VERIFIER,
    ClaimDefinition,
    ClaimLedger,
    DataFlowClaim,
    DataFlowClaimKind,
    Freshness,
    VerificationVerdict,
    handle_request,
    ingest_traversal_result,
    verify_data_flow_claim,
)


COMPLETE = "COMPLETE_FOR_SUPPORTED_CONSTRUCT"


def _key(item: dict[str, object]) -> str:
    fields: list[tuple[str, str]] = [
        ("r", str(item.get("relation") or "")),
        ("s", str(item.get("source") or "")),
        ("t", str(item.get("target") or "")),
        ("f", str(item.get("source_file") or "")),
        ("l", str(item.get("source_location") or "")),
        ("p", str(item.get("provenance") or "")),
    ]
    if item.get("argument_index") is not None:
        fields.append(("ai", str(item["argument_index"])))
    canonical = json.dumps(sorted(fields), sort_keys=True, separators=(",", ":"))
    return "df:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _evidence(
    source: str,
    target: str,
    *,
    relation: str = "FLOWS_TO",
    receiver_confidence: str = "PROVEN",
    analysis_completeness: str = COMPLETE,
    location: str | None = None,
) -> dict[str, object]:
    item: dict[str, object] = {
        "relation": relation,
        "source": source,
        "target": target,
        "source_file": "src/Flow.java",
        "source_location": location or f"{source}->{target}",
        "provenance": "STATIC_AST",
        "confidence_score": 1.0,
        "argument_index": None,
        "receiver_confidence": receiver_confidence,
        "analysis_completeness": analysis_completeness,
    }
    item["key"] = _key(item)
    return item


def _path(
    *items: dict[str, object],
    receiver_confidence: str = "PROVEN",
    coverage: str = COMPLETE,
) -> dict[str, object]:
    return {
        "steps": [
            {
                "source": item["source"],
                "target": item["target"],
                "relation": item["relation"],
                "evidence": deepcopy(item),
            }
            for item in items
        ],
        "supporting_evidence": [deepcopy(item) for item in items],
        "path_identity": [item.get("key", "") for item in items],
        "path_exactness": "EXACT_FOR_RETURNED_PATH",
        "path_receiver_confidence": receiver_confidence,
        "path_coverage": coverage,
    }


def _result(
    paths: list[dict[str, object]],
    *,
    start: str = "A",
    target: str = "C",
    direction: str = "FORWARD",
    complete_supported_search: bool = True,
    search_coverage: str = COMPLETE,
    truncated: bool = False,
    termination_reason: str = "COMPLETE",
    input_resolution: str = "RESOLVED",
    start_node_found: bool = True,
    target_node_found: bool | None = True,
    boundary_events: list[dict[str, object]] | None = None,
    encountered_partial_evidence: bool = False,
    encountered_unknown_evidence: bool = False,
    encountered_may_evidence: bool = False,
) -> dict[str, object]:
    return {
        "paths": deepcopy(paths),
        "start": start,
        "target": target,
        "direction": direction,
        "visited_count": 3 if start_node_found else 0,
        "expanded_count": sum(len(path["steps"]) for path in paths),
        "truncated": truncated,
        "termination_reason": termination_reason,
        "query_bounds": {
            "direction": direction,
            "max_depth": 4,
            "max_paths": 50,
            "max_expansions": 2000,
            "requested_allowed_relations": ["FLOWS_TO"],
            "effective_allowed_relations": ["FLOWS_TO"],
            "rejected_relations": [],
            "stop_nodes": [],
        },
        "boundary_events": deepcopy(boundary_events or []),
        "search_coverage": search_coverage,
        "complete_supported_search": complete_supported_search,
        "start_node_found": start_node_found,
        "target_node_found": target_node_found,
        "query_validity": True,
        "input_resolution": input_resolution,
        "rejected_relations": [],
        "encountered_partial_evidence": encountered_partial_evidence,
        "encountered_unknown_evidence": encountered_unknown_evidence,
        "encountered_may_evidence": encountered_may_evidence,
    }


def _claim(kind: DataFlowClaimKind = DataFlowClaimKind.CAN_FLOW_TO) -> DataFlowClaim:
    return DataFlowClaim(kind=kind, start="A", target="C")


def _codes(report) -> set[str]:
    return {issue.code for issue in report.issues}


def test_exact_proven_complete_path_passes_can_flow_to_with_exact_dependencies():
    ab = _evidence("A", "B")
    bc = _evidence("B", "C")
    report = verify_data_flow_claim(_claim(), _result([_path(ab, bc)]))

    assert report.verdict is VerificationVerdict.PASS
    assert report.verifier == DATA_FLOW_VERIFIER
    assert report.evidence_ids == tuple(sorted((ab["key"], bc["key"])))
    assert report.metadata["selected_path_identity"] == [ab["key"], bc["key"]]
    assert report.metadata["graphify"]["complete_supported_search"] is True


def test_may_path_is_unknown():
    ab = _evidence("A", "C", receiver_confidence="MAY")
    report = verify_data_flow_claim(
        _claim(),
        _result([_path(ab, receiver_confidence="MAY")], encountered_may_evidence=True),
    )
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "MAY_PATH" in _codes(report)


def test_partial_path_is_unknown():
    ab = _evidence("A", "C", analysis_completeness="PARTIAL")
    report = verify_data_flow_claim(
        _claim(),
        _result(
            [_path(ab, coverage="PARTIAL")],
            complete_supported_search=False,
            search_coverage="PARTIAL",
            encountered_partial_evidence=True,
        ),
    )
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "PARTIAL_PATH" in _codes(report)


def test_exact_path_can_prove_positive_claim_despite_partial_overall_search():
    exact = _evidence("A", "C")
    report = verify_data_flow_claim(
        _claim(),
        _result(
            [_path(exact)],
            complete_supported_search=False,
            search_coverage="PARTIAL",
            truncated=True,
            termination_reason="MAX_DEPTH",
        ),
    )
    assert report.verdict is VerificationVerdict.PASS
    assert report.metadata["graphify"]["search_coverage"] == "PARTIAL"
    assert report.metadata["graphify"]["complete_supported_search"] is False


def test_complete_empty_search_proves_both_positive_failure_and_negative_pass():
    result = _result([])
    positive = verify_data_flow_claim(_claim(), result)
    negative = verify_data_flow_claim(_claim(DataFlowClaimKind.NO_SUPPORTED_PATH), result)

    assert positive.verdict is VerificationVerdict.FAIL
    assert negative.verdict is VerificationVerdict.PASS
    assert positive.evidence_ids == negative.evidence_ids == ()


def test_truncated_empty_search_keeps_both_absence_dependent_claims_unknown():
    result = _result(
        [],
        complete_supported_search=False,
        search_coverage="PARTIAL",
        truncated=True,
        termination_reason="MAX_PATHS",
    )
    assert verify_data_flow_claim(_claim(), result).verdict is VerificationVerdict.UNKNOWN
    assert verify_data_flow_claim(
        _claim(DataFlowClaimKind.NO_SUPPORTED_PATH), result
    ).verdict is VerificationVerdict.UNKNOWN


def test_missing_start_is_unknown():
    result = _result(
        [],
        complete_supported_search=False,
        search_coverage="UNKNOWN",
        termination_reason="START_NODE_NOT_FOUND",
        input_resolution="START_NODE_NOT_FOUND",
        start_node_found=False,
        target_node_found=True,
    )
    report = verify_data_flow_claim(_claim(), result)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "START_NODE_NOT_FOUND" in _codes(report)


def test_missing_target_is_unknown():
    result = _result(
        [],
        complete_supported_search=False,
        search_coverage="UNKNOWN",
        termination_reason="TARGET_NODE_NOT_FOUND",
        input_resolution="TARGET_NODE_NOT_FOUND",
        target_node_found=False,
    )
    report = verify_data_flow_claim(_claim(), result)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "TARGET_NODE_NOT_FOUND" in _codes(report)


def test_blocking_boundary_prevents_absence_proof_and_is_exposed_as_evidence():
    boundary = {
        "type": "boundary_event",
        "boundary_evidence_key": "bnd:ambiguous-call",
        "diagnostic_evidence_key": "diag:42",
        "resolution": "AMBIGUOUS",
        "reason": "overload ambiguity",
        "canonical_caller_file": "src/Flow.java",
        "caller_location": "L42",
    }
    result = _result(
        [],
        complete_supported_search=False,
        search_coverage="PARTIAL",
        boundary_events=[boundary],
    )
    report = verify_data_flow_claim(_claim(DataFlowClaimKind.NO_SUPPORTED_PATH), result)
    ingested = ingest_traversal_result(result)

    assert report.verdict is VerificationVerdict.UNKNOWN
    assert report.evidence_ids == ("bnd:ambiguous-call",)
    assert "BLOCKING_BOUNDARY" in _codes(report)
    assert [item.id for item in ingested.boundary_evidence] == ["bnd:ambiguous-call"]
    assert [item.id for item in ingested.evidence] == list(report.evidence_ids)


def test_unsupported_relation_inside_fake_path_is_rejected():
    fake = _evidence("A", "C", relation="CALLS")
    report = verify_data_flow_claim(_claim(), _result([_path(fake)]))
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "UNSUPPORTED_PATH_RELATION" in _codes(report)


def test_missing_duplicate_or_empty_evidence_keys_fail_closed():
    missing = _evidence("A", "C")
    missing.pop("key")
    duplicate_1 = _evidence("A", "B", location="L1")
    duplicate_2 = _evidence("B", "C", location="L2")
    duplicate_2["key"] = duplicate_1["key"]

    for path in (_path(missing), _path(duplicate_1, duplicate_2)):
        report = verify_data_flow_claim(_claim(), _result([path]))
        assert report.verdict is VerificationVerdict.UNKNOWN
        assert "INVALID_EVIDENCE_KEY" in _codes(report)


def test_complete_search_cannot_contradict_truncation():
    result = _result([], truncated=True, termination_reason="MAX_EXPANSIONS")
    report = verify_data_flow_claim(_claim(DataFlowClaimKind.NO_SUPPORTED_PATH), result)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "CONTRADICTORY_TRAVERSAL" in _codes(report)


def test_path_proven_cannot_override_may_direct_evidence():
    may = _evidence("A", "C", receiver_confidence="MAY")
    report = verify_data_flow_claim(_claim(), _result([_path(may)]))
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "EVIDENCE_CONFIDENCE_CONTRADICTION" in _codes(report)


def test_path_complete_cannot_override_partial_direct_evidence():
    partial = _evidence("A", "C", analysis_completeness="PARTIAL")
    report = verify_data_flow_claim(_claim(), _result([_path(partial)]))
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "EVIDENCE_COMPLETENESS_CONTRADICTION" in _codes(report)


def test_output_is_deterministic_under_reordered_paths_and_boundaries():
    path_b = _path(_evidence("A", "B", location="B1"), _evidence("B", "C", location="B2"))
    path_d = _path(_evidence("A", "D", location="D1"), _evidence("D", "C", location="D2"))
    boundary_a = {"boundary_evidence_key": "bnd:a", "resolution": "UNRESOLVED"}
    boundary_z = {"boundary_evidence_key": "bnd:z", "resolution": "UNSUPPORTED"}
    first = _result(
        [path_b, path_d],
        complete_supported_search=False,
        search_coverage="PARTIAL",
        boundary_events=[boundary_z, boundary_a],
    )
    second = _result(
        [path_d, path_b],
        complete_supported_search=False,
        search_coverage="PARTIAL",
        boundary_events=[boundary_a, boundary_z],
    )
    assert verify_data_flow_claim(_claim(), first) == verify_data_flow_claim(_claim(), second)


def test_multiple_may_paths_do_not_aggregate_into_truth():
    path_b = _path(_evidence("A", "C", receiver_confidence="MAY", location="B"), receiver_confidence="MAY")
    path_d = _path(_evidence("A", "C", receiver_confidence="MAY", location="D"), receiver_confidence="MAY")
    report = verify_data_flow_claim(
        _claim(), _result([path_b, path_d], encountered_may_evidence=True)
    )
    assert report.verdict is VerificationVerdict.UNKNOWN


def test_empty_search_with_encountered_may_evidence_cannot_prove_absence():
    result = _result([], encountered_may_evidence=True)
    assert verify_data_flow_claim(_claim(), result).verdict is VerificationVerdict.UNKNOWN
    assert verify_data_flow_claim(
        _claim(DataFlowClaimKind.NO_SUPPORTED_PATH), result
    ).verdict is VerificationVerdict.UNKNOWN


def test_non_boolean_epistemic_flags_fail_closed():
    result = _result([])
    result["encountered_partial_evidence"] = "false"
    report = verify_data_flow_claim(_claim(DataFlowClaimKind.NO_SUPPORTED_PATH), result)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "MALFORMED_TRAVERSAL" in _codes(report)


def test_malformed_query_bounds_cannot_support_absence():
    result = _result([])
    result["query_bounds"]["max_depth"] = "4"
    report = verify_data_flow_claim(_claim(DataFlowClaimKind.NO_SUPPORTED_PATH), result)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "MALFORMED_TRAVERSAL" in _codes(report)


def test_invalid_requested_effective_rejected_relation_partition_fails_closed():
    result = _result([])
    result["query_bounds"]["effective_allowed_relations"] = []
    report = verify_data_flow_claim(_claim(DataFlowClaimKind.NO_SUPPORTED_PATH), result)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "CONTRADICTORY_TRAVERSAL" in _codes(report)


def test_false_incomplete_flag_with_otherwise_complete_search_fails_closed():
    exact = _evidence("A", "C")
    result = _result(
        [_path(exact)],
        complete_supported_search=False,
        search_coverage=COMPLETE,
    )
    report = verify_data_flow_claim(_claim(), result)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "CONTRADICTORY_TRAVERSAL" in _codes(report)


def test_returned_path_cannot_coexist_with_zero_traversal_accounting():
    exact = _evidence("A", "C")
    result = _result([_path(exact)])
    result["visited_count"] = 0
    result["expanded_count"] = 0
    report = verify_data_flow_claim(_claim(), result)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "CONTRADICTORY_TRAVERSAL" in _codes(report)


def test_path_relation_must_be_in_the_effective_query_allowlist():
    returned = _evidence("A", "C", relation="RETURNED_AS")
    result = _result([_path(returned)])
    report = verify_data_flow_claim(_claim(), result)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "CONTRADICTORY_TRAVERSAL" in _codes(report)


def test_boundary_requires_its_portable_boundary_evidence_key():
    result = _result(
        [],
        complete_supported_search=False,
        search_coverage="PARTIAL",
        boundary_events=[{
            "diagnostic_evidence_key": "diag:42",
            "resolution": "AMBIGUOUS",
        }],
    )
    report = verify_data_flow_claim(_claim(DataFlowClaimKind.NO_SUPPORTED_PATH), result)
    assert report.verdict is VerificationVerdict.UNKNOWN
    assert "MALFORMED_TRAVERSAL" in _codes(report)


def test_no_supported_path_fails_when_proven_path_exists():
    exact = _evidence("A", "C")
    report = verify_data_flow_claim(
        _claim(DataFlowClaimKind.NO_SUPPORTED_PATH), _result([_path(exact)])
    )
    assert report.verdict is VerificationVerdict.FAIL
    assert report.evidence_ids == (exact["key"],)


def test_library_api_normalizes_a_valid_string_claim_kind():
    exact = _evidence("A", "C")
    claim = DataFlowClaim(kind="CAN_FLOW_TO", start="A", target="C")  # type: ignore[arg-type]
    assert verify_data_flow_claim(claim, _result([_path(exact)])).verdict is VerificationVerdict.PASS


def test_positive_claim_recorded_in_ledger_becomes_stale_after_evidence_mutation_or_removal():
    exact = _evidence("A", "C")
    result = _result([_path(exact)])
    report = verify_data_flow_claim(_claim(), result)
    evidence = ingest_traversal_result(result).evidence

    for mutate in ("replace", "remove"):
        ledger = ClaimLedger()
        ledger.define(ClaimDefinition("flow", "A can flow to C", DATA_FLOW_VERIFIER))
        for item in evidence:
            ledger.put_evidence(item.id, item.payload)
        ledger.record_verification("flow", report)
        assert ledger.status("flow").effective_verdict is VerificationVerdict.PASS
        if mutate == "replace":
            ledger.put_evidence(exact["key"], {"changed": True})
        else:
            ledger.remove_evidence(exact["key"])
        status = ledger.status("flow")
        assert status.freshness is Freshness.STALE
        assert status.effective_verdict is VerificationVerdict.UNKNOWN


def test_version_1_wire_operation_preserves_auditable_fields():
    exact = _evidence("A", "C")
    out = handle_request({
        "schema_version": 1,
        "op": "verify_data_flow_claim",
        "payload": {
            "claim_kind": "CAN_FLOW_TO",
            "start": "A",
            "target": "C",
            "traversal_result": _result([_path(exact)]),
        },
    })

    assert out["kind"] == "data_flow_claim_verification"
    report = out["payload"]
    assert report["verdict"] == "PASS"
    assert report["verifier"] == DATA_FLOW_VERIFIER
    assert report["evidence_ids"] == [exact["key"]]
    assert report["metadata"]["claim_kind"] == "CAN_FLOW_TO"
    assert report["metadata"]["start"] == "A"
    assert report["metadata"]["target"] == "C"
    assert report["metadata"]["graphify"]["termination_reason"] == "COMPLETE"
    assert report["metadata"]["graphify"]["search_coverage"] == COMPLETE
    assert report["metadata"]["graphify"]["complete_supported_search"] is True
