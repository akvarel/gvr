from __future__ import annotations

import hashlib
import json
from copy import deepcopy

import pytest

from gvr import (
    DATA_FLOW_VERIFIER,
    VERIFICATION_BUNDLE_KIND,
    VERIFICATION_BUNDLE_SCHEMA_VERSION,
    BundleValidationError,
    ClaimDefinition,
    ClaimLedger,
    DataFlowClaim,
    DataFlowClaimKind,
    Evidence,
    Freshness,
    VerificationBundle,
    VerificationIssue,
    VerificationReport,
    VerificationVerdict,
    build_verification_bundle,
    handle_request,
    safe_handle_request,
    verify_data_flow_claim_bundle,
)


COMPLETE = "COMPLETE_FOR_SUPPORTED_CONSTRUCT"
FULL_RELATIONS = (
    "FLOWS_TO",
    "PASSED_AS_ARGUMENT",
    "READ_FROM",
    "RETURNED_AS",
    "TRANSFORMED_BY",
    "WRITTEN_TO",
)


def _key(item: dict[str, object]) -> str:
    fields: list[tuple[str, str]] = [
        ("r", str(item.get("relation") or "")),
        ("s", str(item.get("source") or "")),
        ("t", str(item.get("target") or "")),
        ("f", str(item.get("source_file") or "")),
        ("l", str(item.get("source_location") or "")),
        ("p", str(item.get("provenance") or "")),
    ]
    canonical = json.dumps(sorted(fields), sort_keys=True, separators=(",", ":"))
    return "df:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _direct(
    source: str,
    target: str,
    *,
    location: str | None = None,
) -> dict[str, object]:
    item: dict[str, object] = {
        "relation": "FLOWS_TO",
        "source": source,
        "target": target,
        "source_file": "src/Flow.java",
        "source_location": location or f"{source}->{target}",
        "provenance": "STATIC_AST",
        "confidence_score": 1.0,
        "argument_index": None,
        "receiver_confidence": "PROVEN",
        "analysis_completeness": COMPLETE,
    }
    item["key"] = _key(item)
    return item


def _path(*items: dict[str, object]) -> dict[str, object]:
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
        "path_identity": [item["key"] for item in items],
        "path_exactness": "EXACT_FOR_RETURNED_PATH",
        "path_receiver_confidence": "PROVEN",
        "path_coverage": COMPLETE,
    }


def _result(
    paths: list[dict[str, object]],
    *,
    start: str = "A",
    target: str = "C",
    complete_supported_search: bool = True,
    search_coverage: str = COMPLETE,
    boundary_events: list[dict[str, object]] | None = None,
    max_depth: int = 4,
) -> dict[str, object]:
    expanded_count = sum(len(path["steps"]) for path in paths)
    return {
        "paths": deepcopy(paths),
        "start": start,
        "target": target,
        "direction": "FORWARD",
        "visited_count": 1 + expanded_count,
        "expanded_count": expanded_count,
        "truncated": False,
        "termination_reason": "COMPLETE",
        "query_bounds": {
            "direction": "FORWARD",
            "max_depth": max_depth,
            "max_paths": 50,
            "max_expansions": 2000,
            "requested_allowed_relations": list(FULL_RELATIONS),
            "effective_allowed_relations": list(FULL_RELATIONS),
            "rejected_relations": [],
            "stop_nodes": [],
        },
        "boundary_events": deepcopy(boundary_events or []),
        "search_coverage": search_coverage,
        "complete_supported_search": complete_supported_search,
        "start_node_found": True,
        "target_node_found": True,
        "query_validity": True,
        "input_resolution": "RESOLVED",
        "rejected_relations": [],
        "encountered_partial_evidence": False,
        "encountered_unknown_evidence": False,
        "encountered_may_evidence": False,
    }


def _claim(
    kind: DataFlowClaimKind = DataFlowClaimKind.CAN_FLOW_TO,
    *,
    start: str = "A",
    target: str = "C",
    source_context: str | None = "rev1",
) -> DataFlowClaim:
    return DataFlowClaim(
        kind,
        start,
        target,
        evidence_namespace="bundle-tests",
        source_context=source_context,
    )


def _report(
    *,
    verdict: VerificationVerdict = VerificationVerdict.PASS,
    verifier: str = "v",
    evidence_ids: tuple[str, ...] = (),
    issues: tuple[VerificationIssue, ...] = (),
    metadata: dict[str, object] | None = None,
) -> VerificationReport:
    return VerificationReport(
        verdict=verdict,
        verifier=verifier,
        issues=issues,
        evidence_ids=evidence_ids,
        metadata={} if metadata is None else metadata,
    )


def _evidence(
    evidence_id: str,
    payload: dict[str, object],
    *,
    kind: str = "test.evidence",
    source: str | None = None,
    fingerprint: str | None = None,
) -> Evidence:
    return Evidence(evidence_id, kind, payload, source, fingerprint)


def test_positive_path_bundle_contains_only_selected_direct_dependencies():
    first = _direct("A", "B")
    second = _direct("B", "C")
    result = _result([_path(first, second)])

    bundle = verify_data_flow_claim_bundle(_claim(), result)

    assert bundle.report.verdict is VerificationVerdict.PASS
    assert tuple(item.id for item in bundle.evidence) == bundle.report.evidence_ids
    assert set(bundle.report.metadata["selected_path_identity"]) < set(bundle.report.evidence_ids)
    assert bundle.report.metadata["query_evidence_id"] in bundle.report.evidence_ids


def test_two_qualifying_paths_bundle_only_the_canonical_selected_path():
    path_b = _path(_direct("A", "B", location="B1"), _direct("B", "C", location="B2"))
    path_d = _path(_direct("A", "D", location="D1"), _direct("D", "C", location="D2"))

    bundle = verify_data_flow_claim_bundle(_claim(), _result([path_d, path_b]))

    selected = tuple(bundle.report.metadata["selected_path_identity"])
    all_ids = {item["key"] for path in (path_b, path_d) for item in path["supporting_evidence"]}
    assert set(bundle.report.evidence_ids) == set(selected) | {bundle.report.metadata["query_evidence_id"]}
    assert {item.id for item in bundle.evidence} == set(selected) | {bundle.report.metadata["query_evidence_id"]}
    assert all_ids - set(selected)
    assert not (all_ids - set(selected)) & {item.id for item in bundle.evidence}


def test_complete_empty_search_bundle_contains_exactly_query_result_evidence():
    bundle = verify_data_flow_claim_bundle(
        _claim(DataFlowClaimKind.NO_SUPPORTED_PATH),
        _result([]),
    )

    assert bundle.report.verdict is VerificationVerdict.PASS
    assert len(bundle.evidence) == 1
    assert bundle.evidence[0].id.startswith("gvrq:")
    assert bundle.report.evidence_ids == (bundle.evidence[0].id,)


def test_zero_step_identity_bundle_contains_query_result_evidence_not_direct_edge():
    bundle = verify_data_flow_claim_bundle(
        _claim(start="A", target="A"),
        _result([_path()], start="A", target="A", max_depth=0),
    )

    assert bundle.report.verdict is VerificationVerdict.PASS
    assert all(item.id.startswith("gvrq:") for item in bundle.evidence)
    assert not any(item.id.startswith("df:") for item in bundle.evidence)


def test_boundary_unknown_bundle_contains_exact_boundary_evidence():
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

    bundle = verify_data_flow_claim_bundle(
        _claim(DataFlowClaimKind.NO_SUPPORTED_PATH),
        result,
    )

    assert bundle.report.verdict is VerificationVerdict.UNKNOWN
    assert set(bundle.report.evidence_ids) == {"bnd:ambiguous-call", bundle.report.metadata["query_evidence_id"]}
    assert any(item.id == "bnd:ambiguous-call" for item in bundle.evidence)
    assert any(item.id == bundle.report.metadata["query_evidence_id"] for item in bundle.evidence)


def test_data_flow_bundle_rejects_conflicting_boundary_records_with_one_id():
    first = {
        "boundary_evidence_key": "bnd:shared",
        "resolution": "AMBIGUOUS",
        "reason": "first",
    }
    second = {
        "boundary_evidence_key": "bnd:shared",
        "resolution": "UNRESOLVED",
        "reason": "second",
    }
    result = _result(
        [],
        complete_supported_search=False,
        search_coverage="PARTIAL",
        boundary_events=[first, second],
    )

    with pytest.raises(BundleValidationError, match="conflicting Graphify evidence"):
        verify_data_flow_claim_bundle(
            _claim(DataFlowClaimKind.NO_SUPPORTED_PATH),
            result,
        )


def test_unknown_without_dependencies_has_explicit_deterministic_empty_manifest():
    result = _result([], complete_supported_search=False, search_coverage="PARTIAL")
    first = verify_data_flow_claim_bundle(_claim(), result)
    second = verify_data_flow_claim_bundle(_claim(), deepcopy(result))

    assert first.report.verdict is VerificationVerdict.UNKNOWN
    assert first.report.evidence_ids == (first.report.metadata["query_evidence_id"],)
    assert tuple(item.id for item in first.evidence) == first.report.evidence_ids
    assert first.fingerprint == second.fingerprint


def test_missing_report_dependency_is_rejected():
    with pytest.raises(BundleValidationError, match="missing evidence"):
        build_verification_bundle(_report(evidence_ids=("E",)), ())


def test_duplicate_evidence_id_with_different_semantics_is_rejected():
    report = _report(evidence_ids=("E",))
    with pytest.raises(BundleValidationError, match="conflicting evidence"):
        build_verification_bundle(
            report,
            (_evidence("E", {"x": 1}), _evidence("E", {"x": 2})),
        )


def test_duplicate_evidence_id_with_identical_semantics_is_deduplicated():
    report = _report(evidence_ids=("E",))
    evidence = _evidence("E", {"x": 1})

    bundle = build_verification_bundle(report, (evidence, deepcopy(evidence)))

    assert bundle.evidence == (evidence,)


def test_unreferenced_extra_evidence_is_rejected():
    with pytest.raises(BundleValidationError, match="unreferenced evidence"):
        build_verification_bundle(
            _report(evidence_ids=("E1",)),
            (_evidence("E1", {"x": 1}), _evidence("E2", {"x": 2})),
        )


def test_issue_evidence_must_be_a_report_dependency():
    issue = VerificationIssue(
        code="BLOCKED",
        message="blocked",
        verdict=VerificationVerdict.UNKNOWN,
        evidence_ids=("E2",),
    )
    with pytest.raises(BundleValidationError, match="issue evidence"):
        build_verification_bundle(
            _report(
                verdict=VerificationVerdict.UNKNOWN,
                evidence_ids=("E1",),
                issues=(issue,),
            ),
            (_evidence("E1", {"x": 1}),),
        )


def test_reordered_evidence_input_has_identical_bundle_and_fingerprint():
    report = _report(evidence_ids=("E1", "E2"))
    first = build_verification_bundle(
        report,
        (_evidence("E1", {"x": 1}), _evidence("E2", {"x": 2})),
    )
    second = build_verification_bundle(
        report,
        (_evidence("E2", {"x": 2}), _evidence("E1", {"x": 1})),
    )

    assert first == second
    assert first.fingerprint == second.fingerprint
    assert tuple(item.id for item in first.evidence) == ("E1", "E2")


def test_reordered_mapping_keys_have_identical_bundle_fingerprint():
    first = build_verification_bundle(
        _report(evidence_ids=("E",), metadata={"a": 1, "b": {"x": 2, "y": 3}}),
        (_evidence("E", {"a": 1, "b": {"x": 2, "y": 3}}),),
    )
    second = build_verification_bundle(
        _report(evidence_ids=("E",), metadata={"b": {"y": 3, "x": 2}, "a": 1}),
        (_evidence("E", {"b": {"y": 3, "x": 2}, "a": 1}),),
    )

    assert first.fingerprint == second.fingerprint


def test_bundle_snapshots_and_freezes_report_and_evidence_semantic_content():
    metadata = {"nested": {"value": 1}}
    payload = {"nested": {"value": 1}}
    bundle = build_verification_bundle(
        _report(evidence_ids=("E",), metadata=metadata),
        (_evidence("E", payload),),
    )
    fingerprint = bundle.fingerprint

    metadata["nested"]["value"] = 2
    payload["nested"]["value"] = 2

    assert bundle.report.metadata["nested"]["value"] == 1
    assert bundle.evidence[0].payload["nested"]["value"] == 1
    assert bundle.fingerprint == fingerprint
    with pytest.raises(TypeError):
        bundle.report.metadata["nested"]["value"] = 3
    with pytest.raises(TypeError):
        bundle.evidence[0].payload["nested"]["value"] = 3


def test_semantic_report_or_evidence_changes_change_bundle_fingerprint():
    base = build_verification_bundle(
        _report(evidence_ids=("E",)),
        (_evidence("E", {"x": 1}),),
    )
    payload_changed = build_verification_bundle(
        _report(evidence_ids=("E",)),
        (_evidence("E", {"x": 2}),),
    )
    verdict_changed = build_verification_bundle(
        _report(verdict=VerificationVerdict.FAIL, evidence_ids=("E",)),
        (_evidence("E", {"x": 1}),),
    )
    verifier_changed = build_verification_bundle(
        _report(verifier="v2", evidence_ids=("E",)),
        (_evidence("E", {"x": 1}),),
    )
    issue_changed = build_verification_bundle(
        _report(
            verdict=VerificationVerdict.UNKNOWN,
            evidence_ids=("E",),
            issues=(VerificationIssue("X", "x", VerificationVerdict.UNKNOWN, ("E",)),),
        ),
        (_evidence("E", {"x": 1}),),
    )

    assert len({
        base.fingerprint,
        payload_changed.fingerprint,
        verdict_changed.fingerprint,
        verifier_changed.fingerprint,
        issue_changed.fingerprint,
    }) == 5


def test_dependency_id_changes_change_bundle_fingerprint():
    report = _report()
    first = build_verification_bundle(report, (), claim_dependency_ids=("C1",))
    second = build_verification_bundle(report, (), claim_dependency_ids=("C2",))

    assert first.fingerprint != second.fingerprint


def test_bundle_exposes_version_kind_verifier_and_sha256_identity():
    bundle = build_verification_bundle(_report(), ())

    assert bundle.schema_version == VERIFICATION_BUNDLE_SCHEMA_VERSION == 1
    assert bundle.kind == VERIFICATION_BUNDLE_KIND
    assert bundle.verifier == bundle.report.verifier
    assert len(bundle.fingerprint) == 64
    int(bundle.fingerprint, 16)


def test_claim_ledger_records_a_valid_bundle_atomically_and_fresh():
    bundle = verify_data_flow_claim_bundle(_claim(), _result([_path(_direct("A", "C"))]))
    ledger = ClaimLedger()
    ledger.define(ClaimDefinition("flow", "A flows to C", DATA_FLOW_VERIFIER))

    snapshot = ledger.record_bundle("flow", bundle)

    assert snapshot.report == bundle.report
    assert snapshot.evidence_ids == bundle.report.evidence_ids
    assert ledger.status("flow").effective_verdict is VerificationVerdict.PASS
    assert ledger.status("flow").freshness is Freshness.FRESH
    assert set(ledger.dependencies.evidence) == set(bundle.report.evidence_ids)


def _semantic_bundle(
    *,
    kind: str = "provider.kind.v1",
    payload: dict[str, object] | None = None,
    source: str = "revision-A",
    producer_fingerprint: str = "producer-fp-A",
    claim_dependency_ids: tuple[str, ...] = (),
):
    evidence = _evidence(
        "E",
        {"value": 1} if payload is None else payload,
        kind=kind,
        source=source,
        fingerprint=producer_fingerprint,
    )
    return build_verification_bundle(
        _report(evidence_ids=("E",)),
        (evidence,),
        claim_dependency_ids=claim_dependency_ids,
    )


def _recorded_semantic_bundle():
    bundle = _semantic_bundle()
    ledger = ClaimLedger()
    ledger.define(ClaimDefinition("C", "semantic evidence claim", "v"))
    ledger.record_bundle("C", bundle)
    return ledger, bundle


def test_source_only_evidence_change_versions_and_stales_bundle_claim():
    ledger, bundle = _recorded_semantic_bundle()
    before = ledger.dependencies.evidence["E"]
    changed = Evidence(
        id="E",
        kind=bundle.evidence[0].kind,
        payload=bundle.evidence[0].payload,
        source="revision-B",
        fingerprint=bundle.evidence[0].fingerprint,
    )

    ledger.put_evidence_record(changed)

    after = ledger.dependencies.evidence["E"]
    assert after.version != before.version
    assert after.source == "revision-B"
    assert ledger.status("C").effective_verdict is VerificationVerdict.UNKNOWN


def test_producer_fingerprint_only_change_versions_and_stales_bundle_claim():
    ledger, bundle = _recorded_semantic_bundle()
    before = ledger.dependencies.evidence["E"]
    changed = Evidence(
        id="E",
        kind=bundle.evidence[0].kind,
        payload=bundle.evidence[0].payload,
        source=bundle.evidence[0].source,
        fingerprint="producer-fp-B",
    )

    ledger.put_evidence_record(changed)

    after = ledger.dependencies.evidence["E"]
    assert after.version != before.version
    assert after.producer_fingerprint == "producer-fp-B"
    assert ledger.status("C").effective_verdict is VerificationVerdict.UNKNOWN


def test_kind_only_change_versions_and_stales_bundle_claim():
    ledger, bundle = _recorded_semantic_bundle()
    before = ledger.dependencies.evidence["E"]
    changed = Evidence(
        id="E",
        kind="provider.kind.v2",
        payload=bundle.evidence[0].payload,
        source=bundle.evidence[0].source,
        fingerprint=bundle.evidence[0].fingerprint,
    )

    ledger.put_evidence_record(changed)

    after = ledger.dependencies.evidence["E"]
    assert after.version != before.version
    assert after.kind == "provider.kind.v2"
    assert ledger.status("C").effective_verdict is VerificationVerdict.UNKNOWN


def test_bundle_recording_retains_the_exact_full_evidence_record():
    ledger, bundle = _recorded_semantic_bundle()

    stored = ledger.dependencies.evidence["E"]
    expected = bundle.evidence[0]
    assert stored.id == expected.id
    assert stored.kind == expected.kind
    assert stored.payload == expected.payload
    assert stored.source == expected.source
    assert stored.producer_fingerprint == expected.fingerprint


def test_semantic_mapping_reordering_is_an_evidence_version_noop():
    ledger, bundle = _recorded_semantic_bundle()
    before = ledger.dependencies.evidence["E"]
    reordered = Evidence(
        id="E",
        kind=bundle.evidence[0].kind,
        payload={"nested": {"b": 2, "a": 1}, "value": 1},
        source=bundle.evidence[0].source,
        fingerprint=bundle.evidence[0].fingerprint,
    )
    baseline = Evidence(
        id="E",
        kind=bundle.evidence[0].kind,
        payload={"value": 1, "nested": {"a": 1, "b": 2}},
        source=bundle.evidence[0].source,
        fingerprint=bundle.evidence[0].fingerprint,
    )
    ledger.put_evidence_record(baseline)
    changed_once = ledger.dependencies.evidence["E"]

    ledger.put_evidence_record(reordered)

    assert ledger.dependencies.evidence["E"].version == changed_once.version
    assert changed_once.version != before.version


def test_changed_bundle_evidence_basis_reversions_upstream_and_stales_downstream():
    first = _semantic_bundle()
    changed = _semantic_bundle(
        source="revision-B",
        producer_fingerprint="producer-fp-B",
    )
    ledger = ClaimLedger()
    ledger.define(ClaimDefinition("A", "upstream", "v"))
    ledger.define(ClaimDefinition("B", "downstream", "v"))
    ledger.record_bundle("A", first)
    downstream = build_verification_bundle(
        _report(),
        (),
        claim_dependency_ids=("A",),
    )
    ledger.record_bundle("B", downstream)
    upstream_version = ledger.status("A").version

    ledger.record_bundle("A", changed)

    assert ledger.status("A").freshness is Freshness.FRESH
    assert ledger.status("A").version != upstream_version
    assert ledger.status("B").freshness is Freshness.STALE
    assert ledger.status("B").effective_verdict is VerificationVerdict.UNKNOWN


def test_semantically_identical_bundle_rerecord_is_noop_for_downstream():
    first = _semantic_bundle(payload={"value": 1, "nested": {"a": 1, "b": 2}})
    reordered = _semantic_bundle(payload={"nested": {"b": 2, "a": 1}, "value": 1})
    ledger = ClaimLedger()
    ledger.define(ClaimDefinition("A", "upstream", "v"))
    ledger.define(ClaimDefinition("B", "downstream", "v"))
    ledger.record_bundle("A", first)
    ledger.record_bundle(
        "B",
        build_verification_bundle(_report(), (), claim_dependency_ids=("A",)),
    )
    evidence_version = ledger.dependencies.evidence["E"].version
    upstream_version = ledger.status("A").version

    ledger.record_bundle("A", reordered)

    assert ledger.dependencies.evidence["E"].version == evidence_version
    assert ledger.status("A").version == upstream_version
    assert ledger.status("B").freshness is Freshness.FRESH


def test_replacing_query_result_payload_stales_a_bundle_recorded_claim():
    first = verify_data_flow_claim_bundle(
        _claim(DataFlowClaimKind.NO_SUPPORTED_PATH),
        _result([]),
    )
    changed = verify_data_flow_claim_bundle(
        _claim(DataFlowClaimKind.NO_SUPPORTED_PATH, source_context="rev2"),
        _result([]),
    )
    ledger = ClaimLedger()
    ledger.define(ClaimDefinition("no-flow", "No path", DATA_FLOW_VERIFIER))
    ledger.record_bundle("no-flow", first)

    assert first.evidence[0].id == changed.evidence[0].id
    assert first.evidence[0].payload != changed.evidence[0].payload
    ledger.put_evidence(changed.evidence[0].id, changed.evidence[0].payload)

    assert ledger.status("no-flow").effective_verdict is VerificationVerdict.UNKNOWN
    assert ledger.status("no-flow").freshness is Freshness.STALE


def test_reverification_from_a_replacement_bundle_restores_freshness():
    first = verify_data_flow_claim_bundle(
        _claim(DataFlowClaimKind.NO_SUPPORTED_PATH),
        _result([]),
    )
    changed = verify_data_flow_claim_bundle(
        _claim(DataFlowClaimKind.NO_SUPPORTED_PATH, source_context="rev2"),
        _result([]),
    )
    ledger = ClaimLedger()
    ledger.define(ClaimDefinition("no-flow", "No path", DATA_FLOW_VERIFIER))
    ledger.record_bundle("no-flow", first)

    ledger.record_bundle("no-flow", changed)

    assert ledger.status("no-flow").effective_verdict is VerificationVerdict.PASS
    assert ledger.status("no-flow").freshness is Freshness.FRESH
    assert len(ledger.history("no-flow")) == 2


def test_replacing_direct_payload_stales_a_bundle_recorded_claim():
    bundle = verify_data_flow_claim_bundle(_claim(), _result([_path(_direct("A", "C"))]))
    ledger = ClaimLedger()
    ledger.define(ClaimDefinition("flow", "A flows to C", DATA_FLOW_VERIFIER))
    ledger.record_bundle("flow", bundle)
    direct = bundle.evidence[0]
    changed_payload = dict(direct.payload)
    changed_payload["confidence_score"] = 0.5

    ledger.put_evidence(direct.id, changed_payload)

    assert ledger.status("flow").effective_verdict is VerificationVerdict.UNKNOWN


def test_removing_bundle_evidence_stales_the_recorded_claim():
    bundle = verify_data_flow_claim_bundle(_claim(), _result([_path(_direct("A", "C"))]))
    ledger = ClaimLedger()
    ledger.define(ClaimDefinition("flow", "A flows to C", DATA_FLOW_VERIFIER))
    ledger.record_bundle("flow", bundle)

    ledger.remove_evidence(bundle.evidence[0].id)

    assert ledger.status("flow").effective_verdict is VerificationVerdict.UNKNOWN
    assert ledger.status("flow").freshness is Freshness.STALE


def test_bundle_claim_dependencies_preserve_transitive_stale_propagation():
    ledger = ClaimLedger()
    ledger.define(ClaimDefinition("source", "source claim", "v"))
    ledger.define(ClaimDefinition("derived", "derived claim", "v"))
    ledger.put_evidence("E", {"value": 1})
    ledger.record_verification(
        "source",
        _report(evidence_ids=("E",)),
    )
    bundle = build_verification_bundle(
        _report(),
        (),
        claim_dependency_ids=("source",),
    )
    ledger.record_bundle("derived", bundle)

    ledger.put_evidence("E", {"value": 2})

    assert ledger.status("source").effective_verdict is VerificationVerdict.UNKNOWN
    assert ledger.status("derived").effective_verdict is VerificationVerdict.UNKNOWN


def test_failed_bundle_recording_does_not_partially_mutate_ledger():
    bundle = build_verification_bundle(
        _report(verifier="other", evidence_ids=("E",)),
        (_evidence("E", {"x": 1}),),
    )
    ledger = ClaimLedger()
    ledger.define(ClaimDefinition("C", "claim", "required"))

    with pytest.raises(ValueError, match="requires verifier"):
        ledger.record_bundle("C", bundle)

    assert "E" not in ledger.dependencies.evidence
    assert ledger.history("C") == ()
    assert ledger.status("C").effective_verdict is VerificationVerdict.UNKNOWN


def test_undefined_bundle_claim_dependency_does_not_register_evidence():
    bundle = build_verification_bundle(
        _report(evidence_ids=("E",)),
        (_evidence("E", {"x": 1}),),
        claim_dependency_ids=("missing-claim",),
    )
    ledger = ClaimLedger()
    ledger.define(ClaimDefinition("C", "claim", "v"))

    with pytest.raises(ValueError, match="undefined claim dependency"):
        ledger.record_bundle("C", bundle)

    assert "E" not in ledger.dependencies.evidence
    assert ledger.history("C") == ()


def test_existing_and_bundle_wire_operations_remain_distinct_and_compatible():
    traversal = _result([_path(_direct("A", "C"))])
    payload = {
        "claim_kind": "CAN_FLOW_TO",
        "start": "A",
        "target": "C",
        "evidence_namespace": "wire-tests",
        "source_context": "rev1",
        "traversal_result": traversal,
    }

    report_out = handle_request({
        "schema_version": 1,
        "op": "verify_data_flow_claim",
        "payload": payload,
    })
    bundle_out = handle_request({
        "schema_version": 1,
        "op": "verify_data_flow_claim_bundle",
        "payload": payload,
    })

    assert report_out["kind"] == "data_flow_claim_verification"
    assert "fingerprint" not in report_out["payload"]
    assert bundle_out["kind"] == "verification_bundle"
    assert bundle_out["payload"]["schema_version"] == 1
    assert bundle_out["payload"]["kind"] == VERIFICATION_BUNDLE_KIND
    assert bundle_out["payload"]["verifier"] == DATA_FLOW_VERIFIER
    assert bundle_out["payload"]["report"] == report_out["payload"]
    assert [item["id"] for item in bundle_out["payload"]["evidence"]] == report_out["payload"]["evidence_ids"]


def test_bundle_wire_output_is_deterministic_under_reordered_paths_and_keys():
    path_b = _path(_direct("A", "B", location="B1"), _direct("B", "C", location="B2"))
    path_d = _path(_direct("A", "D", location="D1"), _direct("D", "C", location="D2"))
    first_result = _result([path_b, path_d])
    second_result = _result([path_d, path_b])
    second_result["query_bounds"] = {
        key: second_result["query_bounds"][key]
        for key in reversed(tuple(second_result["query_bounds"]))
    }

    def request(result: dict[str, object]) -> dict[str, object]:
        return handle_request({
            "schema_version": 1,
            "op": "verify_data_flow_claim_bundle",
            "payload": {
                "claim_kind": "CAN_FLOW_TO",
                "start": "A",
                "target": "C",
                "traversal_result": result,
            },
        })

    assert request(first_result) == request(second_result)


def test_safe_bundle_wire_operation_fails_closed_on_ambiguous_evidence():
    result = _result(
        [],
        complete_supported_search=False,
        search_coverage="PARTIAL",
        boundary_events=[
            {"boundary_evidence_key": "bnd:x", "resolution": "AMBIGUOUS"},
            {"boundary_evidence_key": "bnd:x", "resolution": "UNRESOLVED"},
        ],
    )

    response = safe_handle_request({
        "schema_version": 1,
        "op": "verify_data_flow_claim_bundle",
        "payload": {
            "claim_kind": "NO_SUPPORTED_PATH",
            "start": "A",
            "target": "C",
            "traversal_result": result,
        },
    })

    assert response["kind"] == "protocol_error"
    assert response["payload"]["code"] == "INVALID_VERIFICATION_BUNDLE"
