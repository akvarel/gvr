from __future__ import annotations

from copy import deepcopy

import pytest

from gvr import (
    AtomicClaim,
    BundleValidationError,
    ClaimGraph,
    ClaimGraphValidationError,
    ClaimOperator,
    CompositeClaim,
    Evidence,
    Freshness,
    SessionBudget,
    SessionTermination,
    VerificationReport,
    VerificationSession,
    VerificationSessionError,
    VerificationVerdict,
    build_verification_bundle,
    envelope,
    handle_request,
    safe_handle_request,
)


def _atomic(
    claim_id: str,
    *,
    verifier: str = "test.verifier.v1",
    dependencies: tuple[str, ...] = (),
    spec: dict[str, object] | None = None,
    scope: dict[str, object] | None = None,
    description: str | None = None,
) -> AtomicClaim:
    return AtomicClaim(
        claim_id=claim_id,
        claim_kind="TEST_ASSERTION",
        spec={"subject": claim_id} if spec is None else spec,
        verifier=verifier,
        scope={} if scope is None else scope,
        dependencies=dependencies,
        description=description,
    )


def _composite(
    claim_id: str,
    operator: ClaimOperator,
    *dependencies: str,
) -> CompositeClaim:
    return CompositeClaim(
        claim_id=claim_id,
        operator=operator,
        dependencies=dependencies,
    )


def _bundle(
    claim_id: str,
    verdict: VerificationVerdict,
    *,
    verifier: str = "test.verifier.v1",
    value: object = 1,
    source: str = "revision-A",
    producer_fingerprint: str = "producer-A",
    claim_dependency_ids: tuple[str, ...] = (),
):
    evidence_id = f"E:{claim_id}"
    evidence = Evidence(
        evidence_id,
        "test.evidence.v1",
        {"value": value},
        source,
        producer_fingerprint,
    )
    report = VerificationReport(
        verdict=verdict,
        verifier=verifier,
        evidence_ids=(evidence_id,),
        metadata={"claim_id": claim_id},
    )
    return build_verification_bundle(
        report,
        (evidence,),
        claim_dependency_ids=claim_dependency_ids,
    )


def _graph_for(operator: ClaimOperator) -> ClaimGraph:
    return ClaimGraph(nodes=(
        _atomic("A"),
        _atomic("B"),
        _composite("ROOT", operator, "A", "B"),
    ))


def _compose_binary(
    operator: ClaimOperator,
    left: VerificationVerdict,
    right: VerificationVerdict,
) -> VerificationSession:
    return VerificationSession.compose(
        graph=_graph_for(operator),
        roots=("ROOT",),
        bundles={"A": _bundle("A", left), "B": _bundle("B", right)},
    )


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        (VerificationVerdict.PASS, VerificationVerdict.PASS, VerificationVerdict.PASS),
        (VerificationVerdict.PASS, VerificationVerdict.UNKNOWN, VerificationVerdict.UNKNOWN),
        (VerificationVerdict.PASS, VerificationVerdict.FAIL, VerificationVerdict.FAIL),
    ],
)
def test_and_uses_exact_tri_state_logic(left, right, expected):
    session = _compose_binary(ClaimOperator.AND, left, right)
    assert session.root_verdicts["ROOT"] is expected


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        (VerificationVerdict.FAIL, VerificationVerdict.FAIL, VerificationVerdict.FAIL),
        (VerificationVerdict.FAIL, VerificationVerdict.UNKNOWN, VerificationVerdict.UNKNOWN),
        (VerificationVerdict.FAIL, VerificationVerdict.PASS, VerificationVerdict.PASS),
    ],
)
def test_or_uses_exact_tri_state_logic(left, right, expected):
    session = _compose_binary(ClaimOperator.OR, left, right)
    assert session.root_verdicts["ROOT"] is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (VerificationVerdict.PASS, VerificationVerdict.FAIL),
        (VerificationVerdict.FAIL, VerificationVerdict.PASS),
        (VerificationVerdict.UNKNOWN, VerificationVerdict.UNKNOWN),
    ],
)
def test_not_uses_exact_tri_state_logic(value, expected):
    graph = ClaimGraph(nodes=(
        _atomic("A"),
        _composite("ROOT", ClaimOperator.NOT, "A"),
    ))
    session = VerificationSession.compose(
        graph=graph,
        roots=("ROOT",),
        bundles={"A": _bundle("A", value)},
    )
    assert session.root_verdicts["ROOT"] is expected


def test_nested_composite_graph_is_deterministic():
    graph = ClaimGraph(nodes=(
        _composite("ROOT", ClaimOperator.AND, "NOT_C", "A_OR_B"),
        _atomic("C"),
        _atomic("B"),
        _composite("A_OR_B", ClaimOperator.OR, "B", "A"),
        _atomic("A"),
        _composite("NOT_C", ClaimOperator.NOT, "C"),
    ))
    session = VerificationSession.compose(
        graph=graph,
        roots=("ROOT",),
        bundles={
            "C": _bundle("C", VerificationVerdict.FAIL),
            "B": _bundle("B", VerificationVerdict.FAIL),
            "A": _bundle("A", VerificationVerdict.PASS),
        },
    )
    assert session.root_verdicts["ROOT"] is VerificationVerdict.PASS
    assert tuple(state.claim_id for state in session.claim_states) == (
        "A",
        "A_OR_B",
        "B",
        "C",
        "NOT_C",
        "ROOT",
    )


def test_graph_and_session_fingerprints_ignore_input_and_dependency_order():
    first = ClaimGraph(nodes=(
        _atomic("A"),
        _atomic("B"),
        _composite("ROOT", ClaimOperator.AND, "B", "A"),
    ))
    second = ClaimGraph(nodes=(
        _composite("ROOT", ClaimOperator.AND, "A", "B"),
        _atomic("B"),
        _atomic("A"),
    ))
    first_session = VerificationSession.compose(
        graph=first,
        roots=("ROOT",),
        bundles={"B": _bundle("B", VerificationVerdict.PASS), "A": _bundle("A", VerificationVerdict.PASS)},
    )
    second_session = VerificationSession.compose(
        graph=second,
        roots=("ROOT",),
        bundles={"A": _bundle("A", VerificationVerdict.PASS), "B": _bundle("B", VerificationVerdict.PASS)},
    )
    assert first.fingerprint == second.fingerprint
    assert first_session.fingerprint == second_session.fingerprint
    assert first_session.to_dict() == second_session.to_dict()


def _incremental_session(
    *,
    graph: ClaimGraph,
    roots: tuple[str, ...],
    order: tuple[str, ...],
    bundles: dict[str, object],
) -> VerificationSession:
    session = VerificationSession(graph=graph, roots=roots)
    for claim_id in order:
        session.record_bundle(claim_id, bundles[claim_id])
    session.recompute()
    return session


def _claim_versions(session: VerificationSession) -> dict[str, int]:
    return {
        item["claim_id"]: item["version"]
        for item in session.to_dict()["claims"]
    }


def test_opposite_incremental_record_order_is_semantically_identical_for_composite_root():
    graph = _graph_for(ClaimOperator.AND)
    bundles = {
        "A": _bundle("A", VerificationVerdict.PASS),
        "B": _bundle("B", VerificationVerdict.PASS),
    }
    first = _incremental_session(
        graph=graph,
        roots=("ROOT",),
        order=("A", "B"),
        bundles=bundles,
    )
    second = _incremental_session(
        graph=graph,
        roots=("ROOT",),
        order=("B", "A"),
        bundles=bundles,
    )

    assert first.ledger.status("A").version != second.ledger.status("A").version
    assert _claim_versions(first) == {"A": 1, "B": 1, "ROOT": 1}
    assert first.claim_states == second.claim_states
    assert first.fingerprint == second.fingerprint
    assert first.to_dict() == second.to_dict()


def test_opposite_incremental_record_order_is_semantically_identical_for_independent_roots():
    graph = ClaimGraph(nodes=(_atomic("A"), _atomic("B")))
    bundles = {
        "A": _bundle("A", VerificationVerdict.PASS),
        "B": _bundle("B", VerificationVerdict.FAIL),
    }
    first = _incremental_session(
        graph=graph,
        roots=("A", "B"),
        order=("A", "B"),
        bundles=bundles,
    )
    second = _incremental_session(
        graph=graph,
        roots=("B", "A"),
        order=("B", "A"),
        bundles=bundles,
    )

    assert first.ledger.status("A").version != second.ledger.status("A").version
    assert _claim_versions(first) == {"A": 1, "B": 1}
    assert first.claim_states == second.claim_states
    assert first.fingerprint == second.fingerprint
    assert first.to_dict() == second.to_dict()


def test_opposite_semantic_noop_rerecord_order_preserves_session_identity():
    graph = _graph_for(ClaimOperator.AND)
    bundles = {
        "A": _bundle("A", VerificationVerdict.PASS),
        "B": _bundle("B", VerificationVerdict.PASS),
    }
    first = VerificationSession.compose(graph=graph, roots=("ROOT",), bundles=bundles)
    second = VerificationSession.compose(graph=graph, roots=("ROOT",), bundles=bundles)

    for claim_id in ("A", "B"):
        first.record_bundle(claim_id, deepcopy(bundles[claim_id]))
    for claim_id in ("B", "A"):
        second.record_bundle(claim_id, deepcopy(bundles[claim_id]))

    assert first.ledger.history("A")[-1].run_id != second.ledger.history("A")[-1].run_id
    assert _claim_versions(first) == {"A": 1, "B": 1, "ROOT": 1}
    assert first.claim_states == second.claim_states
    assert first.fingerprint == second.fingerprint
    assert first.to_dict() == second.to_dict()


def test_opposite_changed_evidence_order_has_one_deterministic_semantic_identity():
    graph = _graph_for(ClaimOperator.AND)
    initial = {
        "A": _bundle("A", VerificationVerdict.PASS),
        "B": _bundle("B", VerificationVerdict.PASS),
    }
    changed = {
        "A": _bundle("A", VerificationVerdict.PASS, source="revision-B"),
        "B": _bundle("B", VerificationVerdict.PASS, source="revision-B"),
    }
    first = VerificationSession.compose(graph=graph, roots=("ROOT",), bundles=initial)
    second = VerificationSession.compose(graph=graph, roots=("ROOT",), bundles=initial)

    for claim_id in ("A", "B"):
        first.record_bundle(claim_id, changed[claim_id])
    for claim_id in ("B", "A"):
        second.record_bundle(claim_id, changed[claim_id])
    first.recompute()
    second.recompute()

    assert first.ledger.status("A").version != second.ledger.status("A").version
    assert _claim_versions(first) == {"A": 2, "B": 2, "ROOT": 2}
    assert first.claim_states == second.claim_states
    assert first.fingerprint == second.fingerprint
    assert first.to_dict() == second.to_dict()


def test_opposite_stale_recompute_histories_have_deterministic_semantic_identity():
    graph = _graph_for(ClaimOperator.AND)
    initial = {
        "A": _bundle("A", VerificationVerdict.PASS),
        "B": _bundle("B", VerificationVerdict.PASS),
    }
    changed = {
        "A": _bundle("A", VerificationVerdict.PASS, source="revision-B"),
        "B": _bundle("B", VerificationVerdict.PASS, source="revision-B"),
    }
    first = VerificationSession.compose(graph=graph, roots=("ROOT",), bundles=initial)
    second = VerificationSession.compose(graph=graph, roots=("ROOT",), bundles=initial)

    for session, order in ((first, ("A", "B")), (second, ("B", "A"))):
        for claim_id in order:
            session.record_bundle(claim_id, changed[claim_id])
            assert session.claim_state("ROOT").freshness is Freshness.STALE
            session.recompute()

    assert first.ledger.status("A").version != second.ledger.status("A").version
    assert _claim_versions(first) == {"A": 2, "B": 2, "ROOT": 3}
    assert first.claim_states == second.claim_states
    assert first.fingerprint == second.fingerprint
    assert first.to_dict() == second.to_dict()


def test_existing_compose_order_contract_uses_deterministic_semantic_versions():
    graph = _graph_for(ClaimOperator.AND)
    first = VerificationSession.compose(
        graph=graph,
        roots=("ROOT",),
        bundles={
            "B": _bundle("B", VerificationVerdict.PASS),
            "A": _bundle("A", VerificationVerdict.PASS),
        },
    )
    second = VerificationSession.compose(
        graph=graph,
        roots=("ROOT",),
        bundles={
            "A": _bundle("A", VerificationVerdict.PASS),
            "B": _bundle("B", VerificationVerdict.PASS),
        },
    )

    assert _claim_versions(first) == {"A": 1, "B": 1, "ROOT": 1}
    assert first.to_dict() == second.to_dict()


def test_claim_graph_lookup_cache_and_exported_content_are_immutable():
    graph = ClaimGraph(nodes=(_atomic("A", spec={"nested": {"value": 1}}),))
    before = graph.to_dict()

    with pytest.raises(TypeError):
        graph._by_id["B"] = _atomic("B")

    exported = graph.to_dict()
    exported["nodes"][0]["spec"]["nested"]["value"] = 2
    assert graph.to_dict() == before
    assert graph.claim("A").spec["nested"]["value"] == 1


def test_description_is_not_truth_bearing_graph_identity():
    first = ClaimGraph(nodes=(_atomic("A", description="human wording A"),))
    second = ClaimGraph(nodes=(_atomic("A", description="different wording"),))
    assert first.fingerprint == second.fingerprint


def test_duplicate_id_with_different_semantics_is_rejected():
    with pytest.raises(ClaimGraphValidationError, match="duplicate"):
        ClaimGraph(nodes=(
            _atomic("A", spec={"value": 1}),
            _atomic("A", spec={"value": 2}),
        ))


def test_unknown_self_and_multi_node_dependencies_are_rejected():
    with pytest.raises(ClaimGraphValidationError, match="unknown"):
        ClaimGraph(nodes=(_composite("ROOT", ClaimOperator.NOT, "NOPE"),))
    with pytest.raises(ClaimGraphValidationError, match="self"):
        ClaimGraph(nodes=(_composite("ROOT", ClaimOperator.NOT, "ROOT"),))
    with pytest.raises(ClaimGraphValidationError, match="cycle"):
        ClaimGraph(nodes=(
            _composite("A", ClaimOperator.NOT, "B"),
            _composite("B", ClaimOperator.NOT, "A"),
        ))


def test_invalid_composite_arity_is_rejected():
    with pytest.raises(ClaimGraphValidationError, match="NOT"):
        ClaimGraph(nodes=(
            _atomic("A"),
            _atomic("B"),
            _composite("ROOT", ClaimOperator.NOT, "A", "B"),
        ))
    with pytest.raises(ClaimGraphValidationError, match="AND"):
        ClaimGraph(nodes=(_atomic("A"), _composite("ROOT", ClaimOperator.AND, "A")))


def test_claim_semantics_reject_unsupported_runtime_objects_instead_of_repr_hashing():
    with pytest.raises(ClaimGraphValidationError, match="unsupported semantic value"):
        ClaimGraph(nodes=(_atomic("A", spec={"bad": object()}),))


def test_missing_atomic_bundle_is_explicit_unknown_never_false_truth():
    session = VerificationSession.compose(
        graph=_graph_for(ClaimOperator.AND),
        roots=("ROOT",),
        bundles={"A": _bundle("A", VerificationVerdict.PASS)},
    )
    assert session.claim_state("B").effective_verdict is VerificationVerdict.UNKNOWN
    assert session.root_verdicts["ROOT"] is VerificationVerdict.UNKNOWN
    assert session.unverified_claim_ids == ("B",)
    assert session.termination_reason is SessionTermination.UNSUPPORTED_CLAIM


def test_bundle_verifier_or_claim_dependency_mismatch_fails_closed_without_mutation():
    graph = ClaimGraph(nodes=(_atomic("A"),))
    session = VerificationSession(graph=graph, roots=("A",))
    before = session.to_dict()
    with pytest.raises(VerificationSessionError, match="verifier"):
        session.record_bundle("A", _bundle("A", VerificationVerdict.PASS, verifier="wrong"))
    with pytest.raises(VerificationSessionError, match="claim dependencies"):
        session.record_bundle(
            "A",
            _bundle("A", VerificationVerdict.PASS, claim_dependency_ids=("A",)),
        )
    assert session.to_dict() == before


def test_atomic_unknown_bundle_propagates_unknown_but_is_materialized():
    session = _compose_binary(
        ClaimOperator.AND,
        VerificationVerdict.PASS,
        VerificationVerdict.UNKNOWN,
    )
    assert session.claim_state("B").bundle_fingerprint is not None
    assert session.unverified_claim_ids == ()
    assert session.root_verdicts["ROOT"] is VerificationVerdict.UNKNOWN
    assert session.termination_reason is SessionTermination.COMPLETE


def test_changed_exact_evidence_semantics_stale_then_recompute_dependent_root():
    session = _compose_binary(
        ClaimOperator.AND,
        VerificationVerdict.PASS,
        VerificationVerdict.PASS,
    )
    root_before = session.claim_state("ROOT")
    atomic_before = session.claim_state("A")

    session.record_bundle(
        "A",
        _bundle("A", VerificationVerdict.PASS, source="revision-B"),
    )

    assert session.claim_state("A").version != atomic_before.version
    assert session.claim_state("ROOT").freshness is Freshness.STALE
    assert session.root_verdicts["ROOT"] is VerificationVerdict.UNKNOWN

    session.recompute()
    assert session.root_verdicts["ROOT"] is VerificationVerdict.PASS
    assert session.claim_state("ROOT").freshness is Freshness.FRESH
    assert session.claim_state("ROOT").version != root_before.version


def test_semantically_identical_bundle_rerecord_is_downstream_noop():
    bundle_a = _bundle("A", VerificationVerdict.PASS)
    session = VerificationSession.compose(
        graph=_graph_for(ClaimOperator.AND),
        roots=("ROOT",),
        bundles={"A": bundle_a, "B": _bundle("B", VerificationVerdict.PASS)},
    )
    root_before = session.claim_state("ROOT")
    atomic_before = session.claim_state("A")

    session.record_bundle("A", deepcopy(bundle_a))

    assert session.claim_state("A").version == atomic_before.version
    assert session.claim_state("ROOT") == root_before
    assert session.root_verdicts["ROOT"] is VerificationVerdict.PASS


def test_removed_evidence_and_stale_stored_pass_cannot_compose_as_pass():
    session = _compose_binary(
        ClaimOperator.AND,
        VerificationVerdict.PASS,
        VerificationVerdict.PASS,
    )
    assert session.claim_state("A").stored_verdict is VerificationVerdict.PASS

    session.remove_evidence("E:A")
    session.recompute()

    atomic = session.claim_state("A")
    assert atomic.stored_verdict is VerificationVerdict.PASS
    assert atomic.effective_verdict is VerificationVerdict.UNKNOWN
    assert atomic.freshness is Freshness.STALE
    assert session.root_verdicts["ROOT"] is VerificationVerdict.UNKNOWN


def test_session_owned_ledger_view_cannot_bypass_bundle_only_atomic_recording():
    session = VerificationSession(
        graph=ClaimGraph(nodes=(_atomic("A"),)),
        roots=("A",),
    )

    exposed = session.ledger
    exposed.record_verification(
        "A",
        VerificationReport(
            verdict=VerificationVerdict.PASS,
            verifier="test.verifier.v1",
        ),
    )

    assert session.root_verdicts["A"] is VerificationVerdict.UNKNOWN
    assert session.unverified_claim_ids == ("A",)


def test_session_graph_definition_cannot_be_replaced_after_construction():
    session = VerificationSession(
        graph=ClaimGraph(nodes=(_atomic("A"),)),
        roots=("A",),
    )

    with pytest.raises(AttributeError):
        session.graph = ClaimGraph(nodes=(_atomic("B"),))


def test_stale_composite_cannot_report_complete_termination_before_recompute():
    session = _compose_binary(
        ClaimOperator.AND,
        VerificationVerdict.PASS,
        VerificationVerdict.PASS,
    )

    session.record_bundle(
        "A",
        _bundle("A", VerificationVerdict.PASS, source="revision-B"),
    )

    assert session.root_verdicts["ROOT"] is VerificationVerdict.UNKNOWN
    assert session.termination_reason is SessionTermination.UNSUPPORTED_CLAIM


@pytest.mark.parametrize(
    "budget",
    [
        SessionBudget(max_claims=2),
        SessionBudget(max_evidence_records=0),
        SessionBudget(max_evidence_bytes=0),
        SessionBudget(max_steps=0),
    ],
)
def test_every_deterministic_budget_dimension_fails_closed(budget):
    session = VerificationSession.compose(
        graph=_graph_for(ClaimOperator.AND),
        roots=("ROOT",),
        bundles={
            "A": _bundle("A", VerificationVerdict.PASS),
            "B": _bundle("B", VerificationVerdict.PASS),
        },
        budget=budget,
    )

    assert session.root_verdicts["ROOT"] is VerificationVerdict.UNKNOWN
    assert session.termination_reason is SessionTermination.BUDGET_EXHAUSTED


def test_budget_cutoff_leaves_affected_root_unknown_with_explicit_termination():
    session = VerificationSession.compose(
        graph=_graph_for(ClaimOperator.AND),
        roots=("ROOT",),
        bundles={"A": _bundle("A", VerificationVerdict.PASS), "B": _bundle("B", VerificationVerdict.PASS)},
        budget=SessionBudget(max_bundles=1),
    )
    assert session.consumption.bundles == 1
    assert session.root_verdicts["ROOT"] is VerificationVerdict.UNKNOWN
    assert session.termination_reason is SessionTermination.BUDGET_EXHAUSTED


def test_irrelevant_unconnected_claim_does_not_change_root_but_changes_session_identity():
    base = ClaimGraph(nodes=(_atomic("A"),))
    extended = ClaimGraph(nodes=(_atomic("A"), _atomic("IRRELEVANT")))
    first = VerificationSession.compose(
        graph=base,
        roots=("A",),
        bundles={"A": _bundle("A", VerificationVerdict.PASS)},
    )
    second = VerificationSession.compose(
        graph=extended,
        roots=("A",),
        bundles={"A": _bundle("A", VerificationVerdict.PASS)},
    )
    assert first.root_verdicts["A"] is VerificationVerdict.PASS
    assert second.root_verdicts["A"] is VerificationVerdict.PASS
    assert first.fingerprint != second.fingerprint


def test_root_selection_and_budget_semantics_change_session_fingerprint():
    graph = ClaimGraph(nodes=(_atomic("A"), _atomic("B")))
    bundles = {
        "A": _bundle("A", VerificationVerdict.PASS),
        "B": _bundle("B", VerificationVerdict.PASS),
    }
    first = VerificationSession.compose(graph=graph, roots=("A",), bundles=bundles)
    second = VerificationSession.compose(graph=graph, roots=("B",), bundles=bundles)
    third = VerificationSession.compose(
        graph=graph,
        roots=("A",),
        bundles=bundles,
        budget=SessionBudget(max_bundles=5),
    )
    assert first.fingerprint != second.fingerprint
    assert first.fingerprint != third.fingerprint


def test_malformed_bundle_cannot_partially_mutate_session_or_ledger():
    session = VerificationSession(graph=ClaimGraph(nodes=(_atomic("A"),)), roots=("A",))
    malformed = _bundle("A", VerificationVerdict.PASS)
    object.__setattr__(malformed, "fingerprint", "0" * 64)
    before = session.to_dict()

    with pytest.raises(BundleValidationError):
        session.record_bundle("A", malformed)

    assert session.to_dict() == before
    assert session.ledger.history("A") == ()


def _wire_bundle(bundle) -> dict[str, object]:
    return envelope("fixture", bundle)["payload"]


def _wire_request(*, reverse: bool = False) -> dict[str, object]:
    nodes = [
        {
            "node_type": "ATOMIC",
            "claim_id": "A",
            "claim_kind": "TEST_ASSERTION",
            "spec": {"b": 2, "a": 1},
            "verifier": "test.verifier.v1",
            "scope": {},
            "dependencies": [],
        },
        {
            "node_type": "ATOMIC",
            "claim_id": "B",
            "claim_kind": "TEST_ASSERTION",
            "spec": {"subject": "B"},
            "verifier": "test.verifier.v1",
            "scope": {},
            "dependencies": [],
        },
        {
            "node_type": "COMPOSITE",
            "claim_id": "ROOT",
            "operator": "AND",
            "dependencies": ["B", "A"],
        },
    ]
    bundles = [
        {"claim_id": "A", "bundle": _wire_bundle(_bundle("A", VerificationVerdict.PASS))},
        {"claim_id": "B", "bundle": _wire_bundle(_bundle("B", VerificationVerdict.PASS))},
    ]
    if reverse:
        nodes = list(reversed(nodes))
        nodes[-1]["spec"] = {"a": 1, "b": 2}
        nodes[0]["dependencies"] = ["A", "B"]
        bundles = list(reversed(bundles))
    return {
        "schema_version": 1,
        "op": "compose_verification_session",
        "payload": {
            "claim_graph": {"nodes": nodes},
            "roots": ["ROOT"],
            "bundles": bundles,
            "budget": {
                "max_claims": 10,
                "max_bundles": 10,
                "max_evidence_records": 10,
                "max_evidence_bytes": 10000,
                "max_steps": 10,
            },
        },
    }


def test_schema_v1_compose_verification_session_is_deterministic_and_complete():
    first = handle_request(_wire_request())
    second = handle_request(_wire_request(reverse=True))

    assert first == second
    assert first["kind"] == "verification_session"
    payload = first["payload"]
    assert payload["schema_version"] == 1
    assert payload["kind"] == "gvr.verification_session"
    assert payload["root_verdicts"] == {"ROOT": "PASS"}
    assert payload["termination_reason"] == "COMPLETE"
    assert [item["claim_id"] for item in payload["claims"]] == ["A", "B", "ROOT"]
    assert payload["atomic_verifications"][0]["evidence_ids"] == ["E:A"]
    assert len(payload["fingerprint"]) == 64


def test_wire_cycle_and_malformed_bundle_fail_closed_as_protocol_errors():
    cyclic = _wire_request()
    cyclic["payload"]["claim_graph"]["nodes"] = [
        {"node_type": "COMPOSITE", "claim_id": "A", "operator": "NOT", "dependencies": ["B"]},
        {"node_type": "COMPOSITE", "claim_id": "B", "operator": "NOT", "dependencies": ["A"]},
    ]
    cyclic["payload"]["roots"] = ["A"]
    cyclic["payload"]["bundles"] = []
    cycle_out = safe_handle_request(cyclic)
    assert cycle_out["kind"] == "protocol_error"
    assert cycle_out["payload"]["code"] == "INVALID_CLAIM_GRAPH"

    malformed = _wire_request()
    malformed["payload"]["bundles"][0]["bundle"]["fingerprint"] = "0" * 64
    bundle_out = safe_handle_request(malformed)
    assert bundle_out["kind"] == "protocol_error"
    assert bundle_out["payload"]["code"] == "INVALID_VERIFICATION_BUNDLE"
