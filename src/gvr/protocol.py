from __future__ import annotations

from typing import Any, Mapping

from .core import Action, Goal, Predicate, Proposal, StateEffect, VerificationContext, default_registry
from .text_search import TextSearchAssertion, evaluate_text_search
from .verifiers.data_flow import (
    DataFlowClaim,
    DataFlowClaimKind,
    DataFlowQueryScope,
    SUPPORTED_DATA_FLOW_RELATIONS,
    verify_data_flow_claim,
)
from .wire import SCHEMA_VERSION, decode_markers, envelope
from .software import Coverage, FunctionalSnapshot, Observable, RevisionRef, compare_functionality, verify_functional_regression


class ProtocolError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _require_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ProtocolError("INVALID_PAYLOAD", f"{name} must be an object")
    return value


def _predicate(data: Mapping[str, Any]) -> Predicate:
    if "slot" not in data or "op" not in data:
        raise ProtocolError("INVALID_PREDICATE", "predicate requires slot and op")
    return Predicate(str(data["slot"]), str(data["op"]), decode_markers(data.get("expected")))


def _effect(data: Mapping[str, Any]) -> StateEffect:
    if "slot" not in data:
        raise ProtocolError("INVALID_EFFECT", "effect requires slot")
    return StateEffect(
        slot=str(data["slot"]),
        value=decode_markers(data.get("value")),
        supported=bool(data.get("supported", True)),
    )


def _action(data: Mapping[str, Any]) -> Action:
    if "id" not in data:
        raise ProtocolError("INVALID_ACTION", "action requires id")
    return Action(
        id=str(data["id"]),
        preconditions=tuple(_predicate(_require_mapping(p, "precondition")) for p in data.get("preconditions", ())),
        effects=tuple(_effect(_require_mapping(e, "effect")) for e in data.get("effects", ())),
    )


def _revision(data: Mapping[str, Any]) -> RevisionRef:
    if "repository" not in data or "revision" not in data:
        raise ProtocolError("INVALID_REVISION", "revision requires repository and revision")
    return RevisionRef(str(data["repository"]), str(data["revision"]))


def _observable(data: Mapping[str, Any]) -> Observable:
    if "kind" not in data or "key" not in data or "value" not in data:
        raise ProtocolError("INVALID_OBSERVABLE", "observable requires kind, key and value")
    evidence = data.get("evidence_ids", ())
    if not isinstance(evidence, (list, tuple)):
        raise ProtocolError("INVALID_OBSERVABLE", "evidence_ids must be an array")
    return Observable(
        kind=str(data["kind"]),
        key=str(data["key"]),
        value=decode_markers(data["value"]),
        evidence_ids=tuple(str(x) for x in evidence),
        receiver_confidence=str(data.get("receiver_confidence", "PROVEN")),
        analysis_completeness=str(data.get("analysis_completeness", "COMPLETE_FOR_SUPPORTED_CONSTRUCT")),
    )


def _snapshot(data: Mapping[str, Any]) -> FunctionalSnapshot:
    revision = _revision(_require_mapping(data.get("revision", {}), "revision"))
    observables = data.get("observables", ())
    coverage = _require_mapping(data.get("coverage_by_kind", {}), "coverage_by_kind")
    if not isinstance(observables, (list, tuple)):
        raise ProtocolError("INVALID_SNAPSHOT", "observables must be an array")
    try:
        parsed_coverage = {str(k): Coverage(str(v)) for k, v in coverage.items()}
    except ValueError as exc:
        raise ProtocolError("INVALID_COVERAGE", str(exc)) from exc
    return FunctionalSnapshot(
        revision=revision,
        observables=tuple(_observable(_require_mapping(x, "observable")) for x in observables),
        coverage_by_kind=parsed_coverage,
    )


def handle_request(request: Mapping[str, Any]) -> dict[str, Any]:
    if request.get("schema_version") != SCHEMA_VERSION:
        raise ProtocolError(
            "UNSUPPORTED_SCHEMA_VERSION",
            f"expected schema_version={SCHEMA_VERSION}",
        )
    op = str(request.get("op") or "")
    payload = _require_mapping(request.get("payload", {}), "payload")

    if op == "verify_goal":
        state = decode_markers(dict(_require_mapping(payload.get("initial_state", {}), "initial_state")))
        goal_data = payload.get("goal", ())
        actions_data = payload.get("actions", ())
        if not isinstance(goal_data, (list, tuple)) or not isinstance(actions_data, (list, tuple)):
            raise ProtocolError("INVALID_PAYLOAD", "goal and actions must be arrays")
        context = VerificationContext(
            initial_state=state,
            goal=Goal(tuple(_predicate(_require_mapping(p, "goal predicate")) for p in goal_data)),
        )
        proposal = Proposal(tuple(_action(_require_mapping(a, "action")) for a in actions_data))
        report = default_registry().verify(proposal, context)
        return envelope("verification_report", report)

    if op == "compare_functionality":
        baseline = _snapshot(_require_mapping(payload.get("baseline", {}), "baseline"))
        candidate = _snapshot(_require_mapping(payload.get("candidate", {}), "candidate"))
        return envelope("functional_delta", compare_functionality(baseline, candidate))

    if op == "verify_functional_regression":
        baseline = _snapshot(_require_mapping(payload.get("baseline", {}), "baseline"))
        candidate = _snapshot(_require_mapping(payload.get("candidate", {}), "candidate"))
        required = payload.get("required_kinds")
        if required is not None and not isinstance(required, (list, tuple)):
            raise ProtocolError("INVALID_PAYLOAD", "required_kinds must be an array")
        delta, report = verify_functional_regression(
            baseline,
            candidate,
            required_kinds=(None if required is None else tuple(str(x) for x in required)),
        )
        return envelope("functional_regression_verification", {"delta": delta, "report": report})

    if op == "verify_text_search":
        corpus = payload.get("corpus", ())
        claimed = payload.get("claimed_matches", ())
        if not isinstance(corpus, (list, tuple)) or not isinstance(claimed, (list, tuple)):
            raise ProtocolError("INVALID_PAYLOAD", "corpus and claimed_matches must be arrays")
        if "needle" not in payload:
            raise ProtocolError("INVALID_PAYLOAD", "needle is required")
        assertion = TextSearchAssertion(
            corpus=tuple(str(x) for x in corpus),
            needle=str(payload["needle"]),
            claimed_matches=tuple(str(x) for x in claimed),
            requested_needle=(None if payload.get("requested_needle") is None else str(payload["requested_needle"])),
            require_grounding=bool(payload.get("require_grounding", True)),
            reverse=bool(payload.get("reverse", False)),
            normalization=str(payload.get("normalization", "NFC")),
        )
        result, report = evaluate_text_search(assertion)
        return envelope("text_search_verification", {"result": result, "report": report})

    if op == "verify_data_flow_claim":
        if not payload.get("start") or not payload.get("target"):
            raise ProtocolError("INVALID_PAYLOAD", "start and target are required")
        try:
            kind = DataFlowClaimKind(str(payload.get("claim_kind") or ""))
        except ValueError as exc:
            raise ProtocolError("INVALID_CLAIM_KIND", "claim_kind is not supported") from exc
        traversal = _require_mapping(payload.get("traversal_result", {}), "traversal_result")
        scope_data = _require_mapping(payload.get("scope", {}), "scope")
        relations = scope_data.get(
            "effective_allowed_relations",
            sorted(SUPPORTED_DATA_FLOW_RELATIONS),
        )
        stop_nodes = scope_data.get("stop_nodes", ())
        if not isinstance(relations, (list, tuple)) or not all(
            isinstance(item, str) for item in relations
        ):
            raise ProtocolError("INVALID_CLAIM_SCOPE", "effective_allowed_relations must be an array of strings")
        if not isinstance(stop_nodes, (list, tuple)) or not all(
            isinstance(item, str) for item in stop_nodes
        ):
            raise ProtocolError("INVALID_CLAIM_SCOPE", "stop_nodes must be an array of strings")
        try:
            scope = DataFlowQueryScope(
                direction=str(scope_data.get("direction", "FORWARD")),
                effective_allowed_relations=frozenset(relations),
                stop_nodes=frozenset(stop_nodes),
            )
            claim = DataFlowClaim(
                kind=kind,
                start=str(payload["start"]),
                target=str(payload["target"]),
                scope=scope,
                evidence_namespace=str(payload.get("evidence_namespace") or "default"),
                source_context=(
                    None
                    if payload.get("source_context") is None
                    else str(payload.get("source_context"))
                ),
            )
        except ValueError as exc:
            raise ProtocolError("INVALID_CLAIM_SCOPE", str(exc)) from exc
        report = verify_data_flow_claim(claim, traversal)
        return envelope("data_flow_claim_verification", report)

    raise ProtocolError("UNKNOWN_OPERATION", f"unsupported operation: {op!r}")


def safe_handle_request(request: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return handle_request(request)
    except ProtocolError as exc:
        return envelope("protocol_error", {"code": exc.code, "message": exc.message})
