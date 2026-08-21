from __future__ import annotations

from typing import Any, Mapping

from .bundle import BundleValidationError, VerificationBundle
from .capabilities import (
    VerifierCapabilityError,
    VerifierCapabilityRegistry,
    builtin_verifier_capability_registry,
)
from .evidence_providers import (
    EvidenceAcquisitionStatus,
    EvidenceCompleteness,
    EvidenceCoverage,
    EvidenceProviderError,
    EvidenceProviderCapability,
    EvidenceProviderRegistry,
    EvidenceProviderResult,
    EvidenceRequest,
    builtin_evidence_provider_registry,
    validate_evidence_provider_result,
)
from .core import Action, Goal, Predicate, Proposal, StateEffect, VerificationContext, default_registry
from .model import Evidence, VerificationIssue, VerificationReport, VerificationVerdict
from .session import (
    AtomicClaim,
    ClaimGraph,
    ClaimGraphValidationError,
    ClaimOperator,
    CompositeClaim,
    SessionBudget,
    VerificationSession,
    VerificationSessionError,
)
from .text_search import TextSearchAssertion, evaluate_text_search
from .verifiers.data_flow import (
    DataFlowClaim,
    DataFlowClaimKind,
    DataFlowQueryScope,
    SUPPORTED_DATA_FLOW_RELATIONS,
    verify_data_flow_claim,
    verify_data_flow_claim_bundle,
)
from .wire import SCHEMA_VERSION, decode_markers, envelope
from .software import (
    Coverage,
    FunctionalSnapshot,
    Observable,
    RevisionRef,
    compare_functionality,
    verify_functional_regression,
)


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


def _string_array(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ProtocolError("INVALID_PAYLOAD", f"{name} must be an array of non-empty strings")
    return tuple(value)


def _evidence_provider_request(data: Mapping[str, Any]) -> EvidenceRequest:
    try:
        return EvidenceRequest(
            request_id=str(data.get("request_id") or ""),
            provider_id=str(data.get("provider_id") or ""),
            provider_version=str(data.get("provider_version") or ""),
            claim_kind=str(data.get("claim_kind") or ""),
            required_evidence_kinds=_string_array(data.get("required_evidence_kinds", ()), "required_evidence_kinds"),
            accepted_evidence_kinds=_string_array(data.get("accepted_evidence_kinds", ()), "accepted_evidence_kinds"),
            input=decode_markers(dict(_require_mapping(data.get("input", {}), "input"))),
            bounds=decode_markers(dict(_require_mapping(data.get("bounds", {}), "bounds"))),
        )
    except EvidenceProviderError as exc:
        raise ProtocolError("INVALID_EVIDENCE_PROVIDER_REQUEST", str(exc)) from exc


def _evidence_provider_capability(data: Mapping[str, Any]) -> EvidenceProviderCapability:
    try:
        capability = EvidenceProviderCapability(
            provider_id=str(data.get("provider_id") or ""),
            version=str(data.get("version") or ""),
            claim_kinds=_string_array(data.get("claim_kinds", ()), "claim_kinds"),
            produced_evidence_kinds=_string_array(data.get("produced_evidence_kinds", ()), "produced_evidence_kinds"),
            input_schema=decode_markers(dict(_require_mapping(data.get("input_schema", {}), "input_schema"))),
            output_schema=decode_markers(dict(_require_mapping(data.get("output_schema", {}), "output_schema"))),
            determinism=str(data.get("determinism") or ""),
            side_effect_free=data.get("side_effect_free"),
            cost=str(data.get("cost") or ""),
            bounds=decode_markers(dict(_require_mapping(data.get("bounds", {}), "bounds"))),
            coverage=decode_markers(dict(_require_mapping(data.get("coverage", {}), "coverage"))),
            description=data.get("description"),
        )
    except EvidenceProviderError as exc:
        raise ProtocolError("INVALID_EVIDENCE_PROVIDER_CAPABILITY", str(exc)) from exc
    supplied = data.get("fingerprint")
    if supplied is not None and supplied != capability.fingerprint:
        raise ProtocolError("INVALID_EVIDENCE_PROVIDER_CAPABILITY", "capability fingerprint does not match canonical content")
    return capability


def _evidence_provider_result(data: Mapping[str, Any]) -> EvidenceProviderResult:
    try:
        coverage_data = _require_mapping(data.get("coverage", {}), "coverage")
        evidence_data = data.get("evidence", ())
        issues_data = data.get("issues", ())
        if not isinstance(evidence_data, (list, tuple)) or not isinstance(issues_data, (list, tuple)):
            raise ProtocolError("INVALID_EVIDENCE_PROVIDER_RESULT", "evidence and issues must be arrays")
        return EvidenceProviderResult(
            request_id=str(data.get("request_id") or ""),
            provider_id=str(data.get("provider_id") or ""),
            provider_version=str(data.get("provider_version") or ""),
            status=EvidenceAcquisitionStatus(str(data.get("status") or "")),
            coverage=EvidenceCoverage(
                completeness=EvidenceCompleteness(str(coverage_data.get("completeness") or "")),
                covered_evidence_kinds=_string_array(coverage_data.get("covered_evidence_kinds", ()), "covered_evidence_kinds"),
                truncated=coverage_data.get("truncated"),
                details=decode_markers(dict(_require_mapping(coverage_data.get("details", {}), "coverage details"))),
            ),
            evidence=tuple(
                Evidence(
                    id=str(record.get("id") or ""),
                    kind=str(record.get("kind") or ""),
                    payload=decode_markers(dict(_require_mapping(record.get("payload", {}), "evidence payload"))),
                    source=record.get("source"),
                    fingerprint=record.get("fingerprint"),
                )
                for record in (_require_mapping(item, "evidence record") for item in evidence_data)
            ),
            issues=tuple(
                VerificationIssue(
                    code=str(issue.get("code") or ""),
                    message=str(issue.get("message") or ""),
                    verdict=VerificationVerdict(str(issue.get("verdict") or "")),
                    evidence_ids=_string_array(issue.get("evidence_ids", ()), "issue evidence_ids"),
                )
                for issue in (_require_mapping(item, "issue") for item in issues_data)
            ),
            capability_fingerprint=str(data.get("capability_fingerprint") or ""),
        )
    except ProtocolError:
        raise
    except (EvidenceProviderError, ValueError) as exc:
        raise ProtocolError("INVALID_EVIDENCE_PROVIDER_RESULT", str(exc)) from exc


def _verification_bundle(data: Mapping[str, Any]) -> VerificationBundle:
    report_data = _require_mapping(data.get("report", {}), "bundle report")
    issues_data = report_data.get("issues", ())
    if not isinstance(issues_data, (list, tuple)):
        raise ProtocolError("INVALID_VERIFICATION_BUNDLE", "bundle report issues must be an array")
    try:
        report = VerificationReport(
            verdict=VerificationVerdict(str(report_data.get("verdict") or "")),
            verifier=str(report_data.get("verifier") or ""),
            issues=tuple(
                VerificationIssue(
                    code=str(issue_data.get("code") or ""),
                    message=str(issue_data.get("message") or ""),
                    verdict=VerificationVerdict(str(issue_data.get("verdict") or "")),
                    evidence_ids=_string_array(
                        issue_data.get("evidence_ids", ()),
                        "issue evidence_ids",
                    ),
                )
                for issue_data in (
                    _require_mapping(item, "bundle issue")
                    for item in issues_data
                )
            ),
            evidence_ids=_string_array(
                report_data.get("evidence_ids", ()),
                "bundle report evidence_ids",
            ),
            metadata=decode_markers(dict(_require_mapping(
                report_data.get("metadata", {}),
                "bundle report metadata",
            ))),
        )
    except ValueError as exc:
        raise ProtocolError("INVALID_VERIFICATION_BUNDLE", str(exc)) from exc

    evidence_data = data.get("evidence", ())
    if not isinstance(evidence_data, (list, tuple)):
        raise ProtocolError("INVALID_VERIFICATION_BUNDLE", "bundle evidence must be an array")
    evidence: list[Evidence] = []
    for item in evidence_data:
        record = _require_mapping(item, "bundle evidence record")
        payload = _require_mapping(record.get("payload", {}), "evidence payload")
        source = record.get("source")
        fingerprint = record.get("fingerprint")
        if source is not None and not isinstance(source, str):
            raise ProtocolError("INVALID_VERIFICATION_BUNDLE", "evidence source must be a string")
        if fingerprint is not None and not isinstance(fingerprint, str):
            raise ProtocolError("INVALID_VERIFICATION_BUNDLE", "evidence fingerprint must be a string")
        evidence.append(Evidence(
            id=str(record.get("id") or ""),
            kind=str(record.get("kind") or ""),
            payload=decode_markers(dict(payload)),
            source=source,
            fingerprint=fingerprint,
        ))

    try:
        bundle = VerificationBundle(
            schema_version=data.get("schema_version", 1),
            kind=data.get("kind", "gvr.verification_bundle"),
            fingerprint_format=str(data.get("fingerprint_format") or ""),
            report=report,
            evidence=tuple(evidence),
            claim_dependency_ids=_string_array(
                data.get("claim_dependency_ids", ()),
                "bundle claim_dependency_ids",
            ),
        )
    except (BundleValidationError, TypeError, ValueError) as exc:
        raise ProtocolError("INVALID_VERIFICATION_BUNDLE", str(exc)) from exc
    supplied_verifier = data.get("verifier")
    if supplied_verifier is not None and supplied_verifier != bundle.verifier:
        raise ProtocolError(
            "INVALID_VERIFICATION_BUNDLE",
            "bundle verifier does not match the normalized report",
        )
    supplied_fingerprint = data.get("fingerprint")
    if supplied_fingerprint is not None and supplied_fingerprint != bundle.fingerprint:
        raise ProtocolError(
            "INVALID_VERIFICATION_BUNDLE",
            "bundle fingerprint does not match canonical content",
        )
    return bundle


def _claim_graph(data: Mapping[str, Any]) -> ClaimGraph:
    nodes_data = data.get("nodes", ())
    if not isinstance(nodes_data, (list, tuple)):
        raise ProtocolError("INVALID_CLAIM_GRAPH", "claim graph nodes must be an array")
    nodes = []
    try:
        for item in nodes_data:
            node = _require_mapping(item, "claim graph node")
            node_type = node.get("node_type")
            dependencies = _string_array(
                node.get("dependencies", ()),
                "claim dependencies",
            )
            if node_type == "ATOMIC":
                nodes.append(AtomicClaim(
                    claim_id=str(node.get("claim_id") or ""),
                    claim_kind=str(node.get("claim_kind") or ""),
                    spec=decode_markers(dict(_require_mapping(
                        node.get("spec", {}),
                        "claim spec",
                    ))),
                    verifier=str(node.get("verifier") or ""),
                    scope=decode_markers(dict(_require_mapping(
                        node.get("scope", {}),
                        "claim scope",
                    ))),
                    dependencies=dependencies,
                    description=node.get("description"),
                ))
            elif node_type == "COMPOSITE":
                nodes.append(CompositeClaim(
                    claim_id=str(node.get("claim_id") or ""),
                    operator=ClaimOperator(str(node.get("operator") or "")),
                    dependencies=dependencies,
                    description=node.get("description"),
                ))
            else:
                raise ClaimGraphValidationError(
                    f"unsupported claim node_type {node_type!r}"
                )
        return ClaimGraph(
            schema_version=data.get("schema_version", 1),
            kind=data.get("kind", "gvr.claim_graph"),
            nodes=tuple(nodes),
        )
    except (ClaimGraphValidationError, TypeError, ValueError) as exc:
        raise ProtocolError("INVALID_CLAIM_GRAPH", str(exc)) from exc


def _session_budget(data: Mapping[str, Any]) -> SessionBudget:
    try:
        return SessionBudget(
            max_claims=data.get("max_claims"),
            max_bundles=data.get("max_bundles"),
            max_evidence_records=data.get("max_evidence_records"),
            max_evidence_bytes=data.get("max_evidence_bytes"),
            max_steps=data.get("max_steps"),
        )
    except VerificationSessionError as exc:
        raise ProtocolError("INVALID_BUDGET", str(exc)) from exc


def _data_flow_inputs(
    payload: Mapping[str, Any],
) -> tuple[DataFlowClaim, Mapping[str, Any]]:
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
        raise ProtocolError(
            "INVALID_CLAIM_SCOPE",
            "effective_allowed_relations must be an array of strings",
        )
    if not isinstance(stop_nodes, (list, tuple)) or not all(
        isinstance(item, str) for item in stop_nodes
    ):
        raise ProtocolError(
            "INVALID_CLAIM_SCOPE",
            "stop_nodes must be an array of strings",
        )
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
    return claim, traversal


def handle_request(request: Mapping[str, Any]) -> dict[str, Any]:
    if request.get("schema_version") != SCHEMA_VERSION:
        raise ProtocolError(
            "UNSUPPORTED_SCHEMA_VERSION",
            f"expected schema_version={SCHEMA_VERSION}",
        )
    op = str(request.get("op") or "")
    payload = _require_mapping(request.get("payload", {}), "payload")

    if op == "describe_verifier_capabilities":
        unexpected = set(payload) - {"claim_kind", "authoritative_only"}
        if unexpected:
            raise ProtocolError(
                "INVALID_PAYLOAD",
                "unsupported capability query fields: " + ", ".join(sorted(unexpected)),
            )
        claim_kind = payload.get("claim_kind")
        if claim_kind is not None and not isinstance(claim_kind, str):
            raise ProtocolError("INVALID_PAYLOAD", "claim_kind must be a string")
        authoritative_only = payload.get("authoritative_only", False)
        if not isinstance(authoritative_only, bool):
            raise ProtocolError(
                "INVALID_PAYLOAD",
                "authoritative_only must be a boolean",
            )
        try:
            capabilities = builtin_verifier_capability_registry().query(
                claim_kind=claim_kind,
                authoritative_only=authoritative_only,
            )
            registry = VerifierCapabilityRegistry(capabilities)
        except VerifierCapabilityError as exc:
            raise ProtocolError("INVALID_PAYLOAD", str(exc)) from exc
        return envelope("verifier_capability_registry", registry.to_dict())

    if op == "describe_evidence_provider_capabilities":
        unexpected = set(payload) - {"request_kind", "evidence_kind"}
        if unexpected:
            raise ProtocolError(
                "INVALID_PAYLOAD",
                "unsupported evidence provider capability query fields: "
                + ", ".join(sorted(unexpected)),
            )
        request_kind = payload.get("request_kind")
        evidence_kind = payload.get("evidence_kind")
        if request_kind is not None and not isinstance(request_kind, str):
            raise ProtocolError("INVALID_PAYLOAD", "request_kind must be a string")
        if evidence_kind is not None and not isinstance(evidence_kind, str):
            raise ProtocolError("INVALID_PAYLOAD", "evidence_kind must be a string")
        try:
            capabilities = builtin_evidence_provider_registry().query(
                request_kind=request_kind,
                evidence_kind=evidence_kind,
            )
            registry = EvidenceProviderRegistry(capabilities)
        except EvidenceProviderError as exc:
            raise ProtocolError("INVALID_PAYLOAD", str(exc)) from exc
        return envelope("evidence_provider_capability_registry", registry.to_dict())

    if op == "validate_evidence_provider_result":
        unexpected = set(payload) - {"request", "capability", "result"}
        if unexpected:
            raise ProtocolError(
                "INVALID_PAYLOAD",
                "unsupported evidence provider result validation fields: "
                + ", ".join(sorted(unexpected)),
            )
        try:
            parsed_request = _evidence_provider_request(_require_mapping(payload.get("request", {}), "request"))
            parsed_capability = _evidence_provider_capability(_require_mapping(payload.get("capability", {}), "capability"))
            parsed_result = _evidence_provider_result(_require_mapping(payload.get("result", {}), "result"))
            normalized = validate_evidence_provider_result(parsed_result, parsed_request, parsed_capability)
        except ProtocolError:
            raise
        except EvidenceProviderError as exc:
            raise ProtocolError("INVALID_EVIDENCE_PROVIDER_RESULT", str(exc)) from exc
        return envelope("evidence_provider_result", normalized.to_dict())

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
        claim, traversal = _data_flow_inputs(payload)
        report = verify_data_flow_claim(claim, traversal)
        return envelope("data_flow_claim_verification", report)

    if op == "verify_data_flow_claim_bundle":
        claim, traversal = _data_flow_inputs(payload)
        try:
            bundle = verify_data_flow_claim_bundle(claim, traversal)
        except BundleValidationError as exc:
            raise ProtocolError("INVALID_VERIFICATION_BUNDLE", str(exc)) from exc
        return envelope("verification_bundle", bundle)

    if op == "compose_verification_session":
        graph = _claim_graph(_require_mapping(
            payload.get("claim_graph", {}),
            "claim_graph",
        ))
        roots = _string_array(payload.get("roots", ()), "roots")
        bundle_items = payload.get("bundles", ())
        if not isinstance(bundle_items, (list, tuple)):
            raise ProtocolError("INVALID_VERIFICATION_BUNDLE", "bundles must be an array")
        bundles: dict[str, VerificationBundle] = {}
        for item in bundle_items:
            entry = _require_mapping(item, "session bundle")
            claim_id = str(entry.get("claim_id") or "")
            if not claim_id:
                raise ProtocolError(
                    "INVALID_VERIFICATION_BUNDLE",
                    "session bundle requires claim_id",
                )
            if claim_id in bundles:
                raise ProtocolError(
                    "INVALID_VERIFICATION_BUNDLE",
                    f"duplicate session bundle for claim {claim_id}",
                )
            bundles[claim_id] = _verification_bundle(_require_mapping(
                entry.get("bundle", {}),
                "verification bundle",
            ))
        budget = _session_budget(_require_mapping(
            payload.get("budget", {}),
            "budget",
        ))
        try:
            session = VerificationSession.compose(
                graph=graph,
                roots=roots,
                bundles=bundles,
                budget=budget,
            )
        except BundleValidationError as exc:
            raise ProtocolError("INVALID_VERIFICATION_BUNDLE", str(exc)) from exc
        except VerificationSessionError as exc:
            code = (
                "INVALID_VERIFICATION_BUNDLE"
                if "bundle" in str(exc).lower()
                else "INVALID_VERIFICATION_SESSION"
            )
            raise ProtocolError(code, str(exc)) from exc
        return envelope("verification_session", session.to_dict())

    raise ProtocolError("UNKNOWN_OPERATION", f"unsupported operation: {op!r}")


def safe_handle_request(request: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return handle_request(request)
    except ProtocolError as exc:
        return envelope("protocol_error", {"code": exc.code, "message": exc.message})
