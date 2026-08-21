from __future__ import annotations

from typing import Any, Mapping

from .bundle import BundleValidationError, VerificationBundle
from .capabilities import (
    VERIFIER_CAPABILITY_FINGERPRINT_FORMAT,
    VERIFIER_CAPABILITY_KIND,
    VERIFIER_CAPABILITY_REGISTRY_FINGERPRINT_FORMAT,
    VERIFIER_CAPABILITY_REGISTRY_KIND,
    VERIFIER_CAPABILITY_REGISTRY_SCHEMA_VERSION,
    VERIFIER_CAPABILITY_SCHEMA_VERSION,
    FalsificationRequirement,
    FalsificationStrategyKind,
    VerifierCapability,
    VerifierCapabilityError,
    VerifierCapabilityRegistry,
    VerifierCost,
    VerifierDeterminism,
    builtin_verifier_capability_registry,
)
from .falsification import (
    FALSIFICATION_STRATEGY_CAPABILITY_REGISTRY_FINGERPRINT_FORMAT,
    FALSIFICATION_STRATEGY_CAPABILITY_REGISTRY_KIND,
    FALSIFICATION_STRATEGY_CAPABILITY_REGISTRY_SCHEMA_VERSION,
    FALSIFICATION_STRATEGY_DESCRIPTOR_FINGERPRINT_FORMAT,
    FALSIFICATION_STRATEGY_DESCRIPTOR_KIND,
    FALSIFICATION_STRATEGY_DESCRIPTOR_SCHEMA_VERSION,
    FALSIFICATION_STRATEGY_RUNTIME_REGISTRY_FINGERPRINT_FORMAT,
    FALSIFICATION_STRATEGY_RUNTIME_REGISTRY_KIND,
    FALSIFICATION_STRATEGY_RUNTIME_REGISTRY_SCHEMA_VERSION,
    FalsificationStrategyCapabilityRegistry,
    FalsificationStrategyDescriptor,
    FalsificationStrategyError,
    FalsificationStrategyRuntimeRegistry,
    builtin_falsification_strategy_capability_registry,
    builtin_falsification_strategy_runtime_registry,
)
from .evidence_providers import (
    EVIDENCE_PROVIDER_CAPABILITY_FINGERPRINT_FORMAT,
    EVIDENCE_PROVIDER_CAPABILITY_KIND,
    EVIDENCE_PROVIDER_CAPABILITY_REGISTRY_FINGERPRINT_FORMAT,
    EVIDENCE_PROVIDER_CAPABILITY_REGISTRY_KIND,
    EVIDENCE_PROVIDER_CAPABILITY_REGISTRY_SCHEMA_VERSION,
    EVIDENCE_PROVIDER_CAPABILITY_SCHEMA_VERSION,
    EVIDENCE_PROVIDER_RUNTIME_REGISTRY_FINGERPRINT_FORMAT,
    EVIDENCE_PROVIDER_RUNTIME_REGISTRY_KIND,
    EVIDENCE_PROVIDER_RUNTIME_REGISTRY_SCHEMA_VERSION,
    EvidenceAcquisitionStatus,
    EvidenceCompleteness,
    EvidenceCoverage,
    EvidenceProviderError,
    EvidenceProviderCapability,
    EvidenceProviderCapabilityRegistry,
    EvidenceProviderIssue,
    EvidenceProviderResult,
    EvidenceProviderRuntimeRegistry,
    EvidenceRequest,
    builtin_evidence_provider_capability_registry,
    validate_evidence_provider_result,
)
from .planning import (
    ATOMIC_CLAIM_BINDING_FINGERPRINT_FORMAT,
    ATOMIC_CLAIM_BINDING_KIND,
    ATOMIC_CLAIM_BINDING_SCHEMA_VERSION,
    FALSIFICATION_STRATEGY_BINDING_FINGERPRINT_FORMAT,
    FALSIFICATION_STRATEGY_BINDING_KIND,
    FALSIFICATION_STRATEGY_BINDING_SCHEMA_VERSION,
    VERIFICATION_PLANNING_REQUEST_FINGERPRINT_FORMAT,
    VERIFICATION_PLANNING_REQUEST_KIND,
    VERIFICATION_PLANNING_REQUEST_SCHEMA_VERSION,
    VERIFICATION_PLAN_FINGERPRINT_FORMAT,
    VERIFICATION_PLAN_KIND,
    VERIFICATION_PLAN_SCHEMA_VERSION,
    AtomicClaimBinding,
    FalsificationStrategyBinding,
    VerificationPlan,
    VerificationPlannerIssue,
    VerificationPlanningConsumption,
    VerificationPlanningBudget,
    VerificationPlanningError,
    VerificationPlanningRequest,
    VerificationPlanStep,
    VerificationPlanStepKind,
    VerificationPlanTermination,
    compile_verification_plan,
)
from .execution import (
    VERIFICATION_EXECUTION_REQUEST_FINGERPRINT_FORMAT,
    VERIFICATION_EXECUTION_REQUEST_KIND,
    VERIFICATION_EXECUTION_REQUEST_SCHEMA_VERSION,
    VERIFIER_RUNTIME_REGISTRY_FINGERPRINT_FORMAT,
    VERIFIER_RUNTIME_REGISTRY_KIND,
    VERIFIER_RUNTIME_REGISTRY_SCHEMA_VERSION,
    VerificationExecutionError,
    VerificationExecutionLimits,
    VerificationExecutionRequest,
    VerifierRuntimeRegistry,
    builtin_verifier_runtime_registry,
    execute_verification_plan,
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


def _reject_unexpected_fields(
    data: Mapping[str, Any],
    allowed: set[str],
    *,
    code: str,
    noun: str,
) -> None:
    unexpected = set(data) - allowed
    if unexpected:
        raise ProtocolError(
            code,
            f"unsupported {noun} fields: " + ", ".join(sorted(unexpected)),
        )


def _evidence_provider_request(data: Mapping[str, Any]) -> EvidenceRequest:
    _reject_unexpected_fields(
        data,
        {
            "schema_version", "kind", "fingerprint_format", "fingerprint",
            "request_id", "provider_id", "provider_version", "request_kind",
            "requested_evidence_kinds", "subject", "spec", "semantic_scope",
            "source_class", "snapshot_class", "source_context",
            "snapshot_context", "bounds",
        },
        code="INVALID_EVIDENCE_PROVIDER_REQUEST",
        noun="evidence provider request",
    )
    try:
        request = EvidenceRequest(
            schema_version=data.get("schema_version"),
            kind=data.get("kind"),
            fingerprint_format=data.get("fingerprint_format"),
            request_id=str(data.get("request_id") or ""),
            provider_id=str(data.get("provider_id") or ""),
            provider_version=str(data.get("provider_version") or ""),
            request_kind=str(data.get("request_kind") or ""),
            requested_evidence_kinds=_string_array(data.get("requested_evidence_kinds", ()), "requested_evidence_kinds"),
            source_class=data.get("source_class"),
            snapshot_class=data.get("snapshot_class"),
            subject=decode_markers(dict(_require_mapping(data.get("subject", {}), "subject"))),
            spec=decode_markers(dict(_require_mapping(data.get("spec", {}), "spec"))),
            semantic_scope=decode_markers(dict(_require_mapping(data.get("semantic_scope", {}), "semantic_scope"))),
            source_context=decode_markers(dict(_require_mapping(data.get("source_context", {}), "source_context"))),
            snapshot_context=decode_markers(dict(_require_mapping(data.get("snapshot_context", {}), "snapshot_context"))),
            bounds=decode_markers(dict(_require_mapping(data.get("bounds", {}), "bounds"))),
        )
    except EvidenceProviderError as exc:
        raise ProtocolError("INVALID_EVIDENCE_PROVIDER_REQUEST", str(exc)) from exc
    supplied = data.get("fingerprint")
    if supplied is not None and supplied != request.fingerprint:
        raise ProtocolError("INVALID_EVIDENCE_PROVIDER_REQUEST", "request fingerprint does not match canonical content")
    return request


def _evidence_provider_capability(data: Mapping[str, Any]) -> EvidenceProviderCapability:
    _reject_unexpected_fields(
        data,
        {
            "schema_version", "kind", "fingerprint_format", "fingerprint",
            "provider_id", "version", "request_kinds", "produced_evidence_kinds",
            "source_classes", "snapshot_classes",
            "input_schema", "output_schema", "determinism", "side_effect_free",
            "cost", "bounds", "coverage", "description",
        },
        code="INVALID_EVIDENCE_PROVIDER_CAPABILITY",
        noun="evidence provider capability",
    )
    if type(data.get("schema_version")) is not int or data.get("schema_version") != EVIDENCE_PROVIDER_CAPABILITY_SCHEMA_VERSION:
        raise ProtocolError("INVALID_EVIDENCE_PROVIDER_CAPABILITY", "unsupported capability schema_version")
    if data.get("kind") != EVIDENCE_PROVIDER_CAPABILITY_KIND:
        raise ProtocolError("INVALID_EVIDENCE_PROVIDER_CAPABILITY", "unsupported capability kind")
    if data.get("fingerprint_format") != EVIDENCE_PROVIDER_CAPABILITY_FINGERPRINT_FORMAT:
        raise ProtocolError("INVALID_EVIDENCE_PROVIDER_CAPABILITY", "unsupported capability fingerprint_format")
    try:
        capability = EvidenceProviderCapability(
            provider_id=str(data.get("provider_id") or ""),
            version=str(data.get("version") or ""),
            request_kinds=_string_array(data.get("request_kinds", ()), "request_kinds"),
            produced_evidence_kinds=_string_array(data.get("produced_evidence_kinds", ()), "produced_evidence_kinds"),
            source_classes=_string_array(data.get("source_classes", ()), "source_classes"),
            snapshot_classes=_string_array(data.get("snapshot_classes", ()), "snapshot_classes"),
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
        _reject_unexpected_fields(
            data,
            {
                "schema_version", "kind", "fingerprint_format", "fingerprint",
                "request_id", "request_fingerprint", "provider_id",
                "provider_version", "status", "coverage", "evidence", "issues",
                "capability_fingerprint",
            },
            code="INVALID_EVIDENCE_PROVIDER_RESULT",
            noun="evidence provider result",
        )
        coverage_data = _require_mapping(data.get("coverage", {}), "coverage")
        _reject_unexpected_fields(
            coverage_data,
            {
                "schema_version", "kind", "fingerprint_format", "fingerprint",
                "completeness", "covered_evidence_kinds", "declared_scope",
                "observed_scope", "declared_bounds", "consumed", "termination",
                "truncated", "termination_reason", "source_identity",
                "snapshot_identity", "details",
            },
            code="INVALID_EVIDENCE_PROVIDER_RESULT",
            noun="evidence coverage",
        )
        evidence_data = data.get("evidence", ())
        issues_data = data.get("issues", ())
        if not isinstance(evidence_data, (list, tuple)) or not isinstance(issues_data, (list, tuple)):
            raise ProtocolError("INVALID_EVIDENCE_PROVIDER_RESULT", "evidence and issues must be arrays")
        coverage = EvidenceCoverage(
            schema_version=coverage_data.get("schema_version"),
            kind=coverage_data.get("kind"),
            fingerprint_format=coverage_data.get("fingerprint_format"),
            completeness=EvidenceCompleteness(str(coverage_data.get("completeness") or "")),
            covered_evidence_kinds=_string_array(coverage_data.get("covered_evidence_kinds", ()), "covered_evidence_kinds"),
            declared_scope=decode_markers(dict(_require_mapping(coverage_data.get("declared_scope", {}), "coverage declared_scope"))),
            observed_scope=decode_markers(dict(_require_mapping(coverage_data.get("observed_scope", {}), "coverage observed_scope"))),
            declared_bounds=decode_markers(dict(_require_mapping(coverage_data.get("declared_bounds", {}), "coverage declared_bounds"))),
            consumed=decode_markers(dict(_require_mapping(coverage_data.get("consumed", {}), "coverage consumed"))),
            termination=decode_markers(dict(_require_mapping(coverage_data.get("termination", {}), "coverage termination"))),
            truncated=coverage_data.get("truncated", False),
            termination_reason=str(coverage_data.get("termination_reason") or "UNKNOWN"),
            source_identity=decode_markers(dict(_require_mapping(coverage_data.get("source_identity", {}), "coverage source_identity"))),
            snapshot_identity=decode_markers(dict(_require_mapping(coverage_data.get("snapshot_identity", {}), "coverage snapshot_identity"))),
            details=decode_markers(dict(_require_mapping(coverage_data.get("details", {}), "coverage details"))),
        )
        supplied_coverage_fingerprint = coverage_data.get("fingerprint")
        if supplied_coverage_fingerprint is not None and supplied_coverage_fingerprint != coverage.fingerprint:
            raise ProtocolError("INVALID_EVIDENCE_PROVIDER_RESULT", "coverage fingerprint does not match canonical content")
        result = EvidenceProviderResult(
            schema_version=data.get("schema_version"),
            kind=data.get("kind"),
            fingerprint_format=data.get("fingerprint_format"),
            request_id=str(data.get("request_id") or ""),
            request_fingerprint=str(data.get("request_fingerprint") or ""),
            provider_id=str(data.get("provider_id") or ""),
            provider_version=str(data.get("provider_version") or ""),
            status=EvidenceAcquisitionStatus(str(data.get("status") or "")),
            coverage=coverage,
            evidence=tuple(_evidence_provider_evidence_record(_require_mapping(item, "evidence record")) for item in evidence_data),
            issues=tuple(_evidence_provider_issue(_require_mapping(item, "issue")) for item in issues_data),
            capability_fingerprint=str(data.get("capability_fingerprint") or ""),
        )
        supplied_result_fingerprint = data.get("fingerprint")
        if supplied_result_fingerprint is not None and supplied_result_fingerprint != result.fingerprint:
            raise ProtocolError("INVALID_EVIDENCE_PROVIDER_RESULT", "result fingerprint does not match canonical content")
        return result
    except ProtocolError:
        raise
    except (EvidenceProviderError, ValueError) as exc:
        raise ProtocolError("INVALID_EVIDENCE_PROVIDER_RESULT", str(exc)) from exc


def _evidence_provider_evidence_record(record: Mapping[str, Any]) -> Evidence:
    _reject_unexpected_fields(
        record,
        {"id", "kind", "payload", "source", "fingerprint"},
        code="INVALID_EVIDENCE_PROVIDER_RESULT",
        noun="evidence record",
    )
    return Evidence(
        id=str(record.get("id") or ""),
        kind=str(record.get("kind") or ""),
        payload=decode_markers(dict(_require_mapping(record.get("payload", {}), "evidence payload"))),
        source=record.get("source"),
        fingerprint=record.get("fingerprint"),
    )


def _evidence_provider_issue(issue: Mapping[str, Any]) -> EvidenceProviderIssue:
    _reject_unexpected_fields(
        issue,
        {"code", "category", "evidence_ids"},
        code="INVALID_EVIDENCE_PROVIDER_RESULT",
        noun="provider issue",
    )
    return EvidenceProviderIssue(
        code=issue.get("code"),
        category=issue.get("category"),
        evidence_ids=_string_array(issue.get("evidence_ids", ()), "issue evidence_ids"),
    )


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


def _strict_claim_graph(data: Mapping[str, Any]) -> ClaimGraph:
    _reject_unexpected_fields(
        data,
        {"schema_version", "kind", "nodes", "fingerprint"},
        code="INVALID_VERIFICATION_PLANNING_REQUEST",
        noun="claim graph",
    )
    if type(data.get("schema_version")) is not int:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "claim graph schema_version must be an integer",
        )
    nodes = data.get("nodes")
    if not isinstance(nodes, (list, tuple)):
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "claim graph nodes must be an array",
        )
    for item in nodes:
        node = _require_mapping(item, "claim graph node")
        node_type = node.get("node_type")
        allowed = (
            {
                "node_type", "claim_id", "claim_kind", "spec", "verifier",
                "scope", "dependencies",
            }
            if node_type == "ATOMIC"
            else {"node_type", "claim_id", "operator", "dependencies"}
        )
        _reject_unexpected_fields(
            node,
            allowed,
            code="INVALID_VERIFICATION_PLANNING_REQUEST",
            noun="claim graph node",
        )
    try:
        graph = _claim_graph(data)
    except ProtocolError as exc:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            exc.message,
        ) from exc
    supplied = data.get("fingerprint")
    if not isinstance(supplied, str) or supplied != graph.fingerprint:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "claim graph fingerprint does not match canonical content",
        )
    return graph


def _verifier_capability(data: Mapping[str, Any]) -> VerifierCapability:
    _reject_unexpected_fields(
        data,
        {
            "schema_version", "kind", "fingerprint_format", "fingerprint",
            "verifier_id", "version", "claim_kinds",
            "accepted_evidence_kinds", "required_evidence_kinds",
            "input_schema", "output_schema", "determinism",
            "side_effect_free", "cost", "bounds", "coverage",
            "authoritative", "description",
            "accepted_falsification_strategy_kinds",
            "falsification_requirement",
        },
        code="INVALID_VERIFICATION_PLANNING_REQUEST",
        noun="verifier capability",
    )
    if data.get("schema_version") != VERIFIER_CAPABILITY_SCHEMA_VERSION:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "unsupported verifier capability schema_version",
        )
    if data.get("kind") != VERIFIER_CAPABILITY_KIND:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "unsupported verifier capability kind",
        )
    if data.get("fingerprint_format") != VERIFIER_CAPABILITY_FINGERPRINT_FORMAT:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "unsupported verifier capability fingerprint format",
        )
    try:
        capability = VerifierCapability(
            verifier_id=data.get("verifier_id"),
            version=data.get("version"),
            claim_kinds=_string_array(data.get("claim_kinds"), "claim_kinds"),
            accepted_evidence_kinds=_string_array(
                data.get("accepted_evidence_kinds"),
                "accepted_evidence_kinds",
            ),
            required_evidence_kinds=_string_array(
                data.get("required_evidence_kinds"),
                "required_evidence_kinds",
            ),
            input_schema=decode_markers(dict(_require_mapping(
                data.get("input_schema"),
                "verifier input_schema",
            ))),
            output_schema=decode_markers(dict(_require_mapping(
                data.get("output_schema"),
                "verifier output_schema",
            ))),
            determinism=VerifierDeterminism(data.get("determinism")),
            side_effect_free=data.get("side_effect_free"),
            cost=VerifierCost(data.get("cost")),
            bounds=decode_markers(dict(_require_mapping(
                data.get("bounds"),
                "verifier bounds",
            ))),
            coverage=decode_markers(dict(_require_mapping(
                data.get("coverage"),
                "verifier coverage",
            ))),
            authoritative=data.get("authoritative"),
            accepted_falsification_strategy_kinds=tuple(
                FalsificationStrategyKind(item)
                for item in _string_array(
                    data.get("accepted_falsification_strategy_kinds", ()),
                    "accepted_falsification_strategy_kinds",
                )
            ),
            falsification_requirement=FalsificationRequirement(
                data.get("falsification_requirement", "NONE")
            ),
            description=data.get("description"),
        )
    except (ProtocolError, VerifierCapabilityError, TypeError, ValueError) as exc:
        if isinstance(exc, ProtocolError):
            raise ProtocolError(
                "INVALID_VERIFICATION_PLANNING_REQUEST",
                exc.message,
            ) from exc
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            str(exc),
        ) from exc
    if data.get("fingerprint") != capability.fingerprint:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "verifier capability fingerprint does not match canonical content",
        )
    return capability


def _verifier_capability_registry(
    data: Mapping[str, Any],
) -> VerifierCapabilityRegistry:
    _reject_unexpected_fields(
        data,
        {
            "schema_version", "kind", "fingerprint_format", "fingerprint",
            "capabilities",
        },
        code="INVALID_VERIFICATION_PLANNING_REQUEST",
        noun="verifier capability registry",
    )
    if data.get("schema_version") != VERIFIER_CAPABILITY_REGISTRY_SCHEMA_VERSION:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "unsupported verifier capability registry schema_version",
        )
    if data.get("kind") != VERIFIER_CAPABILITY_REGISTRY_KIND:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "unsupported verifier capability registry kind",
        )
    if (
        data.get("fingerprint_format")
        != VERIFIER_CAPABILITY_REGISTRY_FINGERPRINT_FORMAT
    ):
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "unsupported verifier capability registry fingerprint format",
        )
    items = data.get("capabilities")
    if not isinstance(items, (list, tuple)):
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "verifier capabilities must be an array",
        )
    try:
        registry = VerifierCapabilityRegistry(tuple(
            _verifier_capability(_require_mapping(item, "verifier capability"))
            for item in items
        ))
    except VerifierCapabilityError as exc:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            str(exc),
        ) from exc
    if data.get("fingerprint") != registry.fingerprint:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "verifier capability registry fingerprint does not match canonical content",
        )
    return registry


def _provider_capability_registry(
    data: Mapping[str, Any],
) -> EvidenceProviderCapabilityRegistry:
    _reject_unexpected_fields(
        data,
        {
            "schema_version", "kind", "fingerprint_format", "fingerprint",
            "capabilities",
        },
        code="INVALID_VERIFICATION_PLANNING_REQUEST",
        noun="evidence provider capability registry",
    )
    if data.get("schema_version") != EVIDENCE_PROVIDER_CAPABILITY_REGISTRY_SCHEMA_VERSION:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "unsupported evidence provider capability registry schema_version",
        )
    if data.get("kind") != EVIDENCE_PROVIDER_CAPABILITY_REGISTRY_KIND:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "unsupported evidence provider capability registry kind",
        )
    if (
        data.get("fingerprint_format")
        != EVIDENCE_PROVIDER_CAPABILITY_REGISTRY_FINGERPRINT_FORMAT
    ):
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "unsupported evidence provider capability registry fingerprint format",
        )
    items = data.get("capabilities")
    if not isinstance(items, (list, tuple)):
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "evidence provider capabilities must be an array",
        )
    try:
        capabilities = []
        for item in items:
            capability_data = _require_mapping(
                item,
                "evidence provider capability",
            )
            if not isinstance(capability_data.get("fingerprint"), str):
                raise ProtocolError(
                    "INVALID_VERIFICATION_PLANNING_REQUEST",
                    "evidence provider capability fingerprint is required",
                )
            capabilities.append(_evidence_provider_capability(capability_data))
        registry = EvidenceProviderCapabilityRegistry(tuple(capabilities))
    except (EvidenceProviderError, ProtocolError) as exc:
        if isinstance(exc, ProtocolError):
            raise ProtocolError(
                "INVALID_VERIFICATION_PLANNING_REQUEST",
                exc.message,
            ) from exc
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            str(exc),
        ) from exc
    if data.get("fingerprint") != registry.fingerprint:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "evidence provider capability registry fingerprint does not match canonical content",
        )
    return registry


def _falsification_strategy_descriptor(
    data: Mapping[str, Any],
) -> FalsificationStrategyDescriptor:
    _reject_unexpected_fields(
        data,
        {
            "schema_version", "kind", "fingerprint_format", "fingerprint",
            "strategy_id", "version", "strategy_kind", "claim_kinds",
            "input_schema", "output_schema", "determinism", "side_effect_free",
            "cost", "bounds", "coverage", "description",
        },
        code="INVALID_VERIFICATION_PLANNING_REQUEST",
        noun="falsification strategy descriptor",
    )
    if data.get("schema_version") != FALSIFICATION_STRATEGY_DESCRIPTOR_SCHEMA_VERSION:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "unsupported falsification strategy descriptor schema_version",
        )
    if data.get("kind") != FALSIFICATION_STRATEGY_DESCRIPTOR_KIND:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "unsupported falsification strategy descriptor kind",
        )
    if (
        data.get("fingerprint_format")
        != FALSIFICATION_STRATEGY_DESCRIPTOR_FINGERPRINT_FORMAT
    ):
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "unsupported falsification strategy descriptor fingerprint format",
        )
    try:
        descriptor = FalsificationStrategyDescriptor(
            strategy_id=data.get("strategy_id"),
            version=data.get("version"),
            strategy_kind=FalsificationStrategyKind(data.get("strategy_kind")),
            claim_kinds=_string_array(data.get("claim_kinds"), "claim_kinds"),
            input_schema=decode_markers(dict(_require_mapping(
                data.get("input_schema"),
                "falsification input_schema",
            ))),
            output_schema=decode_markers(dict(_require_mapping(
                data.get("output_schema"),
                "falsification output_schema",
            ))),
            determinism=VerifierDeterminism(data.get("determinism")),
            side_effect_free=data.get("side_effect_free"),
            cost=VerifierCost(data.get("cost")),
            bounds=decode_markers(dict(_require_mapping(
                data.get("bounds"),
                "falsification bounds",
            ))),
            coverage=decode_markers(dict(_require_mapping(
                data.get("coverage"),
                "falsification coverage",
            ))),
            description=data.get("description"),
            schema_version=data.get("schema_version"),
            kind=data.get("kind"),
            fingerprint_format=data.get("fingerprint_format"),
        )
    except (ProtocolError, FalsificationStrategyError, TypeError, ValueError) as exc:
        message = exc.message if isinstance(exc, ProtocolError) else str(exc)
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            message,
        ) from exc
    if data.get("fingerprint") != descriptor.fingerprint:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "falsification descriptor fingerprint does not match canonical content",
        )
    return descriptor


def _falsification_capability_registry(
    data: Mapping[str, Any],
) -> FalsificationStrategyCapabilityRegistry:
    _reject_unexpected_fields(
        data,
        {
            "schema_version", "kind", "fingerprint_format", "fingerprint",
            "capabilities",
        },
        code="INVALID_VERIFICATION_PLANNING_REQUEST",
        noun="falsification capability registry",
    )
    if (
        data.get("schema_version")
        != FALSIFICATION_STRATEGY_CAPABILITY_REGISTRY_SCHEMA_VERSION
        or data.get("kind") != FALSIFICATION_STRATEGY_CAPABILITY_REGISTRY_KIND
        or data.get("fingerprint_format")
        != FALSIFICATION_STRATEGY_CAPABILITY_REGISTRY_FINGERPRINT_FORMAT
    ):
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "unsupported falsification capability registry contract",
        )
    items = data.get("capabilities")
    if not isinstance(items, (list, tuple)):
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "falsification capabilities must be an array",
        )
    try:
        registry = FalsificationStrategyCapabilityRegistry(tuple(
            _falsification_strategy_descriptor(
                _require_mapping(item, "falsification strategy descriptor")
            )
            for item in items
        ))
    except FalsificationStrategyError as exc:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            str(exc),
        ) from exc
    if data.get("fingerprint") != registry.fingerprint:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "falsification capability registry fingerprint does not match canonical content",
        )
    return registry


def _planning_budget(data: Mapping[str, Any]) -> VerificationPlanningBudget:
    allowed = {
        "max_atomic_claims", "max_composite_claims", "max_steps",
        "max_requests", "max_dependency_edges", "max_requests_per_claim",
        "max_depth", "max_falsification_steps", "max_falsifications_per_claim",
    }
    _reject_unexpected_fields(
        data,
        allowed,
        code="INVALID_VERIFICATION_PLANNING_REQUEST",
        noun="verification planning budget",
    )
    try:
        return VerificationPlanningBudget(**{key: data.get(key) for key in allowed})
    except VerificationPlanningError as exc:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            str(exc),
        ) from exc


def _falsification_strategy_binding(
    data: Mapping[str, Any],
) -> FalsificationStrategyBinding:
    _reject_unexpected_fields(
        data,
        {
            "schema_version", "kind", "fingerprint_format", "fingerprint",
            "binding_id", "verifier_id", "strategy_id", "strategy_version",
            "strategy_capability_fingerprint", "parameters",
        },
        code="INVALID_VERIFICATION_PLANNING_REQUEST",
        noun="falsification strategy binding",
    )
    if (
        data.get("schema_version") != FALSIFICATION_STRATEGY_BINDING_SCHEMA_VERSION
        or data.get("kind") != FALSIFICATION_STRATEGY_BINDING_KIND
        or data.get("fingerprint_format")
        != FALSIFICATION_STRATEGY_BINDING_FINGERPRINT_FORMAT
    ):
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "unsupported falsification strategy binding contract",
        )
    try:
        binding = FalsificationStrategyBinding(
            binding_id=data.get("binding_id"),
            verifier_id=data.get("verifier_id"),
            strategy_id=data.get("strategy_id"),
            strategy_version=data.get("strategy_version"),
            strategy_capability_fingerprint=data.get(
                "strategy_capability_fingerprint"
            ),
            parameters=decode_markers(dict(_require_mapping(
                data.get("parameters"),
                "falsification strategy parameters",
            ))),
            schema_version=data.get("schema_version"),
            kind=data.get("kind"),
            fingerprint_format=data.get("fingerprint_format"),
        )
    except (ProtocolError, VerificationPlanningError) as exc:
        message = exc.message if isinstance(exc, ProtocolError) else str(exc)
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            message,
        ) from exc
    if data.get("fingerprint") != binding.fingerprint:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "falsification strategy binding fingerprint does not match canonical content",
        )
    return binding


def _atomic_claim_binding(data: Mapping[str, Any]) -> AtomicClaimBinding:
    _reject_unexpected_fields(
        data,
        {
            "schema_version", "kind", "fingerprint_format", "fingerprint",
            "claim_id", "verifier_id", "verifier_version",
            "verifier_capability_fingerprint", "evidence_requests",
            "falsification_bindings",
        },
        code="INVALID_VERIFICATION_PLANNING_REQUEST",
        noun="atomic claim binding",
    )
    if data.get("schema_version") != ATOMIC_CLAIM_BINDING_SCHEMA_VERSION:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "unsupported atomic claim binding schema_version",
        )
    if data.get("kind") != ATOMIC_CLAIM_BINDING_KIND:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "unsupported atomic claim binding kind",
        )
    if data.get("fingerprint_format") != ATOMIC_CLAIM_BINDING_FINGERPRINT_FORMAT:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "unsupported atomic claim binding fingerprint format",
        )
    items = data.get("evidence_requests")
    if not isinstance(items, (list, tuple)):
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "evidence_requests must be an array",
        )
    try:
        requests = []
        for item in items:
            request_data = _require_mapping(item, "evidence request")
            if not isinstance(request_data.get("fingerprint"), str):
                raise ProtocolError(
                    "INVALID_VERIFICATION_PLANNING_REQUEST",
                    "evidence request fingerprint is required",
                )
            requests.append(_evidence_provider_request(request_data))
        falsification_items = data.get("falsification_bindings", ())
        if not isinstance(falsification_items, (list, tuple)):
            raise ProtocolError(
                "INVALID_VERIFICATION_PLANNING_REQUEST",
                "falsification_bindings must be an array",
            )
        binding = AtomicClaimBinding(
            schema_version=data.get("schema_version"),
            kind=data.get("kind"),
            fingerprint_format=data.get("fingerprint_format"),
            claim_id=data.get("claim_id"),
            verifier_id=data.get("verifier_id"),
            verifier_version=data.get("verifier_version"),
            verifier_capability_fingerprint=data.get(
                "verifier_capability_fingerprint"
            ),
            evidence_requests=tuple(requests),
            falsification_bindings=tuple(
                _falsification_strategy_binding(_require_mapping(
                    item,
                    "falsification strategy binding",
                ))
                for item in falsification_items
            ),
        )
    except ProtocolError as exc:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            exc.message,
        ) from exc
    except VerificationPlanningError as exc:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            str(exc),
        ) from exc
    if data.get("fingerprint") != binding.fingerprint:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "atomic claim binding fingerprint does not match canonical content",
        )
    return binding


def _verification_planning_request(
    data: Mapping[str, Any],
) -> VerificationPlanningRequest:
    _reject_unexpected_fields(
        data,
        {
            "schema_version", "kind", "fingerprint_format", "fingerprint",
            "claim_graph", "bindings", "verifier_capability_registry",
            "verifier_capability_registry_fingerprint",
            "evidence_provider_capability_registry",
            "evidence_provider_capability_registry_fingerprint", "budget",
            "falsification_strategy_capability_registry",
            "falsification_strategy_capability_registry_fingerprint",
        },
        code="INVALID_VERIFICATION_PLANNING_REQUEST",
        noun="verification planning request",
    )
    if data.get("schema_version") != VERIFICATION_PLANNING_REQUEST_SCHEMA_VERSION:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "unsupported verification planning request schema_version",
        )
    if data.get("kind") != VERIFICATION_PLANNING_REQUEST_KIND:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "unsupported verification planning request kind",
        )
    if (
        data.get("fingerprint_format")
        != VERIFICATION_PLANNING_REQUEST_FINGERPRINT_FORMAT
    ):
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "unsupported verification planning request fingerprint format",
        )
    bindings_data = data.get("bindings")
    if not isinstance(bindings_data, (list, tuple)):
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "bindings must be an array",
        )
    try:
        request = VerificationPlanningRequest(
            schema_version=data.get("schema_version"),
            kind=data.get("kind"),
            fingerprint_format=data.get("fingerprint_format"),
            claim_graph=_strict_claim_graph(_require_mapping(
                data.get("claim_graph"),
                "claim_graph",
            )),
            bindings=tuple(
                _atomic_claim_binding(_require_mapping(item, "atomic claim binding"))
                for item in bindings_data
            ),
            verifier_capability_registry=_verifier_capability_registry(
                _require_mapping(
                    data.get("verifier_capability_registry"),
                    "verifier_capability_registry",
                )
            ),
            verifier_capability_registry_fingerprint=data.get(
                "verifier_capability_registry_fingerprint"
            ),
            evidence_provider_capability_registry=_provider_capability_registry(
                _require_mapping(
                    data.get("evidence_provider_capability_registry"),
                    "evidence_provider_capability_registry",
                )
            ),
            evidence_provider_capability_registry_fingerprint=data.get(
                "evidence_provider_capability_registry_fingerprint"
            ),
            falsification_strategy_capability_registry=(
                None
                if data.get("falsification_strategy_capability_registry") is None
                else _falsification_capability_registry(_require_mapping(
                    data.get("falsification_strategy_capability_registry"),
                    "falsification_strategy_capability_registry",
                ))
            ),
            falsification_strategy_capability_registry_fingerprint=data.get(
                "falsification_strategy_capability_registry_fingerprint"
            ),
            budget=_planning_budget(_require_mapping(data.get("budget"), "budget")),
        )
    except ProtocolError:
        raise
    except VerificationPlanningError as exc:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            str(exc),
        ) from exc
    if data.get("fingerprint") != request.fingerprint:
        raise ProtocolError(
            "INVALID_VERIFICATION_PLANNING_REQUEST",
            "verification planning request fingerprint does not match canonical content",
        )
    return request


def _execution_protocol_error(message: str) -> ProtocolError:
    return ProtocolError("INVALID_VERIFICATION_EXECUTION_REQUEST", message)


def _optional_string(value: Any, *, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise _execution_protocol_error(f"{name} must be a string or null")
    return value


def _verification_plan_step(data: Mapping[str, Any]) -> VerificationPlanStep:
    _reject_unexpected_fields(
        data,
        {
            "kind", "dependency_step_ids", "claim_id", "claim_kind",
            "claim_fingerprint", "operator", "request_id",
            "request_fingerprint", "request_kind", "requested_evidence_kinds",
            "provider_id", "provider_version", "provider_capability_fingerprint",
            "verifier_id", "verifier_version", "verifier_capability_fingerprint",
            "binding_id", "strategy_id", "strategy_version", "strategy_kind",
            "strategy_capability_fingerprint", "strategy_parameters",
            "strategy_parameters_fingerprint", "fingerprint", "step_id",
        },
        code="INVALID_VERIFICATION_EXECUTION_REQUEST",
        noun="verification plan step",
    )
    try:
        raw_operator = data.get("operator")
        step = VerificationPlanStep(
            kind=VerificationPlanStepKind(data.get("kind")),
            dependency_step_ids=_string_array(
                data.get("dependency_step_ids", ()),
                "dependency_step_ids",
            ),
            claim_id=_optional_string(data.get("claim_id"), name="claim_id"),
            claim_kind=_optional_string(data.get("claim_kind"), name="claim_kind"),
            claim_fingerprint=_optional_string(
                data.get("claim_fingerprint"),
                name="claim_fingerprint",
            ),
            operator=(
                None if raw_operator is None else ClaimOperator(raw_operator)
            ),
            request_id=_optional_string(data.get("request_id"), name="request_id"),
            request_fingerprint=_optional_string(
                data.get("request_fingerprint"),
                name="request_fingerprint",
            ),
            request_kind=_optional_string(
                data.get("request_kind"),
                name="request_kind",
            ),
            requested_evidence_kinds=_string_array(
                data.get("requested_evidence_kinds", ()),
                "requested_evidence_kinds",
            ),
            provider_id=_optional_string(
                data.get("provider_id"),
                name="provider_id",
            ),
            provider_version=_optional_string(
                data.get("provider_version"),
                name="provider_version",
            ),
            provider_capability_fingerprint=_optional_string(
                data.get("provider_capability_fingerprint"),
                name="provider_capability_fingerprint",
            ),
            verifier_id=_optional_string(
                data.get("verifier_id"),
                name="verifier_id",
            ),
            verifier_version=_optional_string(
                data.get("verifier_version"),
                name="verifier_version",
            ),
            verifier_capability_fingerprint=_optional_string(
                data.get("verifier_capability_fingerprint"),
                name="verifier_capability_fingerprint",
            ),
            binding_id=_optional_string(data.get("binding_id"), name="binding_id"),
            strategy_id=_optional_string(data.get("strategy_id"), name="strategy_id"),
            strategy_version=_optional_string(
                data.get("strategy_version"),
                name="strategy_version",
            ),
            strategy_kind=(
                None
                if data.get("strategy_kind") is None
                else FalsificationStrategyKind(data.get("strategy_kind"))
            ),
            strategy_capability_fingerprint=_optional_string(
                data.get("strategy_capability_fingerprint"),
                name="strategy_capability_fingerprint",
            ),
            strategy_parameters=(
                None
                if data.get("strategy_parameters") is None
                else decode_markers(dict(_require_mapping(
                    data.get("strategy_parameters"),
                    "strategy_parameters",
                )))
            ),
        )
    except (ProtocolError, VerificationPlanningError, TypeError, ValueError) as exc:
        if isinstance(exc, ProtocolError):
            raise _execution_protocol_error(exc.message) from exc
        raise _execution_protocol_error(str(exc)) from exc
    if data.get("fingerprint") != step.fingerprint:
        raise _execution_protocol_error(
            "verification plan step fingerprint does not match canonical content"
        )
    if data.get("step_id") != step.step_id:
        raise _execution_protocol_error(
            "verification plan step_id does not match canonical content"
        )
    if (
        "strategy_parameters_fingerprint" in data
        and data.get("strategy_parameters_fingerprint")
        != step.strategy_parameters_fingerprint
    ):
        raise _execution_protocol_error(
            "strategy parameters fingerprint does not match canonical content"
        )
    return step


def _verification_plan(data: Mapping[str, Any]) -> VerificationPlan:
    _reject_unexpected_fields(
        data,
        {
            "schema_version", "kind", "fingerprint_format", "fingerprint",
            "request_fingerprint", "claim_graph_fingerprint",
            "verifier_capability_registry_fingerprint",
            "evidence_provider_capability_registry_fingerprint", "budget",
            "falsification_strategy_capability_registry_fingerprint",
            "consumption", "termination", "steps", "issues",
        },
        code="INVALID_VERIFICATION_EXECUTION_REQUEST",
        noun="verification plan",
    )
    if data.get("schema_version") != VERIFICATION_PLAN_SCHEMA_VERSION:
        raise _execution_protocol_error(
            "unsupported verification plan schema_version"
        )
    if data.get("kind") != VERIFICATION_PLAN_KIND:
        raise _execution_protocol_error("unsupported verification plan kind")
    if data.get("fingerprint_format") != VERIFICATION_PLAN_FINGERPRINT_FORMAT:
        raise _execution_protocol_error(
            "unsupported verification plan fingerprint format"
        )
    consumption_data = _require_mapping(
        data.get("consumption"),
        "verification plan consumption",
    )
    _reject_unexpected_fields(
        consumption_data,
        {
            "atomic_claims", "composite_claims", "steps", "requests",
            "dependency_edges", "requests_per_claim", "depth",
            "falsification_steps", "falsifications_per_claim",
        },
        code="INVALID_VERIFICATION_EXECUTION_REQUEST",
        noun="verification plan consumption",
    )
    steps_data = data.get("steps")
    issues_data = data.get("issues")
    if not isinstance(steps_data, (list, tuple)):
        raise _execution_protocol_error("verification plan steps must be an array")
    if not isinstance(issues_data, (list, tuple)):
        raise _execution_protocol_error("verification plan issues must be an array")
    try:
        issues: list[VerificationPlannerIssue] = []
        for item in issues_data:
            issue_data = _require_mapping(item, "verification planner issue")
            _reject_unexpected_fields(
                issue_data,
                {"code", "claim_id", "request_id", "details"},
                code="INVALID_VERIFICATION_EXECUTION_REQUEST",
                noun="verification planner issue",
            )
            issues.append(VerificationPlannerIssue(
                code=issue_data.get("code"),
                claim_id=_optional_string(
                    issue_data.get("claim_id"),
                    name="issue claim_id",
                ),
                request_id=_optional_string(
                    issue_data.get("request_id"),
                    name="issue request_id",
                ),
                details=decode_markers(dict(_require_mapping(
                    issue_data.get("details", {}),
                    "verification planner issue details",
                ))),
            ))
        plan = VerificationPlan(
            request_fingerprint=data.get("request_fingerprint"),
            claim_graph_fingerprint=data.get("claim_graph_fingerprint"),
            verifier_capability_registry_fingerprint=data.get(
                "verifier_capability_registry_fingerprint"
            ),
            evidence_provider_capability_registry_fingerprint=data.get(
                "evidence_provider_capability_registry_fingerprint"
            ),
            falsification_strategy_capability_registry_fingerprint=data.get(
                "falsification_strategy_capability_registry_fingerprint"
            ),
            budget=_planning_budget(_require_mapping(data.get("budget"), "budget")),
            consumption=VerificationPlanningConsumption(
                atomic_claims=consumption_data.get("atomic_claims"),
                composite_claims=consumption_data.get("composite_claims"),
                steps=consumption_data.get("steps"),
                requests=consumption_data.get("requests"),
                dependency_edges=consumption_data.get("dependency_edges"),
                requests_per_claim=consumption_data.get("requests_per_claim"),
                depth=consumption_data.get("depth"),
                falsification_steps=consumption_data.get(
                    "falsification_steps",
                    0,
                ),
                falsifications_per_claim=consumption_data.get(
                    "falsifications_per_claim",
                    0,
                ),
            ),
            termination=VerificationPlanTermination(data.get("termination")),
            steps=tuple(
                _verification_plan_step(_require_mapping(item, "verification plan step"))
                for item in steps_data
            ),
            issues=tuple(issues),
            schema_version=data.get("schema_version"),
            kind=data.get("kind"),
            fingerprint_format=data.get("fingerprint_format"),
        )
    except ProtocolError:
        raise
    except (VerificationPlanningError, TypeError, ValueError) as exc:
        raise _execution_protocol_error(str(exc)) from exc
    if data.get("fingerprint") != plan.fingerprint:
        raise _execution_protocol_error(
            "verification plan fingerprint does not match canonical content"
        )
    return plan


def _runtime_keys(value: Any, *, noun: str) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, (list, tuple)):
        raise _execution_protocol_error(f"{noun} runtime_keys must be an array")
    keys: list[tuple[str, str]] = []
    for item in value:
        if (
            not isinstance(item, (list, tuple))
            or len(item) != 2
            or not all(isinstance(part, str) and part for part in item)
        ):
            raise _execution_protocol_error(
                f"{noun} runtime_keys must contain [id, version] pairs"
            )
        keys.append((item[0], item[1]))
    if len(set(keys)) != len(keys):
        raise _execution_protocol_error(f"{noun} runtime_keys contain duplicates")
    return tuple(keys)


def _verifier_runtime_registry(
    data: Mapping[str, Any],
    supplied: VerifierRuntimeRegistry | None,
) -> VerifierRuntimeRegistry:
    _reject_unexpected_fields(
        data,
        {
            "schema_version", "kind", "fingerprint_format", "fingerprint",
            "capability_registry_fingerprint", "runtime_keys",
            "capability_registry",
        },
        code="INVALID_VERIFICATION_EXECUTION_REQUEST",
        noun="verifier runtime registry",
    )
    if data.get("schema_version") != VERIFIER_RUNTIME_REGISTRY_SCHEMA_VERSION:
        raise _execution_protocol_error(
            "unsupported verifier runtime registry schema_version"
        )
    if data.get("kind") != VERIFIER_RUNTIME_REGISTRY_KIND:
        raise _execution_protocol_error("unsupported verifier runtime registry kind")
    if data.get("fingerprint_format") != VERIFIER_RUNTIME_REGISTRY_FINGERPRINT_FORMAT:
        raise _execution_protocol_error(
            "unsupported verifier runtime registry fingerprint format"
        )
    try:
        capability_registry = _verifier_capability_registry(_require_mapping(
            data.get("capability_registry"),
            "verifier capability registry",
        ))
    except ProtocolError as exc:
        raise _execution_protocol_error(exc.message) from exc
    registry = (
        builtin_verifier_runtime_registry(capability_registry)
        if supplied is None
        else supplied
    )
    if type(registry) is not VerifierRuntimeRegistry:
        raise _execution_protocol_error(
            "verifier_runtime_registry must be an exact VerifierRuntimeRegistry"
        )
    expected_keys = _runtime_keys(
        data.get("runtime_keys"),
        noun="verifier runtime registry",
    )
    if registry.capability_registry.fingerprint != capability_registry.fingerprint:
        raise _execution_protocol_error(
            "verifier runtime capability registry does not match payload"
        )
    if set(expected_keys) != set(registry.runtime_keys):
        raise _execution_protocol_error(
            "verifier runtime keys do not match exact runtime registry"
        )
    if data.get("capability_registry_fingerprint") != capability_registry.fingerprint:
        raise _execution_protocol_error(
            "verifier runtime capability fingerprint does not match registry"
        )
    if data.get("fingerprint") != registry.fingerprint:
        raise _execution_protocol_error(
            "verifier runtime registry fingerprint does not match exact registry"
        )
    return registry


def _provider_runtime_registry(
    data: Mapping[str, Any],
    supplied: EvidenceProviderRuntimeRegistry | None,
) -> EvidenceProviderRuntimeRegistry:
    _reject_unexpected_fields(
        data,
        {
            "schema_version", "kind", "fingerprint_format", "fingerprint",
            "capability_registry_fingerprint", "runtime_keys",
            "capability_registry",
        },
        code="INVALID_VERIFICATION_EXECUTION_REQUEST",
        noun="evidence provider runtime registry",
    )
    if data.get("schema_version") != EVIDENCE_PROVIDER_RUNTIME_REGISTRY_SCHEMA_VERSION:
        raise _execution_protocol_error(
            "unsupported evidence provider runtime registry schema_version"
        )
    if data.get("kind") != EVIDENCE_PROVIDER_RUNTIME_REGISTRY_KIND:
        raise _execution_protocol_error(
            "unsupported evidence provider runtime registry kind"
        )
    if (
        data.get("fingerprint_format")
        != EVIDENCE_PROVIDER_RUNTIME_REGISTRY_FINGERPRINT_FORMAT
    ):
        raise _execution_protocol_error(
            "unsupported evidence provider runtime registry fingerprint format"
        )
    try:
        capability_registry = _provider_capability_registry(_require_mapping(
            data.get("capability_registry"),
            "evidence provider capability registry",
        ))
    except ProtocolError as exc:
        raise _execution_protocol_error(exc.message) from exc
    registry = (
        EvidenceProviderRuntimeRegistry(capability_registry, {})
        if supplied is None
        else supplied
    )
    if type(registry) is not EvidenceProviderRuntimeRegistry:
        raise _execution_protocol_error(
            "evidence_provider_runtime_registry must be an exact EvidenceProviderRuntimeRegistry"
        )
    expected_keys = _runtime_keys(
        data.get("runtime_keys"),
        noun="evidence provider runtime registry",
    )
    if registry.capability_registry.fingerprint != capability_registry.fingerprint:
        raise _execution_protocol_error(
            "provider runtime capability registry does not match payload"
        )
    if set(expected_keys) != set(registry.runtime_keys):
        raise _execution_protocol_error(
            "provider runtime keys do not match exact runtime registry"
        )
    if data.get("capability_registry_fingerprint") != capability_registry.fingerprint:
        raise _execution_protocol_error(
            "provider runtime capability fingerprint does not match registry"
        )
    if data.get("fingerprint") != registry.fingerprint:
        raise _execution_protocol_error(
            "provider runtime registry fingerprint does not match exact registry"
        )
    return registry


def _falsification_runtime_registry(
    data: Mapping[str, Any],
    supplied: FalsificationStrategyRuntimeRegistry | None,
) -> FalsificationStrategyRuntimeRegistry:
    _reject_unexpected_fields(
        data,
        {
            "schema_version", "kind", "fingerprint_format", "fingerprint",
            "capability_registry_fingerprint", "runtime_keys",
            "capability_registry",
        },
        code="INVALID_VERIFICATION_EXECUTION_REQUEST",
        noun="falsification runtime registry",
    )
    if (
        data.get("schema_version")
        != FALSIFICATION_STRATEGY_RUNTIME_REGISTRY_SCHEMA_VERSION
        or data.get("kind") != FALSIFICATION_STRATEGY_RUNTIME_REGISTRY_KIND
        or data.get("fingerprint_format")
        != FALSIFICATION_STRATEGY_RUNTIME_REGISTRY_FINGERPRINT_FORMAT
    ):
        raise _execution_protocol_error(
            "unsupported falsification runtime registry contract"
        )
    try:
        capability_registry = _falsification_capability_registry(
            _require_mapping(
                data.get("capability_registry"),
                "falsification capability registry",
            )
        )
    except ProtocolError as exc:
        raise _execution_protocol_error(exc.message) from exc
    registry = (
        builtin_falsification_strategy_runtime_registry(capability_registry)
        if supplied is None
        else supplied
    )
    if type(registry) is not FalsificationStrategyRuntimeRegistry:
        raise _execution_protocol_error(
            "falsification_strategy_runtime_registry must be exact"
        )
    expected_keys = _runtime_keys(
        data.get("runtime_keys"),
        noun="falsification runtime registry",
    )
    if registry.capability_registry.fingerprint != capability_registry.fingerprint:
        raise _execution_protocol_error(
            "falsification runtime capability registry does not match payload"
        )
    if set(expected_keys) != set(registry.runtime_keys):
        raise _execution_protocol_error(
            "falsification runtime keys do not match exact runtime registry"
        )
    if data.get("capability_registry_fingerprint") != capability_registry.fingerprint:
        raise _execution_protocol_error(
            "falsification runtime capability fingerprint does not match registry"
        )
    if data.get("fingerprint") != registry.fingerprint:
        raise _execution_protocol_error(
            "falsification runtime registry fingerprint does not match exact registry"
        )
    return registry


def _execution_limits(data: Mapping[str, Any]) -> VerificationExecutionLimits:
    allowed = {
        "max_steps", "max_acquisitions", "max_verifier_invocations",
        "max_compositions", "max_evidence_records", "max_evidence_bytes",
        "max_falsification_invocations",
    }
    _reject_unexpected_fields(
        data,
        allowed,
        code="INVALID_VERIFICATION_EXECUTION_REQUEST",
        noun="verification execution limits",
    )
    try:
        return VerificationExecutionLimits(**{
            key: data.get(key) for key in allowed
        })
    except VerificationExecutionError as exc:
        raise _execution_protocol_error(str(exc)) from exc


def _verification_execution_request(
    data: Mapping[str, Any],
    *,
    verifier_runtime_registry: VerifierRuntimeRegistry | None,
    evidence_provider_runtime_registry: EvidenceProviderRuntimeRegistry | None,
    falsification_strategy_runtime_registry: (
        FalsificationStrategyRuntimeRegistry | None
    ),
) -> VerificationExecutionRequest:
    _reject_unexpected_fields(
        data,
        {
            "schema_version", "kind", "fingerprint_format", "fingerprint",
            "plan", "plan_fingerprint", "claim_graph",
            "claim_graph_fingerprint", "roots", "verifier_runtime_registry",
            "verifier_capability_registry_fingerprint",
            "evidence_provider_runtime_registry",
            "evidence_provider_capability_registry_fingerprint",
            "falsification_strategy_runtime_registry",
            "falsification_strategy_capability_registry_fingerprint",
            "evidence_requests", "limits", "correlation_id",
        },
        code="INVALID_VERIFICATION_EXECUTION_REQUEST",
        noun="verification execution request",
    )
    if data.get("schema_version") != VERIFICATION_EXECUTION_REQUEST_SCHEMA_VERSION:
        raise _execution_protocol_error(
            "unsupported verification execution request schema_version"
        )
    if data.get("kind") != VERIFICATION_EXECUTION_REQUEST_KIND:
        raise _execution_protocol_error(
            "unsupported verification execution request kind"
        )
    if (
        data.get("fingerprint_format")
        != VERIFICATION_EXECUTION_REQUEST_FINGERPRINT_FORMAT
    ):
        raise _execution_protocol_error(
            "unsupported verification execution request fingerprint format"
        )
    requests_data = data.get("evidence_requests")
    if not isinstance(requests_data, (list, tuple)):
        raise _execution_protocol_error("evidence_requests must be an array")
    exact_requests: dict[tuple[str, str], EvidenceRequest] = {}
    for item in requests_data:
        entry = _require_mapping(item, "exact evidence request")
        _reject_unexpected_fields(
            entry,
            {"request_id", "request_fingerprint", "request"},
            code="INVALID_VERIFICATION_EXECUTION_REQUEST",
            noun="exact evidence request",
        )
        request_data = _require_mapping(entry.get("request"), "evidence request")
        if not isinstance(request_data.get("fingerprint"), str):
            raise _execution_protocol_error(
                "nested evidence request fingerprint is required"
            )
        try:
            parsed = _evidence_provider_request(request_data)
        except ProtocolError as exc:
            raise _execution_protocol_error(exc.message) from exc
        key = (entry.get("request_id"), entry.get("request_fingerprint"))
        if key != (parsed.request_id, parsed.fingerprint):
            raise _execution_protocol_error(
                "exact evidence request key does not match nested request"
            )
        if key in exact_requests:
            raise _execution_protocol_error(
                "duplicate exact evidence request identity"
            )
        exact_requests[key] = parsed
    correlation_id = data.get("correlation_id")
    if correlation_id is not None and not isinstance(correlation_id, str):
        raise _execution_protocol_error("correlation_id must be a string or null")
    try:
        request = VerificationExecutionRequest(
            schema_version=data.get("schema_version"),
            kind=data.get("kind"),
            fingerprint_format=data.get("fingerprint_format"),
            plan=_verification_plan(_require_mapping(data.get("plan"), "plan")),
            plan_fingerprint=data.get("plan_fingerprint"),
            claim_graph=_strict_claim_graph(_require_mapping(
                data.get("claim_graph"),
                "claim_graph",
            )),
            claim_graph_fingerprint=data.get("claim_graph_fingerprint"),
            roots=_string_array(data.get("roots"), "roots"),
            verifier_runtime_registry=_verifier_runtime_registry(
                _require_mapping(
                    data.get("verifier_runtime_registry"),
                    "verifier_runtime_registry",
                ),
                verifier_runtime_registry,
            ),
            verifier_capability_registry_fingerprint=data.get(
                "verifier_capability_registry_fingerprint"
            ),
            evidence_provider_runtime_registry=_provider_runtime_registry(
                _require_mapping(
                    data.get("evidence_provider_runtime_registry"),
                    "evidence_provider_runtime_registry",
                ),
                evidence_provider_runtime_registry,
            ),
            evidence_provider_capability_registry_fingerprint=data.get(
                "evidence_provider_capability_registry_fingerprint"
            ),
            evidence_requests=exact_requests,
            falsification_strategy_runtime_registry=(
                None
                if data.get("falsification_strategy_runtime_registry") is None
                else _falsification_runtime_registry(
                    _require_mapping(
                        data.get("falsification_strategy_runtime_registry"),
                        "falsification_strategy_runtime_registry",
                    ),
                    falsification_strategy_runtime_registry,
                )
            ),
            falsification_strategy_capability_registry_fingerprint=data.get(
                "falsification_strategy_capability_registry_fingerprint"
            ),
            limits=_execution_limits(_require_mapping(data.get("limits"), "limits")),
            correlation_id=correlation_id,
        )
    except ProtocolError as exc:
        if exc.code == "INVALID_VERIFICATION_EXECUTION_REQUEST":
            raise
        raise _execution_protocol_error(exc.message) from exc
    except VerificationExecutionError as exc:
        raise _execution_protocol_error(str(exc)) from exc
    if data.get("fingerprint") != request.fingerprint:
        raise _execution_protocol_error(
            "verification execution request fingerprint does not match canonical content"
        )
    return request


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


def handle_request(
    request: Mapping[str, Any],
    *,
    verifier_runtime_registry: VerifierRuntimeRegistry | None = None,
    evidence_provider_runtime_registry: EvidenceProviderRuntimeRegistry | None = None,
    falsification_strategy_runtime_registry: (
        FalsificationStrategyRuntimeRegistry | None
    ) = None,
) -> dict[str, Any]:
    if request.get("schema_version") != SCHEMA_VERSION:
        raise ProtocolError(
            "UNSUPPORTED_SCHEMA_VERSION",
            f"expected schema_version={SCHEMA_VERSION}",
        )
    op = str(request.get("op") or "")
    try:
        payload = _require_mapping(request.get("payload", {}), "payload")
    except ProtocolError as exc:
        if op == "execute_verification_plan":
            raise ProtocolError(
                "INVALID_VERIFICATION_EXECUTION_REQUEST",
                exc.message,
            ) from exc
        raise

    if op == "execute_verification_plan":
        unexpected_request_fields = set(request) - {
            "schema_version", "op", "payload",
        }
        if unexpected_request_fields:
            raise ProtocolError(
                "INVALID_VERIFICATION_EXECUTION_REQUEST",
                "unsupported protocol request fields: "
                + ", ".join(sorted(unexpected_request_fields)),
            )
        try:
            execution_request = _verification_execution_request(
                payload,
                verifier_runtime_registry=verifier_runtime_registry,
                evidence_provider_runtime_registry=evidence_provider_runtime_registry,
                falsification_strategy_runtime_registry=(
                    falsification_strategy_runtime_registry
                ),
            )
        except ProtocolError as exc:
            if exc.code == "INVALID_VERIFICATION_EXECUTION_REQUEST":
                raise
            raise ProtocolError(
                "INVALID_VERIFICATION_EXECUTION_REQUEST",
                exc.message,
            ) from exc
        try:
            result = execute_verification_plan(execution_request)
        except VerificationExecutionError as exc:
            raise ProtocolError(
                "INVALID_VERIFICATION_EXECUTION_REQUEST",
                str(exc),
            ) from exc
        return envelope("verification_execution_result", result.to_dict())

    if op == "compile_verification_plan":
        unexpected_request_fields = set(request) - {
            "schema_version", "op", "payload",
        }
        if unexpected_request_fields:
            raise ProtocolError(
                "INVALID_VERIFICATION_PLANNING_REQUEST",
                "unsupported protocol request fields: "
                + ", ".join(sorted(unexpected_request_fields)),
            )
        planning_request = _verification_planning_request(payload)
        try:
            plan = compile_verification_plan(planning_request)
        except VerificationPlanningError as exc:
            raise ProtocolError(
                "INVALID_VERIFICATION_PLANNING_REQUEST",
                str(exc),
            ) from exc
        return envelope("verification_plan", plan.to_dict())

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
            capabilities = builtin_evidence_provider_capability_registry().query(
                request_kind=request_kind,
                evidence_kind=evidence_kind,
            )
            registry = EvidenceProviderCapabilityRegistry(capabilities)
        except EvidenceProviderError as exc:
            raise ProtocolError("INVALID_PAYLOAD", str(exc)) from exc
        return envelope("evidence_provider_capability_registry", registry.to_dict())

    if op == "describe_falsification_strategy_capabilities":
        unexpected = set(payload) - {"strategy_kind", "claim_kind"}
        if unexpected:
            raise ProtocolError(
                "INVALID_PAYLOAD",
                "unsupported falsification capability query fields: "
                + ", ".join(sorted(unexpected)),
            )
        strategy_kind = payload.get("strategy_kind")
        claim_kind = payload.get("claim_kind")
        if strategy_kind is not None and not isinstance(strategy_kind, str):
            raise ProtocolError(
                "INVALID_PAYLOAD",
                "strategy_kind must be a string",
            )
        if claim_kind is not None and not isinstance(claim_kind, str):
            raise ProtocolError("INVALID_PAYLOAD", "claim_kind must be a string")
        try:
            capabilities = (
                builtin_falsification_strategy_capability_registry().query(
                    strategy_kind=(
                        None
                        if strategy_kind is None
                        else FalsificationStrategyKind(strategy_kind)
                    ),
                    claim_kind=claim_kind,
                )
            )
            registry = FalsificationStrategyCapabilityRegistry(capabilities)
        except (FalsificationStrategyError, ValueError) as exc:
            raise ProtocolError("INVALID_PAYLOAD", str(exc)) from exc
        return envelope(
            "falsification_strategy_capability_registry",
            registry.to_dict(),
        )

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


def safe_handle_request(
    request: Mapping[str, Any],
    *,
    verifier_runtime_registry: VerifierRuntimeRegistry | None = None,
    evidence_provider_runtime_registry: EvidenceProviderRuntimeRegistry | None = None,
    falsification_strategy_runtime_registry: (
        FalsificationStrategyRuntimeRegistry | None
    ) = None,
) -> dict[str, Any]:
    try:
        return handle_request(
            request,
            verifier_runtime_registry=verifier_runtime_registry,
            evidence_provider_runtime_registry=evidence_provider_runtime_registry,
            falsification_strategy_runtime_registry=(
                falsification_strategy_runtime_registry
            ),
        )
    except ProtocolError as exc:
        return envelope("protocol_error", {"code": exc.code, "message": exc.message})
