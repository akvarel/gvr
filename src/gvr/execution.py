from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
import re
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Protocol, runtime_checkable

from .bundle import BundleValidationError, VerificationBundle, build_verification_bundle
from .canonical import (
    CanonicalizationError,
    canonical_fingerprint,
    canonical_transport_json,
    canonical_utf8_key,
)
from .capabilities import (
    FalsificationRequirement,
    VerifierCapability,
    VerifierCapabilityError,
    VerifierCapabilityRegistry,
    builtin_verifier_capability_registry,
)
from .code_graph import (
    CODE_GRAPH_OBSERVATION_EVIDENCE_KIND,
    CodeGraphObservationError,
    decode_code_graph_observation_evidence,
    GraphQueryScope,
    SourceRevisionIdentity,
)
from .falsification import (
    FalsificationDependency,
    FalsificationExecutionInput,
    FalsificationOutcome,
    FalsificationResult,
    FalsificationStrategyCapabilityRegistry,
    FalsificationStrategyDescriptor,
    FalsificationStrategyError,
    FalsificationStrategyRuntimeRegistry,
    UnknownFalsificationStrategyError,
    validate_falsification_result,
)
from .evidence_providers import (
    EvidenceAcquisitionStatus,
    EvidenceCoverage,
    EvidenceProviderCapability,
    EvidenceProviderCapabilityRegistry,
    EvidenceProviderError,
    EvidenceProviderResult,
    EvidenceProviderRuntimeRegistry,
    EvidenceProviderVerifierInput,
    EvidenceRequest,
    UnknownEvidenceProviderError,
    provider_result_for_verifier,
    validate_evidence_provider_result,
)
from .model import (
    Evidence,
    VerificationIssue,
    VerificationReport,
    VerificationVerdict,
)
from .planning import (
    ATOMIC_CLAIM_FINGERPRINT_FORMAT,
    COMPOSITE_CLAIM_FINGERPRINT_FORMAT,
    AtomicClaimBinding,
    FalsificationStrategyBinding,
    VerificationPlan,
    VerificationPlannerIssue,
    VerificationPlanningBudget,
    VerificationPlanningConsumption,
    VerificationPlanningError,
    VerificationPlanningRequest,
    VerificationPlanStep,
    VerificationPlanStepKind,
    VerificationPlanTermination,
    compile_verification_plan,
)
from .session import (
    AtomicClaim,
    ClaimGraph,
    ClaimGraphValidationError,
    CompositeClaim,
    VerificationSession,
    VerificationSessionError,
)
from .verifiers.data_flow import (
    DATA_FLOW_VERIFIER,
    DataFlowClaim,
    DataFlowClaimKind,
    DataFlowQueryScope,
    SourceRevision,
    SUPPORTED_DATA_FLOW_RELATIONS,
    verify_data_flow_claim,
)
from .verifiers.code_graph import (
    CODE_GRAPH_VERIFIER,
    CodeGraphClaim,
    CodeGraphClaimKind,
    CodeGraphScope,
    verify_code_graph_claim,
    verify_code_graph_observation,
)
from .verifiers.corroboration import (
    ProviderVerificationObservation,
    reconcile_provider_observations,
)


VERIFIER_RUNTIME_REGISTRY_SCHEMA_VERSION = 1
VERIFIER_RUNTIME_REGISTRY_KIND = "gvr.verifier_runtime_registry"
VERIFIER_RUNTIME_REGISTRY_FINGERPRINT_FORMAT = (
    "gvr.verifier_runtime_registry.ieee754-json.v1"
)
VERIFICATION_EXECUTION_REQUEST_SCHEMA_VERSION = 1
VERIFICATION_EXECUTION_REQUEST_KIND = "gvr.verification_execution_request"
VERIFICATION_EXECUTION_REQUEST_FINGERPRINT_FORMAT = (
    "gvr.verification_execution_request.ieee754-json.v1"
)
VERIFICATION_EXECUTION_RESULT_SCHEMA_VERSION = 1
VERIFICATION_EXECUTION_RESULT_KIND = "gvr.verification_execution_result"
VERIFICATION_EXECUTION_RESULT_FINGERPRINT_FORMAT = (
    "gvr.verification_execution_result.ieee754-json.v1"
)
_STABLE_ISSUE_CODE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$")


class VerificationExecutionError(ValueError):
    """Raised when an execution request or exact runtime identity is invalid."""


class UnknownVerifierRuntimeError(LookupError):
    """Raised when an exact verifier ID and version has no runtime."""


class VerificationExecutionStepStatus(str, Enum):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


class VerificationExecutionTermination(str, Enum):
    COMPLETE = "COMPLETE"
    FAILED_CLOSED = "FAILED_CLOSED"
    LIMIT_EXHAUSTED = "LIMIT_EXHAUSTED"


def _identifier(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise VerificationExecutionError(f"{name} must be a non-empty string")
    if value != value.strip() or any(character.isspace() for character in value):
        raise VerificationExecutionError(f"{name} must not contain whitespace")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise VerificationExecutionError(f"{name} must not contain control characters")
    try:
        canonical_utf8_key(value, path=name)
    except CanonicalizationError as exc:
        raise VerificationExecutionError(str(exc)) from exc
    return value


def _optional_correlation(value: Any) -> str | None:
    if value is None:
        return None
    return _identifier(value, name="correlation_id")


def _sha256(value: Any, *, name: str) -> str:
    fingerprint = _identifier(value, name=name)
    if len(fingerprint) != 64 or any(
        character not in "0123456789abcdef" for character in fingerprint
    ):
        raise VerificationExecutionError(
            f"{name} must be a lowercase SHA-256 fingerprint"
        )
    return fingerprint


def _string_tuple(values: Iterable[str], *, name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise VerificationExecutionError(f"{name} must be an iterable of strings")
    try:
        supplied = tuple(values)
    except TypeError as exc:
        raise VerificationExecutionError(
            f"{name} must be an iterable of strings"
        ) from exc
    normalized = tuple(_identifier(item, name=f"{name} item") for item in supplied)
    if len(set(normalized)) != len(normalized):
        raise VerificationExecutionError(f"{name} contains duplicate values")
    return tuple(
        sorted(normalized, key=lambda item: canonical_utf8_key(item, path=name))
    )


def _export(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _export(value[key]) for key in value}
    if isinstance(value, tuple):
        return [_export(item) for item in value]
    if isinstance(value, Enum):
        return value.value
    return value


def _fingerprint(value: Any, *, fingerprint_format: str) -> str:
    try:
        return canonical_fingerprint(value, fingerprint_format=fingerprint_format)
    except CanonicalizationError as exc:
        raise VerificationExecutionError(str(exc)) from exc


def _limit(value: int | None, *, name: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 0:
        raise VerificationExecutionError(
            f"{name} must be a non-negative integer or null"
        )
    return value


def _claim_fingerprint(claim: AtomicClaim | CompositeClaim) -> str:
    definition = (
        claim.semantic_definition()
        if isinstance(claim, AtomicClaim)
        else claim.semantic_definition()
    )
    return _fingerprint(
        definition,
        fingerprint_format=(
            ATOMIC_CLAIM_FINGERPRINT_FORMAT
            if isinstance(claim, AtomicClaim)
            else COMPOSITE_CLAIM_FINGERPRINT_FORMAT
        ),
    )


def _evidence_definition(evidence: Evidence) -> dict[str, Any]:
    return {
        "id": evidence.id,
        "kind": evidence.kind,
        "payload": evidence.payload,
        "source": evidence.source,
        "fingerprint": evidence.fingerprint,
    }


def _evidence_bytes(evidence: Iterable[Evidence]) -> int:
    canonical = canonical_transport_json(
        tuple(_evidence_definition(item) for item in evidence)
    )
    return len(canonical.encode("utf-8"))


@dataclass(frozen=True, kw_only=True)
class VerificationExecutionLimits:
    max_steps: int | None = None
    max_acquisitions: int | None = None
    max_falsification_invocations: int | None = None
    max_verifier_invocations: int | None = None
    max_compositions: int | None = None
    max_evidence_records: int | None = None
    max_evidence_bytes: int | None = None

    def __post_init__(self) -> None:
        for name in (
            "max_steps",
            "max_acquisitions",
            "max_falsification_invocations",
            "max_verifier_invocations",
            "max_compositions",
            "max_evidence_records",
            "max_evidence_bytes",
        ):
            object.__setattr__(self, name, _limit(getattr(self, name), name=name))

    def to_dict(self) -> dict[str, int | None]:
        value = {
            "max_steps": self.max_steps,
            "max_acquisitions": self.max_acquisitions,
            "max_verifier_invocations": self.max_verifier_invocations,
            "max_compositions": self.max_compositions,
            "max_evidence_records": self.max_evidence_records,
            "max_evidence_bytes": self.max_evidence_bytes,
        }
        if self.max_falsification_invocations is not None:
            value["max_falsification_invocations"] = (
                self.max_falsification_invocations
            )
        return value


@dataclass(frozen=True, kw_only=True)
class VerificationExecutionConsumption:
    steps_started: int = 0
    completed_steps: int = 0
    failed_steps: int = 0
    blocked_steps: int = 0
    acquisitions: int = 0
    falsification_invocations: int = 0
    verifier_invocations: int = 0
    compositions: int = 0
    evidence_records: int = 0
    evidence_bytes: int = 0

    def __post_init__(self) -> None:
        for name in (
            "steps_started",
            "completed_steps",
            "failed_steps",
            "blocked_steps",
            "acquisitions",
            "falsification_invocations",
            "verifier_invocations",
            "compositions",
            "evidence_records",
            "evidence_bytes",
        ):
            if type(getattr(self, name)) is not int or getattr(self, name) < 0:
                raise VerificationExecutionError(
                    f"execution consumption {name} must be a non-negative integer"
                )

    def to_dict(self) -> dict[str, int]:
        value = {
            "steps_started": self.steps_started,
            "completed_steps": self.completed_steps,
            "failed_steps": self.failed_steps,
            "blocked_steps": self.blocked_steps,
            "acquisitions": self.acquisitions,
            "verifier_invocations": self.verifier_invocations,
            "compositions": self.compositions,
            "evidence_records": self.evidence_records,
            "evidence_bytes": self.evidence_bytes,
        }
        if self.falsification_invocations:
            value["falsification_invocations"] = self.falsification_invocations
        return value


@dataclass(frozen=True, kw_only=True)
class VerificationExecutionIssue:
    code: str
    step_id: str | None = None
    claim_id: str | None = None
    request_id: str | None = None

    def __post_init__(self) -> None:
        code = _identifier(self.code, name="execution issue code")
        if _STABLE_ISSUE_CODE.fullmatch(code) is None:
            raise VerificationExecutionError(
                "execution issue code must be a stable uppercase identifier"
            )
        object.__setattr__(self, "code", code)
        for name in ("step_id", "claim_id", "request_id"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _identifier(value, name=name))

    def to_dict(self) -> dict[str, str | None]:
        return {
            "code": self.code,
            "step_id": self.step_id,
            "claim_id": self.claim_id,
            "request_id": self.request_id,
        }


@dataclass(frozen=True, kw_only=True)
class VerificationExecutionStep:
    step_id: str
    kind: VerificationPlanStepKind
    status: VerificationExecutionStepStatus
    issue_codes: tuple[str, ...] = ()
    verdict: VerificationVerdict | None = None
    provider_result_fingerprint: str | None = None
    falsification_result_fingerprint: str | None = None
    bundle_fingerprint: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "step_id", _identifier(self.step_id, name="step_id"))
        if type(self.kind) is not VerificationPlanStepKind:
            raise VerificationExecutionError(
                "execution step kind must be an exact VerificationPlanStepKind"
            )
        if type(self.status) is not VerificationExecutionStepStatus:
            raise VerificationExecutionError(
                "execution step status must be an exact VerificationExecutionStepStatus"
            )
        codes = _string_tuple(self.issue_codes, name="execution step issue_codes")
        for code in codes:
            if _STABLE_ISSUE_CODE.fullmatch(code) is None:
                raise VerificationExecutionError(
                    "execution step issue code must be a stable uppercase identifier"
                )
        object.__setattr__(self, "issue_codes", codes)
        if self.verdict is not None and type(self.verdict) is not VerificationVerdict:
            raise VerificationExecutionError(
                "execution step verdict must be an exact VerificationVerdict"
            )
        for name in (
            "provider_result_fingerprint",
            "falsification_result_fingerprint",
            "bundle_fingerprint",
        ):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _sha256(value, name=name))

    def to_dict(self) -> dict[str, Any]:
        value = {
            "step_id": self.step_id,
            "kind": self.kind.value,
            "status": self.status.value,
            "issue_codes": list(self.issue_codes),
            "verdict": None if self.verdict is None else self.verdict.value,
            "provider_result_fingerprint": self.provider_result_fingerprint,
            "bundle_fingerprint": self.bundle_fingerprint,
        }
        if self.falsification_result_fingerprint is not None:
            value["falsification_result_fingerprint"] = (
                self.falsification_result_fingerprint
            )
        return value


@dataclass(frozen=True, kw_only=True)
class VerifierDependency:
    claim_id: str
    claim_fingerprint: str
    verdict: VerificationVerdict

    def __post_init__(self) -> None:
        object.__setattr__(self, "claim_id", _identifier(self.claim_id, name="claim_id"))
        object.__setattr__(
            self,
            "claim_fingerprint",
            _sha256(self.claim_fingerprint, name="claim_fingerprint"),
        )
        if type(self.verdict) is not VerificationVerdict:
            raise VerificationExecutionError(
                "dependency verdict must be an exact VerificationVerdict"
            )

    def to_dict(self) -> dict[str, str]:
        return {
            "claim_id": self.claim_id,
            "claim_fingerprint": self.claim_fingerprint,
            "verdict": self.verdict.value,
        }


@dataclass(frozen=True, kw_only=True)
class VerifierExecutionInput:
    claim: AtomicClaim
    capability: VerifierCapability
    acquisitions: tuple[EvidenceProviderVerifierInput, ...]
    evidence: tuple[Evidence, ...]
    dependencies: tuple[VerifierDependency, ...]
    falsification_results: tuple[FalsificationResult, ...] = ()

    def __post_init__(self) -> None:
        if type(self.claim) is not AtomicClaim:
            raise VerificationExecutionError(
                "verifier input claim must be an exact AtomicClaim"
            )
        if type(self.capability) is not VerifierCapability:
            raise VerificationExecutionError(
                "verifier input capability must be an exact VerifierCapability"
            )
        acquisitions = tuple(self.acquisitions)
        evidence = tuple(self.evidence)
        dependencies = tuple(self.dependencies)
        falsification_results = tuple(self.falsification_results)
        if any(type(item) is not EvidenceProviderVerifierInput for item in acquisitions):
            raise VerificationExecutionError(
                "verifier acquisitions must contain exact EvidenceProviderVerifierInput records"
            )
        if any(type(item) is not Evidence for item in evidence):
            raise VerificationExecutionError(
                "verifier evidence must contain exact Evidence records"
            )
        if any(type(item) is not VerifierDependency for item in dependencies):
            raise VerificationExecutionError(
                "verifier dependencies must contain exact VerifierDependency records"
            )
        if any(type(item) is not FalsificationResult for item in falsification_results):
            raise VerificationExecutionError(
                "verifier falsification_results must contain exact FalsificationResult records"
            )
        if self.claim.verifier != self.capability.verifier_id:
            raise VerificationExecutionError(
                "verifier input capability does not match the claim declared verifier"
            )
        claim_fingerprint = _claim_fingerprint(self.claim)
        binding_ids: set[str] = set()
        for result in falsification_results:
            if result.binding_id in binding_ids:
                raise VerificationExecutionError(
                    "verifier falsification_results contain a duplicate binding identity"
                )
            binding_ids.add(result.binding_id)
            if result.declared_verifier_id != self.capability.verifier_id:
                raise VerificationExecutionError(
                    "falsification result does not match the declared verifier"
                )
            if (
                result.claim_id != self.claim.claim_id
                or result.claim_fingerprint != claim_fingerprint
            ):
                raise VerificationExecutionError(
                    "falsification result does not match the verifier input claim"
                )
            if (
                result.strategy_kind
                not in self.capability.accepted_falsification_strategy_kinds
            ):
                raise VerificationExecutionError(
                    "verifier capability does not accept the falsification strategy kind"
                )
        object.__setattr__(self, "acquisitions", acquisitions)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "dependencies", dependencies)
        object.__setattr__(self, "falsification_results", falsification_results)


@runtime_checkable
class VerifierRuntime(Protocol):
    verifier_id: str
    version: str
    capability: VerifierCapability

    def verify(self, verifier_input: VerifierExecutionInput) -> VerificationReport: ...


def _validate_runtime_verifier(
    runtime: VerifierRuntime,
    key: tuple[str, str],
    capability: VerifierCapability,
) -> Callable[[VerifierExecutionInput], VerificationReport]:
    verify = getattr(runtime, "verify", None)
    if not callable(verify):
        raise VerificationExecutionError("runtime verifier verify must be callable")
    verifier_id = getattr(runtime, "verifier_id", None)
    version = getattr(runtime, "version", None)
    runtime_capability = getattr(runtime, "capability", None)
    if verifier_id != key[0] or version != key[1]:
        raise VerificationExecutionError(
            "runtime verifier identity does not match registry key"
        )
    if type(runtime_capability) is not VerifierCapability:
        raise VerificationExecutionError(
            "runtime verifier capability must be an exact VerifierCapability"
        )
    if (
        runtime_capability.verifier_id != verifier_id
        or runtime_capability.version != version
        or runtime_capability.fingerprint != capability.fingerprint
    ):
        raise VerificationExecutionError(
            "runtime verifier capability does not match registered capability"
        )
    return verify


@dataclass(frozen=True, kw_only=True)
class VerifierRuntimeRegistry:
    capability_registry: VerifierCapabilityRegistry
    runtime_verifiers: Mapping[tuple[str, str], VerifierRuntime]
    fingerprint: str = field(init=False)
    _runtime_by_key: Mapping[tuple[str, str], VerifierRuntime] = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if type(self.capability_registry) is not VerifierCapabilityRegistry:
            raise VerificationExecutionError(
                "capability_registry must be an exact VerifierCapabilityRegistry"
            )
        if not isinstance(self.runtime_verifiers, Mapping):
            raise VerificationExecutionError("runtime_verifiers must be a mapping")
        runtime: dict[tuple[str, str], VerifierRuntime] = {}
        for key, verifier in self.runtime_verifiers.items():
            if not isinstance(key, tuple) or len(key) != 2:
                raise VerificationExecutionError(
                    "runtime verifier keys must be (verifier_id, version)"
                )
            normalized_key = (
                _identifier(key[0], name="verifier_id"),
                _identifier(key[1], name="version"),
            )
            try:
                capability = self.capability_registry.lookup(*normalized_key)
            except (VerifierCapabilityError, LookupError) as exc:
                raise VerificationExecutionError(str(exc)) from exc
            _validate_runtime_verifier(verifier, normalized_key, capability)
            runtime[normalized_key] = verifier
        runtime_proxy = MappingProxyType(dict(runtime))
        object.__setattr__(self, "runtime_verifiers", runtime_proxy)
        object.__setattr__(self, "_runtime_by_key", runtime_proxy)
        object.__setattr__(
            self,
            "fingerprint",
            _fingerprint(
                self.semantic_definition(),
                fingerprint_format=VERIFIER_RUNTIME_REGISTRY_FINGERPRINT_FORMAT,
            ),
        )

    @property
    def runtime_keys(self) -> tuple[tuple[str, str], ...]:
        return tuple(
            sorted(
                self._runtime_by_key,
                key=lambda item: (
                    canonical_utf8_key(item[0], path="verifier_id"),
                    canonical_utf8_key(item[1], path="version"),
                ),
            )
        )

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "schema_version": VERIFIER_RUNTIME_REGISTRY_SCHEMA_VERSION,
            "kind": VERIFIER_RUNTIME_REGISTRY_KIND,
            "capability_registry_fingerprint": self.capability_registry.fingerprint,
            "runtime_keys": self.runtime_keys,
        }

    def to_dict(self) -> dict[str, Any]:
        value = _export(self.semantic_definition())
        value.update({
            "fingerprint_format": VERIFIER_RUNTIME_REGISTRY_FINGERPRINT_FORMAT,
            "fingerprint": self.fingerprint,
            "capability_registry": self.capability_registry.to_dict(),
        })
        return value

    def export(self) -> dict[str, Any]:
        return self.to_dict()

    def validate_runtime(self, verifier_id: str, version: str) -> VerifierRuntime:
        key = (
            _identifier(verifier_id, name="verifier_id"),
            _identifier(version, name="version"),
        )
        try:
            capability = self.capability_registry.lookup(*key)
        except (VerifierCapabilityError, LookupError) as exc:
            raise VerificationExecutionError(str(exc)) from exc
        try:
            runtime = self._runtime_by_key[key]
        except KeyError as exc:
            raise UnknownVerifierRuntimeError(
                f"no runtime verifier for {key[0]} version {key[1]}"
            ) from exc
        _validate_runtime_verifier(runtime, key, capability)
        return runtime

    def verify(
        self,
        verifier_id: str,
        version: str,
        verifier_input: VerifierExecutionInput,
    ) -> VerificationReport:
        runtime = self.validate_runtime(verifier_id, version)
        capability = self.capability_registry.lookup(verifier_id, version)
        verify = _validate_runtime_verifier(
            runtime,
            (verifier_id, version),
            capability,
        )
        return verify(verifier_input)


class _DataFlowVerifierRuntime:
    def __init__(self, capability: VerifierCapability) -> None:
        self.verifier_id = capability.verifier_id
        self.version = capability.version
        self.capability = capability

    def verify(self, verifier_input: VerifierExecutionInput) -> VerificationReport:
        claim = verifier_input.claim
        spec = claim.spec
        start = spec.get("start")
        target = spec.get("target")
        if not isinstance(start, str) or not start:
            raise ValueError("data-flow claim requires start")
        if not isinstance(target, str) or not target:
            raise ValueError("data-flow claim requires target")
        scope_data = spec.get("scope", {})
        if not isinstance(scope_data, Mapping):
            raise ValueError("data-flow claim scope must be a mapping")
        relations = scope_data.get(
            "effective_allowed_relations",
            tuple(sorted(SUPPORTED_DATA_FLOW_RELATIONS)),
        )
        stop_nodes = scope_data.get("stop_nodes", ())
        scope = DataFlowQueryScope(
            direction=str(scope_data.get("direction", "FORWARD")),
            effective_allowed_relations=frozenset(str(item) for item in relations),
            stop_nodes=frozenset(str(item) for item in stop_nodes),
        )
        data_flow_claim = DataFlowClaim(
            kind=DataFlowClaimKind(claim.claim_kind),
            start=start,
            target=target,
            scope=scope,
            evidence_namespace=str(spec.get("evidence_namespace", "default")),
            source_context=(
                None
                if spec.get("source_context") is None
                else str(spec.get("source_context"))
            ),
            source_revision=(
                None
                if not isinstance(spec.get("source_revision"), Mapping)
                else SourceRevision(**dict(spec["source_revision"]))
            ),
        )
        query_records = tuple(
            item
            for item in verifier_input.evidence
            if item.kind == "graphify.data_flow_query_result"
        )
        if len(query_records) > 1:
            raise ValueError("data-flow verifier received multiple query results")
        traversal: Mapping[str, Any] = {}
        if query_records:
            payload = query_records[0].payload
            candidate = payload.get("result")
            if not isinstance(candidate, Mapping):
                raise ValueError("data-flow query result evidence is malformed")
            traversal = candidate
        return verify_data_flow_claim(data_flow_claim, traversal)


class _CodeGraphVerifierRuntime:
    def __init__(self, capability: VerifierCapability) -> None:
        self.verifier_id = capability.verifier_id
        self.version = capability.version
        self.capability = capability

    def verify(self, verifier_input: VerifierExecutionInput) -> VerificationReport:
        claim = verifier_input.claim
        expected_claim_fingerprint = _claim_fingerprint(claim)
        code_graph_claim = _code_graph_claim_from_atomic(claim)
        observations: list[ProviderVerificationObservation | object] = []
        for evidence in verifier_input.evidence:
            if evidence.kind != CODE_GRAPH_OBSERVATION_EVIDENCE_KIND:
                continue
            try:
                decoded = decode_code_graph_observation_evidence(evidence)
                if decoded.claim_fingerprint != expected_claim_fingerprint:
                    mismatch_report = VerificationReport(
                        verdict=VerificationVerdict.UNKNOWN,
                        verifier=CODE_GRAPH_VERIFIER,
                        issues=(VerificationIssue(
                            code="CLAIM_FINGERPRINT_MISMATCH",
                            message="Provider observation claim identity does not match the atomic claim.",
                            verdict=VerificationVerdict.UNKNOWN,
                            evidence_ids=(evidence.id,),
                        ),),
                        evidence_ids=(evidence.id,),
                    )
                    observations.append(ProviderVerificationObservation(
                        provider_id=decoded.provider_id,
                        implementation_id=decoded.implementation_id,
                        family_id=decoded.family_id,
                        source_snapshot=decoded.graph_model.source_snapshot,
                        claim_fingerprint=decoded.claim_fingerprint,
                        report=mismatch_report,
                        independence=decoded.independence,
                        origin_attestation=decoded.origin_attestation,
                    ))
                    observations.append(ProviderVerificationObservation(
                        provider_id="gvr.expected_claim",
                        implementation_id="gvr.expected_claim",
                        family_id="gvr.expected_claim",
                        source_snapshot=decoded.graph_model.source_snapshot,
                        claim_fingerprint=expected_claim_fingerprint,
                        report=VerificationReport(
                            verdict=VerificationVerdict.UNKNOWN,
                            verifier=CODE_GRAPH_VERIFIER,
                        ),
                    ))
                    continue
                provider_report = verify_code_graph_observation(
                    code_graph_claim,
                    decoded.graph_model,
                )
                provider_report = _provider_report_with_outer_evidence(
                    provider_report,
                    evidence.id,
                )
                observations.append(ProviderVerificationObservation(
                    provider_id=decoded.provider_id,
                    implementation_id=decoded.implementation_id,
                    family_id=decoded.family_id,
                    source_snapshot=decoded.graph_model.source_snapshot,
                    claim_fingerprint=decoded.claim_fingerprint,
                    report=provider_report,
                    independence=decoded.independence,
                    origin_attestation=decoded.origin_attestation,
                    metadata={
                        "evidence_id": evidence.id,
                        "graph_model_fingerprint": decoded.graph_model_fingerprint,
                    },
                ))
            except (CodeGraphObservationError, ValueError):
                observations.append(object())
        reconciled = reconcile_provider_observations(observations)
        metadata = dict(reconciled.metadata)
        metadata["expected_claim_fingerprint"] = expected_claim_fingerprint
        return VerificationReport(
            verdict=reconciled.verdict,
            verifier=CODE_GRAPH_VERIFIER,
            issues=reconciled.issues,
            evidence_ids=reconciled.evidence_ids,
            metadata=metadata,
        )


def _code_graph_claim_from_atomic(claim: AtomicClaim) -> CodeGraphClaim:
    spec = claim.spec
    scope_data = spec.get("scope", claim.scope)
    if not isinstance(scope_data, Mapping):
        raise ValueError("code graph claim scope must be a mapping")
    snapshot = scope_data.get("snapshot", {})
    if not isinstance(snapshot, Mapping):
        raise ValueError("code graph claim snapshot must be a mapping")
    repository = str(snapshot.get("repository") or snapshot.get("repo") or "unknown")
    revision = snapshot.get("revision") or snapshot.get("commit") or snapshot.get("sha")
    if revision is None:
        revision = canonical_fingerprint(snapshot, fingerprint_format="gvr.code_graph.claim_revision.v1")
    query_scope = GraphQueryScope(
        start=str(spec.get("source") or spec.get("node") or ""),
        target=None if spec.get("target") is None else str(spec.get("target")),
        direction=str(scope_data.get("direction", "FORWARD")),
        requested_relations=frozenset(str(item) for item in scope_data.get("requested_relations", scope_data.get("relations", spec.get("relations", ())))),
        effective_relations=frozenset(str(item) for item in scope_data.get("effective_relations", scope_data.get("relations", spec.get("relations", ())))),
        rejected_relations=frozenset(str(item) for item in scope_data.get("rejected_relations", ())),
        evidence_namespace=str(scope_data.get("evidence_namespace", spec.get("evidence_namespace", "default"))),
        max_depth=None if scope_data.get("max_depth") is None else int(scope_data.get("max_depth")),
        max_paths=None if scope_data.get("max_paths") is None else int(scope_data.get("max_paths")),
        max_expansions=None if scope_data.get("max_expansions") is None else int(scope_data.get("max_expansions")),
        stop_nodes=frozenset(str(item) for item in scope_data.get("stop_nodes", ())),
    )
    scope = CodeGraphScope(
        snapshot=scope_data.get("snapshot", {}),
        relations=frozenset(str(item) for item in scope_data.get("relations", ())),
        direction=str(scope_data.get("direction", "FORWARD")),
        evidence_namespace=str(scope_data.get("evidence_namespace", spec.get("evidence_namespace", "default"))),
        max_depth=(None if scope_data.get("max_depth") is None else int(scope_data.get("max_depth"))),
        stop_nodes=frozenset(str(item) for item in scope_data.get("stop_nodes", ())),
        source_revision=SourceRevisionIdentity(repository, str(revision)),
        query_scope=query_scope,
    )
    relations = spec.get("relations", ())
    return CodeGraphClaim(
        kind=CodeGraphClaimKind(claim.claim_kind),
        node=(None if spec.get("node") is None else str(spec.get("node"))),
        source=(None if spec.get("source") is None else str(spec.get("source"))),
        target=(None if spec.get("target") is None else str(spec.get("target"))),
        through=(None if spec.get("through") is None else str(spec.get("through"))),
        max_depth=(
            None
            if spec.get("max_depth") is None
            else int(spec.get("max_depth"))
        ),
        relations=frozenset(str(item) for item in relations),
        scope=scope,
        evidence_namespace=str(spec.get("evidence_namespace", "default")),
    )


def _provider_report_with_outer_evidence(
    report: VerificationReport,
    evidence_id: str,
) -> VerificationReport:
    has_inner_evidence = bool(report.evidence_ids) or any(
        issue.evidence_ids for issue in report.issues
    )
    use_outer_evidence = report.verdict in (
        VerificationVerdict.PASS,
        VerificationVerdict.FAIL,
    ) or has_inner_evidence
    mapped_ids = (evidence_id,) if use_outer_evidence else ()
    mapped_issues = tuple(
        VerificationIssue(
            code=issue.code,
            message=issue.message,
            verdict=issue.verdict,
            evidence_ids=(evidence_id,) if issue.evidence_ids or report.verdict in (
                VerificationVerdict.PASS,
                VerificationVerdict.FAIL,
            ) else (),
        )
        for issue in report.issues
    )
    metadata = dict(report.metadata)
    metadata["canonical_graph_evidence_ids"] = report.evidence_ids
    metadata["provider_observation_evidence_id"] = evidence_id
    return VerificationReport(
        verdict=report.verdict,
        verifier=report.verifier,
        issues=mapped_issues,
        evidence_ids=mapped_ids,
        metadata=metadata,
    )


def builtin_verifier_runtime_registry(
    capability_registry: VerifierCapabilityRegistry | None = None,
) -> VerifierRuntimeRegistry:
    registry = (
        builtin_verifier_capability_registry()
        if capability_registry is None
        else capability_registry
    )
    if type(registry) is not VerifierCapabilityRegistry:
        raise VerificationExecutionError(
            "capability_registry must be an exact VerifierCapabilityRegistry"
        )
    builtin = builtin_verifier_capability_registry()
    runtimes: dict[tuple[str, str], VerifierRuntime] = {}
    for capability in registry.capabilities:
        try:
            exact = builtin.lookup(capability.verifier_id, capability.version)
        except LookupError:
            continue
        if exact.fingerprint != capability.fingerprint:
            continue
        if capability.verifier_id == DATA_FLOW_VERIFIER:
            runtimes[(capability.verifier_id, capability.version)] = (
                _DataFlowVerifierRuntime(capability)
            )
        elif capability.verifier_id == CODE_GRAPH_VERIFIER:
            runtimes[(capability.verifier_id, capability.version)] = (
                _CodeGraphVerifierRuntime(capability)
            )
    return VerifierRuntimeRegistry(
        capability_registry=registry,
        runtime_verifiers=runtimes,
    )


def _revalidate_claim_graph(graph: ClaimGraph) -> ClaimGraph:
    if type(graph) is not ClaimGraph:
        raise VerificationExecutionError("claim_graph must be an exact ClaimGraph")
    nodes: list[AtomicClaim | CompositeClaim] = []
    for node in graph.nodes:
        if type(node) is AtomicClaim:
            nodes.append(AtomicClaim(
                claim_id=node.claim_id,
                claim_kind=node.claim_kind,
                spec=node.spec,
                verifier=node.verifier,
                scope=node.scope,
                dependencies=node.dependencies,
                description=node.description,
            ))
        elif type(node) is CompositeClaim:
            nodes.append(CompositeClaim(
                claim_id=node.claim_id,
                operator=node.operator,
                dependencies=node.dependencies,
                description=node.description,
            ))
        else:
            raise VerificationExecutionError(
                "claim_graph must contain exact AtomicClaim or CompositeClaim records"
            )
    try:
        rebuilt = ClaimGraph(
            nodes=tuple(nodes),
            schema_version=graph.schema_version,
            kind=graph.kind,
        )
    except ClaimGraphValidationError as exc:
        raise VerificationExecutionError(str(exc)) from exc
    if rebuilt.to_dict() != graph.to_dict():
        raise VerificationExecutionError(
            "claim graph content or fingerprint is inconsistent"
        )
    return rebuilt


def _revalidate_verifier_capability(
    capability: VerifierCapability,
) -> VerifierCapability:
    if type(capability) is not VerifierCapability:
        raise VerificationExecutionError(
            "verifier capability must be an exact VerifierCapability"
        )
    try:
        rebuilt = VerifierCapability(
            verifier_id=capability.verifier_id,
            version=capability.version,
            claim_kinds=capability.claim_kinds,
            accepted_evidence_kinds=capability.accepted_evidence_kinds,
            required_evidence_kinds=capability.required_evidence_kinds,
            input_schema=capability.input_schema,
            output_schema=capability.output_schema,
            determinism=capability.determinism,
            side_effect_free=capability.side_effect_free,
            cost=capability.cost,
            bounds=capability.bounds,
            coverage=capability.coverage,
            authoritative=capability.authoritative,
            accepted_falsification_strategy_kinds=(
                capability.accepted_falsification_strategy_kinds
            ),
            falsification_requirement=capability.falsification_requirement,
            description=capability.description,
        )
    except VerifierCapabilityError as exc:
        raise VerificationExecutionError(str(exc)) from exc
    if rebuilt.to_dict() != capability.to_dict():
        raise VerificationExecutionError(
            "verifier capability content or fingerprint is inconsistent"
        )
    return rebuilt


def _revalidate_provider_capability(
    capability: EvidenceProviderCapability,
) -> EvidenceProviderCapability:
    if type(capability) is not EvidenceProviderCapability:
        raise VerificationExecutionError(
            "provider capability must be an exact EvidenceProviderCapability"
        )
    try:
        rebuilt = EvidenceProviderCapability(
            provider_id=capability.provider_id,
            version=capability.version,
            request_kinds=capability.request_kinds,
            produced_evidence_kinds=capability.produced_evidence_kinds,
            source_classes=capability.source_classes,
            snapshot_classes=capability.snapshot_classes,
            input_schema=capability.input_schema,
            output_schema=capability.output_schema,
            determinism=capability.determinism,
            side_effect_free=capability.side_effect_free,
            cost=capability.cost,
            bounds=capability.bounds,
            coverage=capability.coverage,
            description=capability.description,
        )
    except EvidenceProviderError as exc:
        raise VerificationExecutionError(str(exc)) from exc
    if rebuilt.to_dict() != capability.to_dict():
        raise VerificationExecutionError(
            "provider capability content or fingerprint is inconsistent"
        )
    return rebuilt


def _revalidate_verifier_registry(
    registry: VerifierCapabilityRegistry,
) -> VerifierCapabilityRegistry:
    if type(registry) is not VerifierCapabilityRegistry:
        raise VerificationExecutionError(
            "verifier capability registry must be an exact VerifierCapabilityRegistry"
        )
    try:
        rebuilt = VerifierCapabilityRegistry(tuple(
            _revalidate_verifier_capability(item)
            for item in registry.capabilities
        ))
    except VerifierCapabilityError as exc:
        raise VerificationExecutionError(str(exc)) from exc
    if rebuilt.to_dict() != registry.to_dict():
        raise VerificationExecutionError(
            "verifier capability registry content or fingerprint is inconsistent"
        )
    return rebuilt


def _revalidate_provider_registry(
    registry: EvidenceProviderCapabilityRegistry,
) -> EvidenceProviderCapabilityRegistry:
    if type(registry) is not EvidenceProviderCapabilityRegistry:
        raise VerificationExecutionError(
            "provider capability registry must be an exact EvidenceProviderCapabilityRegistry"
        )
    try:
        rebuilt = EvidenceProviderCapabilityRegistry(tuple(
            _revalidate_provider_capability(item)
            for item in registry.capabilities
        ))
    except EvidenceProviderError as exc:
        raise VerificationExecutionError(str(exc)) from exc
    if rebuilt.to_dict() != registry.to_dict():
        raise VerificationExecutionError(
            "provider capability registry content or fingerprint is inconsistent"
        )
    return rebuilt


def _revalidate_falsification_descriptor(
    descriptor: FalsificationStrategyDescriptor,
) -> FalsificationStrategyDescriptor:
    if type(descriptor) is not FalsificationStrategyDescriptor:
        raise VerificationExecutionError(
            "falsification descriptor must be an exact FalsificationStrategyDescriptor"
        )
    try:
        rebuilt = FalsificationStrategyDescriptor(
            strategy_id=descriptor.strategy_id,
            version=descriptor.version,
            strategy_kind=descriptor.strategy_kind,
            claim_kinds=descriptor.claim_kinds,
            input_schema=descriptor.input_schema,
            output_schema=descriptor.output_schema,
            determinism=descriptor.determinism,
            side_effect_free=descriptor.side_effect_free,
            cost=descriptor.cost,
            bounds=descriptor.bounds,
            coverage=descriptor.coverage,
            description=descriptor.description,
            schema_version=descriptor.schema_version,
            kind=descriptor.kind,
            fingerprint_format=descriptor.fingerprint_format,
        )
    except FalsificationStrategyError as exc:
        raise VerificationExecutionError(str(exc)) from exc
    if rebuilt.to_dict() != descriptor.to_dict():
        raise VerificationExecutionError(
            "falsification descriptor content or fingerprint is inconsistent"
        )
    return rebuilt


def _revalidate_falsification_registry(
    registry: FalsificationStrategyCapabilityRegistry,
) -> FalsificationStrategyCapabilityRegistry:
    if type(registry) is not FalsificationStrategyCapabilityRegistry:
        raise VerificationExecutionError(
            "falsification capability registry must be exact"
        )
    try:
        rebuilt = FalsificationStrategyCapabilityRegistry(tuple(
            _revalidate_falsification_descriptor(item)
            for item in registry.capabilities
        ))
    except FalsificationStrategyError as exc:
        raise VerificationExecutionError(str(exc)) from exc
    if rebuilt.to_dict() != registry.to_dict():
        raise VerificationExecutionError(
            "falsification capability registry content or fingerprint is inconsistent"
        )
    return rebuilt


def _revalidate_evidence_request(request: EvidenceRequest) -> EvidenceRequest:
    if type(request) is not EvidenceRequest:
        raise VerificationExecutionError(
            "evidence request must be an exact EvidenceRequest"
        )
    try:
        rebuilt = EvidenceRequest(
            request_id=request.request_id,
            provider_id=request.provider_id,
            provider_version=request.provider_version,
            request_kind=request.request_kind,
            requested_evidence_kinds=request.requested_evidence_kinds,
            subject=request.subject,
            spec=request.spec,
            semantic_scope=request.semantic_scope,
            source_context=request.source_context,
            snapshot_context=request.snapshot_context,
            bounds=request.bounds,
            source_class=request.source_class,
            snapshot_class=request.snapshot_class,
            schema_version=request.schema_version,
            kind=request.kind,
            fingerprint_format=request.fingerprint_format,
        )
    except EvidenceProviderError as exc:
        raise VerificationExecutionError(str(exc)) from exc
    if rebuilt.to_dict() != request.to_dict():
        raise VerificationExecutionError(
            "evidence request content or fingerprint is inconsistent"
        )
    return rebuilt


def _revalidate_plan_step(step: VerificationPlanStep) -> VerificationPlanStep:
    if type(step) is not VerificationPlanStep:
        raise VerificationExecutionError(
            "plan steps must contain exact VerificationPlanStep records"
        )
    try:
        rebuilt = VerificationPlanStep(
            kind=step.kind,
            dependency_step_ids=step.dependency_step_ids,
            claim_id=step.claim_id,
            claim_kind=step.claim_kind,
            claim_fingerprint=step.claim_fingerprint,
            operator=step.operator,
            request_id=step.request_id,
            request_fingerprint=step.request_fingerprint,
            request_kind=step.request_kind,
            requested_evidence_kinds=step.requested_evidence_kinds,
            provider_id=step.provider_id,
            provider_version=step.provider_version,
            provider_capability_fingerprint=step.provider_capability_fingerprint,
            verifier_id=step.verifier_id,
            verifier_version=step.verifier_version,
            verifier_capability_fingerprint=step.verifier_capability_fingerprint,
            binding_id=step.binding_id,
            strategy_id=step.strategy_id,
            strategy_version=step.strategy_version,
            strategy_kind=step.strategy_kind,
            strategy_capability_fingerprint=(
                step.strategy_capability_fingerprint
            ),
            strategy_parameters=step.strategy_parameters,
        )
    except VerificationPlanningError as exc:
        raise VerificationExecutionError(str(exc)) from exc
    if rebuilt.to_dict() != step.to_dict():
        raise VerificationExecutionError(
            "verification plan step content or fingerprint is inconsistent"
        )
    return rebuilt


def _revalidate_plan(plan: VerificationPlan) -> VerificationPlan:
    if type(plan) is not VerificationPlan:
        raise VerificationExecutionError("plan must be an exact VerificationPlan")
    try:
        budget = VerificationPlanningBudget(**plan.budget.to_dict())
        consumption = VerificationPlanningConsumption(**plan.consumption.to_dict())
        issues = tuple(
            VerificationPlannerIssue(
                code=item.code,
                claim_id=item.claim_id,
                request_id=item.request_id,
                details=item.details,
            )
            for item in plan.issues
        )
        rebuilt = VerificationPlan(
            request_fingerprint=plan.request_fingerprint,
            claim_graph_fingerprint=plan.claim_graph_fingerprint,
            verifier_capability_registry_fingerprint=(
                plan.verifier_capability_registry_fingerprint
            ),
            evidence_provider_capability_registry_fingerprint=(
                plan.evidence_provider_capability_registry_fingerprint
            ),
            falsification_strategy_capability_registry_fingerprint=(
                plan.falsification_strategy_capability_registry_fingerprint
            ),
            budget=budget,
            consumption=consumption,
            termination=plan.termination,
            steps=tuple(_revalidate_plan_step(item) for item in plan.steps),
            issues=issues,
            schema_version=plan.schema_version,
            kind=plan.kind,
            fingerprint_format=plan.fingerprint_format,
        )
    except VerificationPlanningError as exc:
        raise VerificationExecutionError(str(exc)) from exc
    if rebuilt.to_dict() != plan.to_dict():
        raise VerificationExecutionError(
            "verification plan content or fingerprint is inconsistent"
        )
    return rebuilt


def _derive_exact_planning_request(
    *,
    plan: VerificationPlan,
    graph: ClaimGraph,
    verifier_registry: VerifierCapabilityRegistry,
    provider_registry: EvidenceProviderCapabilityRegistry,
    falsification_registry: FalsificationStrategyCapabilityRegistry | None,
    evidence_requests: Mapping[tuple[str, str], EvidenceRequest],
) -> VerificationPlanningRequest:
    if plan.termination is not VerificationPlanTermination.COMPLETE:
        raise VerificationExecutionError(
            "only a complete verification plan can be executed"
        )
    steps_by_id = {step.step_id: step for step in plan.steps}
    acquisition_steps = {
        step.step_id: step
        for step in plan.steps
        if step.kind is VerificationPlanStepKind.ACQUIRE_EVIDENCE
    }
    final_by_claim: dict[str, VerificationPlanStep] = {}
    falsification_by_claim: dict[str, list[VerificationPlanStep]] = {}
    for step in plan.steps:
        if step.kind is VerificationPlanStepKind.RUN_FALSIFICATION:
            assert step.claim_id is not None
            falsification_by_claim.setdefault(step.claim_id, []).append(step)
            continue
        if step.kind is VerificationPlanStepKind.ACQUIRE_EVIDENCE:
            continue
        assert step.claim_id is not None
        if step.claim_id in final_by_claim:
            raise VerificationExecutionError(
                f"verification plan contains multiple final steps for claim {step.claim_id}"
            )
        final_by_claim[step.claim_id] = step
    if set(final_by_claim) != {node.claim_id for node in graph.nodes}:
        raise VerificationExecutionError(
            "verification plan final claim steps do not match ClaimGraph"
        )

    expected_request_keys: set[tuple[str, str]] = set()
    for step in acquisition_steps.values():
        assert step.request_id is not None and step.request_fingerprint is not None
        key = (step.request_id, step.request_fingerprint)
        expected_request_keys.add(key)
        try:
            request = evidence_requests[key]
        except KeyError as exc:
            raise VerificationExecutionError(
                f"missing exact evidence request {step.request_id}"
            ) from exc
        if (
            request.request_kind != step.request_kind
            or request.requested_evidence_kinds != step.requested_evidence_kinds
            or request.provider_id != step.provider_id
            or request.provider_version != step.provider_version
        ):
            raise VerificationExecutionError(
                f"acquisition step {step.step_id} does not match exact EvidenceRequest"
            )
        try:
            capability = provider_registry.lookup(
                request.provider_id,
                request.provider_version,
            )
        except UnknownEvidenceProviderError as exc:
            raise VerificationExecutionError(str(exc)) from exc
        if capability.fingerprint != step.provider_capability_fingerprint:
            raise VerificationExecutionError(
                f"acquisition step {step.step_id} provider capability mismatch"
            )
    if expected_request_keys != set(evidence_requests):
        raise VerificationExecutionError(
            "evidence_requests must contain exactly the plan acquisition identities"
        )

    bindings: list[AtomicClaimBinding] = []
    for claim in graph.atomic_claims:
        step = final_by_claim[claim.claim_id]
        if step.kind is not VerificationPlanStepKind.VERIFY_ATOMIC_CLAIM:
            raise VerificationExecutionError(
                f"atomic claim {claim.claim_id} does not have a verifier step"
            )
        request_dependencies: list[EvidenceRequest] = []
        claim_dependency_steps: list[str] = []
        falsification_dependency_steps: list[VerificationPlanStep] = []
        for dependency_id in step.dependency_step_ids:
            dependency = steps_by_id.get(dependency_id)
            if dependency is None:
                raise VerificationExecutionError(
                    f"step {step.step_id} has an unknown dependency"
                )
            if dependency.kind is VerificationPlanStepKind.ACQUIRE_EVIDENCE:
                assert (
                    dependency.request_id is not None
                    and dependency.request_fingerprint is not None
                )
                request_dependencies.append(evidence_requests[
                    (dependency.request_id, dependency.request_fingerprint)
                ])
            elif dependency.kind is VerificationPlanStepKind.RUN_FALSIFICATION:
                falsification_dependency_steps.append(dependency)
            else:
                claim_dependency_steps.append(dependency_id)
        expected_claim_dependencies = tuple(
            final_by_claim[item].step_id for item in claim.dependencies
        )
        if set(claim_dependency_steps) != set(expected_claim_dependencies):
            raise VerificationExecutionError(
                f"verifier dependencies for claim {claim.claim_id} do not match ClaimGraph"
            )
        expected_falsification_steps = tuple(
            falsification_by_claim.get(claim.claim_id, ())
        )
        if {
            item.step_id for item in falsification_dependency_steps
        } != {item.step_id for item in expected_falsification_steps}:
            raise VerificationExecutionError(
                f"verifier falsification dependencies for claim {claim.claim_id} "
                "do not match exact plan bindings"
            )
        if (
            step.claim_kind != claim.claim_kind
            or step.claim_fingerprint != _claim_fingerprint(claim)
            or step.verifier_id != claim.verifier
        ):
            raise VerificationExecutionError(
                f"verifier step for claim {claim.claim_id} does not match exact claim identity"
            )
        assert (
            step.verifier_id is not None
            and step.verifier_version is not None
            and step.verifier_capability_fingerprint is not None
        )
        exact_falsification_bindings: list[FalsificationStrategyBinding] = []
        prerequisite_step_ids = {
            dependency_id
            for dependency_id in step.dependency_step_ids
            if steps_by_id[dependency_id].kind
            is VerificationPlanStepKind.ACQUIRE_EVIDENCE
        } | set(expected_claim_dependencies)
        for falsification_step in expected_falsification_steps:
            if falsification_registry is None:
                raise VerificationExecutionError(
                    "falsification plan steps require an exact capability registry"
                )
            if set(falsification_step.dependency_step_ids) != prerequisite_step_ids:
                raise VerificationExecutionError(
                    f"falsification step {falsification_step.step_id} has invalid prerequisites"
                )
            if (
                falsification_step.claim_id != claim.claim_id
                or falsification_step.claim_kind != claim.claim_kind
                or falsification_step.claim_fingerprint != _claim_fingerprint(claim)
                or falsification_step.verifier_id != step.verifier_id
                or falsification_step.verifier_version != step.verifier_version
                or falsification_step.verifier_capability_fingerprint
                != step.verifier_capability_fingerprint
            ):
                raise VerificationExecutionError(
                    f"falsification step for claim {claim.claim_id} does not match exact claim/verifier"
                )
            assert (
                falsification_step.binding_id is not None
                and falsification_step.strategy_id is not None
                and falsification_step.strategy_version is not None
                and falsification_step.strategy_kind is not None
                and falsification_step.strategy_capability_fingerprint is not None
                and falsification_step.strategy_parameters is not None
            )
            try:
                descriptor = falsification_registry.lookup(
                    falsification_step.strategy_id,
                    falsification_step.strategy_version,
                )
            except UnknownFalsificationStrategyError as exc:
                raise VerificationExecutionError(str(exc)) from exc
            if (
                descriptor.strategy_kind is not falsification_step.strategy_kind
                or descriptor.fingerprint
                != falsification_step.strategy_capability_fingerprint
            ):
                raise VerificationExecutionError(
                    f"falsification step {falsification_step.step_id} capability mismatch"
                )
            exact_falsification_bindings.append(FalsificationStrategyBinding(
                binding_id=falsification_step.binding_id,
                verifier_id=falsification_step.verifier_id,
                strategy_id=falsification_step.strategy_id,
                strategy_version=falsification_step.strategy_version,
                strategy_capability_fingerprint=(
                    falsification_step.strategy_capability_fingerprint
                ),
                parameters=falsification_step.strategy_parameters,
            ))
        bindings.append(AtomicClaimBinding(
            claim_id=claim.claim_id,
            verifier_id=step.verifier_id,
            verifier_version=step.verifier_version,
            verifier_capability_fingerprint=step.verifier_capability_fingerprint,
            evidence_requests=tuple(request_dependencies),
            falsification_bindings=tuple(exact_falsification_bindings),
        ))

    for claim in graph.composite_claims:
        step = final_by_claim[claim.claim_id]
        if (
            step.kind is not VerificationPlanStepKind.COMPOSE_CLAIM
            or step.operator is not claim.operator
            or step.claim_fingerprint != _claim_fingerprint(claim)
            or set(step.dependency_step_ids)
            != {final_by_claim[item].step_id for item in claim.dependencies}
        ):
            raise VerificationExecutionError(
                f"composition step for claim {claim.claim_id} does not match ClaimGraph"
            )

    try:
        planning = VerificationPlanningRequest(
            claim_graph=graph,
            bindings=tuple(bindings),
            verifier_capability_registry=verifier_registry,
            verifier_capability_registry_fingerprint=verifier_registry.fingerprint,
            evidence_provider_capability_registry=provider_registry,
            evidence_provider_capability_registry_fingerprint=provider_registry.fingerprint,
            falsification_strategy_capability_registry=falsification_registry,
            falsification_strategy_capability_registry_fingerprint=(
                None
                if falsification_registry is None
                else falsification_registry.fingerprint
            ),
            budget=plan.budget,
        )
    except VerificationPlanningError as exc:
        raise VerificationExecutionError(str(exc)) from exc
    if planning.fingerprint != plan.request_fingerprint:
        raise VerificationExecutionError(
            "plan request fingerprint does not match exact execution inputs"
        )
    expected_plan = compile_verification_plan(planning)
    if expected_plan.to_dict() != plan.to_dict():
        raise VerificationExecutionError(
            "verification plan does not match exact deterministic recompilation"
        )
    return planning


@dataclass(frozen=True, kw_only=True)
class VerificationExecutionRequest:
    plan: VerificationPlan
    plan_fingerprint: str
    claim_graph: ClaimGraph
    claim_graph_fingerprint: str
    roots: tuple[str, ...]
    verifier_runtime_registry: VerifierRuntimeRegistry
    verifier_capability_registry_fingerprint: str
    evidence_provider_runtime_registry: EvidenceProviderRuntimeRegistry
    evidence_provider_capability_registry_fingerprint: str
    evidence_requests: Mapping[tuple[str, str], EvidenceRequest]
    falsification_strategy_runtime_registry: (
        FalsificationStrategyRuntimeRegistry | None
    ) = None
    falsification_strategy_capability_registry_fingerprint: str | None = None
    limits: VerificationExecutionLimits = field(
        default_factory=VerificationExecutionLimits
    )
    correlation_id: str | None = None
    schema_version: int = VERIFICATION_EXECUTION_REQUEST_SCHEMA_VERSION
    kind: str = VERIFICATION_EXECUTION_REQUEST_KIND
    fingerprint_format: str = VERIFICATION_EXECUTION_REQUEST_FINGERPRINT_FORMAT
    fingerprint: str = field(init=False)
    _planning_request: VerificationPlanningRequest = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise VerificationExecutionError(
                f"unsupported verification execution request schema version {self.schema_version}"
            )
        if self.kind != VERIFICATION_EXECUTION_REQUEST_KIND:
            raise VerificationExecutionError(
                f"unsupported verification execution request kind {self.kind}"
            )
        if self.fingerprint_format != VERIFICATION_EXECUTION_REQUEST_FINGERPRINT_FORMAT:
            raise VerificationExecutionError(
                "unsupported verification execution request fingerprint format"
            )
        plan = _revalidate_plan(self.plan)
        graph = _revalidate_claim_graph(self.claim_graph)
        plan_fingerprint = _sha256(self.plan_fingerprint, name="plan_fingerprint")
        graph_fingerprint = _sha256(
            self.claim_graph_fingerprint,
            name="claim_graph_fingerprint",
        )
        if plan_fingerprint != plan.fingerprint:
            raise VerificationExecutionError(
                "plan fingerprint does not match exact VerificationPlan"
            )
        if graph_fingerprint != graph.fingerprint:
            raise VerificationExecutionError(
                "claim graph fingerprint does not match exact ClaimGraph"
            )
        if plan.claim_graph_fingerprint != graph.fingerprint:
            raise VerificationExecutionError(
                "plan claim graph fingerprint does not match exact ClaimGraph"
            )
        if type(self.verifier_runtime_registry) is not VerifierRuntimeRegistry:
            raise VerificationExecutionError(
                "verifier_runtime_registry must be an exact VerifierRuntimeRegistry"
            )
        if type(self.evidence_provider_runtime_registry) is not EvidenceProviderRuntimeRegistry:
            raise VerificationExecutionError(
                "evidence_provider_runtime_registry must be an exact EvidenceProviderRuntimeRegistry"
            )
        verifier_registry = _revalidate_verifier_registry(
            self.verifier_runtime_registry.capability_registry
        )
        provider_registry = _revalidate_provider_registry(
            self.evidence_provider_runtime_registry.capability_registry
        )
        try:
            verifier_runtime_registry = VerifierRuntimeRegistry(
                capability_registry=verifier_registry,
                runtime_verifiers=self.verifier_runtime_registry.runtime_verifiers,
            )
            provider_runtime_registry = EvidenceProviderRuntimeRegistry(
                capability_registry=provider_registry,
                runtime_providers=(
                    self.evidence_provider_runtime_registry.runtime_providers
                ),
            )
        except (EvidenceProviderError, VerificationExecutionError) as exc:
            raise VerificationExecutionError(str(exc)) from exc

        falsification_runtime_registry: FalsificationStrategyRuntimeRegistry | None
        falsification_registry: FalsificationStrategyCapabilityRegistry | None
        falsification_fingerprint: str | None
        if self.falsification_strategy_runtime_registry is None:
            if self.falsification_strategy_capability_registry_fingerprint is not None:
                raise VerificationExecutionError(
                    "falsification registry fingerprint requires an exact runtime registry"
                )
            if plan.falsification_strategy_capability_registry_fingerprint is not None:
                raise VerificationExecutionError(
                    "plan falsification steps require an exact runtime registry"
                )
            falsification_runtime_registry = None
            falsification_registry = None
            falsification_fingerprint = None
        else:
            if (
                type(self.falsification_strategy_runtime_registry)
                is not FalsificationStrategyRuntimeRegistry
            ):
                raise VerificationExecutionError(
                    "falsification_strategy_runtime_registry must be exact"
                )
            if self.falsification_strategy_capability_registry_fingerprint is None:
                raise VerificationExecutionError(
                    "falsification capability registry fingerprint is required"
                )
            falsification_registry = _revalidate_falsification_registry(
                self.falsification_strategy_runtime_registry.capability_registry
            )
            try:
                falsification_runtime_registry = FalsificationStrategyRuntimeRegistry(
                    capability_registry=falsification_registry,
                    runtime_strategies=(
                        self.falsification_strategy_runtime_registry.runtime_strategies
                    ),
                )
            except FalsificationStrategyError as exc:
                raise VerificationExecutionError(str(exc)) from exc
            supplied_runtime_fingerprint = _sha256(
                self.falsification_strategy_runtime_registry.fingerprint,
                name="falsification_strategy_runtime_registry fingerprint",
            )
            if supplied_runtime_fingerprint != falsification_runtime_registry.fingerprint:
                raise VerificationExecutionError(
                    "falsification runtime registry fingerprint is inconsistent"
                )
            falsification_fingerprint = _sha256(
                self.falsification_strategy_capability_registry_fingerprint,
                name="falsification_strategy_capability_registry_fingerprint",
            )
            if falsification_fingerprint != falsification_registry.fingerprint:
                raise VerificationExecutionError(
                    "falsification capability registry fingerprint does not match runtime registry"
                )
            if (
                plan.falsification_strategy_capability_registry_fingerprint
                != falsification_fingerprint
            ):
                raise VerificationExecutionError(
                    "plan falsification capability registry fingerprint mismatch"
                )
        if (
            _sha256(
                self.verifier_runtime_registry.fingerprint,
                name="verifier_runtime_registry fingerprint",
            )
            != verifier_runtime_registry.fingerprint
        ):
            raise VerificationExecutionError(
                "verifier runtime registry fingerprint is inconsistent"
            )
        if (
            _sha256(
                self.evidence_provider_runtime_registry.fingerprint,
                name="evidence_provider_runtime_registry fingerprint",
            )
            != provider_runtime_registry.fingerprint
        ):
            raise VerificationExecutionError(
                "provider runtime registry fingerprint is inconsistent"
            )
        verifier_fingerprint = _sha256(
            self.verifier_capability_registry_fingerprint,
            name="verifier_capability_registry_fingerprint",
        )
        provider_fingerprint = _sha256(
            self.evidence_provider_capability_registry_fingerprint,
            name="evidence_provider_capability_registry_fingerprint",
        )
        if verifier_fingerprint != verifier_registry.fingerprint:
            raise VerificationExecutionError(
                "verifier capability registry fingerprint does not match runtime registry"
            )
        if provider_fingerprint != provider_registry.fingerprint:
            raise VerificationExecutionError(
                "provider capability registry fingerprint does not match runtime registry"
            )
        if plan.verifier_capability_registry_fingerprint != verifier_fingerprint:
            raise VerificationExecutionError(
                "plan verifier capability registry fingerprint mismatch"
            )
        if (
            plan.evidence_provider_capability_registry_fingerprint
            != provider_fingerprint
        ):
            raise VerificationExecutionError(
                "plan provider capability registry fingerprint mismatch"
            )
        if type(self.limits) is not VerificationExecutionLimits:
            raise VerificationExecutionError(
                "limits must be an exact VerificationExecutionLimits"
            )
        roots = _string_tuple(self.roots, name="roots")
        if not roots:
            raise VerificationExecutionError("at least one root claim is required")
        unknown_roots = set(roots) - {node.claim_id for node in graph.nodes}
        if unknown_roots:
            raise VerificationExecutionError(
                "roots reference unknown claims: " + ", ".join(sorted(unknown_roots))
            )
        if not isinstance(self.evidence_requests, Mapping):
            raise VerificationExecutionError("evidence_requests must be a mapping")
        exact_requests: dict[tuple[str, str], EvidenceRequest] = {}
        request_ids: dict[str, str] = {}
        for key, request in self.evidence_requests.items():
            if not isinstance(key, tuple) or len(key) != 2:
                raise VerificationExecutionError(
                    "evidence request keys must be (request_id, fingerprint)"
                )
            normalized_key = (
                _identifier(key[0], name="request_id"),
                _sha256(key[1], name="request_fingerprint"),
            )
            rebuilt = _revalidate_evidence_request(request)
            if normalized_key != (rebuilt.request_id, rebuilt.fingerprint):
                raise VerificationExecutionError(
                    "evidence request mapping key does not match exact request identity"
                )
            previous = request_ids.get(rebuilt.request_id)
            if previous is not None and previous != rebuilt.fingerprint:
                raise VerificationExecutionError(
                    f"evidence request ID {rebuilt.request_id} has conflicting semantics"
                )
            request_ids[rebuilt.request_id] = rebuilt.fingerprint
            exact_requests[normalized_key] = rebuilt
        exact_proxy = MappingProxyType(dict(exact_requests))
        planning = _derive_exact_planning_request(
            plan=plan,
            graph=graph,
            verifier_registry=verifier_registry,
            provider_registry=provider_registry,
            falsification_registry=falsification_registry,
            evidence_requests=exact_proxy,
        )
        for step in plan.steps:
            if step.kind is VerificationPlanStepKind.ACQUIRE_EVIDENCE:
                assert step.provider_id is not None and step.provider_version is not None
                try:
                    provider_runtime_registry.validate_runtime(
                        step.provider_id,
                        step.provider_version,
                    )
                except (EvidenceProviderError, UnknownEvidenceProviderError) as exc:
                    raise VerificationExecutionError(str(exc)) from exc
            elif step.kind is VerificationPlanStepKind.VERIFY_ATOMIC_CLAIM:
                assert step.verifier_id is not None and step.verifier_version is not None
                try:
                    verifier_runtime_registry.validate_runtime(
                        step.verifier_id,
                        step.verifier_version,
                    )
                except (VerificationExecutionError, UnknownVerifierRuntimeError) as exc:
                    raise VerificationExecutionError(str(exc)) from exc
            elif step.kind is VerificationPlanStepKind.RUN_FALSIFICATION:
                assert (
                    step.strategy_id is not None
                    and step.strategy_version is not None
                    and falsification_runtime_registry is not None
                )
                try:
                    falsification_runtime_registry.validate_runtime(
                        step.strategy_id,
                        step.strategy_version,
                    )
                except (
                    FalsificationStrategyError,
                    UnknownFalsificationStrategyError,
                ) as exc:
                    raise VerificationExecutionError(str(exc)) from exc
        object.__setattr__(self, "plan", plan)
        object.__setattr__(self, "plan_fingerprint", plan_fingerprint)
        object.__setattr__(self, "claim_graph", graph)
        object.__setattr__(self, "claim_graph_fingerprint", graph_fingerprint)
        object.__setattr__(self, "roots", roots)
        object.__setattr__(
            self,
            "verifier_runtime_registry",
            verifier_runtime_registry,
        )
        object.__setattr__(
            self,
            "evidence_provider_runtime_registry",
            provider_runtime_registry,
        )
        object.__setattr__(
            self,
            "verifier_capability_registry_fingerprint",
            verifier_fingerprint,
        )
        object.__setattr__(
            self,
            "evidence_provider_capability_registry_fingerprint",
            provider_fingerprint,
        )
        object.__setattr__(self, "evidence_requests", exact_proxy)
        object.__setattr__(
            self,
            "falsification_strategy_runtime_registry",
            falsification_runtime_registry,
        )
        object.__setattr__(
            self,
            "falsification_strategy_capability_registry_fingerprint",
            falsification_fingerprint,
        )
        object.__setattr__(self, "correlation_id", _optional_correlation(self.correlation_id))
        object.__setattr__(self, "_planning_request", planning)
        object.__setattr__(
            self,
            "fingerprint",
            _fingerprint(
                self.semantic_definition(),
                fingerprint_format=self.fingerprint_format,
            ),
        )

    def semantic_definition(self) -> dict[str, Any]:
        request_items = tuple(
            {
                "request_id": key[0],
                "request_fingerprint": key[1],
                "request": self.evidence_requests[key].to_dict(),
            }
            for key in sorted(
                self.evidence_requests,
                key=lambda item: (
                    canonical_utf8_key(item[1], path="request fingerprint"),
                    canonical_utf8_key(item[0], path="request_id"),
                ),
            )
        )
        definition = {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "plan": self.plan.to_dict(),
            "plan_fingerprint": self.plan_fingerprint,
            "claim_graph": self.claim_graph.to_dict(),
            "claim_graph_fingerprint": self.claim_graph_fingerprint,
            "roots": self.roots,
            "verifier_runtime_registry": (
                self.verifier_runtime_registry.semantic_definition()
            ),
            "verifier_capability_registry_fingerprint": (
                self.verifier_capability_registry_fingerprint
            ),
            "evidence_provider_runtime_registry": (
                self.evidence_provider_runtime_registry.semantic_definition()
            ),
            "evidence_provider_capability_registry_fingerprint": (
                self.evidence_provider_capability_registry_fingerprint
            ),
            "evidence_requests": request_items,
            "limits": self.limits.to_dict(),
        }
        if self.falsification_strategy_runtime_registry is not None:
            definition["falsification_strategy_runtime_registry"] = (
                self.falsification_strategy_runtime_registry.semantic_definition()
            )
            definition[
                "falsification_strategy_capability_registry_fingerprint"
            ] = self.falsification_strategy_capability_registry_fingerprint
        return definition

    def to_dict(self) -> dict[str, Any]:
        value = _export(self.semantic_definition())
        value["verifier_runtime_registry"] = (
            self.verifier_runtime_registry.to_dict()
        )
        value["evidence_provider_runtime_registry"] = (
            self.evidence_provider_runtime_registry.to_dict()
        )
        if self.falsification_strategy_runtime_registry is not None:
            value["falsification_strategy_runtime_registry"] = (
                self.falsification_strategy_runtime_registry.to_dict()
            )
        value.update({
            "fingerprint_format": self.fingerprint_format,
            "fingerprint": self.fingerprint,
            "correlation_id": self.correlation_id,
        })
        return value

    def export(self) -> dict[str, Any]:
        return self.to_dict()


@dataclass(frozen=True, kw_only=True)
class VerificationExecutionResult:
    request_fingerprint: str
    plan_fingerprint: str
    claim_graph_fingerprint: str
    verifier_capability_registry_fingerprint: str
    evidence_provider_capability_registry_fingerprint: str
    session: VerificationSession
    provider_results: Mapping[tuple[str, str], EvidenceProviderResult]
    bundles: Mapping[str, VerificationBundle]
    steps: tuple[VerificationExecutionStep, ...]
    issues: tuple[VerificationExecutionIssue, ...]
    consumption: VerificationExecutionConsumption
    termination: VerificationExecutionTermination
    falsification_strategy_capability_registry_fingerprint: str | None = None
    falsification_results: Mapping[str, FalsificationResult] = field(
        default_factory=dict
    )
    correlation_id: str | None = None
    schema_version: int = VERIFICATION_EXECUTION_RESULT_SCHEMA_VERSION
    kind: str = VERIFICATION_EXECUTION_RESULT_KIND
    fingerprint_format: str = VERIFICATION_EXECUTION_RESULT_FINGERPRINT_FORMAT
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise VerificationExecutionError(
                f"unsupported verification execution result schema version {self.schema_version}"
            )
        if self.kind != VERIFICATION_EXECUTION_RESULT_KIND:
            raise VerificationExecutionError(
                f"unsupported verification execution result kind {self.kind}"
            )
        if self.fingerprint_format != VERIFICATION_EXECUTION_RESULT_FINGERPRINT_FORMAT:
            raise VerificationExecutionError(
                "unsupported verification execution result fingerprint format"
            )
        for name in (
            "request_fingerprint",
            "plan_fingerprint",
            "claim_graph_fingerprint",
            "verifier_capability_registry_fingerprint",
            "evidence_provider_capability_registry_fingerprint",
        ):
            object.__setattr__(self, name, _sha256(getattr(self, name), name=name))
        if self.falsification_strategy_capability_registry_fingerprint is not None:
            object.__setattr__(
                self,
                "falsification_strategy_capability_registry_fingerprint",
                _sha256(
                    self.falsification_strategy_capability_registry_fingerprint,
                    name=(
                        "falsification_strategy_capability_registry_fingerprint"
                    ),
                ),
            )
        if type(self.session) is not VerificationSession:
            raise VerificationExecutionError(
                "session must be an exact VerificationSession"
            )
        if not self.session.sealed:
            raise VerificationExecutionError(
                "execution result session must be sealed"
            )
        if not isinstance(self.provider_results, Mapping):
            raise VerificationExecutionError("provider_results must be a mapping")
        provider_results: dict[tuple[str, str], EvidenceProviderResult] = {}
        for key, result in self.provider_results.items():
            if not isinstance(key, tuple) or len(key) != 2:
                raise VerificationExecutionError(
                    "provider result keys must be (request_id, fingerprint)"
                )
            if type(result) is not EvidenceProviderResult:
                raise VerificationExecutionError(
                    "provider_results must contain exact EvidenceProviderResult records"
                )
            normalized_key = (
                _identifier(key[0], name="request_id"),
                _sha256(key[1], name="request_fingerprint"),
            )
            if normalized_key != (result.request_id, result.request_fingerprint):
                raise VerificationExecutionError(
                    "provider result key does not match result request identity"
                )
            provider_results[normalized_key] = result
        if not isinstance(self.bundles, Mapping):
            raise VerificationExecutionError("bundles must be a mapping")
        bundles: dict[str, VerificationBundle] = {}
        for claim_id, bundle in self.bundles.items():
            normalized_id = _identifier(claim_id, name="claim_id")
            if type(bundle) is not VerificationBundle:
                raise VerificationExecutionError(
                    "bundles must contain exact VerificationBundle records"
                )
            bundles[normalized_id] = bundle
        if not isinstance(self.falsification_results, Mapping):
            raise VerificationExecutionError(
                "falsification_results must be a mapping"
            )
        falsification_results: dict[str, FalsificationResult] = {}
        binding_ids: set[str] = set()
        for step_id, result in self.falsification_results.items():
            normalized_step_id = _identifier(step_id, name="falsification step_id")
            if type(result) is not FalsificationResult:
                raise VerificationExecutionError(
                    "falsification_results must contain exact FalsificationResult records"
                )
            if result.binding_id in binding_ids:
                raise VerificationExecutionError(
                    "falsification_results contain a duplicate binding identity"
                )
            binding_ids.add(result.binding_id)
            falsification_results[normalized_step_id] = result
        steps = tuple(self.steps)
        issues = tuple(self.issues)
        if any(type(item) is not VerificationExecutionStep for item in steps):
            raise VerificationExecutionError(
                "steps must contain exact VerificationExecutionStep records"
            )
        if any(type(item) is not VerificationExecutionIssue for item in issues):
            raise VerificationExecutionError(
                "issues must contain exact VerificationExecutionIssue records"
            )
        steps_by_id: dict[str, VerificationExecutionStep] = {}
        for step in steps:
            if step.step_id in steps_by_id:
                raise VerificationExecutionError(
                    "execution result steps contain a duplicate step identity"
                )
            steps_by_id[step.step_id] = step
        if (
            falsification_results
            and self.falsification_strategy_capability_registry_fingerprint is None
        ):
            raise VerificationExecutionError(
                "falsification results require a capability registry fingerprint"
            )
        for step_id, result in falsification_results.items():
            step = steps_by_id.get(step_id)
            if (
                step is None
                or step.kind is not VerificationPlanStepKind.RUN_FALSIFICATION
            ):
                raise VerificationExecutionError(
                    "falsification result must reference an exact RUN_FALSIFICATION step"
                )
            if step.status is not VerificationExecutionStepStatus.COMPLETED:
                raise VerificationExecutionError(
                    "falsification result cannot reference an incomplete RUN_FALSIFICATION step"
                )
            if step.falsification_result_fingerprint != result.fingerprint:
                raise VerificationExecutionError(
                    "falsification result fingerprint does not match its execution step"
                )
        for step in steps:
            if step.kind is VerificationPlanStepKind.RUN_FALSIFICATION:
                result = falsification_results.get(step.step_id)
                if step.status is VerificationExecutionStepStatus.COMPLETED:
                    if result is None:
                        raise VerificationExecutionError(
                            "completed RUN_FALSIFICATION step is missing its result"
                        )
                    if step.falsification_result_fingerprint is None:
                        raise VerificationExecutionError(
                            "completed RUN_FALSIFICATION step is missing its result fingerprint"
                        )
                elif step.falsification_result_fingerprint is not None:
                    raise VerificationExecutionError(
                        "incomplete RUN_FALSIFICATION step cannot publish a result fingerprint"
                    )
            elif step.falsification_result_fingerprint is not None:
                raise VerificationExecutionError(
                    "only RUN_FALSIFICATION steps may publish falsification fingerprints"
                )
        if type(self.consumption) is not VerificationExecutionConsumption:
            raise VerificationExecutionError(
                "consumption must be an exact VerificationExecutionConsumption"
            )
        if type(self.termination) is not VerificationExecutionTermination:
            raise VerificationExecutionError(
                "termination must be an exact VerificationExecutionTermination"
            )
        object.__setattr__(self, "provider_results", MappingProxyType(provider_results))
        object.__setattr__(self, "bundles", MappingProxyType(bundles))
        object.__setattr__(
            self,
            "falsification_results",
            MappingProxyType(falsification_results),
        )
        object.__setattr__(self, "steps", steps)
        object.__setattr__(self, "issues", issues)
        object.__setattr__(self, "correlation_id", _optional_correlation(self.correlation_id))
        object.__setattr__(
            self,
            "fingerprint",
            _fingerprint(
                self.semantic_definition(),
                fingerprint_format=self.fingerprint_format,
            ),
        )

    def semantic_definition(self) -> dict[str, Any]:
        provider_results = tuple(
            {
                "request_id": key[0],
                "request_fingerprint": key[1],
                "result": self.provider_results[key].semantic_transport(),
            }
            for key in sorted(
                self.provider_results,
                key=lambda item: (
                    canonical_utf8_key(item[1], path="request fingerprint"),
                    canonical_utf8_key(item[0], path="request_id"),
                ),
            )
        )
        bundles = tuple(
            {
                "claim_id": claim_id,
                "bundle": self.bundles[claim_id].to_dict(),
            }
            for claim_id in sorted(
                self.bundles,
                key=lambda item: canonical_utf8_key(item, path="claim_id"),
            )
        )
        definition = {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "request_fingerprint": self.request_fingerprint,
            "plan_fingerprint": self.plan_fingerprint,
            "claim_graph_fingerprint": self.claim_graph_fingerprint,
            "verifier_capability_registry_fingerprint": (
                self.verifier_capability_registry_fingerprint
            ),
            "evidence_provider_capability_registry_fingerprint": (
                self.evidence_provider_capability_registry_fingerprint
            ),
            "session": self.session.to_dict(),
            "provider_results": provider_results,
            "bundles": bundles,
            "steps": tuple(item.to_dict() for item in self.steps),
            "issues": tuple(item.to_dict() for item in self.issues),
            "consumption": self.consumption.to_dict(),
            "termination": self.termination.value,
        }
        if self.falsification_strategy_capability_registry_fingerprint is not None:
            definition[
                "falsification_strategy_capability_registry_fingerprint"
            ] = self.falsification_strategy_capability_registry_fingerprint
        if self.falsification_results:
            definition["falsification_results"] = tuple(
                {
                    "step_id": step_id,
                    "result": self.falsification_results[step_id].to_dict(),
                }
                for step_id in sorted(
                    self.falsification_results,
                    key=lambda item: canonical_utf8_key(
                        item,
                        path="falsification step_id",
                    ),
                )
            )
        return definition

    def to_dict(self) -> dict[str, Any]:
        value = _export(self.semantic_definition())
        value["provider_results"] = _export(
            tuple(
                {
                    "request_id": key[0],
                    "request_fingerprint": key[1],
                    "result": self.provider_results[key].to_dict(),
                }
                for key in sorted(
                    self.provider_results,
                    key=lambda item: (
                        canonical_utf8_key(
                            item[1],
                            path="request fingerprint",
                        ),
                        canonical_utf8_key(item[0], path="request_id"),
                    ),
                )
            )
        )
        value.update({
            "fingerprint_format": self.fingerprint_format,
            "fingerprint": self.fingerprint,
            "correlation_id": self.correlation_id,
        })
        return value

    def export(self) -> dict[str, Any]:
        return self.to_dict()


_REPORT_MESSAGES = {
    "CONFLICTING_REACHABLE_EVIDENCE_ID": (
        "Reachable evidence contains a conflicting identity."
    ),
    "EXECUTION_LIMIT_EXHAUSTED": (
        "The deterministic execution limit blocked verification."
    ),
    "INVALID_VERIFICATION_PREREQUISITE": (
        "An exact verification prerequisite is unavailable or invalid."
    ),
    "REQUIRED_FALSIFICATION_INCOMPLETE": (
        "Required falsification coverage is absent or incomplete."
    ),
    "VERIFIER_IGNORED_FALSIFICATION_COUNTEREXAMPLE": (
        "The verifier returned PASS while a declared counterexample was present."
    ),
    "VERIFIER_EXECUTION_ERROR": (
        "The exact verifier runtime failed during execution."
    ),
    "VERIFIER_RESULT_INVALID": (
        "The exact verifier runtime returned an invalid report."
    ),
}


def _unknown_bundle(
    *,
    claim: AtomicClaim,
    verifier_id: str,
    code: str,
    evidence: tuple[Evidence, ...],
) -> VerificationBundle:
    evidence_ids = tuple(item.id for item in evidence)
    report = VerificationReport(
        verdict=VerificationVerdict.UNKNOWN,
        verifier=verifier_id,
        issues=(VerificationIssue(
            code=code,
            message=_REPORT_MESSAGES[code],
            verdict=VerificationVerdict.UNKNOWN,
            evidence_ids=evidence_ids,
        ),),
        evidence_ids=evidence_ids,
    )
    return build_verification_bundle(
        report,
        evidence,
        claim_dependency_ids=claim.dependencies,
    )


def _revalidate_provider_result(
    result: EvidenceProviderResult,
    request: EvidenceRequest,
    capability: EvidenceProviderCapability,
) -> EvidenceProviderResult:
    if type(result) is not EvidenceProviderResult:
        raise EvidenceProviderError("result must be an exact EvidenceProviderResult")
    coverage = result.coverage
    if type(coverage) is not EvidenceCoverage:
        raise EvidenceProviderError("coverage must be an exact EvidenceCoverage")
    rebuilt_coverage = EvidenceCoverage(
        completeness=coverage.completeness,
        covered_evidence_kinds=coverage.covered_evidence_kinds,
        truncated=coverage.truncated,
        details=coverage.details,
        declared_scope=coverage.declared_scope,
        observed_scope=coverage.observed_scope,
        declared_bounds=coverage.declared_bounds,
        consumed=coverage.consumed,
        termination=coverage.termination,
        termination_reason=coverage.termination_reason,
        source_identity=coverage.source_identity,
        snapshot_identity=coverage.snapshot_identity,
        audit=coverage.audit,
        schema_version=coverage.schema_version,
        kind=coverage.kind,
        fingerprint_format=coverage.fingerprint_format,
    )
    rebuilt = EvidenceProviderResult(
        request_id=result.request_id,
        request_fingerprint=result.request_fingerprint,
        provider_id=result.provider_id,
        provider_version=result.provider_version,
        status=result.status,
        coverage=rebuilt_coverage,
        evidence=result.evidence,
        issues=result.issues,
        capability_fingerprint=result.capability_fingerprint,
        evidence_slot_identities=result.evidence_slot_identities,
        schema_version=result.schema_version,
        kind=result.kind,
        fingerprint_format=result.fingerprint_format,
    )
    if rebuilt.to_dict() != result.to_dict():
        raise EvidenceProviderError(
            "provider result content or fingerprint is inconsistent"
        )
    return validate_evidence_provider_result(rebuilt, request, capability)


def _runtime_request_copy(request: VerificationExecutionRequest) -> VerificationExecutionRequest:
    if type(request) is not VerificationExecutionRequest:
        raise VerificationExecutionError(
            "request must be an exact VerificationExecutionRequest"
        )
    rebuilt = VerificationExecutionRequest(
        plan=request.plan,
        plan_fingerprint=request.plan_fingerprint,
        claim_graph=request.claim_graph,
        claim_graph_fingerprint=request.claim_graph_fingerprint,
        roots=request.roots,
        verifier_runtime_registry=request.verifier_runtime_registry,
        verifier_capability_registry_fingerprint=(
            request.verifier_capability_registry_fingerprint
        ),
        evidence_provider_runtime_registry=(
            request.evidence_provider_runtime_registry
        ),
        evidence_provider_capability_registry_fingerprint=(
            request.evidence_provider_capability_registry_fingerprint
        ),
        evidence_requests=request.evidence_requests,
        falsification_strategy_runtime_registry=(
            request.falsification_strategy_runtime_registry
        ),
        falsification_strategy_capability_registry_fingerprint=(
            request.falsification_strategy_capability_registry_fingerprint
        ),
        limits=request.limits,
        correlation_id=request.correlation_id,
        schema_version=request.schema_version,
        kind=request.kind,
        fingerprint_format=request.fingerprint_format,
    )
    if rebuilt.fingerprint != request.fingerprint:
        raise VerificationExecutionError(
            "verification execution request content or fingerprint is inconsistent"
        )
    return rebuilt


def _limit_blocks(
    *,
    step: VerificationPlanStep,
    limits: VerificationExecutionLimits,
    consumption: VerificationExecutionConsumption,
) -> bool:
    if (
        limits.max_steps is not None
        and consumption.steps_started + 1 > limits.max_steps
    ):
        return True
    if (
        step.kind is VerificationPlanStepKind.ACQUIRE_EVIDENCE
        and limits.max_acquisitions is not None
        and consumption.acquisitions + 1 > limits.max_acquisitions
    ):
        return True
    if (
        step.kind is VerificationPlanStepKind.RUN_FALSIFICATION
        and limits.max_falsification_invocations is not None
        and consumption.falsification_invocations + 1
        > limits.max_falsification_invocations
    ):
        return True
    if (
        step.kind is VerificationPlanStepKind.VERIFY_ATOMIC_CLAIM
        and limits.max_verifier_invocations is not None
        and consumption.verifier_invocations + 1
        > limits.max_verifier_invocations
    ):
        return True
    if (
        step.kind is VerificationPlanStepKind.COMPOSE_CLAIM
        and limits.max_compositions is not None
        and consumption.compositions + 1 > limits.max_compositions
    ):
        return True
    return False


def _add_issue(
    issues: list[VerificationExecutionIssue],
    *,
    code: str,
    step: VerificationPlanStep,
) -> None:
    issue = VerificationExecutionIssue(
        code=code,
        step_id=step.step_id,
        claim_id=step.claim_id,
        request_id=step.request_id,
    )
    if issue not in issues:
        issues.append(issue)


def _status_consumption(
    consumption: VerificationExecutionConsumption,
    status: VerificationExecutionStepStatus,
) -> VerificationExecutionConsumption:
    if status is VerificationExecutionStepStatus.COMPLETED:
        return replace(
            consumption,
            completed_steps=consumption.completed_steps + 1,
        )
    if status is VerificationExecutionStepStatus.FAILED:
        return replace(
            consumption,
            failed_steps=consumption.failed_steps + 1,
        )
    return replace(
        consumption,
        blocked_steps=consumption.blocked_steps + 1,
    )


def execute_verification_plan(
    request: VerificationExecutionRequest,
    *,
    storage: Any | None = None,
    unit_of_work: Any | None = None,
) -> VerificationExecutionResult:
    """Execute one exact immutable plan with optional explicit durable recording.

    Storage is never discovered globally. When supplied, the completed evidence,
    bundle, claim, falsification, and session basis is recorded atomically before
    a result can be returned to the caller.
    """

    if storage is not None and unit_of_work is not None:
        raise VerificationExecutionError(
            "storage and unit_of_work are mutually exclusive"
        )

    request = _runtime_request_copy(request)
    session = VerificationSession(graph=request.claim_graph, roots=request.roots)
    provider_results: dict[tuple[str, str], EvidenceProviderResult] = {}
    falsification_results: dict[str, FalsificationResult] = {}
    bundles: dict[str, VerificationBundle] = {}
    step_results: list[VerificationExecutionStep] = []
    issues: list[VerificationExecutionIssue] = []
    results_by_step: dict[str, VerificationExecutionStep] = {}
    plan_steps_by_id = {item.step_id: item for item in request.plan.steps}
    consumption = VerificationExecutionConsumption()
    limit_exhausted = False

    for step in request.plan.steps:
        if limit_exhausted or _limit_blocks(
            step=step,
            limits=request.limits,
            consumption=consumption,
        ):
            limit_exhausted = True
            _add_issue(issues, code="EXECUTION_LIMIT_EXHAUSTED", step=step)
            bundle_fingerprint: str | None = None
            verdict: VerificationVerdict | None = None
            if step.kind is VerificationPlanStepKind.VERIFY_ATOMIC_CLAIM:
                assert step.claim_id is not None and step.verifier_id is not None
                claim = request.claim_graph.claim(step.claim_id)
                assert isinstance(claim, AtomicClaim)
                bundle = _unknown_bundle(
                    claim=claim,
                    verifier_id=step.verifier_id,
                    code="EXECUTION_LIMIT_EXHAUSTED",
                    evidence=(),
                )
                session.record_bundle(claim.claim_id, bundle)
                bundles[claim.claim_id] = bundle
                bundle_fingerprint = bundle.fingerprint
                verdict = VerificationVerdict.UNKNOWN
            elif step.kind is VerificationPlanStepKind.COMPOSE_CLAIM:
                verdict = VerificationVerdict.UNKNOWN
            record = VerificationExecutionStep(
                step_id=step.step_id,
                kind=step.kind,
                status=VerificationExecutionStepStatus.BLOCKED,
                issue_codes=("EXECUTION_LIMIT_EXHAUSTED",),
                verdict=verdict,
                bundle_fingerprint=bundle_fingerprint,
            )
            step_results.append(record)
            results_by_step[step.step_id] = record
            consumption = _status_consumption(
                consumption,
                VerificationExecutionStepStatus.BLOCKED,
            )
            continue

        if step.kind is VerificationPlanStepKind.ACQUIRE_EVIDENCE:
            assert step.request_id is not None and step.request_fingerprint is not None
            key = (step.request_id, step.request_fingerprint)
            exact_request = request.evidence_requests[key]
            consumption = replace(
                consumption,
                steps_started=consumption.steps_started + 1,
                acquisitions=consumption.acquisitions + 1,
            )
            try:
                result = request.evidence_provider_runtime_registry.acquire(
                    exact_request,
                    fail_closed=True,
                )
                capability = (
                    request.evidence_provider_runtime_registry.capability_registry.lookup(
                        exact_request.provider_id,
                        exact_request.provider_version,
                    )
                )
                result = _revalidate_provider_result(
                    result,
                    exact_request,
                    capability,
                )
            except (EvidenceProviderError, UnknownEvidenceProviderError):
                _add_issue(issues, code="PROVIDER_RESULT_INVALID", step=step)
                record = VerificationExecutionStep(
                    step_id=step.step_id,
                    kind=step.kind,
                    status=VerificationExecutionStepStatus.FAILED,
                    issue_codes=("PROVIDER_RESULT_INVALID",),
                )
                step_results.append(record)
                results_by_step[step.step_id] = record
                consumption = _status_consumption(
                    consumption,
                    VerificationExecutionStepStatus.FAILED,
                )
                continue
            provider_results[key] = result
            evidence_records = len(result.evidence)
            evidence_bytes = _evidence_bytes(result.evidence)
            consumption = replace(
                consumption,
                evidence_records=consumption.evidence_records + evidence_records,
                evidence_bytes=consumption.evidence_bytes + evidence_bytes,
            )
            exceeds_evidence_limit = (
                request.limits.max_evidence_records is not None
                and consumption.evidence_records
                > request.limits.max_evidence_records
            ) or (
                request.limits.max_evidence_bytes is not None
                and consumption.evidence_bytes > request.limits.max_evidence_bytes
            )
            if exceeds_evidence_limit:
                limit_exhausted = True
                _add_issue(issues, code="EXECUTION_LIMIT_EXHAUSTED", step=step)
                status = VerificationExecutionStepStatus.FAILED
                issue_code = "EXECUTION_LIMIT_EXHAUSTED"
            else:
                status = VerificationExecutionStepStatus.COMPLETED
                issue_code = None
            record = VerificationExecutionStep(
                step_id=step.step_id,
                kind=step.kind,
                status=status,
                issue_codes=(() if issue_code is None else (issue_code,)),
                provider_result_fingerprint=result.fingerprint,
            )
            step_results.append(record)
            results_by_step[step.step_id] = record
            consumption = _status_consumption(consumption, status)
            continue

        if step.kind is VerificationPlanStepKind.RUN_FALSIFICATION:
            assert (
                step.claim_id is not None
                and step.claim_fingerprint is not None
                and step.verifier_id is not None
                and step.verifier_version is not None
                and step.binding_id is not None
                and step.strategy_id is not None
                and step.strategy_version is not None
                and step.strategy_parameters is not None
                and request.falsification_strategy_runtime_registry is not None
            )
            claim = request.claim_graph.claim(step.claim_id)
            assert isinstance(claim, AtomicClaim)
            capability = request.verifier_runtime_registry.capability_registry.lookup(
                step.verifier_id,
                step.verifier_version,
            )
            direct = tuple(results_by_step[item] for item in step.dependency_step_ids)
            invalid_prerequisite = any(
                item.status is not VerificationExecutionStepStatus.COMPLETED
                for item in direct
            )
            acquisition_inputs: list[EvidenceProviderVerifierInput] = []
            evidence_by_id: dict[str, Evidence] = {}
            for dependency_id in step.dependency_step_ids:
                dependency_step = plan_steps_by_id[dependency_id]
                if dependency_step.kind is not VerificationPlanStepKind.ACQUIRE_EVIDENCE:
                    continue
                assert (
                    dependency_step.request_id is not None
                    and dependency_step.request_fingerprint is not None
                )
                provider_result = provider_results.get((
                    dependency_step.request_id,
                    dependency_step.request_fingerprint,
                ))
                if provider_result is None:
                    invalid_prerequisite = True
                    continue
                try:
                    acquisition_input = provider_result_for_verifier(
                        provider_result,
                        capability,
                    )
                except EvidenceProviderError:
                    invalid_prerequisite = True
                    continue
                acquisition_inputs.append(acquisition_input)
                if (
                    provider_result.status
                    in (
                        EvidenceAcquisitionStatus.UNAVAILABLE,
                        EvidenceAcquisitionStatus.UNSUPPORTED,
                    )
                    or acquisition_input.missing_required_evidence_kinds
                ):
                    invalid_prerequisite = True
                for evidence in provider_result.evidence:
                    previous = evidence_by_id.get(evidence.id)
                    if previous is not None and previous != evidence:
                        invalid_prerequisite = True
                    else:
                        evidence_by_id.setdefault(evidence.id, evidence)
            reachable_evidence = tuple(
                evidence_by_id[key]
                for key in sorted(
                    evidence_by_id,
                    key=lambda item: canonical_utf8_key(item, path="evidence id"),
                )
            )
            if invalid_prerequisite:
                code = "FALSIFICATION_PREREQUISITE_INVALID"
                _add_issue(issues, code=code, step=step)
                record = VerificationExecutionStep(
                    step_id=step.step_id,
                    kind=step.kind,
                    status=VerificationExecutionStepStatus.BLOCKED,
                    issue_codes=(code,),
                )
                step_results.append(record)
                results_by_step[step.step_id] = record
                consumption = _status_consumption(
                    consumption,
                    VerificationExecutionStepStatus.BLOCKED,
                )
                continue

            descriptor = (
                request.falsification_strategy_runtime_registry.capability_registry.lookup(
                    step.strategy_id,
                    step.strategy_version,
                )
            )
            dependencies = tuple(
                FalsificationDependency(
                    claim_id=dependency_id,
                    claim_fingerprint=_claim_fingerprint(
                        request.claim_graph.claim(dependency_id)
                    ),
                    outcome=session.claim_state(
                        dependency_id
                    ).effective_verdict.value,
                )
                for dependency_id in claim.dependencies
            )
            consumption = replace(
                consumption,
                steps_started=consumption.steps_started + 1,
                falsification_invocations=(
                    consumption.falsification_invocations + 1
                ),
            )
            try:
                strategy_input = FalsificationExecutionInput(
                    binding_id=step.binding_id,
                    declared_verifier_id=step.verifier_id,
                    claim=claim,
                    claim_fingerprint=step.claim_fingerprint,
                    descriptor=descriptor,
                    parameters=step.strategy_parameters,
                    acquisitions=tuple(acquisition_inputs),
                    evidence=reachable_evidence,
                    dependencies=dependencies,
                )
                falsification_result = (
                    request.falsification_strategy_runtime_registry.run(
                        strategy_input
                    )
                )
                falsification_result = validate_falsification_result(
                    falsification_result,
                    strategy_input,
                    descriptor,
                )
            except (FalsificationStrategyError, UnknownFalsificationStrategyError):
                code = "FALSIFICATION_RESULT_INVALID"
                status = VerificationExecutionStepStatus.FAILED
                falsification_result = None
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                code = "FALSIFICATION_EXECUTION_ERROR"
                status = VerificationExecutionStepStatus.FAILED
                falsification_result = None
            else:
                code = ""
                status = VerificationExecutionStepStatus.COMPLETED
                falsification_results[step.step_id] = falsification_result
            if code:
                _add_issue(issues, code=code, step=step)
            record = VerificationExecutionStep(
                step_id=step.step_id,
                kind=step.kind,
                status=status,
                issue_codes=(() if not code else (code,)),
                falsification_result_fingerprint=(
                    None
                    if falsification_result is None
                    else falsification_result.fingerprint
                ),
            )
            step_results.append(record)
            results_by_step[step.step_id] = record
            consumption = _status_consumption(consumption, status)
            continue

        if step.kind is VerificationPlanStepKind.VERIFY_ATOMIC_CLAIM:
            assert (
                step.claim_id is not None
                and step.verifier_id is not None
                and step.verifier_version is not None
            )
            claim = request.claim_graph.claim(step.claim_id)
            assert isinstance(claim, AtomicClaim)
            direct = tuple(results_by_step[item] for item in step.dependency_step_ids)
            invalid_lifecycle = any(
                item.status is not VerificationExecutionStepStatus.COMPLETED
                for item in direct
            )
            acquisition_inputs: list[EvidenceProviderVerifierInput] = []
            reachable_falsification_results: list[FalsificationResult] = []
            evidence_by_id: dict[str, Evidence] = {}
            conflicting_evidence = False
            invalid_acquisition = False
            for dependency_id in step.dependency_step_ids:
                dependency_step = plan_steps_by_id[dependency_id]
                if dependency_step.kind is VerificationPlanStepKind.RUN_FALSIFICATION:
                    result = falsification_results.get(dependency_id)
                    if result is None or result.declared_verifier_id != step.verifier_id:
                        invalid_acquisition = True
                    else:
                        reachable_falsification_results.append(result)
                    continue
                if dependency_step.kind is not VerificationPlanStepKind.ACQUIRE_EVIDENCE:
                    continue
                assert (
                    dependency_step.request_id is not None
                    and dependency_step.request_fingerprint is not None
                )
                result = provider_results.get((
                    dependency_step.request_id,
                    dependency_step.request_fingerprint,
                ))
                if result is None:
                    invalid_acquisition = True
                    continue
                capability = (
                    request.verifier_runtime_registry.capability_registry.lookup(
                        step.verifier_id,
                        step.verifier_version,
                    )
                )
                try:
                    verifier_input = provider_result_for_verifier(result, capability)
                except EvidenceProviderError:
                    invalid_acquisition = True
                    continue
                acquisition_inputs.append(verifier_input)
                if (
                    result.status
                    in (
                        EvidenceAcquisitionStatus.UNAVAILABLE,
                        EvidenceAcquisitionStatus.UNSUPPORTED,
                    )
                    or verifier_input.missing_required_evidence_kinds
                ):
                    invalid_acquisition = True
                for evidence in result.evidence:
                    previous = evidence_by_id.get(evidence.id)
                    if previous is not None and previous != evidence:
                        conflicting_evidence = True
                    else:
                        evidence_by_id.setdefault(evidence.id, evidence)
            reachable_evidence = tuple(
                evidence_by_id[key]
                for key in sorted(
                    evidence_by_id,
                    key=lambda item: canonical_utf8_key(item, path="evidence id"),
                )
            )
            if conflicting_evidence:
                code = "CONFLICTING_REACHABLE_EVIDENCE_ID"
                _add_issue(issues, code=code, step=step)
                bundle = _unknown_bundle(
                    claim=claim,
                    verifier_id=step.verifier_id,
                    code=code,
                    evidence=(),
                )
                session.record_bundle(claim.claim_id, bundle)
                bundles[claim.claim_id] = bundle
                record = VerificationExecutionStep(
                    step_id=step.step_id,
                    kind=step.kind,
                    status=VerificationExecutionStepStatus.BLOCKED,
                    issue_codes=(code,),
                    verdict=VerificationVerdict.UNKNOWN,
                    bundle_fingerprint=bundle.fingerprint,
                )
                step_results.append(record)
                results_by_step[step.step_id] = record
                consumption = _status_consumption(
                    consumption,
                    VerificationExecutionStepStatus.BLOCKED,
                )
                continue
            if invalid_lifecycle or invalid_acquisition:
                code = "INVALID_VERIFICATION_PREREQUISITE"
                _add_issue(issues, code=code, step=step)
                bundle = _unknown_bundle(
                    claim=claim,
                    verifier_id=step.verifier_id,
                    code=code,
                    evidence=reachable_evidence,
                )
                session.record_bundle(claim.claim_id, bundle)
                bundles[claim.claim_id] = bundle
                record = VerificationExecutionStep(
                    step_id=step.step_id,
                    kind=step.kind,
                    status=VerificationExecutionStepStatus.BLOCKED,
                    issue_codes=(code,),
                    verdict=VerificationVerdict.UNKNOWN,
                    bundle_fingerprint=bundle.fingerprint,
                )
                step_results.append(record)
                results_by_step[step.step_id] = record
                consumption = _status_consumption(
                    consumption,
                    VerificationExecutionStepStatus.BLOCKED,
                )
                continue

            capability = request.verifier_runtime_registry.capability_registry.lookup(
                step.verifier_id,
                step.verifier_version,
            )
            dependencies = tuple(
                VerifierDependency(
                    claim_id=dependency_id,
                    claim_fingerprint=_claim_fingerprint(
                        request.claim_graph.claim(dependency_id)
                    ),
                    verdict=session.claim_state(dependency_id).effective_verdict,
                )
                for dependency_id in claim.dependencies
            )
            runtime_input = VerifierExecutionInput(
                claim=claim,
                capability=capability,
                acquisitions=tuple(acquisition_inputs),
                evidence=reachable_evidence,
                dependencies=dependencies,
                falsification_results=tuple(reachable_falsification_results),
            )
            consumption = replace(
                consumption,
                steps_started=consumption.steps_started + 1,
                verifier_invocations=consumption.verifier_invocations + 1,
            )
            try:
                report = request.verifier_runtime_registry.verify(
                    step.verifier_id,
                    step.verifier_version,
                    runtime_input,
                )
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                code = "VERIFIER_EXECUTION_ERROR"
                status = VerificationExecutionStepStatus.FAILED
                report = None
            else:
                code = "VERIFIER_RESULT_INVALID"
                status = VerificationExecutionStepStatus.FAILED
                if type(report) is VerificationReport and report.verifier == step.verifier_id:
                    gate_code = ""
                    if report.verdict is VerificationVerdict.PASS:
                        if any(
                            result.has_counterexample
                            for result in reachable_falsification_results
                        ):
                            gate_code = (
                                "VERIFIER_IGNORED_FALSIFICATION_COUNTEREXAMPLE"
                            )
                        elif (
                            capability.falsification_requirement
                            is FalsificationRequirement.REQUIRED_BEFORE_PASS
                            and (
                                not reachable_falsification_results
                                or any(
                                    not result.is_complete
                                    or result.outcome
                                    is FalsificationOutcome.INCOMPLETE
                                    for result in reachable_falsification_results
                                )
                            )
                        ):
                            gate_code = "REQUIRED_FALSIFICATION_INCOMPLETE"
                    reachable_by_id = {item.id: item for item in reachable_evidence}
                    if gate_code:
                        code = gate_code
                    elif set(report.evidence_ids) <= set(reachable_by_id):
                        try:
                            selected = tuple(
                                reachable_by_id[item]
                                for item in report.evidence_ids
                            )
                            bundle = build_verification_bundle(
                                report,
                                selected,
                                claim_dependency_ids=claim.dependencies,
                            )
                            session.record_bundle(claim.claim_id, bundle)
                        except (BundleValidationError, VerificationSessionError):
                            bundle = None
                        else:
                            bundles[claim.claim_id] = bundle
                            status = VerificationExecutionStepStatus.COMPLETED
                            code = ""
            if status is not VerificationExecutionStepStatus.COMPLETED:
                _add_issue(issues, code=code, step=step)
                bundle = _unknown_bundle(
                    claim=claim,
                    verifier_id=step.verifier_id,
                    code=code,
                    evidence=reachable_evidence,
                )
                session.record_bundle(claim.claim_id, bundle)
                bundles[claim.claim_id] = bundle
            record = VerificationExecutionStep(
                step_id=step.step_id,
                kind=step.kind,
                status=status,
                issue_codes=(() if not code else (code,)),
                verdict=bundle.report.verdict,
                bundle_fingerprint=bundle.fingerprint,
            )
            step_results.append(record)
            results_by_step[step.step_id] = record
            consumption = _status_consumption(consumption, status)
            continue

        assert step.claim_id is not None
        consumption = replace(
            consumption,
            steps_started=consumption.steps_started + 1,
            compositions=consumption.compositions + 1,
        )
        try:
            session.compose_claim(step.claim_id)
            state = session.claim_state(step.claim_id)
        except VerificationSessionError:
            code = "INVALID_VERIFICATION_PREREQUISITE"
            _add_issue(issues, code=code, step=step)
            status = VerificationExecutionStepStatus.FAILED
            verdict = VerificationVerdict.UNKNOWN
        else:
            code = ""
            status = VerificationExecutionStepStatus.COMPLETED
            verdict = state.effective_verdict
        record = VerificationExecutionStep(
            step_id=step.step_id,
            kind=step.kind,
            status=status,
            issue_codes=(() if not code else (code,)),
            verdict=verdict,
        )
        step_results.append(record)
        results_by_step[step.step_id] = record
        consumption = _status_consumption(consumption, status)

    if limit_exhausted:
        termination = VerificationExecutionTermination.LIMIT_EXHAUSTED
    elif any(
        item.status is not VerificationExecutionStepStatus.COMPLETED
        for item in step_results
    ):
        termination = VerificationExecutionTermination.FAILED_CLOSED
    else:
        termination = VerificationExecutionTermination.COMPLETE
    session.seal()
    result = VerificationExecutionResult(
        request_fingerprint=request.fingerprint,
        plan_fingerprint=request.plan_fingerprint,
        claim_graph_fingerprint=request.claim_graph_fingerprint,
        verifier_capability_registry_fingerprint=(
            request.verifier_capability_registry_fingerprint
        ),
        evidence_provider_capability_registry_fingerprint=(
            request.evidence_provider_capability_registry_fingerprint
        ),
        falsification_strategy_capability_registry_fingerprint=(
            request.falsification_strategy_capability_registry_fingerprint
        ),
        session=session,
        provider_results=provider_results,
        falsification_results=falsification_results,
        bundles=bundles,
        steps=tuple(step_results),
        issues=tuple(issues),
        consumption=consumption,
        termination=termination,
        correlation_id=request.correlation_id,
    )
    durable_target = storage if storage is not None else unit_of_work
    if durable_target is not None:
        try:
            from .storage import persist_execution_result

            persist_execution_result(durable_target, request, result)
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise VerificationExecutionError(
                "durable storage recording failed closed"
            ) from exc
    return result
