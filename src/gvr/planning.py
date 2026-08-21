from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from .canonical import (
    CanonicalizationError,
    canonical_fingerprint,
    canonical_transport_value,
    canonical_utf8_key,
)
from .capabilities import (
    UnknownVerifierCapabilityError,
    VerifierCapability,
    VerifierCapabilityRegistry,
)
from .evidence_providers import (
    EvidenceProviderCapability,
    EvidenceProviderCapabilityRegistry,
    EvidenceRequest,
    UnknownEvidenceProviderError,
)
from .session import AtomicClaim, ClaimGraph, ClaimOperator, CompositeClaim


ATOMIC_CLAIM_BINDING_SCHEMA_VERSION = 1
ATOMIC_CLAIM_BINDING_KIND = "gvr.atomic_claim_binding"
ATOMIC_CLAIM_BINDING_FINGERPRINT_FORMAT = (
    "gvr.atomic_claim_binding.ieee754-json.v1"
)
VERIFICATION_PLANNING_REQUEST_SCHEMA_VERSION = 1
VERIFICATION_PLANNING_REQUEST_KIND = "gvr.verification_planning_request"
VERIFICATION_PLANNING_REQUEST_FINGERPRINT_FORMAT = (
    "gvr.verification_planning_request.ieee754-json.v1"
)
VERIFICATION_PLAN_SCHEMA_VERSION = 1
VERIFICATION_PLAN_KIND = "gvr.verification_plan"
VERIFICATION_PLAN_FINGERPRINT_FORMAT = "gvr.verification_plan.ieee754-json.v1"
VERIFICATION_PLAN_STEP_FINGERPRINT_FORMAT = (
    "gvr.verification_plan_step.ieee754-json.v1"
)
ATOMIC_CLAIM_FINGERPRINT_FORMAT = "gvr.atomic_claim.ieee754-json.v1"
COMPOSITE_CLAIM_FINGERPRINT_FORMAT = "gvr.composite_claim.ieee754-json.v1"
_STABLE_ISSUE_CODE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$")
_FORBIDDEN_ISSUE_FIELDS = frozenset({
    "claim_verdict",
    "evidence_adequacy",
    "is_sufficient",
    "message",
    "metadata",
    "outcome",
    "result",
    "status",
    "sufficient",
    "sufficiency",
    "truth",
    "truth_value",
    "unknown",
    "verdict",
})
_FORBIDDEN_ISSUE_FIELD_TOKENS = frozenset({
    "adequacy",
    "fail",
    "outcome",
    "pass",
    "result",
    "status",
    "sufficiency",
    "sufficient",
    "truth",
    "verdict",
})


class VerificationPlanningError(ValueError):
    """Raised when a planning artifact is malformed or internally inconsistent."""


class VerificationPlanStepKind(str, Enum):
    ACQUIRE_EVIDENCE = "ACQUIRE_EVIDENCE"
    VERIFY_ATOMIC_CLAIM = "VERIFY_ATOMIC_CLAIM"
    COMPOSE_CLAIM = "COMPOSE_CLAIM"


class VerificationPlanTermination(str, Enum):
    COMPLETE = "COMPLETE"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    UNSUPPORTED_CLAIM = "UNSUPPORTED_CLAIM"


def _identifier(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise VerificationPlanningError(f"{name} must be a non-empty string")
    if value != value.strip() or any(character.isspace() for character in value):
        raise VerificationPlanningError(f"{name} must not contain whitespace")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise VerificationPlanningError(f"{name} must not contain control characters")
    try:
        canonical_utf8_key(value, path=name)
    except CanonicalizationError as exc:
        raise VerificationPlanningError(str(exc)) from exc
    return value


def _sha256(value: Any, *, name: str) -> str:
    fingerprint = _identifier(value, name=name)
    if len(fingerprint) != 64 or any(
        character not in "0123456789abcdef" for character in fingerprint
    ):
        raise VerificationPlanningError(
            f"{name} must be a lowercase SHA-256 fingerprint"
        )
    return fingerprint


def _string_tuple(values: Iterable[str], *, name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise VerificationPlanningError(f"{name} must be an iterable of strings")
    try:
        items = tuple(values)
    except TypeError as exc:
        raise VerificationPlanningError(
            f"{name} must be an iterable of strings"
        ) from exc
    normalized = tuple(_identifier(item, name=f"{name} item") for item in items)
    if len(set(normalized)) != len(normalized):
        raise VerificationPlanningError(f"{name} contains duplicate values")
    return tuple(
        sorted(normalized, key=lambda item: canonical_utf8_key(item, path=name))
    )


def _freeze(value: Any, *, name: str) -> Any:
    try:
        canonical_transport_value(value, path=name)
    except CanonicalizationError as exc:
        raise VerificationPlanningError(str(exc)) from exc
    if value is None or isinstance(value, (bool, str, int, float)):
        return value
    if isinstance(value, Mapping):
        keys = sorted(
            value,
            key=lambda item: canonical_utf8_key(item, path=f"{name} key"),
        )
        return MappingProxyType(
            {key: _freeze(value[key], name=f"{name}.{key}") for key in keys}
        )
    if isinstance(value, (tuple, list)):
        return tuple(
            _freeze(item, name=f"{name}[{index}]")
            for index, item in enumerate(value)
        )
    raise VerificationPlanningError(
        f"{name} contains unsupported value {type(value).__name__}"
    )


def _reject_forbidden_issue_fields(value: Any, *, path: str) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = key.casefold().replace("-", "_")
            tokens = frozenset(normalized.split("_"))
            if (
                normalized in _FORBIDDEN_ISSUE_FIELDS
                or tokens & _FORBIDDEN_ISSUE_FIELD_TOKENS
            ):
                raise VerificationPlanningError(
                    f"planner issue details contain unsupported field {key!r} at {path}"
                )
            _reject_forbidden_issue_fields(nested, path=f"{path}.{key}")
    elif isinstance(value, (tuple, list)):
        for index, nested in enumerate(value):
            _reject_forbidden_issue_fields(nested, path=f"{path}[{index}]")


def _export(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {key: _export(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_export(item) for item in value]
    return value


def _fingerprint(value: Any, *, fingerprint_format: str) -> str:
    try:
        return canonical_fingerprint(value, fingerprint_format=fingerprint_format)
    except CanonicalizationError as exc:
        raise VerificationPlanningError(str(exc)) from exc


def _budget_value(value: Any, *, name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise VerificationPlanningError(
            f"{name} must be a non-negative integer or null"
        )
    return value


@dataclass(frozen=True, kw_only=True)
class VerificationPlanningBudget:
    max_atomic_claims: int | None = None
    max_composite_claims: int | None = None
    max_steps: int | None = None
    max_requests: int | None = None
    max_dependency_edges: int | None = None
    max_requests_per_claim: int | None = None
    max_depth: int | None = None

    def __post_init__(self) -> None:
        for name in (
            "max_atomic_claims",
            "max_composite_claims",
            "max_steps",
            "max_requests",
            "max_dependency_edges",
            "max_requests_per_claim",
            "max_depth",
        ):
            object.__setattr__(
                self,
                name,
                _budget_value(getattr(self, name), name=name),
            )

    def to_dict(self) -> dict[str, int | None]:
        return {
            "max_atomic_claims": self.max_atomic_claims,
            "max_composite_claims": self.max_composite_claims,
            "max_steps": self.max_steps,
            "max_requests": self.max_requests,
            "max_dependency_edges": self.max_dependency_edges,
            "max_requests_per_claim": self.max_requests_per_claim,
            "max_depth": self.max_depth,
        }


@dataclass(frozen=True, kw_only=True)
class VerificationPlanningConsumption:
    atomic_claims: int
    composite_claims: int
    steps: int
    requests: int
    dependency_edges: int
    requests_per_claim: int
    depth: int

    def __post_init__(self) -> None:
        for name in (
            "atomic_claims",
            "composite_claims",
            "steps",
            "requests",
            "dependency_edges",
            "requests_per_claim",
            "depth",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise VerificationPlanningError(
                    f"{name} must be a non-negative integer"
                )

    def to_dict(self) -> dict[str, int]:
        return {
            "atomic_claims": self.atomic_claims,
            "composite_claims": self.composite_claims,
            "steps": self.steps,
            "requests": self.requests,
            "dependency_edges": self.dependency_edges,
            "requests_per_claim": self.requests_per_claim,
            "depth": self.depth,
        }


@dataclass(frozen=True, kw_only=True)
class AtomicClaimBinding:
    claim_id: str
    verifier_id: str
    verifier_version: str
    verifier_capability_fingerprint: str
    evidence_requests: tuple[EvidenceRequest, ...] = ()
    schema_version: int = ATOMIC_CLAIM_BINDING_SCHEMA_VERSION
    kind: str = ATOMIC_CLAIM_BINDING_KIND
    fingerprint_format: str = ATOMIC_CLAIM_BINDING_FINGERPRINT_FORMAT
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise VerificationPlanningError(
                f"unsupported atomic claim binding schema version {self.schema_version}"
            )
        if self.kind != ATOMIC_CLAIM_BINDING_KIND:
            raise VerificationPlanningError(
                f"unsupported atomic claim binding kind {self.kind}"
            )
        if self.fingerprint_format != ATOMIC_CLAIM_BINDING_FINGERPRINT_FORMAT:
            raise VerificationPlanningError(
                "unsupported atomic claim binding fingerprint format"
            )
        object.__setattr__(self, "claim_id", _identifier(self.claim_id, name="claim_id"))
        object.__setattr__(
            self,
            "verifier_id",
            _identifier(self.verifier_id, name="verifier_id"),
        )
        object.__setattr__(
            self,
            "verifier_version",
            _identifier(self.verifier_version, name="verifier_version"),
        )
        object.__setattr__(
            self,
            "verifier_capability_fingerprint",
            _sha256(
                self.verifier_capability_fingerprint,
                name="verifier_capability_fingerprint",
            ),
        )
        try:
            requests = tuple(self.evidence_requests)
        except TypeError as exc:
            raise VerificationPlanningError(
                "evidence_requests must be iterable"
            ) from exc
        if any(type(item) is not EvidenceRequest for item in requests):
            raise VerificationPlanningError(
                "evidence_requests must contain exact EvidenceRequest records"
            )
        request_ids: set[str] = set()
        for request in requests:
            if request.request_id in request_ids:
                raise VerificationPlanningError(
                    f"duplicate evidence request ID {request.request_id} in claim {self.claim_id}"
                )
            request_ids.add(request.request_id)
        requests = tuple(
            sorted(
                requests,
                key=lambda item: (
                    canonical_utf8_key(item.fingerprint, path="request fingerprint"),
                    canonical_utf8_key(item.request_id, path="request_id"),
                ),
            )
        )
        object.__setattr__(self, "evidence_requests", requests)
        object.__setattr__(
            self,
            "fingerprint",
            _fingerprint(
                self.semantic_definition(),
                fingerprint_format=self.fingerprint_format,
            ),
        )

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "claim_id": self.claim_id,
            "verifier_id": self.verifier_id,
            "verifier_version": self.verifier_version,
            "verifier_capability_fingerprint": self.verifier_capability_fingerprint,
            "evidence_requests": tuple(
                request.to_dict() for request in self.evidence_requests
            ),
        }

    def to_dict(self) -> dict[str, Any]:
        value = _export(self.semantic_definition())
        value.update(
            {
                "fingerprint_format": self.fingerprint_format,
                "fingerprint": self.fingerprint,
            }
        )
        return value


@dataclass(frozen=True, kw_only=True)
class VerificationPlanningRequest:
    claim_graph: ClaimGraph
    bindings: tuple[AtomicClaimBinding, ...]
    verifier_capability_registry: VerifierCapabilityRegistry
    verifier_capability_registry_fingerprint: str
    evidence_provider_capability_registry: EvidenceProviderCapabilityRegistry
    evidence_provider_capability_registry_fingerprint: str
    budget: VerificationPlanningBudget = field(default_factory=VerificationPlanningBudget)
    schema_version: int = VERIFICATION_PLANNING_REQUEST_SCHEMA_VERSION
    kind: str = VERIFICATION_PLANNING_REQUEST_KIND
    fingerprint_format: str = VERIFICATION_PLANNING_REQUEST_FINGERPRINT_FORMAT
    fingerprint: str = field(init=False)
    _bindings_by_claim: Mapping[str, AtomicClaimBinding] = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise VerificationPlanningError(
                f"unsupported verification planning request schema version {self.schema_version}"
            )
        if self.kind != VERIFICATION_PLANNING_REQUEST_KIND:
            raise VerificationPlanningError(
                f"unsupported verification planning request kind {self.kind}"
            )
        if self.fingerprint_format != VERIFICATION_PLANNING_REQUEST_FINGERPRINT_FORMAT:
            raise VerificationPlanningError(
                "unsupported verification planning request fingerprint format"
            )
        if type(self.claim_graph) is not ClaimGraph:
            raise VerificationPlanningError("claim_graph must be an exact ClaimGraph")
        if any(
            type(node) not in (AtomicClaim, CompositeClaim)
            for node in self.claim_graph.nodes
        ):
            raise VerificationPlanningError(
                "claim_graph must contain exact AtomicClaim or CompositeClaim records"
            )
        if type(self.verifier_capability_registry) is not VerifierCapabilityRegistry:
            raise VerificationPlanningError(
                "verifier_capability_registry must be an exact VerifierCapabilityRegistry"
            )
        if any(
            type(capability) is not VerifierCapability
            for capability in self.verifier_capability_registry.capabilities
        ):
            raise VerificationPlanningError(
                "verifier_capability_registry must contain exact VerifierCapability descriptors"
            )
        if (
            type(self.evidence_provider_capability_registry)
            is not EvidenceProviderCapabilityRegistry
        ):
            raise VerificationPlanningError(
                "evidence_provider_capability_registry must be an exact EvidenceProviderCapabilityRegistry"
            )
        if any(
            type(capability) is not EvidenceProviderCapability
            for capability in self.evidence_provider_capability_registry.capabilities
        ):
            raise VerificationPlanningError(
                "evidence_provider_capability_registry must contain exact EvidenceProviderCapability descriptors"
            )
        if type(self.budget) is not VerificationPlanningBudget:
            raise VerificationPlanningError(
                "budget must be an exact VerificationPlanningBudget"
            )
        verifier_registry_fingerprint = _sha256(
            self.verifier_capability_registry_fingerprint,
            name="verifier_capability_registry_fingerprint",
        )
        provider_registry_fingerprint = _sha256(
            self.evidence_provider_capability_registry_fingerprint,
            name="evidence_provider_capability_registry_fingerprint",
        )
        if verifier_registry_fingerprint != self.verifier_capability_registry.fingerprint:
            raise VerificationPlanningError(
                "verifier capability registry fingerprint does not match exact registry"
            )
        if (
            provider_registry_fingerprint
            != self.evidence_provider_capability_registry.fingerprint
        ):
            raise VerificationPlanningError(
                "evidence provider capability registry fingerprint does not match exact registry"
            )
        object.__setattr__(
            self,
            "verifier_capability_registry_fingerprint",
            verifier_registry_fingerprint,
        )
        object.__setattr__(
            self,
            "evidence_provider_capability_registry_fingerprint",
            provider_registry_fingerprint,
        )

        try:
            bindings = tuple(self.bindings)
        except TypeError as exc:
            raise VerificationPlanningError("bindings must be iterable") from exc
        if any(type(item) is not AtomicClaimBinding for item in bindings):
            raise VerificationPlanningError(
                "bindings must contain exact AtomicClaimBinding records"
            )
        by_claim: dict[str, AtomicClaimBinding] = {}
        for item in bindings:
            if item.claim_id in by_claim:
                raise VerificationPlanningError(
                    f"duplicate atomic claim binding for {item.claim_id}"
                )
            by_claim[item.claim_id] = item
        atomic_ids = {claim.claim_id for claim in self.claim_graph.atomic_claims}
        binding_ids = set(by_claim)
        missing = sorted(atomic_ids - binding_ids)
        extra = sorted(binding_ids - atomic_ids)
        if missing:
            raise VerificationPlanningError(
                "missing atomic claim bindings: " + ", ".join(missing)
            )
        if extra:
            raise VerificationPlanningError(
                "bindings reference non-atomic claims: " + ", ".join(extra)
            )
        canonical_bindings = tuple(by_claim[claim_id] for claim_id in sorted(by_claim))
        object.__setattr__(self, "bindings", canonical_bindings)
        object.__setattr__(
            self,
            "_bindings_by_claim",
            MappingProxyType(dict(by_claim)),
        )

        requests_by_id: dict[str, EvidenceRequest] = {}
        for item in canonical_bindings:
            for request in item.evidence_requests:
                previous = requests_by_id.get(request.request_id)
                if previous is not None and previous.fingerprint != request.fingerprint:
                    raise VerificationPlanningError(
                        f"request ID conflict for {request.request_id}: different semantics"
                    )
                requests_by_id.setdefault(request.request_id, request)

        object.__setattr__(
            self,
            "fingerprint",
            _fingerprint(
                self.semantic_definition(),
                fingerprint_format=self.fingerprint_format,
            ),
        )

    def binding_for(self, claim_id: str) -> AtomicClaimBinding:
        try:
            return self._bindings_by_claim[claim_id]
        except KeyError as exc:
            raise KeyError(f"unknown atomic claim binding: {claim_id}") from exc

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "claim_graph_fingerprint": self.claim_graph.fingerprint,
            "bindings": tuple(item.to_dict() for item in self.bindings),
            "verifier_capability_registry_fingerprint": (
                self.verifier_capability_registry_fingerprint
            ),
            "evidence_provider_capability_registry_fingerprint": (
                self.evidence_provider_capability_registry_fingerprint
            ),
            "budget": self.budget.to_dict(),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "fingerprint_format": self.fingerprint_format,
            "fingerprint": self.fingerprint,
            "claim_graph": self.claim_graph.to_dict(),
            "bindings": [item.to_dict() for item in self.bindings],
            "verifier_capability_registry": self.verifier_capability_registry.to_dict(),
            "verifier_capability_registry_fingerprint": (
                self.verifier_capability_registry_fingerprint
            ),
            "evidence_provider_capability_registry": (
                self.evidence_provider_capability_registry.to_dict()
            ),
            "evidence_provider_capability_registry_fingerprint": (
                self.evidence_provider_capability_registry_fingerprint
            ),
            "budget": self.budget.to_dict(),
        }


@dataclass(frozen=True, kw_only=True)
class VerificationPlannerIssue:
    code: str
    claim_id: str | None = None
    request_id: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        code = _identifier(self.code, name="issue code")
        if _STABLE_ISSUE_CODE.fullmatch(code) is None:
            raise VerificationPlanningError(
                "issue code must be a stable uppercase identifier"
            )
        object.__setattr__(self, "code", code)
        if self.claim_id is not None:
            object.__setattr__(
                self,
                "claim_id",
                _identifier(self.claim_id, name="issue claim_id"),
            )
        if self.request_id is not None:
            object.__setattr__(
                self,
                "request_id",
                _identifier(self.request_id, name="issue request_id"),
            )
        if not isinstance(self.details, Mapping):
            raise VerificationPlanningError("issue details must be a mapping")
        _reject_forbidden_issue_fields(self.details, path="issue details")
        object.__setattr__(self, "details", _freeze(self.details, name="issue details"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "claim_id": self.claim_id,
            "request_id": self.request_id,
            "details": _export(self.details),
        }


@dataclass(frozen=True, kw_only=True)
class VerificationPlanStep:
    kind: VerificationPlanStepKind
    dependency_step_ids: tuple[str, ...] = ()
    claim_id: str | None = None
    claim_kind: str | None = None
    claim_fingerprint: str | None = None
    operator: ClaimOperator | None = None
    request_id: str | None = None
    request_fingerprint: str | None = None
    request_kind: str | None = None
    requested_evidence_kinds: tuple[str, ...] = ()
    provider_id: str | None = None
    provider_version: str | None = None
    provider_capability_fingerprint: str | None = None
    verifier_id: str | None = None
    verifier_version: str | None = None
    verifier_capability_fingerprint: str | None = None
    fingerprint: str = field(init=False)
    step_id: str = field(init=False)

    def __post_init__(self) -> None:
        try:
            kind = (
                self.kind
                if isinstance(self.kind, VerificationPlanStepKind)
                else VerificationPlanStepKind(str(self.kind))
            )
        except ValueError as exc:
            raise VerificationPlanningError("unsupported verification plan step kind") from exc
        object.__setattr__(self, "kind", kind)
        object.__setattr__(
            self,
            "dependency_step_ids",
            _string_tuple(self.dependency_step_ids, name="dependency_step_ids"),
        )
        object.__setattr__(
            self,
            "requested_evidence_kinds",
            _string_tuple(
                self.requested_evidence_kinds,
                name="requested_evidence_kinds",
            ),
        )
        for name in (
            "claim_id",
            "claim_kind",
            "request_id",
            "request_kind",
            "provider_id",
            "provider_version",
            "verifier_id",
            "verifier_version",
        ):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _identifier(value, name=name))
        for name in (
            "claim_fingerprint",
            "request_fingerprint",
            "provider_capability_fingerprint",
            "verifier_capability_fingerprint",
        ):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _sha256(value, name=name))
        if self.operator is not None and not isinstance(self.operator, ClaimOperator):
            try:
                object.__setattr__(self, "operator", ClaimOperator(str(self.operator)))
            except ValueError as exc:
                raise VerificationPlanningError("unsupported claim operator") from exc
        self._validate_shape()
        fingerprint = _fingerprint(
            self.semantic_definition(),
            fingerprint_format=VERIFICATION_PLAN_STEP_FINGERPRINT_FORMAT,
        )
        object.__setattr__(self, "fingerprint", fingerprint)
        object.__setattr__(self, "step_id", f"step:{fingerprint}")

    def _validate_shape(self) -> None:
        if self.kind is VerificationPlanStepKind.ACQUIRE_EVIDENCE:
            required = (
                self.request_id,
                self.request_fingerprint,
                self.request_kind,
                self.requested_evidence_kinds,
                self.provider_id,
                self.provider_version,
                self.provider_capability_fingerprint,
            )
            if not all(required):
                raise VerificationPlanningError(
                    "ACQUIRE_EVIDENCE step is missing exact request or provider identity"
                )
            if any(
                value is not None
                for value in (
                    self.claim_id,
                    self.claim_kind,
                    self.claim_fingerprint,
                    self.operator,
                    self.verifier_id,
                    self.verifier_version,
                    self.verifier_capability_fingerprint,
                )
            ):
                raise VerificationPlanningError(
                    "ACQUIRE_EVIDENCE step contains claim or verifier fields"
                )
            if self.dependency_step_ids:
                raise VerificationPlanningError(
                    "ACQUIRE_EVIDENCE step cannot depend on another plan step"
                )
            return
        if self.kind is VerificationPlanStepKind.VERIFY_ATOMIC_CLAIM:
            required = (
                self.claim_id,
                self.claim_kind,
                self.claim_fingerprint,
                self.verifier_id,
                self.verifier_version,
                self.verifier_capability_fingerprint,
            )
            if not all(required):
                raise VerificationPlanningError(
                    "VERIFY_ATOMIC_CLAIM step is missing exact claim or verifier identity"
                )
            if self.operator is not None or any(
                value is not None
                for value in (
                    self.request_fingerprint,
                    self.request_kind,
                    self.provider_id,
                    self.provider_version,
                    self.provider_capability_fingerprint,
                )
            ) or self.request_id is not None or self.requested_evidence_kinds:
                raise VerificationPlanningError(
                    "VERIFY_ATOMIC_CLAIM step contains acquisition or composition fields"
                )
            return
        required = (self.claim_id, self.claim_fingerprint, self.operator)
        if not all(required):
            raise VerificationPlanningError(
                "COMPOSE_CLAIM step is missing exact claim or operator identity"
            )
        if not self.dependency_step_ids:
            raise VerificationPlanningError(
                "COMPOSE_CLAIM step requires dependency steps"
            )
        if self.claim_kind is not None or any(
            value is not None
            for value in (
                self.request_fingerprint,
                self.request_kind,
                self.provider_id,
                self.provider_version,
                self.provider_capability_fingerprint,
                self.verifier_id,
                self.verifier_version,
                self.verifier_capability_fingerprint,
            )
        ) or self.request_id is not None or self.requested_evidence_kinds:
            raise VerificationPlanningError(
                "COMPOSE_CLAIM step contains acquisition or verifier fields"
            )

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "dependency_step_ids": self.dependency_step_ids,
            "claim_id": self.claim_id,
            "claim_kind": self.claim_kind,
            "claim_fingerprint": self.claim_fingerprint,
            "operator": None if self.operator is None else self.operator.value,
            "request_id": self.request_id,
            "request_fingerprint": self.request_fingerprint,
            "request_kind": self.request_kind,
            "requested_evidence_kinds": self.requested_evidence_kinds,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "provider_capability_fingerprint": self.provider_capability_fingerprint,
            "verifier_id": self.verifier_id,
            "verifier_version": self.verifier_version,
            "verifier_capability_fingerprint": self.verifier_capability_fingerprint,
        }

    def to_dict(self) -> dict[str, Any]:
        value = _export(self.semantic_definition())
        value.update({"step_id": self.step_id, "fingerprint": self.fingerprint})
        return value


@dataclass(frozen=True, kw_only=True)
class VerificationPlan:
    request_fingerprint: str
    claim_graph_fingerprint: str
    verifier_capability_registry_fingerprint: str
    evidence_provider_capability_registry_fingerprint: str
    budget: VerificationPlanningBudget
    consumption: VerificationPlanningConsumption
    termination: VerificationPlanTermination
    steps: tuple[VerificationPlanStep, ...] = ()
    issues: tuple[VerificationPlannerIssue, ...] = ()
    schema_version: int = VERIFICATION_PLAN_SCHEMA_VERSION
    kind: str = VERIFICATION_PLAN_KIND
    fingerprint_format: str = VERIFICATION_PLAN_FINGERPRINT_FORMAT
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise VerificationPlanningError(
                f"unsupported verification plan schema version {self.schema_version}"
            )
        if self.kind != VERIFICATION_PLAN_KIND:
            raise VerificationPlanningError(
                f"unsupported verification plan kind {self.kind}"
            )
        if self.fingerprint_format != VERIFICATION_PLAN_FINGERPRINT_FORMAT:
            raise VerificationPlanningError(
                "unsupported verification plan fingerprint format"
            )
        for name in (
            "request_fingerprint",
            "claim_graph_fingerprint",
            "verifier_capability_registry_fingerprint",
            "evidence_provider_capability_registry_fingerprint",
        ):
            object.__setattr__(self, name, _sha256(getattr(self, name), name=name))
        if type(self.budget) is not VerificationPlanningBudget:
            raise VerificationPlanningError("plan budget has the wrong type")
        if type(self.consumption) is not VerificationPlanningConsumption:
            raise VerificationPlanningError("plan consumption has the wrong type")
        try:
            termination = (
                self.termination
                if isinstance(self.termination, VerificationPlanTermination)
                else VerificationPlanTermination(str(self.termination))
            )
        except ValueError as exc:
            raise VerificationPlanningError("unsupported plan termination") from exc
        object.__setattr__(self, "termination", termination)
        steps = tuple(self.steps)
        issues = tuple(self.issues)
        if any(type(item) is not VerificationPlanStep for item in steps):
            raise VerificationPlanningError(
                "steps must contain exact VerificationPlanStep records"
            )
        if any(type(item) is not VerificationPlannerIssue for item in issues):
            raise VerificationPlanningError(
                "issues must contain exact VerificationPlannerIssue records"
            )
        if len({item.step_id for item in steps}) != len(steps):
            raise VerificationPlanningError("verification plan contains duplicate step IDs")
        known_steps: set[str] = set()
        for item in steps:
            if not set(item.dependency_step_ids) <= known_steps:
                raise VerificationPlanningError(
                    f"step {item.step_id} has an unknown or forward dependency"
                )
            known_steps.add(item.step_id)
        canonical_issues = tuple(sorted(issues, key=_issue_key))
        if termination is VerificationPlanTermination.COMPLETE:
            if canonical_issues:
                raise VerificationPlanningError(
                    "complete verification plan cannot contain planner issues"
                )
            if len(steps) != self.consumption.steps:
                raise VerificationPlanningError(
                    "complete verification plan step count does not match consumption"
                )
        else:
            if steps:
                raise VerificationPlanningError(
                    "non-complete verification plan cannot contain executable steps"
                )
            if not canonical_issues:
                raise VerificationPlanningError(
                    "non-complete verification plan requires planner issues"
                )
            if termination is VerificationPlanTermination.BUDGET_EXHAUSTED and any(
                issue.code != "BUDGET_EXHAUSTED" for issue in canonical_issues
            ):
                raise VerificationPlanningError(
                    "budget-exhausted plan contains a non-budget issue"
                )
            if termination is VerificationPlanTermination.UNSUPPORTED_CLAIM and any(
                issue.code == "BUDGET_EXHAUSTED" for issue in canonical_issues
            ):
                raise VerificationPlanningError(
                    "unsupported-claim plan contains a budget issue"
                )
        object.__setattr__(self, "steps", steps)
        object.__setattr__(self, "issues", canonical_issues)
        object.__setattr__(
            self,
            "fingerprint",
            _fingerprint(
                self.semantic_definition(),
                fingerprint_format=self.fingerprint_format,
            ),
        )

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "request_fingerprint": self.request_fingerprint,
            "claim_graph_fingerprint": self.claim_graph_fingerprint,
            "verifier_capability_registry_fingerprint": (
                self.verifier_capability_registry_fingerprint
            ),
            "evidence_provider_capability_registry_fingerprint": (
                self.evidence_provider_capability_registry_fingerprint
            ),
            "budget": self.budget.to_dict(),
            "consumption": self.consumption.to_dict(),
            "termination": self.termination.value,
            "steps": tuple(item.to_dict() for item in self.steps),
            "issues": tuple(item.to_dict() for item in self.issues),
        }

    def to_dict(self) -> dict[str, Any]:
        value = _export(self.semantic_definition())
        value.update(
            {
                "fingerprint_format": self.fingerprint_format,
                "fingerprint": self.fingerprint,
            }
        )
        return value


def _issue_key(issue: VerificationPlannerIssue) -> tuple[bytes, bytes, bytes, bytes]:
    details_fingerprint = _fingerprint(
        issue.details,
        fingerprint_format="gvr.verification_planner_issue.ieee754-json.v1",
    )
    return (
        canonical_utf8_key(issue.code, path="issue code"),
        canonical_utf8_key(issue.claim_id or "", path="issue claim_id"),
        canonical_utf8_key(issue.request_id or "", path="issue request_id"),
        canonical_utf8_key(details_fingerprint, path="issue details fingerprint"),
    )


def _claim_fingerprint(claim: AtomicClaim | CompositeClaim) -> str:
    return _fingerprint(
        claim.semantic_definition(),
        fingerprint_format=(
            ATOMIC_CLAIM_FINGERPRINT_FORMAT
            if isinstance(claim, AtomicClaim)
            else COMPOSITE_CLAIM_FINGERPRINT_FORMAT
        ),
    )


def _graph_depth(graph: ClaimGraph) -> int:
    depths: dict[str, int] = {}
    for claim_id in graph.evaluation_order:
        claim = graph.claim(claim_id)
        depths[claim_id] = (
            1
            if not claim.dependencies
            else 1 + max(depths[item] for item in claim.dependencies)
        )
    return max(depths.values(), default=0)


def _consumption(request: VerificationPlanningRequest) -> VerificationPlanningConsumption:
    exact_requests = {
        (evidence_request.request_id, evidence_request.fingerprint)
        for binding in request.bindings
        for evidence_request in binding.evidence_requests
    }
    requests_per_claim = max(
        (len(binding.evidence_requests) for binding in request.bindings),
        default=0,
    )
    atomic_claims = len(request.claim_graph.atomic_claims)
    composite_claims = len(request.claim_graph.composite_claims)
    return VerificationPlanningConsumption(
        atomic_claims=atomic_claims,
        composite_claims=composite_claims,
        steps=len(exact_requests) + atomic_claims + composite_claims,
        requests=len(exact_requests),
        dependency_edges=sum(
            len(claim.dependencies) for claim in request.claim_graph.nodes
        ),
        requests_per_claim=requests_per_claim,
        depth=_graph_depth(request.claim_graph),
    )


def _base_plan(
    request: VerificationPlanningRequest,
    *,
    consumption: VerificationPlanningConsumption,
    termination: VerificationPlanTermination,
    steps: tuple[VerificationPlanStep, ...] = (),
    issues: tuple[VerificationPlannerIssue, ...] = (),
) -> VerificationPlan:
    return VerificationPlan(
        request_fingerprint=request.fingerprint,
        claim_graph_fingerprint=request.claim_graph.fingerprint,
        verifier_capability_registry_fingerprint=(
            request.verifier_capability_registry_fingerprint
        ),
        evidence_provider_capability_registry_fingerprint=(
            request.evidence_provider_capability_registry_fingerprint
        ),
        budget=request.budget,
        consumption=consumption,
        termination=termination,
        steps=steps,
        issues=issues,
    )


def _compatibility_issues(
    request: VerificationPlanningRequest,
) -> tuple[VerificationPlannerIssue, ...]:
    issues: list[VerificationPlannerIssue] = []
    for claim in request.claim_graph.atomic_claims:
        binding = request.binding_for(claim.claim_id)
        if binding.verifier_id != claim.verifier:
            issues.append(
                VerificationPlannerIssue(
                    code="VERIFIER_ID_MISMATCH",
                    claim_id=claim.claim_id,
                    details={
                        "binding_verifier_id": binding.verifier_id,
                        "claim_verifier_id": claim.verifier,
                    },
                )
            )
            continue
        try:
            verifier = request.verifier_capability_registry.lookup(
                binding.verifier_id,
                binding.verifier_version,
            )
        except UnknownVerifierCapabilityError:
            issues.append(
                VerificationPlannerIssue(
                    code="UNKNOWN_VERIFIER_CAPABILITY",
                    claim_id=claim.claim_id,
                    details={
                        "verifier_id": binding.verifier_id,
                        "verifier_version": binding.verifier_version,
                    },
                )
            )
            continue
        if verifier.fingerprint != binding.verifier_capability_fingerprint:
            issues.append(
                VerificationPlannerIssue(
                    code="VERIFIER_CAPABILITY_FINGERPRINT_MISMATCH",
                    claim_id=claim.claim_id,
                    details={
                        "verifier_id": binding.verifier_id,
                        "verifier_version": binding.verifier_version,
                    },
                )
            )
            continue
        if claim.claim_kind not in verifier.claim_kinds:
            issues.append(
                VerificationPlannerIssue(
                    code="UNSUPPORTED_CLAIM_KIND",
                    claim_id=claim.claim_id,
                    details={"claim_kind": claim.claim_kind},
                )
            )
            continue
        if not verifier.authoritative:
            issues.append(
                VerificationPlannerIssue(
                    code="NON_AUTHORITATIVE_VERIFIER",
                    claim_id=claim.claim_id,
                    details={
                        "verifier_id": verifier.verifier_id,
                        "verifier_version": verifier.version,
                    },
                )
            )
            continue
        if verifier.required_evidence_kinds and not binding.evidence_requests:
            issues.append(
                VerificationPlannerIssue(
                    code="MISSING_EVIDENCE_REQUEST",
                    claim_id=claim.claim_id,
                    details={
                        "evidence_kinds": verifier.required_evidence_kinds,
                    },
                )
            )
            continue

        requested_for_verifier: set[str] = set()
        for evidence_request in binding.evidence_requests:
            try:
                provider = request.evidence_provider_capability_registry.lookup(
                    evidence_request.provider_id,
                    evidence_request.provider_version,
                )
            except UnknownEvidenceProviderError:
                issues.append(
                    VerificationPlannerIssue(
                        code="UNKNOWN_EVIDENCE_PROVIDER_CAPABILITY",
                        claim_id=claim.claim_id,
                        request_id=evidence_request.request_id,
                        details={
                            "provider_id": evidence_request.provider_id,
                            "provider_version": evidence_request.provider_version,
                        },
                    )
                )
                continue
            if evidence_request.request_kind not in provider.request_kinds:
                issues.append(
                    VerificationPlannerIssue(
                        code="UNSUPPORTED_REQUEST_KIND",
                        claim_id=claim.claim_id,
                        request_id=evidence_request.request_id,
                        details={"request_kind": evidence_request.request_kind},
                    )
                )
                continue
            unsupported_kinds = tuple(
                sorted(
                    set(evidence_request.requested_evidence_kinds)
                    - set(provider.produced_evidence_kinds)
                )
            )
            if unsupported_kinds:
                issues.append(
                    VerificationPlannerIssue(
                        code="UNSUPPORTED_REQUESTED_EVIDENCE_KIND",
                        claim_id=claim.claim_id,
                        request_id=evidence_request.request_id,
                        details={"evidence_kinds": unsupported_kinds},
                    )
                )
                continue
            if (
                (provider.source_classes and (
                    evidence_request.source_class is None
                    or evidence_request.source_class not in provider.source_classes
                ))
                or (not provider.source_classes and evidence_request.source_class is not None)
            ):
                issues.append(
                    VerificationPlannerIssue(
                        code="UNSUPPORTED_SOURCE_CLASS",
                        claim_id=claim.claim_id,
                        request_id=evidence_request.request_id,
                        details={"source_class": evidence_request.source_class},
                    )
                )
                continue
            if (
                (provider.snapshot_classes and (
                    evidence_request.snapshot_class is None
                    or evidence_request.snapshot_class not in provider.snapshot_classes
                ))
                or (
                    not provider.snapshot_classes
                    and evidence_request.snapshot_class is not None
                )
            ):
                issues.append(
                    VerificationPlannerIssue(
                        code="UNSUPPORTED_SNAPSHOT_CLASS",
                        claim_id=claim.claim_id,
                        request_id=evidence_request.request_id,
                        details={"snapshot_class": evidence_request.snapshot_class},
                    )
                )
                continue
            intersection = set(evidence_request.requested_evidence_kinds) & set(
                verifier.accepted_evidence_kinds
            )
            if not intersection:
                issues.append(
                    VerificationPlannerIssue(
                        code="STRUCTURAL_EVIDENCE_INCOMPATIBILITY",
                        claim_id=claim.claim_id,
                        request_id=evidence_request.request_id,
                        details={
                            "requested_evidence_kinds": (
                                evidence_request.requested_evidence_kinds
                            ),
                            "verifier_id": verifier.verifier_id,
                            "verifier_version": verifier.version,
                        },
                    )
                )
                continue
            requested_for_verifier.update(intersection)

        missing = tuple(
            sorted(
                set(verifier.required_evidence_kinds) - requested_for_verifier
            )
        )
        if missing:
            issues.append(
                VerificationPlannerIssue(
                    code="MISSING_REQUIRED_EVIDENCE_KIND",
                    claim_id=claim.claim_id,
                    details={"evidence_kinds": missing},
                )
            )
    return tuple(sorted(issues, key=_issue_key))


def _budget_issues(
    request: VerificationPlanningRequest,
    consumption: VerificationPlanningConsumption,
) -> tuple[VerificationPlannerIssue, ...]:
    values = consumption.to_dict()
    fields = (
        ("max_atomic_claims", "atomic_claims"),
        ("max_composite_claims", "composite_claims"),
        ("max_steps", "steps"),
        ("max_requests", "requests"),
        ("max_dependency_edges", "dependency_edges"),
        ("max_requests_per_claim", "requests_per_claim"),
        ("max_depth", "depth"),
    )
    issues = []
    for budget_name, consumption_name in fields:
        limit = getattr(request.budget, budget_name)
        required = values[consumption_name]
        if limit is not None and required > limit:
            issues.append(
                VerificationPlannerIssue(
                    code="BUDGET_EXHAUSTED",
                    details={
                        "budget": budget_name,
                        "limit": limit,
                        "required": required,
                    },
                )
            )
    return tuple(issues)


def _build_steps(
    request: VerificationPlanningRequest,
) -> tuple[VerificationPlanStep, ...]:
    requests_by_exact_key: dict[tuple[str, str], EvidenceRequest] = {}
    for binding in request.bindings:
        for evidence_request in binding.evidence_requests:
            requests_by_exact_key.setdefault(
                (evidence_request.request_id, evidence_request.fingerprint),
                evidence_request,
            )

    acquisition_by_exact_key: dict[tuple[str, str], VerificationPlanStep] = {}
    steps: list[VerificationPlanStep] = []
    exact_keys = sorted(
        requests_by_exact_key,
        key=lambda item: (
            canonical_utf8_key(item[1], path="request fingerprint"),
            canonical_utf8_key(item[0], path="request_id"),
        ),
    )
    for exact_key in exact_keys:
        representative = requests_by_exact_key[exact_key]
        provider = request.evidence_provider_capability_registry.lookup(
            representative.provider_id,
            representative.provider_version,
        )
        step = VerificationPlanStep(
            kind=VerificationPlanStepKind.ACQUIRE_EVIDENCE,
            request_id=representative.request_id,
            request_fingerprint=representative.fingerprint,
            request_kind=representative.request_kind,
            requested_evidence_kinds=representative.requested_evidence_kinds,
            provider_id=representative.provider_id,
            provider_version=representative.provider_version,
            provider_capability_fingerprint=provider.fingerprint,
        )
        acquisition_by_exact_key[exact_key] = step
        steps.append(step)

    final_step_by_claim: dict[str, VerificationPlanStep] = {}
    for claim_id in request.claim_graph.evaluation_order:
        claim = request.claim_graph.claim(claim_id)
        claim_dependencies = [
            final_step_by_claim[dependency].step_id
            for dependency in claim.dependencies
        ]
        if isinstance(claim, AtomicClaim):
            binding = request.binding_for(claim.claim_id)
            verifier = request.verifier_capability_registry.lookup(
                binding.verifier_id,
                binding.verifier_version,
            )
            acquisition_dependencies = [
                acquisition_by_exact_key[
                    (item.request_id, item.fingerprint)
                ].step_id
                for item in binding.evidence_requests
            ]
            step = VerificationPlanStep(
                kind=VerificationPlanStepKind.VERIFY_ATOMIC_CLAIM,
                dependency_step_ids=tuple(
                    acquisition_dependencies + claim_dependencies
                ),
                claim_id=claim.claim_id,
                claim_kind=claim.claim_kind,
                claim_fingerprint=_claim_fingerprint(claim),
                verifier_id=verifier.verifier_id,
                verifier_version=verifier.version,
                verifier_capability_fingerprint=verifier.fingerprint,
            )
        else:
            step = VerificationPlanStep(
                kind=VerificationPlanStepKind.COMPOSE_CLAIM,
                dependency_step_ids=tuple(claim_dependencies),
                claim_id=claim.claim_id,
                claim_fingerprint=_claim_fingerprint(claim),
                operator=claim.operator,
            )
        final_step_by_claim[claim_id] = step
        steps.append(step)
    return tuple(steps)


def compile_verification_plan(
    request: VerificationPlanningRequest,
) -> VerificationPlan:
    """Compile an exact deterministic plan without invoking any provider or verifier."""

    if type(request) is not VerificationPlanningRequest:
        raise VerificationPlanningError(
            "request must be an exact VerificationPlanningRequest"
        )
    consumption = _consumption(request)
    compatibility_issues = _compatibility_issues(request)
    if compatibility_issues:
        return _base_plan(
            request,
            consumption=consumption,
            termination=VerificationPlanTermination.UNSUPPORTED_CLAIM,
            issues=compatibility_issues,
        )
    budget_issues = _budget_issues(request, consumption)
    if budget_issues:
        return _base_plan(
            request,
            consumption=consumption,
            termination=VerificationPlanTermination.BUDGET_EXHAUSTED,
            issues=budget_issues,
        )
    return _base_plan(
        request,
        consumption=consumption,
        termination=VerificationPlanTermination.COMPLETE,
        steps=_build_steps(request),
    )
