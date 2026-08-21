from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Protocol, runtime_checkable

from .canonical import CanonicalizationError, canonical_fingerprint, canonical_transport_value, canonical_utf8_key
from .capabilities import VerifierCapability, VerifierCost, VerifierDeterminism
from .model import Evidence, VerificationIssue, VerificationVerdict

EVIDENCE_PROVIDER_CAPABILITY_SCHEMA_VERSION = 1
EVIDENCE_PROVIDER_CAPABILITY_KIND = "gvr.evidence_provider_capability"
EVIDENCE_PROVIDER_CAPABILITY_FINGERPRINT_FORMAT = "gvr.evidence_provider_capability.ieee754-json.v1"
EVIDENCE_PROVIDER_CAPABILITY_REGISTRY_SCHEMA_VERSION = 1
EVIDENCE_PROVIDER_CAPABILITY_REGISTRY_KIND = "gvr.evidence_provider_capability_registry"
EVIDENCE_PROVIDER_CAPABILITY_REGISTRY_FINGERPRINT_FORMAT = "gvr.evidence_provider_capability_registry.ieee754-json.v1"


class EvidenceProviderError(ValueError):
    """Raised when an evidence provider contract or result is inconsistent."""


class UnknownEvidenceProviderError(LookupError):
    """Raised when an exact evidence provider ID and version are not registered."""


class EvidenceAcquisitionStatus(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"
    UNSUPPORTED = "UNSUPPORTED"


class EvidenceCompleteness(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


def _strict_identifier(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise EvidenceProviderError(f"{name} must be a non-empty string")
    if value != value.strip() or any(character.isspace() for character in value):
        raise EvidenceProviderError(f"{name} must not contain whitespace")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise EvidenceProviderError(f"{name} must not contain control characters")
    try:
        canonical_utf8_key(value, path=name)
    except CanonicalizationError as exc:
        raise EvidenceProviderError(str(exc)) from exc
    return value


def _string_tuple(values: Iterable[str], *, name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise EvidenceProviderError(f"{name} must be an iterable of strings")
    try:
        items = tuple(values)
    except TypeError as exc:
        raise EvidenceProviderError(f"{name} must be an iterable of strings") from exc
    normalized = tuple(_strict_identifier(item, name=f"{name} item") for item in items)
    if len(set(normalized)) != len(normalized):
        raise EvidenceProviderError(f"{name} contains duplicate values")
    return tuple(sorted(normalized, key=lambda item: canonical_utf8_key(item, path=name)))


def _freeze_validated(value: Any) -> Any:
    if value is None or isinstance(value, (bool, str, int, float)):
        return value
    if isinstance(value, Mapping):
        keys = sorted(value, key=lambda item: canonical_utf8_key(item, path="mapping key"))
        return MappingProxyType({key: _freeze_validated(value[key]) for key in keys})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_validated(item) for item in value)
    raise EvidenceProviderError(f"unsupported immutable contract value {type(value).__name__}")


def _strict_mapping(value: Any, *, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise EvidenceProviderError(f"{name} must be a mapping")
    try:
        canonical_transport_value(value, path=name)
    except CanonicalizationError as exc:
        raise EvidenceProviderError(str(exc)) from exc
    return _freeze_validated(value)


def _export_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _export_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_export_value(item) for item in value]
    if isinstance(value, Enum):
        return value.value
    return value


def _enum_value(value: Any, enum_type: type[Enum], *, name: str) -> Enum:
    if isinstance(value, enum_type):
        return value
    if not isinstance(value, str):
        raise EvidenceProviderError(f"{name} must be a string enum value")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise EvidenceProviderError(f"unsupported {name} {value!r}") from exc


@dataclass(frozen=True)
class EvidenceRequest:
    request_id: str
    provider_id: str
    provider_version: str
    claim_kind: str
    required_evidence_kinds: tuple[str, ...]
    accepted_evidence_kinds: tuple[str, ...]
    input: Mapping[str, Any] = field(default_factory=dict)
    bounds: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", _strict_identifier(self.request_id, name="request_id"))
        object.__setattr__(self, "provider_id", _strict_identifier(self.provider_id, name="provider_id"))
        object.__setattr__(self, "provider_version", _strict_identifier(self.provider_version, name="provider_version"))
        object.__setattr__(self, "claim_kind", _strict_identifier(self.claim_kind, name="claim_kind"))
        required = _string_tuple(self.required_evidence_kinds, name="required_evidence_kinds")
        accepted = _string_tuple(self.accepted_evidence_kinds, name="accepted_evidence_kinds")
        if not set(required) <= set(accepted):
            raise EvidenceProviderError("required_evidence_kinds must be a subset of accepted_evidence_kinds")
        object.__setattr__(self, "required_evidence_kinds", required)
        object.__setattr__(self, "accepted_evidence_kinds", accepted)
        object.__setattr__(self, "input", _strict_mapping(self.input, name="input"))
        object.__setattr__(self, "bounds", _strict_mapping(self.bounds, name="bounds"))


@dataclass(frozen=True)
class EvidenceCoverage:
    completeness: EvidenceCompleteness
    covered_evidence_kinds: tuple[str, ...] = ()
    truncated: bool = False
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "completeness", _enum_value(self.completeness, EvidenceCompleteness, name="completeness"))
        object.__setattr__(self, "covered_evidence_kinds", _string_tuple(self.covered_evidence_kinds, name="covered_evidence_kinds"))
        if not isinstance(self.truncated, bool):
            raise EvidenceProviderError("truncated must be a boolean")
        object.__setattr__(self, "details", _strict_mapping(self.details, name="details"))
        if self.completeness is EvidenceCompleteness.COMPLETE and self.truncated:
            raise EvidenceProviderError("complete coverage cannot be truncated")
        if self.completeness is EvidenceCompleteness.PARTIAL and not self.truncated:
            raise EvidenceProviderError("partial coverage must declare truncation")
        if self.completeness is EvidenceCompleteness.UNKNOWN and self.covered_evidence_kinds:
            raise EvidenceProviderError("unknown coverage cannot declare covered evidence kinds")

    def to_dict(self) -> dict[str, Any]:
        return {
            "completeness": self.completeness.value,
            "covered_evidence_kinds": list(self.covered_evidence_kinds),
            "truncated": self.truncated,
            "details": _export_value(self.details),
        }


@dataclass(frozen=True)
class EvidenceProviderResult:
    request_id: str
    provider_id: str
    provider_version: str
    status: EvidenceAcquisitionStatus
    coverage: EvidenceCoverage
    evidence: tuple[Evidence, ...] = ()
    issues: tuple[VerificationIssue, ...] = ()
    capability_fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", _strict_identifier(self.request_id, name="request_id"))
        object.__setattr__(self, "provider_id", _strict_identifier(self.provider_id, name="provider_id"))
        object.__setattr__(self, "provider_version", _strict_identifier(self.provider_version, name="provider_version"))
        object.__setattr__(self, "status", _enum_value(self.status, EvidenceAcquisitionStatus, name="status"))
        if not isinstance(self.coverage, EvidenceCoverage):
            raise EvidenceProviderError("coverage must be EvidenceCoverage")
        evidence = tuple(self.evidence)
        if any(not isinstance(item, Evidence) for item in evidence):
            raise EvidenceProviderError("evidence must contain Evidence records")
        ids = [item.id for item in evidence]
        if any(not item for item in ids) or len(set(ids)) != len(ids):
            raise EvidenceProviderError("evidence IDs must be non-empty and unique")
        object.__setattr__(self, "evidence", evidence)
        issues = tuple(self.issues)
        if any(not isinstance(item, VerificationIssue) for item in issues):
            raise EvidenceProviderError("issues must contain VerificationIssue records")
        if any(item.verdict is not VerificationVerdict.UNKNOWN for item in issues):
            raise EvidenceProviderError("provider issues must not carry PASS or FAIL verdicts")
        object.__setattr__(self, "issues", issues)
        object.__setattr__(self, "capability_fingerprint", _strict_identifier(self.capability_fingerprint, name="capability_fingerprint"))
        if self.status is EvidenceAcquisitionStatus.COMPLETE and self.coverage.completeness is not EvidenceCompleteness.COMPLETE:
            raise EvidenceProviderError("COMPLETE status requires complete coverage")
        if self.status is EvidenceAcquisitionStatus.PARTIAL and self.coverage.completeness is not EvidenceCompleteness.PARTIAL:
            raise EvidenceProviderError("PARTIAL status requires partial coverage")
        if self.status in (EvidenceAcquisitionStatus.UNAVAILABLE, EvidenceAcquisitionStatus.UNSUPPORTED):
            if evidence:
                raise EvidenceProviderError("unavailable or unsupported results cannot include evidence")
            if self.coverage.completeness is not EvidenceCompleteness.UNKNOWN:
                raise EvidenceProviderError("unavailable or unsupported results require unknown coverage")

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "status": self.status.value,
            "coverage": self.coverage.to_dict(),
            "evidence": [
                {
                    "id": item.id,
                    "kind": item.kind,
                    "payload": _export_value(item.payload),
                    "source": item.source,
                    "fingerprint": item.fingerprint,
                }
                for item in self.evidence
            ],
            "issues": [
                {
                    "code": item.code,
                    "message": item.message,
                    "verdict": item.verdict.value,
                    "evidence_ids": list(item.evidence_ids),
                }
                for item in self.issues
            ],
            "capability_fingerprint": self.capability_fingerprint,
        }


@dataclass(frozen=True, kw_only=True)
class EvidenceProviderCapability:
    provider_id: str
    version: str
    claim_kinds: tuple[str, ...]
    produced_evidence_kinds: tuple[str, ...]
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any]
    determinism: VerifierDeterminism
    side_effect_free: bool
    cost: VerifierCost
    bounds: Mapping[str, Any]
    coverage: Mapping[str, Any]
    description: str | None = None
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider_id", _strict_identifier(self.provider_id, name="provider_id"))
        object.__setattr__(self, "version", _strict_identifier(self.version, name="version"))
        object.__setattr__(self, "claim_kinds", _string_tuple(self.claim_kinds, name="claim_kinds"))
        object.__setattr__(self, "produced_evidence_kinds", _string_tuple(self.produced_evidence_kinds, name="produced_evidence_kinds"))
        object.__setattr__(self, "input_schema", _strict_mapping(self.input_schema, name="input_schema"))
        object.__setattr__(self, "output_schema", _strict_mapping(self.output_schema, name="output_schema"))
        object.__setattr__(self, "determinism", _enum_value(self.determinism, VerifierDeterminism, name="determinism"))
        if not isinstance(self.side_effect_free, bool):
            raise EvidenceProviderError("side_effect_free must be a boolean")
        object.__setattr__(self, "cost", _enum_value(self.cost, VerifierCost, name="cost"))
        object.__setattr__(self, "bounds", _strict_mapping(self.bounds, name="bounds"))
        object.__setattr__(self, "coverage", _strict_mapping(self.coverage, name="coverage"))
        if self.description is not None:
            if not isinstance(self.description, str):
                raise EvidenceProviderError("description must be a string")
            try:
                canonical_utf8_key(self.description, path="description")
            except CanonicalizationError as exc:
                raise EvidenceProviderError(str(exc)) from exc
        try:
            fingerprint = canonical_fingerprint(self.semantic_definition(), fingerprint_format=EVIDENCE_PROVIDER_CAPABILITY_FINGERPRINT_FORMAT)
        except CanonicalizationError as exc:
            raise EvidenceProviderError(str(exc)) from exc
        object.__setattr__(self, "fingerprint", fingerprint)

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "schema_version": EVIDENCE_PROVIDER_CAPABILITY_SCHEMA_VERSION,
            "kind": EVIDENCE_PROVIDER_CAPABILITY_KIND,
            "provider_id": self.provider_id,
            "version": self.version,
            "claim_kinds": self.claim_kinds,
            "produced_evidence_kinds": self.produced_evidence_kinds,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "determinism": self.determinism.value,
            "side_effect_free": self.side_effect_free,
            "cost": self.cost.value,
            "bounds": self.bounds,
            "coverage": self.coverage,
        }

    def to_dict(self) -> dict[str, Any]:
        value = _export_value(self.semantic_definition())
        value.update({"fingerprint_format": EVIDENCE_PROVIDER_CAPABILITY_FINGERPRINT_FORMAT, "fingerprint": self.fingerprint, "description": self.description})
        return value

    def export(self) -> dict[str, Any]:
        return self.to_dict()

    def supports_request_kind(self, request_kind: str) -> bool:
        return request_kind in self.claim_kinds

    def produces_evidence_kind(self, evidence_kind: str) -> bool:
        return evidence_kind in self.produced_evidence_kinds


@dataclass(frozen=True)
class EvidenceProviderCompatibility:
    compatible: bool
    evidence_kinds: tuple[str, ...] = ()
    missing_required_evidence_kinds: tuple[str, ...] = ()
    unsupported_claim_kind: bool = False
    truth_upgraded: bool = False


def provider_capability_is_compatible_with_verifier(
    provider: EvidenceProviderCapability,
    verifier: VerifierCapability,
    *,
    claim_kind: str,
) -> EvidenceProviderCompatibility:
    claim_kind = _strict_identifier(claim_kind, name="claim_kind")
    unsupported = claim_kind not in provider.claim_kinds or claim_kind not in verifier.claim_kinds
    intersection = tuple(sorted(set(provider.produced_evidence_kinds) & set(verifier.accepted_evidence_kinds), key=lambda item: canonical_utf8_key(item, path="evidence_kind")))
    missing = tuple(sorted(set(verifier.required_evidence_kinds) - set(provider.produced_evidence_kinds), key=lambda item: canonical_utf8_key(item, path="evidence_kind")))
    return EvidenceProviderCompatibility(
        compatible=not unsupported and not missing and bool(intersection),
        evidence_kinds=intersection,
        missing_required_evidence_kinds=missing,
        unsupported_claim_kind=unsupported,
        truth_upgraded=False,
    )


@runtime_checkable
class EvidenceProvider(Protocol):
    def acquire(self, request: EvidenceRequest) -> EvidenceProviderResult: ...


def validate_evidence_provider_result(result: EvidenceProviderResult, request: EvidenceRequest, capability: EvidenceProviderCapability) -> EvidenceProviderResult:
    if not isinstance(result, EvidenceProviderResult):
        raise EvidenceProviderError("result must be EvidenceProviderResult")
    if result.request_id != request.request_id:
        raise EvidenceProviderError("result request_id does not match request")
    if result.provider_id != request.provider_id or result.provider_id != capability.provider_id:
        raise EvidenceProviderError("result provider_id does not match request and capability")
    if result.provider_version != request.provider_version or result.provider_version != capability.version:
        raise EvidenceProviderError("result provider_version does not match request and capability")
    if result.capability_fingerprint != capability.fingerprint:
        raise EvidenceProviderError("result capability fingerprint does not match capability")
    produced = set(capability.produced_evidence_kinds)
    accepted = set(request.accepted_evidence_kinds)
    for item in result.evidence:
        if item.kind not in produced:
            raise EvidenceProviderError(f"evidence kind {item.kind} is not produced by provider capability")
        if item.kind not in accepted:
            raise EvidenceProviderError(f"evidence kind {item.kind} was not accepted by request")
    covered = set(result.coverage.covered_evidence_kinds)
    if not covered <= produced:
        raise EvidenceProviderError("coverage includes evidence kind not produced by provider capability")
    if not set(request.required_evidence_kinds) <= covered and result.status is EvidenceAcquisitionStatus.COMPLETE:
        raise EvidenceProviderError("complete result does not cover all requested required evidence kinds")
    return result


@dataclass(frozen=True)
class EvidenceProviderRegistry:
    capabilities: tuple[EvidenceProviderCapability, ...] = ()
    runtime_providers: Mapping[tuple[str, str], EvidenceProvider] = field(default_factory=dict, compare=False, repr=False)
    fingerprint: str = field(init=False)
    _by_key: Mapping[tuple[str, str], EvidenceProviderCapability] = field(init=False, repr=False, compare=False)
    _runtime_by_key: Mapping[tuple[str, str], EvidenceProvider] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            supplied = tuple(self.capabilities)
        except TypeError as exc:
            raise EvidenceProviderError("capabilities must be iterable") from exc
        if any(not isinstance(item, EvidenceProviderCapability) for item in supplied):
            raise EvidenceProviderError("capabilities must contain EvidenceProviderCapability descriptors")
        grouped: dict[tuple[str, str], list[EvidenceProviderCapability]] = {}
        for cap in supplied:
            grouped.setdefault((cap.provider_id, cap.version), []).append(cap)
        normalized: list[EvidenceProviderCapability] = []
        for key, duplicates in grouped.items():
            if len({item.fingerprint for item in duplicates}) != 1:
                raise EvidenceProviderError(f"conflicting evidence provider capability for {key[0]} version {key[1]}")
            normalized.append(min(duplicates, key=lambda item: (0, b"") if item.description is None else (1, canonical_utf8_key(item.description, path="description"))))
        normalized.sort(key=lambda item: (canonical_utf8_key(item.provider_id, path="provider_id"), canonical_utf8_key(item.version, path="version")))
        by_key = MappingProxyType({(item.provider_id, item.version): item for item in normalized})
        runtime: dict[tuple[str, str], EvidenceProvider] = {}
        for key, provider in self.runtime_providers.items():
            if not isinstance(key, tuple) or len(key) != 2:
                raise EvidenceProviderError("runtime provider keys must be (provider_id, version)")
            normalized_key = (_strict_identifier(key[0], name="provider_id"), _strict_identifier(key[1], name="version"))
            if normalized_key not in by_key:
                raise UnknownEvidenceProviderError(f"runtime provider {normalized_key[0]} version {normalized_key[1]} has no capability")
            if not isinstance(provider, EvidenceProvider):
                raise EvidenceProviderError("runtime provider must implement EvidenceProvider")
            runtime[normalized_key] = provider
        object.__setattr__(self, "capabilities", tuple(normalized))
        object.__setattr__(self, "_by_key", by_key)
        object.__setattr__(self, "_runtime_by_key", MappingProxyType(runtime))
        try:
            fingerprint = canonical_fingerprint(self.semantic_definition(), fingerprint_format=EVIDENCE_PROVIDER_CAPABILITY_REGISTRY_FINGERPRINT_FORMAT)
        except CanonicalizationError as exc:
            raise EvidenceProviderError(str(exc)) from exc
        object.__setattr__(self, "fingerprint", fingerprint)

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "schema_version": EVIDENCE_PROVIDER_CAPABILITY_REGISTRY_SCHEMA_VERSION,
            "kind": EVIDENCE_PROVIDER_CAPABILITY_REGISTRY_KIND,
            "capabilities": tuple(cap.semantic_definition() for cap in self.capabilities),
        }

    def list(self) -> tuple[EvidenceProviderCapability, ...]:
        return self.capabilities

    def list_capabilities(self) -> tuple[EvidenceProviderCapability, ...]:
        return self.list()

    def lookup(self, provider_id: str, version: str) -> EvidenceProviderCapability:
        key = (_strict_identifier(provider_id, name="provider_id"), _strict_identifier(version, name="version"))
        try:
            return self._by_key[key]
        except KeyError as exc:
            raise UnknownEvidenceProviderError(f"unknown evidence provider capability {key[0]} version {key[1]}") from exc

    def query(self, *, request_kind: str | None = None, evidence_kind: str | None = None) -> tuple[EvidenceProviderCapability, ...]:
        if request_kind is not None:
            request_kind = _strict_identifier(request_kind, name="request_kind")
        if evidence_kind is not None:
            evidence_kind = _strict_identifier(evidence_kind, name="evidence_kind")
        return tuple(
            cap
            for cap in self.capabilities
            if (request_kind is None or cap.supports_request_kind(request_kind))
            and (evidence_kind is None or cap.produces_evidence_kind(evidence_kind))
        )

    def acquire(self, request: EvidenceRequest, *, fail_closed: bool = False) -> EvidenceProviderResult:
        capability = self.lookup(request.provider_id, request.provider_version)
        key = (request.provider_id, request.provider_version)
        try:
            provider = self._runtime_by_key[key]
        except KeyError as exc:
            raise UnknownEvidenceProviderError(f"no runtime evidence provider for {key[0]} version {key[1]}") from exc
        try:
            result = provider.acquire(request)
            return validate_evidence_provider_result(result, request, capability)
        except Exception as exc:
            if not fail_closed:
                raise
            return EvidenceProviderResult(
                request_id=request.request_id,
                provider_id=request.provider_id,
                provider_version=request.provider_version,
                status=EvidenceAcquisitionStatus.UNAVAILABLE,
                coverage=EvidenceCoverage(EvidenceCompleteness.UNKNOWN, (), False, {"exception_type": type(exc).__name__}),
                evidence=(),
                issues=(VerificationIssue("PROVIDER_EXCEPTION", str(exc), VerificationVerdict.UNKNOWN),),
                capability_fingerprint=capability.fingerprint,
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": EVIDENCE_PROVIDER_CAPABILITY_REGISTRY_SCHEMA_VERSION,
            "kind": EVIDENCE_PROVIDER_CAPABILITY_REGISTRY_KIND,
            "fingerprint_format": EVIDENCE_PROVIDER_CAPABILITY_REGISTRY_FINGERPRINT_FORMAT,
            "fingerprint": self.fingerprint,
            "capabilities": [item.to_dict() for item in self.capabilities],
        }

    def export(self) -> dict[str, Any]:
        return self.to_dict()


BUILTIN_EVIDENCE_PROVIDER_REGISTRY = EvidenceProviderRegistry(())


def builtin_evidence_provider_registry() -> EvidenceProviderRegistry:
    return BUILTIN_EVIDENCE_PROVIDER_REGISTRY
