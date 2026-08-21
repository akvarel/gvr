from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Protocol, runtime_checkable

from .canonical import CanonicalizationError, canonical_fingerprint, canonical_transport_value, canonical_utf8_key
from .capabilities import VerifierCapability, VerifierCost, VerifierDeterminism
from .model import Evidence

EVIDENCE_REQUEST_SCHEMA_VERSION = 1
EVIDENCE_REQUEST_KIND = "gvr.evidence_request"
EVIDENCE_REQUEST_FINGERPRINT_FORMAT = "gvr.evidence_request.ieee754-json.v1"
EVIDENCE_COVERAGE_SCHEMA_VERSION = 1
EVIDENCE_COVERAGE_KIND = "gvr.evidence_coverage"
EVIDENCE_COVERAGE_FINGERPRINT_FORMAT = "gvr.evidence_coverage.ieee754-json.v1"
EVIDENCE_PROVIDER_RESULT_SCHEMA_VERSION = 1
EVIDENCE_PROVIDER_RESULT_KIND = "gvr.evidence_provider_result"
EVIDENCE_PROVIDER_RESULT_FINGERPRINT_FORMAT = "gvr.evidence_provider_result.ieee754-json.v1"
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


_TRUTH_LIKE_PROVIDER_FIELDS = frozenset({
    "claim_verdict",
    "fail",
    "failed",
    "pass",
    "passed",
    "sufficient",
    "truth",
    "verdict",
    "verified",
})

_TRUTH_LIKE_PROVIDER_TOKENS = frozenset({
    "fail",
    "failed",
    "pass",
    "passed",
    "sufficient",
    "truth",
    "verdict",
    "verified",
})


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


def _strict_sha256_fingerprint(value: Any, *, name: str) -> str:
    fingerprint = _strict_identifier(value, name=name)
    if len(fingerprint) != 64 or any(character not in "0123456789abcdef" for character in fingerprint):
        raise EvidenceProviderError(f"{name} must be a lowercase SHA-256 fingerprint")
    return fingerprint


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


def _reject_truth_like_fields(value: Mapping[str, Any], *, name: str) -> None:
    def visit(item: Any, path: str) -> None:
        if isinstance(item, Mapping):
            for key, nested in item.items():
                normalized = key.casefold().replace("-", "_")
                tokens = frozenset(normalized.split("_"))
                if (
                    normalized in _TRUTH_LIKE_PROVIDER_FIELDS
                    or tokens & _TRUTH_LIKE_PROVIDER_TOKENS
                ):
                    raise EvidenceProviderError(
                        f"{name} contains truth-like field {key!r} at {path}"
                    )
                visit(nested, f"{path}.{key}")
        elif isinstance(item, (list, tuple)):
            for index, nested in enumerate(item):
                visit(nested, f"{path}[{index}]")

    visit(value, name)


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


def _fingerprint(value: Any, *, fingerprint_format: str) -> str:
    try:
        return canonical_fingerprint(value, fingerprint_format=fingerprint_format)
    except CanonicalizationError as exc:
        raise EvidenceProviderError(str(exc)) from exc


def _validate_versioned_domain(
    *,
    schema_version: Any,
    expected_schema_version: int,
    kind: Any,
    expected_kind: str,
    fingerprint_format: Any,
    expected_fingerprint_format: str,
    noun: str,
) -> None:
    if type(schema_version) is not int or schema_version != expected_schema_version:
        raise EvidenceProviderError(f"unsupported {noun} schema version {schema_version}")
    if kind != expected_kind:
        raise EvidenceProviderError(f"unsupported {noun} kind {kind}")
    if fingerprint_format != expected_fingerprint_format:
        raise EvidenceProviderError(f"unsupported {noun} fingerprint format {fingerprint_format}")


@dataclass(frozen=True, kw_only=True)
class EvidenceRequest:
    request_id: str
    provider_id: str
    provider_version: str
    request_kind: str
    requested_evidence_kinds: tuple[str, ...]
    subject: Mapping[str, Any]
    spec: Mapping[str, Any]
    semantic_scope: Mapping[str, Any]
    source_context: Mapping[str, Any]
    snapshot_context: Mapping[str, Any]
    bounds: Mapping[str, Any]
    schema_version: int = EVIDENCE_REQUEST_SCHEMA_VERSION
    kind: str = EVIDENCE_REQUEST_KIND
    fingerprint_format: str = EVIDENCE_REQUEST_FINGERPRINT_FORMAT
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        _validate_versioned_domain(
            schema_version=self.schema_version,
            expected_schema_version=EVIDENCE_REQUEST_SCHEMA_VERSION,
            kind=self.kind,
            expected_kind=EVIDENCE_REQUEST_KIND,
            fingerprint_format=self.fingerprint_format,
            expected_fingerprint_format=EVIDENCE_REQUEST_FINGERPRINT_FORMAT,
            noun="evidence request",
        )
        object.__setattr__(self, "request_id", _strict_identifier(self.request_id, name="request_id"))
        object.__setattr__(self, "provider_id", _strict_identifier(self.provider_id, name="provider_id"))
        object.__setattr__(self, "provider_version", _strict_identifier(self.provider_version, name="provider_version"))
        object.__setattr__(self, "request_kind", _strict_identifier(self.request_kind, name="request_kind"))
        object.__setattr__(self, "requested_evidence_kinds", _string_tuple(self.requested_evidence_kinds, name="requested_evidence_kinds"))
        if not self.requested_evidence_kinds:
            raise EvidenceProviderError("requested_evidence_kinds must not be empty")
        for name in ("subject", "spec", "semantic_scope", "source_context", "snapshot_context", "bounds"):
            object.__setattr__(self, name, _strict_mapping(getattr(self, name), name=name))
        object.__setattr__(self, "fingerprint", _fingerprint(self.semantic_definition(), fingerprint_format=self.fingerprint_format))

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "request_kind": self.request_kind,
            "requested_evidence_kinds": self.requested_evidence_kinds,
            "subject": self.subject,
            "spec": self.spec,
            "semantic_scope": self.semantic_scope,
            "source_context": self.source_context,
            "snapshot_context": self.snapshot_context,
            "bounds": self.bounds,
        }

    def to_dict(self) -> dict[str, Any]:
        value = _export_value(self.semantic_definition())
        value.update({
            "request_id": self.request_id,
            "fingerprint_format": self.fingerprint_format,
            "fingerprint": self.fingerprint,
        })
        return value

    def export(self) -> dict[str, Any]:
        return self.to_dict()


@dataclass(frozen=True)
class EvidenceCoverage:
    completeness: EvidenceCompleteness
    covered_evidence_kinds: tuple[str, ...] = ()
    truncated: bool = False
    details: Mapping[str, Any] = field(default_factory=dict)
    declared_scope: Mapping[str, Any] = field(default_factory=dict)
    observed_scope: Mapping[str, Any] = field(default_factory=dict)
    declared_bounds: Mapping[str, Any] = field(default_factory=dict)
    consumed: Mapping[str, Any] = field(default_factory=dict)
    termination: Mapping[str, Any] = field(default_factory=dict)
    termination_reason: str = "UNKNOWN"
    source_identity: Mapping[str, Any] = field(default_factory=dict)
    snapshot_identity: Mapping[str, Any] = field(default_factory=dict)
    schema_version: int = EVIDENCE_COVERAGE_SCHEMA_VERSION
    kind: str = EVIDENCE_COVERAGE_KIND
    fingerprint_format: str = EVIDENCE_COVERAGE_FINGERPRINT_FORMAT
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        _validate_versioned_domain(
            schema_version=self.schema_version,
            expected_schema_version=EVIDENCE_COVERAGE_SCHEMA_VERSION,
            kind=self.kind,
            expected_kind=EVIDENCE_COVERAGE_KIND,
            fingerprint_format=self.fingerprint_format,
            expected_fingerprint_format=EVIDENCE_COVERAGE_FINGERPRINT_FORMAT,
            noun="evidence coverage",
        )
        object.__setattr__(self, "completeness", _enum_value(self.completeness, EvidenceCompleteness, name="completeness"))
        object.__setattr__(self, "covered_evidence_kinds", _string_tuple(self.covered_evidence_kinds, name="covered_evidence_kinds"))
        if not isinstance(self.truncated, bool):
            raise EvidenceProviderError("truncated must be a boolean")
        object.__setattr__(self, "termination_reason", _strict_identifier(self.termination_reason, name="termination_reason"))
        for name in ("declared_scope", "observed_scope", "declared_bounds", "consumed", "termination", "source_identity", "snapshot_identity", "details"):
            object.__setattr__(self, name, _strict_mapping(getattr(self, name), name=name))
        _reject_truth_like_fields(self.termination, name="termination")
        _reject_truth_like_fields(self.details, name="details")
        if self.completeness is EvidenceCompleteness.COMPLETE and self.truncated:
            raise EvidenceProviderError("complete coverage cannot be truncated")
        if self.completeness is EvidenceCompleteness.UNKNOWN and self.covered_evidence_kinds:
            raise EvidenceProviderError("unknown coverage cannot declare covered evidence kinds")
        object.__setattr__(self, "fingerprint", _fingerprint(self.semantic_definition(), fingerprint_format=self.fingerprint_format))

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "completeness": self.completeness.value,
            "covered_evidence_kinds": self.covered_evidence_kinds,
            "declared_scope": self.declared_scope,
            "observed_scope": self.observed_scope,
            "declared_bounds": self.declared_bounds,
            "consumed": self.consumed,
            "termination": self.termination,
            "truncated": self.truncated,
            "termination_reason": self.termination_reason,
            "source_identity": self.source_identity,
            "snapshot_identity": self.snapshot_identity,
            "details": self.details,
        }

    def to_dict(self) -> dict[str, Any]:
        value = _export_value(self.semantic_definition())
        value.update({"fingerprint_format": self.fingerprint_format, "fingerprint": self.fingerprint})
        return value

    def export(self) -> dict[str, Any]:
        return self.to_dict()


def _normalize_evidence(record: Evidence) -> Evidence:
    if not isinstance(record, Evidence):
        raise EvidenceProviderError("evidence must contain Evidence records")
    evidence_id = _strict_identifier(record.id, name="evidence id")
    evidence_kind = _strict_identifier(record.kind, name=f"evidence {evidence_id} kind")
    payload = _strict_mapping(record.payload, name=f"evidence {evidence_id} payload")
    source = None if record.source is None else _strict_identifier(record.source, name=f"evidence {evidence_id} source")
    producer_fingerprint = None if record.fingerprint is None else _strict_identifier(record.fingerprint, name=f"evidence {evidence_id} fingerprint")
    return Evidence(evidence_id, evidence_kind, payload, source, producer_fingerprint)


def _evidence_definition(record: Evidence) -> dict[str, Any]:
    return {
        "id": record.id,
        "kind": record.kind,
        "payload": record.payload,
        "source": record.source,
        "fingerprint": record.fingerprint,
    }


@dataclass(frozen=True)
class EvidenceProviderIssue:
    code: str
    message: str
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _strict_identifier(self.code, name="issue code"))
        if not isinstance(self.message, str):
            raise EvidenceProviderError("issue message must be a string")
        try:
            canonical_utf8_key(self.message, path="issue message")
        except CanonicalizationError as exc:
            raise EvidenceProviderError(str(exc)) from exc
        object.__setattr__(
            self,
            "evidence_ids",
            _string_tuple(self.evidence_ids, name="issue evidence_ids"),
        )

    def to_dict(self) -> dict[str, Any]:
        return _export_value(_issue_definition(self))

    def export(self) -> dict[str, Any]:
        return self.to_dict()


def _normalize_issue(issue: EvidenceProviderIssue) -> EvidenceProviderIssue:
    if not isinstance(issue, EvidenceProviderIssue):
        raise EvidenceProviderError("issues must contain EvidenceProviderIssue records")
    return EvidenceProviderIssue(issue.code, issue.message, issue.evidence_ids)


def _issue_definition(issue: EvidenceProviderIssue) -> dict[str, Any]:
    return {
        "code": issue.code,
        "message": issue.message,
        "evidence_ids": issue.evidence_ids,
    }


@dataclass(frozen=True, kw_only=True)
class EvidenceProviderResult:
    request_id: str
    request_fingerprint: str
    provider_id: str
    provider_version: str
    status: EvidenceAcquisitionStatus
    coverage: EvidenceCoverage
    evidence: tuple[Evidence, ...] = ()
    issues: tuple[EvidenceProviderIssue, ...] = ()
    capability_fingerprint: str
    schema_version: int = EVIDENCE_PROVIDER_RESULT_SCHEMA_VERSION
    kind: str = EVIDENCE_PROVIDER_RESULT_KIND
    fingerprint_format: str = EVIDENCE_PROVIDER_RESULT_FINGERPRINT_FORMAT
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        _validate_versioned_domain(
            schema_version=self.schema_version,
            expected_schema_version=EVIDENCE_PROVIDER_RESULT_SCHEMA_VERSION,
            kind=self.kind,
            expected_kind=EVIDENCE_PROVIDER_RESULT_KIND,
            fingerprint_format=self.fingerprint_format,
            expected_fingerprint_format=EVIDENCE_PROVIDER_RESULT_FINGERPRINT_FORMAT,
            noun="evidence provider result",
        )
        object.__setattr__(self, "request_id", _strict_identifier(self.request_id, name="request_id"))
        object.__setattr__(self, "request_fingerprint", _strict_sha256_fingerprint(self.request_fingerprint, name="request_fingerprint"))
        object.__setattr__(self, "provider_id", _strict_identifier(self.provider_id, name="provider_id"))
        object.__setattr__(self, "provider_version", _strict_identifier(self.provider_version, name="provider_version"))
        object.__setattr__(self, "status", _enum_value(self.status, EvidenceAcquisitionStatus, name="status"))
        if not isinstance(self.coverage, EvidenceCoverage):
            raise EvidenceProviderError("coverage must be EvidenceCoverage")

        evidence_by_id: dict[str, Evidence] = {}
        semantics_by_id: dict[str, dict[str, Any]] = {}
        try:
            supplied_evidence = tuple(self.evidence)
        except TypeError as exc:
            raise EvidenceProviderError("evidence must be iterable") from exc
        for supplied in supplied_evidence:
            normalized = _normalize_evidence(supplied)
            semantics = _evidence_definition(normalized)
            previous = semantics_by_id.get(normalized.id)
            if previous is not None and previous != semantics:
                raise EvidenceProviderError(f"conflicting evidence records share ID {normalized.id}")
            semantics_by_id[normalized.id] = semantics
            evidence_by_id.setdefault(normalized.id, normalized)
        normalized_evidence = tuple(evidence_by_id[key] for key in sorted(evidence_by_id, key=lambda item: canonical_utf8_key(item, path="evidence id")))
        object.__setattr__(self, "evidence", normalized_evidence)

        try:
            normalized_issues = tuple(_normalize_issue(item) for item in self.issues)
        except TypeError as exc:
            raise EvidenceProviderError("issues must be iterable") from exc
        normalized_issues = tuple(sorted(normalized_issues, key=lambda item: _fingerprint(_issue_definition(item), fingerprint_format=EVIDENCE_PROVIDER_RESULT_FINGERPRINT_FORMAT)))
        evidence_ids = set(evidence_by_id)
        for issue in normalized_issues:
            if not set(issue.evidence_ids) <= evidence_ids:
                raise EvidenceProviderError("provider issue references evidence absent from result")
        object.__setattr__(self, "issues", normalized_issues)
        object.__setattr__(self, "capability_fingerprint", _strict_sha256_fingerprint(self.capability_fingerprint, name="capability_fingerprint"))

        if self.status is EvidenceAcquisitionStatus.COMPLETE and self.coverage.completeness is not EvidenceCompleteness.COMPLETE:
            raise EvidenceProviderError("COMPLETE status requires complete coverage")
        if self.status is EvidenceAcquisitionStatus.PARTIAL and self.coverage.completeness is not EvidenceCompleteness.PARTIAL:
            raise EvidenceProviderError("PARTIAL status requires partial coverage")
        if self.status in (EvidenceAcquisitionStatus.UNAVAILABLE, EvidenceAcquisitionStatus.UNSUPPORTED):
            if normalized_evidence:
                raise EvidenceProviderError("unavailable or unsupported results cannot include evidence")
            if self.coverage.completeness is not EvidenceCompleteness.UNKNOWN:
                raise EvidenceProviderError("unavailable or unsupported results require unknown coverage")
        object.__setattr__(self, "fingerprint", _fingerprint(self.semantic_definition(), fingerprint_format=self.fingerprint_format))

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "request_fingerprint": self.request_fingerprint,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "status": self.status.value,
            "coverage": self.coverage.semantic_definition(),
            "evidence": tuple(_evidence_definition(item) for item in self.evidence),
            "issues": tuple(_issue_definition(item) for item in self.issues),
            "capability_fingerprint": self.capability_fingerprint,
        }

    def to_dict(self) -> dict[str, Any]:
        value = _export_value(self.semantic_definition())
        value.update({
            "request_id": self.request_id,
            "fingerprint_format": self.fingerprint_format,
            "fingerprint": self.fingerprint,
        })
        value["coverage"] = self.coverage.to_dict()
        return value

    def export(self) -> dict[str, Any]:
        return self.to_dict()


@dataclass(frozen=True, kw_only=True)
class EvidenceProviderCapability:
    provider_id: str
    version: str
    request_kinds: tuple[str, ...]
    produced_evidence_kinds: tuple[str, ...]
    source_classes: tuple[str, ...]
    snapshot_classes: tuple[str, ...]
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
        object.__setattr__(self, "request_kinds", _string_tuple(self.request_kinds, name="request_kinds"))
        object.__setattr__(self, "produced_evidence_kinds", _string_tuple(self.produced_evidence_kinds, name="produced_evidence_kinds"))
        object.__setattr__(self, "source_classes", _string_tuple(self.source_classes, name="source_classes"))
        object.__setattr__(self, "snapshot_classes", _string_tuple(self.snapshot_classes, name="snapshot_classes"))
        if not self.request_kinds:
            raise EvidenceProviderError("request_kinds must not be empty")
        if not self.produced_evidence_kinds:
            raise EvidenceProviderError("produced_evidence_kinds must not be empty")
        if not self.source_classes:
            raise EvidenceProviderError("source_classes must not be empty")
        if not self.snapshot_classes:
            raise EvidenceProviderError("snapshot_classes must not be empty")
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
        object.__setattr__(self, "fingerprint", _fingerprint(self.semantic_definition(), fingerprint_format=EVIDENCE_PROVIDER_CAPABILITY_FINGERPRINT_FORMAT))

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "schema_version": EVIDENCE_PROVIDER_CAPABILITY_SCHEMA_VERSION,
            "kind": EVIDENCE_PROVIDER_CAPABILITY_KIND,
            "provider_id": self.provider_id,
            "version": self.version,
            "request_kinds": self.request_kinds,
            "produced_evidence_kinds": self.produced_evidence_kinds,
            "source_classes": self.source_classes,
            "snapshot_classes": self.snapshot_classes,
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
        return request_kind in self.request_kinds

    def produces_evidence_kind(self, evidence_kind: str) -> bool:
        return evidence_kind in self.produced_evidence_kinds


@dataclass(frozen=True)
class EvidenceProviderCompatibility:
    compatible: bool
    evidence_kinds: tuple[str, ...] = ()
    missing_required_evidence_kinds: tuple[str, ...] = ()
    unsupported_request_kind: bool = False
    unsupported_claim_kind: bool = False


def provider_capability_is_compatible_with_verifier(
    provider: EvidenceProviderCapability,
    verifier: VerifierCapability,
    *,
    request_kind: str | None = None,
    claim_kind: str | None = None,
) -> EvidenceProviderCompatibility:
    if request_kind is None or claim_kind is None:
        raise EvidenceProviderError("request_kind and claim_kind are both required")
    request_kind = _strict_identifier(request_kind, name="request_kind")
    claim_kind = _strict_identifier(claim_kind, name="claim_kind")
    unsupported_request = request_kind not in provider.request_kinds
    unsupported_claim = claim_kind not in verifier.claim_kinds
    intersection = tuple(sorted(set(provider.produced_evidence_kinds) & set(verifier.accepted_evidence_kinds), key=lambda item: canonical_utf8_key(item, path="evidence_kind")))
    missing = tuple(sorted(set(verifier.required_evidence_kinds) - set(provider.produced_evidence_kinds), key=lambda item: canonical_utf8_key(item, path="evidence_kind")))
    return EvidenceProviderCompatibility(
        compatible=not unsupported_request and not unsupported_claim and not missing and bool(intersection),
        evidence_kinds=intersection,
        missing_required_evidence_kinds=missing,
        unsupported_request_kind=unsupported_request,
        unsupported_claim_kind=unsupported_claim,
    )


@runtime_checkable
class EvidenceProvider(Protocol):
    provider_id: str
    version: str
    capability: EvidenceProviderCapability

    def acquire(self, request: EvidenceRequest) -> EvidenceProviderResult: ...


@dataclass(frozen=True)
class EvidenceProviderVerifierInput:
    status: EvidenceAcquisitionStatus
    coverage: EvidenceCoverage
    evidence: tuple[Evidence, ...]
    issues: tuple[EvidenceProviderIssue, ...]
    result_fingerprint: str
    verifier_capability_fingerprint: str
    compatible: bool
    emitted_evidence_kinds: tuple[str, ...]
    present_required_evidence_kinds: tuple[str, ...]
    missing_required_evidence_kinds: tuple[str, ...]


def provider_result_for_verifier(result: EvidenceProviderResult, verifier: VerifierCapability) -> EvidenceProviderVerifierInput:
    if not isinstance(result, EvidenceProviderResult):
        raise EvidenceProviderError("result must be an exact EvidenceProviderResult")
    if not isinstance(verifier, VerifierCapability):
        raise EvidenceProviderError("verifier must be an exact VerifierCapability")
    accepted = set(verifier.accepted_evidence_kinds)
    emitted = {record.kind for record in result.evidence}
    unsupported = emitted - accepted
    if unsupported:
        kind = min(unsupported, key=lambda item: canonical_utf8_key(item, path="evidence kind"))
        raise EvidenceProviderError(f"evidence kind {kind} is not accepted by verifier capability")
    required = set(verifier.required_evidence_kinds)
    present_required = required & emitted
    missing_required = required - emitted
    return EvidenceProviderVerifierInput(
        status=result.status,
        coverage=result.coverage,
        evidence=result.evidence,
        issues=result.issues,
        result_fingerprint=result.fingerprint,
        verifier_capability_fingerprint=verifier.fingerprint,
        compatible=not unsupported,
        emitted_evidence_kinds=tuple(sorted(emitted, key=lambda item: canonical_utf8_key(item, path="evidence kind"))),
        present_required_evidence_kinds=tuple(sorted(present_required, key=lambda item: canonical_utf8_key(item, path="evidence kind"))),
        missing_required_evidence_kinds=tuple(sorted(missing_required, key=lambda item: canonical_utf8_key(item, path="evidence kind"))),
    )


def validate_evidence_provider_request(
    request: EvidenceRequest,
    capability: EvidenceProviderCapability,
) -> EvidenceRequest:
    if not isinstance(request, EvidenceRequest):
        raise EvidenceProviderError("request must be EvidenceRequest")
    if not isinstance(capability, EvidenceProviderCapability):
        raise EvidenceProviderError("capability must be EvidenceProviderCapability")
    if request.provider_id != capability.provider_id:
        raise EvidenceProviderError("request provider_id does not match capability")
    if request.provider_version != capability.version:
        raise EvidenceProviderError("request provider_version does not match capability")
    if request.request_kind not in capability.request_kinds:
        raise EvidenceProviderError("request kind is not supported by provider capability")
    if not set(request.requested_evidence_kinds) <= set(capability.produced_evidence_kinds):
        raise EvidenceProviderError("requested evidence kinds are not all produced by provider capability")
    return request


def validate_evidence_provider_result(result: EvidenceProviderResult, request: EvidenceRequest, capability: EvidenceProviderCapability) -> EvidenceProviderResult:
    if not isinstance(result, EvidenceProviderResult):
        raise EvidenceProviderError("result must be EvidenceProviderResult")
    validate_evidence_provider_request(request, capability)
    if result.request_id != request.request_id:
        raise EvidenceProviderError("result request_id does not match request")
    if result.request_fingerprint != request.fingerprint:
        raise EvidenceProviderError("result request fingerprint does not match exact request semantics")
    if result.provider_id != request.provider_id or result.provider_id != capability.provider_id:
        raise EvidenceProviderError("result provider_id does not match request and capability")
    if result.provider_version != request.provider_version or result.provider_version != capability.version:
        raise EvidenceProviderError("result provider_version does not match request and capability")
    produced = set(capability.produced_evidence_kinds)
    requested = set(request.requested_evidence_kinds)
    if result.capability_fingerprint != capability.fingerprint:
        raise EvidenceProviderError("result capability fingerprint does not match capability")
    for item in result.evidence:
        if item.kind not in produced:
            raise EvidenceProviderError(f"evidence kind {item.kind} is not produced by provider capability")
        if item.kind not in requested:
            raise EvidenceProviderError(f"evidence kind {item.kind} was not requested")
    covered = set(result.coverage.covered_evidence_kinds)
    emitted = {item.kind for item in result.evidence}
    if not covered <= produced or not covered <= requested:
        raise EvidenceProviderError("coverage includes an unrequested or unsupported evidence kind")
    if not emitted <= covered:
        raise EvidenceProviderError("emitted evidence kinds are not included in coverage")
    if result.coverage.declared_scope != request.semantic_scope:
        raise EvidenceProviderError("coverage declared scope does not match request semantic scope")
    if result.coverage.declared_bounds != request.bounds:
        raise EvidenceProviderError("coverage declared bounds do not match request bounds")
    if result.coverage.source_identity != request.source_context:
        raise EvidenceProviderError("coverage source identity does not match request source context")
    if result.coverage.snapshot_identity != request.snapshot_context:
        raise EvidenceProviderError("coverage snapshot identity does not match request snapshot context")
    if result.status is EvidenceAcquisitionStatus.COMPLETE:
        if not requested <= covered:
            raise EvidenceProviderError("complete result does not cover all requested evidence kinds")
        if result.coverage.observed_scope != result.coverage.declared_scope:
            raise EvidenceProviderError("complete result observed scope does not match declared scope")
    if (
        result.status is EvidenceAcquisitionStatus.PARTIAL
        and not result.coverage.truncated
        and requested <= covered
        and result.coverage.observed_scope == result.coverage.declared_scope
    ):
        raise EvidenceProviderError(
            "partial result contradicts complete structural coverage"
        )
    return result


@dataclass(frozen=True)
class EvidenceProviderCapabilityRegistry:
    capabilities: tuple[EvidenceProviderCapability, ...] = ()
    fingerprint: str = field(init=False)
    _by_key: Mapping[tuple[str, str], EvidenceProviderCapability] = field(init=False, repr=False, compare=False)

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

        object.__setattr__(self, "capabilities", tuple(normalized))
        object.__setattr__(self, "_by_key", by_key)
        object.__setattr__(self, "fingerprint", _fingerprint(self.semantic_definition(), fingerprint_format=EVIDENCE_PROVIDER_CAPABILITY_REGISTRY_FINGERPRINT_FORMAT))

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


def _validate_runtime_provider(
    provider: EvidenceProvider,
    key: tuple[str, str],
    capability: EvidenceProviderCapability,
) -> Callable[[EvidenceRequest], EvidenceProviderResult]:
    acquire = getattr(provider, "acquire", None)
    if not callable(acquire):
        raise EvidenceProviderError("runtime provider acquire must be callable")
    provider_id = getattr(provider, "provider_id", None)
    provider_version = getattr(provider, "version", None)
    provider_capability = getattr(provider, "capability", None)
    if provider_id != key[0] or provider_version != key[1]:
        raise EvidenceProviderError("runtime provider identity does not match registry key")
    if not isinstance(provider_capability, EvidenceProviderCapability):
        raise EvidenceProviderError(
            "runtime provider capability must be EvidenceProviderCapability"
        )
    if (
        provider_capability.provider_id != provider_id
        or provider_capability.version != provider_version
        or provider_capability.fingerprint != capability.fingerprint
    ):
        raise EvidenceProviderError(
            "runtime provider capability does not match registered capability"
        )
    return acquire


def _execution_exception_result(
    request: EvidenceRequest,
    capability: EvidenceProviderCapability,
) -> EvidenceProviderResult:
    return EvidenceProviderResult(
        request_id=request.request_id,
        request_fingerprint=request.fingerprint,
        provider_id=request.provider_id,
        provider_version=request.provider_version,
        status=EvidenceAcquisitionStatus.UNAVAILABLE,
        coverage=EvidenceCoverage(
            completeness=EvidenceCompleteness.UNKNOWN,
            covered_evidence_kinds=(),
            declared_scope=request.semantic_scope,
            observed_scope={},
            declared_bounds=request.bounds,
            consumed={},
            termination={
                "outcome": "exception",
                "phase": "provider_execution",
            },
            truncated=False,
            termination_reason="PROVIDER_EXECUTION_EXCEPTION",
            source_identity=request.source_context,
            snapshot_identity=request.snapshot_context,
        ),
        evidence=(),
        issues=(EvidenceProviderIssue(
            "PROVIDER_EXECUTION_EXCEPTION",
            "evidence provider execution raised an exception",
        ),),
        capability_fingerprint=capability.fingerprint,
    )


@dataclass(frozen=True)
class EvidenceProviderRuntimeRegistry:
    capability_registry: EvidenceProviderCapabilityRegistry
    runtime_providers: Mapping[tuple[str, str], EvidenceProvider]
    _runtime_by_key: Mapping[tuple[str, str], EvidenceProvider] = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(
            self.capability_registry, EvidenceProviderCapabilityRegistry
        ):
            raise EvidenceProviderError(
                "capability_registry must be EvidenceProviderCapabilityRegistry"
            )
        if not isinstance(self.runtime_providers, Mapping):
            raise EvidenceProviderError("runtime_providers must be a mapping")
        runtime: dict[tuple[str, str], EvidenceProvider] = {}
        for key, provider in self.runtime_providers.items():
            if not isinstance(key, tuple) or len(key) != 2:
                raise EvidenceProviderError(
                    "runtime provider keys must be (provider_id, version)"
                )
            normalized_key = (
                _strict_identifier(key[0], name="provider_id"),
                _strict_identifier(key[1], name="version"),
            )
            capability = self.capability_registry.lookup(*normalized_key)
            _validate_runtime_provider(provider, normalized_key, capability)
            runtime[normalized_key] = provider
        runtime_proxy = MappingProxyType(dict(runtime))
        object.__setattr__(self, "runtime_providers", runtime_proxy)
        object.__setattr__(self, "_runtime_by_key", runtime_proxy)

    def acquire(
        self,
        request: EvidenceRequest,
        *,
        fail_closed: bool = False,
    ) -> EvidenceProviderResult:
        if not isinstance(request, EvidenceRequest):
            raise EvidenceProviderError("request must be EvidenceRequest")
        capability = self.capability_registry.lookup(
            request.provider_id,
            request.provider_version,
        )
        validate_evidence_provider_request(request, capability)
        key = (request.provider_id, request.provider_version)
        try:
            provider = self._runtime_by_key[key]
        except KeyError as exc:
            raise UnknownEvidenceProviderError(
                f"no runtime evidence provider for {key[0]} version {key[1]}"
            ) from exc

        # Runtime provider objects can be mutable. Recheck the full identity
        # immediately before every invocation instead of trusting registration.
        acquire = _validate_runtime_provider(provider, key, capability)
        try:
            result = acquire(request)
        except Exception:
            if not fail_closed:
                raise
            return _execution_exception_result(request, capability)

        # Contract validation is deliberately outside the exception conversion.
        # A provider that executes but returns an invalid result is a protocol bug,
        # not an availability event.
        return validate_evidence_provider_result(result, request, capability)


BUILTIN_EVIDENCE_PROVIDER_CAPABILITY_REGISTRY = EvidenceProviderCapabilityRegistry(())


def builtin_evidence_provider_capability_registry() -> EvidenceProviderCapabilityRegistry:
    return BUILTIN_EVIDENCE_PROVIDER_CAPABILITY_REGISTRY
