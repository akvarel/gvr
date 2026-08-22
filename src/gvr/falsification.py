from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Protocol, runtime_checkable
import unicodedata

from .canonical import (
    CanonicalizationError,
    canonical_fingerprint,
    canonical_transport_value,
    canonical_utf8_key,
)
from .capabilities import (
    FalsificationStrategyKind,
    VerifierCost,
    VerifierDeterminism,
)
from .model import Evidence
from .session import AtomicClaim


FALSIFICATION_STRATEGY_DESCRIPTOR_SCHEMA_VERSION = 1
FALSIFICATION_STRATEGY_DESCRIPTOR_KIND = "gvr.falsification_strategy_descriptor"
FALSIFICATION_STRATEGY_DESCRIPTOR_FINGERPRINT_FORMAT = (
    "gvr.falsification_strategy_descriptor.ieee754-json.v1"
)
FALSIFICATION_STRATEGY_CAPABILITY_REGISTRY_SCHEMA_VERSION = 1
FALSIFICATION_STRATEGY_CAPABILITY_REGISTRY_KIND = (
    "gvr.falsification_strategy_capability_registry"
)
FALSIFICATION_STRATEGY_CAPABILITY_REGISTRY_FINGERPRINT_FORMAT = (
    "gvr.falsification_strategy_capability_registry.ieee754-json.v1"
)
FALSIFICATION_STRATEGY_RUNTIME_REGISTRY_SCHEMA_VERSION = 1
FALSIFICATION_STRATEGY_RUNTIME_REGISTRY_KIND = (
    "gvr.falsification_strategy_runtime_registry"
)
FALSIFICATION_STRATEGY_RUNTIME_REGISTRY_FINGERPRINT_FORMAT = (
    "gvr.falsification_strategy_runtime_registry.ieee754-json.v1"
)
FALSIFICATION_COVERAGE_SCHEMA_VERSION = 1
FALSIFICATION_COVERAGE_KIND = "gvr.falsification_coverage"
FALSIFICATION_COVERAGE_FINGERPRINT_FORMAT = (
    "gvr.falsification_coverage.ieee754-json.v1"
)
FALSIFICATION_PROVENANCE_SCHEMA_VERSION = 1
FALSIFICATION_PROVENANCE_KIND = "gvr.falsification_provenance"
FALSIFICATION_PROVENANCE_FINGERPRINT_FORMAT = (
    "gvr.falsification_provenance.ieee754-json.v1"
)
FALSIFICATION_PROBE_SCHEMA_VERSION = 1
FALSIFICATION_PROBE_KIND = "gvr.falsification_probe"
FALSIFICATION_PROBE_FINGERPRINT_FORMAT = (
    "gvr.falsification_probe.ieee754-json.v1"
)
FALSIFICATION_RESULT_SCHEMA_VERSION = 1
FALSIFICATION_RESULT_KIND = "gvr.falsification_result"
FALSIFICATION_RESULT_FINGERPRINT_FORMAT = (
    "gvr.falsification_result.ieee754-json.v1"
)
FALSIFICATION_EXECUTION_INPUT_FINGERPRINT_FORMAT = (
    "gvr.falsification_execution_input.ieee754-json.v1"
)

WITNESS_SEARCH_STRATEGY_ID = "gvr.falsification.witness_search.v1"
COUNTEREXAMPLE_SEARCH_STRATEGY_ID = (
    "gvr.falsification.counterexample_search.v1"
)
INVARIANT_CHECK_STRATEGY_ID = "gvr.falsification.invariant_check.v1"
METAMORPHIC_TRANSFORM_STRATEGY_ID = (
    "gvr.falsification.metamorphic_transform.v1"
)
INDEPENDENT_RECOMPUTE_STRATEGY_ID = (
    "gvr.falsification.independent_recompute.v1"
)
REPRESENTATION_CHECK_STRATEGY_ID = (
    "gvr.falsification.representation_check.v1"
)
FALSIFICATION_STRATEGY_VERSION = "1"
FINITE_TEXT_SEQUENCE_INPUT_KIND = "gvr.falsification.finite_text_sequence.v1"

_STABLE_IDENTIFIER = re.compile(r"^[^\s\x00-\x1f\x7f]+$")


class FalsificationStrategyError(ValueError):
    """Raised when a falsification contract, runtime, or result is invalid."""


class UnknownFalsificationStrategyError(LookupError):
    """Raised when an exact strategy ID and version are not registered."""


class FalsificationCompleteness(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"


class FalsificationProbeOutcome(str, Enum):
    SATISFIED = "SATISFIED"
    WITNESS = "WITNESS"
    COUNTEREXAMPLE = "COUNTEREXAMPLE"
    INCONCLUSIVE = "INCONCLUSIVE"


class FalsificationOutcome(str, Enum):
    WITNESS_FOUND = "WITNESS_FOUND"
    COUNTEREXAMPLE_FOUND = "COUNTEREXAMPLE_FOUND"
    NO_COUNTEREXAMPLE_FOUND = "NO_COUNTEREXAMPLE_FOUND"
    INCOMPLETE = "INCOMPLETE"


class FiniteSequencePredicateKind(str, Enum):
    EXACT_COUNT = "EXACT_COUNT"
    EXACT_MEMBERSHIP = "EXACT_MEMBERSHIP"
    UNIVERSAL = "UNIVERSAL"
    EXISTENTIAL = "EXISTENTIAL"


class DuplicateSemantics(str, Enum):
    PRESERVE = "PRESERVE"
    DISTINCT = "DISTINCT"


def _identifier(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not value or _STABLE_IDENTIFIER.fullmatch(value) is None:
        raise FalsificationStrategyError(
            f"{name} must be a non-empty string without whitespace or controls"
        )
    try:
        canonical_utf8_key(value, path=name)
    except CanonicalizationError as exc:
        raise FalsificationStrategyError(str(exc)) from exc
    return value


def _sha256(value: Any, *, name: str) -> str:
    fingerprint = _identifier(value, name=name)
    if len(fingerprint) != 64 or any(
        character not in "0123456789abcdef" for character in fingerprint
    ):
        raise FalsificationStrategyError(
            f"{name} must be a lowercase SHA-256 fingerprint"
        )
    return fingerprint


def _non_negative(value: Any, *, name: str, optional: bool = False) -> int | None:
    if optional and value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        suffix = " or null" if optional else ""
        raise FalsificationStrategyError(
            f"{name} must be a non-negative integer{suffix}"
        )
    return value


def _string_tuple(values: Iterable[str], *, name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise FalsificationStrategyError(f"{name} must be an iterable of strings")
    try:
        supplied = tuple(values)
    except TypeError as exc:
        raise FalsificationStrategyError(
            f"{name} must be an iterable of strings"
        ) from exc
    normalized = tuple(_identifier(value, name=f"{name} item") for value in supplied)
    if len(set(normalized)) != len(normalized):
        raise FalsificationStrategyError(f"{name} contains duplicate values")
    return tuple(
        sorted(normalized, key=lambda value: canonical_utf8_key(value, path=name))
    )


def _freeze(value: Any, *, name: str) -> Any:
    try:
        canonical_transport_value(value, path=name)
    except CanonicalizationError as exc:
        raise FalsificationStrategyError(str(exc)) from exc
    if value is None or isinstance(value, (bool, str, int, float)):
        return value
    if isinstance(value, Mapping):
        keys = sorted(
            value,
            key=lambda item: canonical_utf8_key(item, path=f"{name} key"),
        )
        return MappingProxyType({
            key: _freeze(value[key], name=f"{name}.{key}")
            for key in keys
        })
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item, name=f"{name} item") for item in value)
    raise FalsificationStrategyError(
        f"unsupported immutable {name} value {type(value).__name__}"
    )


def _mapping(value: Any, *, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise FalsificationStrategyError(f"{name} must be a mapping")
    if any(not isinstance(key, str) for key in value):
        raise FalsificationStrategyError(f"{name} keys must be strings")
    return _freeze(value, name=name)


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
        raise FalsificationStrategyError(str(exc)) from exc


def _enum(value: Any, enum_type: type[Enum], *, name: str) -> Enum:
    if isinstance(value, enum_type):
        return value
    if not isinstance(value, str):
        raise FalsificationStrategyError(f"{name} must be a string enum value")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise FalsificationStrategyError(f"unsupported {name} {value!r}") from exc


def _evidence_definition(evidence: Evidence) -> dict[str, Any]:
    return {
        "evidence_id": evidence.id,
        "kind": evidence.kind,
        "payload": evidence.payload,
        "source": evidence.source,
        "producer_fingerprint": evidence.fingerprint,
        "fingerprint": evidence.fingerprint,
    }


@dataclass(frozen=True, kw_only=True)
class FalsificationStrategyDescriptor:
    """Immutable capability descriptor for one exact falsification strategy."""

    strategy_id: str
    version: str
    strategy_kind: FalsificationStrategyKind
    claim_kinds: tuple[str, ...]
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any]
    determinism: VerifierDeterminism
    side_effect_free: bool
    cost: VerifierCost
    bounds: Mapping[str, Any]
    coverage: Mapping[str, Any]
    description: str | None = None
    schema_version: int = FALSIFICATION_STRATEGY_DESCRIPTOR_SCHEMA_VERSION
    kind: str = FALSIFICATION_STRATEGY_DESCRIPTOR_KIND
    fingerprint_format: str = FALSIFICATION_STRATEGY_DESCRIPTOR_FINGERPRINT_FORMAT
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise FalsificationStrategyError(
                f"unsupported falsification descriptor schema version {self.schema_version}"
            )
        if self.kind != FALSIFICATION_STRATEGY_DESCRIPTOR_KIND:
            raise FalsificationStrategyError(
                f"unsupported falsification descriptor kind {self.kind}"
            )
        if self.fingerprint_format != FALSIFICATION_STRATEGY_DESCRIPTOR_FINGERPRINT_FORMAT:
            raise FalsificationStrategyError(
                "unsupported falsification descriptor fingerprint format"
            )
        object.__setattr__(self, "strategy_id", _identifier(self.strategy_id, name="strategy_id"))
        object.__setattr__(self, "version", _identifier(self.version, name="version"))
        object.__setattr__(
            self,
            "strategy_kind",
            _enum(self.strategy_kind, FalsificationStrategyKind, name="strategy_kind"),
        )
        object.__setattr__(self, "claim_kinds", _string_tuple(self.claim_kinds, name="claim_kinds"))
        object.__setattr__(self, "input_schema", _mapping(self.input_schema, name="input_schema"))
        object.__setattr__(self, "output_schema", _mapping(self.output_schema, name="output_schema"))
        object.__setattr__(
            self,
            "determinism",
            _enum(self.determinism, VerifierDeterminism, name="determinism"),
        )
        object.__setattr__(self, "cost", _enum(self.cost, VerifierCost, name="cost"))
        if self.determinism not in (VerifierDeterminism.D0, VerifierDeterminism.D1):
            raise FalsificationStrategyError(
                "falsification strategies must use deterministic D0 or D1 execution"
            )
        if self.side_effect_free is not True:
            raise FalsificationStrategyError(
                "falsification strategy descriptors must be side-effect free"
            )
        object.__setattr__(self, "bounds", _mapping(self.bounds, name="bounds"))
        object.__setattr__(self, "coverage", _mapping(self.coverage, name="coverage"))
        if self.description is not None:
            if not isinstance(self.description, str):
                raise FalsificationStrategyError("description must be a string or null")
            try:
                canonical_utf8_key(self.description, path="description")
            except CanonicalizationError as exc:
                raise FalsificationStrategyError(str(exc)) from exc
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
            "strategy_id": self.strategy_id,
            "version": self.version,
            "strategy_kind": self.strategy_kind.value,
            "claim_kinds": self.claim_kinds,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "determinism": self.determinism.value,
            "side_effect_free": self.side_effect_free,
            "cost": self.cost.value,
            "bounds": self.bounds,
            "coverage": self.coverage,
        }

    def to_dict(self) -> dict[str, Any]:
        value = _export(self.semantic_definition())
        value.update({
            "fingerprint_format": self.fingerprint_format,
            "fingerprint": self.fingerprint,
            "description": self.description,
        })
        return value

    def export(self) -> dict[str, Any]:
        return self.to_dict()

    def supports_claim_kind(self, claim_kind: str) -> bool:
        return "*" in self.claim_kinds or claim_kind in self.claim_kinds


@dataclass(frozen=True)
class FalsificationStrategyCapabilityRegistry:
    capabilities: tuple[FalsificationStrategyDescriptor, ...] = ()
    schema_version: int = FALSIFICATION_STRATEGY_CAPABILITY_REGISTRY_SCHEMA_VERSION
    kind: str = FALSIFICATION_STRATEGY_CAPABILITY_REGISTRY_KIND
    fingerprint_format: str = (
        FALSIFICATION_STRATEGY_CAPABILITY_REGISTRY_FINGERPRINT_FORMAT
    )
    fingerprint: str = field(init=False)
    _by_key: Mapping[tuple[str, str], FalsificationStrategyDescriptor] = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise FalsificationStrategyError(
                "unsupported falsification capability registry schema version"
            )
        if self.kind != FALSIFICATION_STRATEGY_CAPABILITY_REGISTRY_KIND:
            raise FalsificationStrategyError(
                "unsupported falsification capability registry kind"
            )
        if self.fingerprint_format != FALSIFICATION_STRATEGY_CAPABILITY_REGISTRY_FINGERPRINT_FORMAT:
            raise FalsificationStrategyError(
                "unsupported falsification capability registry fingerprint format"
            )
        try:
            supplied = tuple(self.capabilities)
        except TypeError as exc:
            raise FalsificationStrategyError("capabilities must be iterable") from exc
        if any(type(item) is not FalsificationStrategyDescriptor for item in supplied):
            raise FalsificationStrategyError(
                "capabilities must contain exact FalsificationStrategyDescriptor records"
            )
        grouped: dict[tuple[str, str], list[FalsificationStrategyDescriptor]] = {}
        for descriptor in supplied:
            grouped.setdefault((descriptor.strategy_id, descriptor.version), []).append(descriptor)
        normalized: list[FalsificationStrategyDescriptor] = []
        for key, duplicates in grouped.items():
            fingerprints = {item.fingerprint for item in duplicates}
            if len(fingerprints) != 1:
                raise FalsificationStrategyError(
                    f"conflicting falsification strategy {key[0]} version {key[1]}"
                )
            normalized.append(min(duplicates, key=lambda item: item.description or ""))
        normalized.sort(
            key=lambda item: (
                canonical_utf8_key(item.strategy_id, path="strategy_id"),
                canonical_utf8_key(item.version, path="version"),
            )
        )
        capabilities = tuple(normalized)
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(
            self,
            "_by_key",
            MappingProxyType({
                (item.strategy_id, item.version): item for item in capabilities
            }),
        )
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
            "capabilities": tuple(item.semantic_definition() for item in self.capabilities),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "capabilities": [item.to_dict() for item in self.capabilities],
            "fingerprint_format": self.fingerprint_format,
            "fingerprint": self.fingerprint,
        }

    def export(self) -> dict[str, Any]:
        return self.to_dict()

    def list(self) -> tuple[FalsificationStrategyDescriptor, ...]:
        return self.capabilities

    def list_capabilities(self) -> tuple[FalsificationStrategyDescriptor, ...]:
        return self.capabilities

    def lookup(self, strategy_id: str, version: str) -> FalsificationStrategyDescriptor:
        key = (
            _identifier(strategy_id, name="strategy_id"),
            _identifier(version, name="version"),
        )
        try:
            return self._by_key[key]
        except KeyError as exc:
            raise UnknownFalsificationStrategyError(
                f"unknown falsification strategy {key[0]} version {key[1]}"
            ) from exc

    def query(
        self,
        *,
        strategy_kind: FalsificationStrategyKind | str | None = None,
        claim_kind: str | None = None,
    ) -> tuple[FalsificationStrategyDescriptor, ...]:
        normalized_kind = (
            None
            if strategy_kind is None
            else _enum(
                strategy_kind,
                FalsificationStrategyKind,
                name="strategy_kind",
            )
        )
        normalized_claim = (
            None if claim_kind is None else _identifier(claim_kind, name="claim_kind")
        )
        return tuple(
            descriptor
            for descriptor in self.capabilities
            if (
                normalized_kind is None
                or descriptor.strategy_kind is normalized_kind
            )
            and (
                normalized_claim is None
                or descriptor.supports_claim_kind(normalized_claim)
            )
        )


@dataclass(frozen=True, kw_only=True)
class FalsificationCoverage:
    completeness: FalsificationCompleteness
    examined_items: int
    total_items: int | None
    bounds: Mapping[str, Any]
    schema_version: int = FALSIFICATION_COVERAGE_SCHEMA_VERSION
    kind: str = FALSIFICATION_COVERAGE_KIND
    fingerprint_format: str = FALSIFICATION_COVERAGE_FINGERPRINT_FORMAT
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise FalsificationStrategyError("unsupported falsification coverage schema version")
        if self.kind != FALSIFICATION_COVERAGE_KIND:
            raise FalsificationStrategyError("unsupported falsification coverage kind")
        if self.fingerprint_format != FALSIFICATION_COVERAGE_FINGERPRINT_FORMAT:
            raise FalsificationStrategyError("unsupported falsification coverage fingerprint format")
        object.__setattr__(
            self,
            "completeness",
            _enum(self.completeness, FalsificationCompleteness, name="completeness"),
        )
        examined = _non_negative(self.examined_items, name="examined_items")
        total = _non_negative(self.total_items, name="total_items", optional=True)
        assert examined is not None
        if total is not None and examined > total:
            raise FalsificationStrategyError("examined_items cannot exceed total_items")
        if self.completeness is FalsificationCompleteness.COMPLETE:
            if total is None or examined != total:
                raise FalsificationStrategyError(
                    "complete coverage requires examined_items equal total_items"
                )
        object.__setattr__(self, "examined_items", examined)
        object.__setattr__(self, "total_items", total)
        object.__setattr__(self, "bounds", _mapping(self.bounds, name="coverage bounds"))
        object.__setattr__(
            self,
            "fingerprint",
            _fingerprint(self.semantic_definition(), fingerprint_format=self.fingerprint_format),
        )

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "completeness": self.completeness.value,
            "examined_items": self.examined_items,
            "total_items": self.total_items,
            "bounds": self.bounds,
        }

    def to_dict(self) -> dict[str, Any]:
        value = _export(self.semantic_definition())
        value.update({
            "fingerprint_format": self.fingerprint_format,
            "fingerprint": self.fingerprint,
        })
        return value


@dataclass(frozen=True, kw_only=True)
class FalsificationProvenance:
    binding_id: str
    declared_verifier_id: str
    strategy_id: str
    strategy_version: str
    strategy_capability_fingerprint: str
    claim_id: str
    claim_fingerprint: str
    input_fingerprint: str
    parameters_fingerprint: str
    implementation_path: str
    transformation: Mapping[str, Any]
    schema_version: int = FALSIFICATION_PROVENANCE_SCHEMA_VERSION
    kind: str = FALSIFICATION_PROVENANCE_KIND
    fingerprint_format: str = FALSIFICATION_PROVENANCE_FINGERPRINT_FORMAT
    fingerprint: str = field(init=False)
    transformation_fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise FalsificationStrategyError("unsupported falsification provenance schema version")
        if self.kind != FALSIFICATION_PROVENANCE_KIND:
            raise FalsificationStrategyError("unsupported falsification provenance kind")
        if self.fingerprint_format != FALSIFICATION_PROVENANCE_FINGERPRINT_FORMAT:
            raise FalsificationStrategyError("unsupported falsification provenance fingerprint format")
        for name in (
            "binding_id", "declared_verifier_id", "strategy_id", "strategy_version",
            "claim_id", "implementation_path",
        ):
            object.__setattr__(self, name, _identifier(getattr(self, name), name=name))
        for name in (
            "strategy_capability_fingerprint", "claim_fingerprint",
            "input_fingerprint", "parameters_fingerprint",
        ):
            object.__setattr__(self, name, _sha256(getattr(self, name), name=name))
        transformation = _mapping(self.transformation, name="transformation")
        object.__setattr__(self, "transformation", transformation)
        object.__setattr__(
            self,
            "transformation_fingerprint",
            _fingerprint(
                transformation,
                fingerprint_format="gvr.falsification.transformation.ieee754-json.v1",
            ),
        )
        object.__setattr__(
            self,
            "fingerprint",
            _fingerprint(self.semantic_definition(), fingerprint_format=self.fingerprint_format),
        )

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "binding_id": self.binding_id,
            "declared_verifier_id": self.declared_verifier_id,
            "strategy_id": self.strategy_id,
            "strategy_version": self.strategy_version,
            "strategy_capability_fingerprint": self.strategy_capability_fingerprint,
            "claim_id": self.claim_id,
            "claim_fingerprint": self.claim_fingerprint,
            "input_fingerprint": self.input_fingerprint,
            "parameters_fingerprint": self.parameters_fingerprint,
            "implementation_path": self.implementation_path,
            "transformation": self.transformation,
            "transformation_fingerprint": self.transformation_fingerprint,
        }

    def to_dict(self) -> dict[str, Any]:
        value = _export(self.semantic_definition())
        value.update({
            "fingerprint_format": self.fingerprint_format,
            "fingerprint": self.fingerprint,
        })
        return value


@dataclass(frozen=True, kw_only=True)
class FalsificationProbe:
    probe_id: str
    predicate_kind: str
    outcome: FalsificationProbeOutcome
    subject: Any
    expected: Any
    observed: Any
    schema_version: int = FALSIFICATION_PROBE_SCHEMA_VERSION
    kind: str = FALSIFICATION_PROBE_KIND
    fingerprint_format: str = FALSIFICATION_PROBE_FINGERPRINT_FORMAT
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise FalsificationStrategyError("unsupported falsification probe schema version")
        if self.kind != FALSIFICATION_PROBE_KIND:
            raise FalsificationStrategyError("unsupported falsification probe kind")
        if self.fingerprint_format != FALSIFICATION_PROBE_FINGERPRINT_FORMAT:
            raise FalsificationStrategyError("unsupported falsification probe fingerprint format")
        object.__setattr__(self, "probe_id", _identifier(self.probe_id, name="probe_id"))
        object.__setattr__(
            self,
            "predicate_kind",
            _identifier(self.predicate_kind, name="predicate_kind"),
        )
        object.__setattr__(
            self,
            "outcome",
            _enum(self.outcome, FalsificationProbeOutcome, name="probe outcome"),
        )
        object.__setattr__(self, "subject", _freeze(self.subject, name="probe subject"))
        object.__setattr__(self, "expected", _freeze(self.expected, name="probe expected"))
        object.__setattr__(self, "observed", _freeze(self.observed, name="probe observed"))
        object.__setattr__(
            self,
            "fingerprint",
            _fingerprint(self.semantic_definition(), fingerprint_format=self.fingerprint_format),
        )

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "probe_id": self.probe_id,
            "predicate_kind": self.predicate_kind,
            "outcome": self.outcome.value,
            "subject": self.subject,
            "expected": self.expected,
            "observed": self.observed,
        }

    def to_dict(self) -> dict[str, Any]:
        value = _export(self.semantic_definition())
        value.update({
            "fingerprint_format": self.fingerprint_format,
            "fingerprint": self.fingerprint,
        })
        return value


@dataclass(frozen=True, kw_only=True)
class FalsificationResult:
    binding_id: str
    declared_verifier_id: str
    strategy_id: str
    strategy_version: str
    strategy_kind: FalsificationStrategyKind
    strategy_capability_fingerprint: str
    claim_id: str
    claim_fingerprint: str
    outcome: FalsificationOutcome
    probes: tuple[FalsificationProbe, ...]
    coverage: FalsificationCoverage
    provenance: FalsificationProvenance
    schema_version: int = FALSIFICATION_RESULT_SCHEMA_VERSION
    kind: str = FALSIFICATION_RESULT_KIND
    fingerprint_format: str = FALSIFICATION_RESULT_FINGERPRINT_FORMAT
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise FalsificationStrategyError("unsupported falsification result schema version")
        if self.kind != FALSIFICATION_RESULT_KIND:
            raise FalsificationStrategyError("unsupported falsification result kind")
        if self.fingerprint_format != FALSIFICATION_RESULT_FINGERPRINT_FORMAT:
            raise FalsificationStrategyError("unsupported falsification result fingerprint format")
        for name in (
            "binding_id", "declared_verifier_id", "strategy_id", "strategy_version", "claim_id",
        ):
            object.__setattr__(self, name, _identifier(getattr(self, name), name=name))
        object.__setattr__(
            self,
            "strategy_kind",
            _enum(self.strategy_kind, FalsificationStrategyKind, name="strategy_kind"),
        )
        object.__setattr__(
            self,
            "strategy_capability_fingerprint",
            _sha256(self.strategy_capability_fingerprint, name="strategy_capability_fingerprint"),
        )
        object.__setattr__(
            self,
            "claim_fingerprint",
            _sha256(self.claim_fingerprint, name="claim_fingerprint"),
        )
        object.__setattr__(
            self,
            "outcome",
            _enum(self.outcome, FalsificationOutcome, name="falsification outcome"),
        )
        probes = tuple(self.probes)
        if any(type(probe) is not FalsificationProbe for probe in probes):
            raise FalsificationStrategyError(
                "probes must contain exact FalsificationProbe records"
            )
        probe_ids = [probe.probe_id for probe in probes]
        if not probes:
            raise FalsificationStrategyError(
                "a falsification result requires at least one probe"
            )
        if len(set(probe_ids)) != len(probe_ids):
            raise FalsificationStrategyError("falsification probe IDs must be unique")
        probes = tuple(sorted(probes, key=lambda item: canonical_utf8_key(item.probe_id, path="probe_id")))
        if type(self.coverage) is not FalsificationCoverage:
            raise FalsificationStrategyError("coverage must be an exact FalsificationCoverage")
        if type(self.provenance) is not FalsificationProvenance:
            raise FalsificationStrategyError("provenance must be an exact FalsificationProvenance")
        object.__setattr__(self, "probes", probes)
        has_counterexample = any(
            probe.outcome is FalsificationProbeOutcome.COUNTEREXAMPLE
            for probe in probes
        )
        has_witness = any(
            probe.outcome is FalsificationProbeOutcome.WITNESS
            for probe in probes
        )
        has_satisfied = any(
            probe.outcome is FalsificationProbeOutcome.SATISFIED
            for probe in probes
        )
        has_inconclusive = any(
            probe.outcome is FalsificationProbeOutcome.INCONCLUSIVE
            for probe in probes
        )
        if self.outcome is FalsificationOutcome.COUNTEREXAMPLE_FOUND and not has_counterexample:
            raise FalsificationStrategyError(
                "COUNTEREXAMPLE_FOUND requires a counterexample probe"
            )
        if self.outcome is not FalsificationOutcome.COUNTEREXAMPLE_FOUND and has_counterexample:
            raise FalsificationStrategyError(
                "counterexample probes contradict the declared result outcome"
            )
        if self.outcome is FalsificationOutcome.WITNESS_FOUND and not has_witness:
            raise FalsificationStrategyError("WITNESS_FOUND requires a witness probe")
        if (
            self.outcome is FalsificationOutcome.NO_COUNTEREXAMPLE_FOUND
            and self.coverage.completeness is not FalsificationCompleteness.COMPLETE
        ):
            raise FalsificationStrategyError(
                "NO_COUNTEREXAMPLE_FOUND requires complete finite coverage"
            )
        if (
            self.outcome is FalsificationOutcome.NO_COUNTEREXAMPLE_FOUND
            and not has_satisfied
        ):
            raise FalsificationStrategyError(
                "NO_COUNTEREXAMPLE_FOUND requires a satisfied probe"
            )
        if (
            self.outcome is FalsificationOutcome.INCOMPLETE
            and self.coverage.completeness is FalsificationCompleteness.COMPLETE
        ):
            raise FalsificationStrategyError(
                "INCOMPLETE requires partial coverage"
            )
        if self.outcome is FalsificationOutcome.INCOMPLETE and not has_inconclusive:
            raise FalsificationStrategyError(
                "INCOMPLETE requires an inconclusive probe"
            )
        provenance = self.provenance
        if (
            provenance.binding_id != self.binding_id
            or provenance.declared_verifier_id != self.declared_verifier_id
            or provenance.strategy_id != self.strategy_id
            or provenance.strategy_version != self.strategy_version
            or provenance.strategy_capability_fingerprint
            != self.strategy_capability_fingerprint
            or provenance.claim_id != self.claim_id
            or provenance.claim_fingerprint != self.claim_fingerprint
        ):
            raise FalsificationStrategyError(
                "falsification result provenance does not match result identity"
            )
        object.__setattr__(
            self,
            "fingerprint",
            _fingerprint(self.semantic_definition(), fingerprint_format=self.fingerprint_format),
        )

    @property
    def has_counterexample(self) -> bool:
        return self.outcome is FalsificationOutcome.COUNTEREXAMPLE_FOUND

    @property
    def is_complete(self) -> bool:
        return self.coverage.completeness is FalsificationCompleteness.COMPLETE

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "binding_id": self.binding_id,
            "declared_verifier_id": self.declared_verifier_id,
            "strategy_id": self.strategy_id,
            "strategy_version": self.strategy_version,
            "strategy_kind": self.strategy_kind.value,
            "strategy_capability_fingerprint": self.strategy_capability_fingerprint,
            "claim_id": self.claim_id,
            "claim_fingerprint": self.claim_fingerprint,
            "outcome": self.outcome.value,
            "probes": tuple(probe.to_dict() for probe in self.probes),
            "coverage": self.coverage.to_dict(),
            "provenance": self.provenance.to_dict(),
        }

    def to_dict(self) -> dict[str, Any]:
        value = _export(self.semantic_definition())
        value.update({
            "fingerprint_format": self.fingerprint_format,
            "fingerprint": self.fingerprint,
        })
        return value

    def export(self) -> dict[str, Any]:
        return self.to_dict()


@dataclass(frozen=True, kw_only=True)
class FalsificationDependency:
    claim_id: str
    claim_fingerprint: str
    outcome: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "claim_id", _identifier(self.claim_id, name="claim_id"))
        object.__setattr__(
            self,
            "claim_fingerprint",
            _sha256(self.claim_fingerprint, name="claim_fingerprint"),
        )
        object.__setattr__(self, "outcome", _identifier(self.outcome, name="dependency outcome"))

    def to_dict(self) -> dict[str, str]:
        return {
            "claim_id": self.claim_id,
            "claim_fingerprint": self.claim_fingerprint,
            "outcome": self.outcome,
        }


@dataclass(frozen=True, kw_only=True)
class FalsificationExecutionInput:
    binding_id: str
    declared_verifier_id: str
    claim: AtomicClaim
    claim_fingerprint: str
    descriptor: FalsificationStrategyDescriptor
    parameters: Mapping[str, Any]
    acquisitions: tuple[Any, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    dependencies: tuple[FalsificationDependency, ...] = ()
    fingerprint: str = field(init=False)
    parameters_fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "binding_id", _identifier(self.binding_id, name="binding_id"))
        object.__setattr__(
            self,
            "declared_verifier_id",
            _identifier(self.declared_verifier_id, name="declared_verifier_id"),
        )
        if type(self.claim) is not AtomicClaim:
            raise FalsificationStrategyError("claim must be an exact AtomicClaim")
        object.__setattr__(
            self,
            "claim_fingerprint",
            _sha256(self.claim_fingerprint, name="claim_fingerprint"),
        )
        if type(self.descriptor) is not FalsificationStrategyDescriptor:
            raise FalsificationStrategyError(
                "descriptor must be an exact FalsificationStrategyDescriptor"
            )
        parameters = _mapping(self.parameters, name="falsification parameters")
        acquisitions = tuple(self.acquisitions)
        evidence = tuple(self.evidence)
        dependencies = tuple(self.dependencies)
        if any(type(item) is not Evidence for item in evidence):
            raise FalsificationStrategyError("evidence must contain exact Evidence records")
        if any(type(item) is not FalsificationDependency for item in dependencies):
            raise FalsificationStrategyError(
                "dependencies must contain exact FalsificationDependency records"
            )
        for acquisition in acquisitions:
            if not callable(getattr(acquisition, "to_dict", None)):
                raise FalsificationStrategyError(
                    "acquisitions must expose canonical to_dict records"
                )
        object.__setattr__(self, "parameters", parameters)
        object.__setattr__(self, "acquisitions", acquisitions)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "dependencies", dependencies)
        parameters_fingerprint = _fingerprint(
            parameters,
            fingerprint_format="gvr.falsification.parameters.ieee754-json.v1",
        )
        object.__setattr__(self, "parameters_fingerprint", parameters_fingerprint)
        semantic = {
            "binding_id": self.binding_id,
            "declared_verifier_id": self.declared_verifier_id,
            "claim": self.claim.semantic_definition(),
            "claim_fingerprint": self.claim_fingerprint,
            "descriptor_fingerprint": self.descriptor.fingerprint,
            "parameters": parameters,
            "parameters_fingerprint": parameters_fingerprint,
            "acquisitions": tuple(item.to_dict() for item in acquisitions),
            "evidence": tuple(_evidence_definition(item) for item in evidence),
            "dependencies": tuple(item.to_dict() for item in dependencies),
        }
        object.__setattr__(
            self,
            "fingerprint",
            _fingerprint(
                semantic,
                fingerprint_format=FALSIFICATION_EXECUTION_INPUT_FINGERPRINT_FORMAT,
            ),
        )


@runtime_checkable
class FalsificationStrategyRuntime(Protocol):
    strategy_id: str
    version: str
    descriptor: FalsificationStrategyDescriptor
    side_effect_free: bool

    def run(self, strategy_input: FalsificationExecutionInput) -> FalsificationResult: ...


def _validate_runtime_strategy(
    runtime: FalsificationStrategyRuntime,
    key: tuple[str, str],
    descriptor: FalsificationStrategyDescriptor,
) -> Callable[[FalsificationExecutionInput], FalsificationResult]:
    run = getattr(runtime, "run", None)
    if not callable(run):
        raise FalsificationStrategyError("runtime strategy run must be callable")
    if getattr(runtime, "strategy_id", None) != key[0] or getattr(runtime, "version", None) != key[1]:
        raise FalsificationStrategyError(
            "runtime strategy identity does not match registry key"
        )
    runtime_descriptor = getattr(runtime, "descriptor", None)
    if type(runtime_descriptor) is not FalsificationStrategyDescriptor:
        raise FalsificationStrategyError(
            "runtime strategy descriptor must be exact"
        )
    if (
        runtime_descriptor.strategy_id != key[0]
        or runtime_descriptor.version != key[1]
        or runtime_descriptor.fingerprint != descriptor.fingerprint
    ):
        raise FalsificationStrategyError(
            "runtime strategy descriptor does not match registered capability"
        )
    if getattr(runtime, "side_effect_free", None) is not True:
        raise FalsificationStrategyError(
            "runtime falsification strategy must declare side_effect_free=True"
        )
    return run


@dataclass(frozen=True, kw_only=True)
class FalsificationStrategyRuntimeRegistry:
    capability_registry: FalsificationStrategyCapabilityRegistry
    runtime_strategies: Mapping[tuple[str, str], FalsificationStrategyRuntime]
    schema_version: int = FALSIFICATION_STRATEGY_RUNTIME_REGISTRY_SCHEMA_VERSION
    kind: str = FALSIFICATION_STRATEGY_RUNTIME_REGISTRY_KIND
    fingerprint_format: str = FALSIFICATION_STRATEGY_RUNTIME_REGISTRY_FINGERPRINT_FORMAT
    fingerprint: str = field(init=False)
    _runtime_by_key: Mapping[tuple[str, str], FalsificationStrategyRuntime] = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise FalsificationStrategyError("unsupported falsification runtime registry schema version")
        if self.kind != FALSIFICATION_STRATEGY_RUNTIME_REGISTRY_KIND:
            raise FalsificationStrategyError("unsupported falsification runtime registry kind")
        if self.fingerprint_format != FALSIFICATION_STRATEGY_RUNTIME_REGISTRY_FINGERPRINT_FORMAT:
            raise FalsificationStrategyError("unsupported falsification runtime registry fingerprint format")
        if type(self.capability_registry) is not FalsificationStrategyCapabilityRegistry:
            raise FalsificationStrategyError(
                "capability_registry must be an exact FalsificationStrategyCapabilityRegistry"
            )
        if not isinstance(self.runtime_strategies, Mapping):
            raise FalsificationStrategyError("runtime_strategies must be a mapping")
        normalized: dict[tuple[str, str], FalsificationStrategyRuntime] = {}
        for key, runtime in self.runtime_strategies.items():
            if not isinstance(key, tuple) or len(key) != 2:
                raise FalsificationStrategyError(
                    "runtime strategy keys must be (strategy_id, version)"
                )
            normalized_key = (
                _identifier(key[0], name="strategy_id"),
                _identifier(key[1], name="version"),
            )
            descriptor = self.capability_registry.lookup(*normalized_key)
            _validate_runtime_strategy(runtime, normalized_key, descriptor)
            normalized[normalized_key] = runtime
        ordered = {
            key: normalized[key]
            for key in sorted(
                normalized,
                key=lambda item: (
                    canonical_utf8_key(item[0], path="strategy_id"),
                    canonical_utf8_key(item[1], path="version"),
                ),
            )
        }
        proxy = MappingProxyType(ordered)
        object.__setattr__(self, "runtime_strategies", proxy)
        object.__setattr__(self, "_runtime_by_key", proxy)
        object.__setattr__(
            self,
            "fingerprint",
            _fingerprint(self.semantic_definition(), fingerprint_format=self.fingerprint_format),
        )

    @property
    def runtime_keys(self) -> tuple[tuple[str, str], ...]:
        return tuple(self._runtime_by_key)

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "capability_registry_fingerprint": self.capability_registry.fingerprint,
            "runtime_keys": self.runtime_keys,
        }

    def to_dict(self) -> dict[str, Any]:
        value = _export(self.semantic_definition())
        value.update({
            "capability_registry": self.capability_registry.to_dict(),
            "fingerprint_format": self.fingerprint_format,
            "fingerprint": self.fingerprint,
        })
        return value

    def export(self) -> dict[str, Any]:
        return self.to_dict()

    def validate_runtime(self, strategy_id: str, version: str) -> None:
        key = (
            _identifier(strategy_id, name="strategy_id"),
            _identifier(version, name="version"),
        )
        try:
            runtime = self._runtime_by_key[key]
        except KeyError as exc:
            raise UnknownFalsificationStrategyError(
                f"no runtime for falsification strategy {key[0]} version {key[1]}"
            ) from exc
        descriptor = self.capability_registry.lookup(*key)
        _validate_runtime_strategy(runtime, key, descriptor)

    def run(self, strategy_input: FalsificationExecutionInput) -> FalsificationResult:
        if type(strategy_input) is not FalsificationExecutionInput:
            raise FalsificationStrategyError(
                "strategy input must be an exact FalsificationExecutionInput"
            )
        key = (
            strategy_input.descriptor.strategy_id,
            strategy_input.descriptor.version,
        )
        try:
            runtime = self._runtime_by_key[key]
        except KeyError as exc:
            raise UnknownFalsificationStrategyError(
                f"no runtime for falsification strategy {key[0]} version {key[1]}"
            ) from exc
        descriptor = self.capability_registry.lookup(*key)
        run = _validate_runtime_strategy(runtime, key, descriptor)
        result = run(strategy_input)
        _validate_runtime_strategy(runtime, key, descriptor)
        return validate_falsification_result(result, strategy_input, descriptor)


def _rebuild_coverage(value: FalsificationCoverage) -> FalsificationCoverage:
    if type(value) is not FalsificationCoverage:
        raise FalsificationStrategyError("result coverage must be exact")
    rebuilt = FalsificationCoverage(
        completeness=value.completeness,
        examined_items=value.examined_items,
        total_items=value.total_items,
        bounds=value.bounds,
        schema_version=value.schema_version,
        kind=value.kind,
        fingerprint_format=value.fingerprint_format,
    )
    if rebuilt.to_dict() != value.to_dict():
        raise FalsificationStrategyError("falsification coverage fingerprint is inconsistent")
    return rebuilt


def _rebuild_provenance(value: FalsificationProvenance) -> FalsificationProvenance:
    if type(value) is not FalsificationProvenance:
        raise FalsificationStrategyError("result provenance must be exact")
    rebuilt = FalsificationProvenance(
        binding_id=value.binding_id,
        declared_verifier_id=value.declared_verifier_id,
        strategy_id=value.strategy_id,
        strategy_version=value.strategy_version,
        strategy_capability_fingerprint=value.strategy_capability_fingerprint,
        claim_id=value.claim_id,
        claim_fingerprint=value.claim_fingerprint,
        input_fingerprint=value.input_fingerprint,
        parameters_fingerprint=value.parameters_fingerprint,
        implementation_path=value.implementation_path,
        transformation=value.transformation,
        schema_version=value.schema_version,
        kind=value.kind,
        fingerprint_format=value.fingerprint_format,
    )
    if rebuilt.to_dict() != value.to_dict():
        raise FalsificationStrategyError("falsification provenance fingerprint is inconsistent")
    return rebuilt


def _rebuild_probe(value: FalsificationProbe) -> FalsificationProbe:
    if type(value) is not FalsificationProbe:
        raise FalsificationStrategyError("result probes must be exact")
    rebuilt = FalsificationProbe(
        probe_id=value.probe_id,
        predicate_kind=value.predicate_kind,
        outcome=value.outcome,
        subject=value.subject,
        expected=value.expected,
        observed=value.observed,
        schema_version=value.schema_version,
        kind=value.kind,
        fingerprint_format=value.fingerprint_format,
    )
    if rebuilt.to_dict() != value.to_dict():
        raise FalsificationStrategyError("falsification probe fingerprint is inconsistent")
    return rebuilt


def validate_falsification_result(
    result: FalsificationResult,
    strategy_input: FalsificationExecutionInput,
    descriptor: FalsificationStrategyDescriptor,
) -> FalsificationResult:
    if type(result) is not FalsificationResult:
        raise FalsificationStrategyError(
            "runtime must return an exact FalsificationResult"
        )
    if type(strategy_input) is not FalsificationExecutionInput:
        raise FalsificationStrategyError("strategy_input must be exact")
    if type(descriptor) is not FalsificationStrategyDescriptor:
        raise FalsificationStrategyError("descriptor must be exact")
    probes = tuple(_rebuild_probe(probe) for probe in result.probes)
    coverage = _rebuild_coverage(result.coverage)
    provenance = _rebuild_provenance(result.provenance)
    rebuilt = FalsificationResult(
        binding_id=result.binding_id,
        declared_verifier_id=result.declared_verifier_id,
        strategy_id=result.strategy_id,
        strategy_version=result.strategy_version,
        strategy_kind=result.strategy_kind,
        strategy_capability_fingerprint=result.strategy_capability_fingerprint,
        claim_id=result.claim_id,
        claim_fingerprint=result.claim_fingerprint,
        outcome=result.outcome,
        probes=probes,
        coverage=coverage,
        provenance=provenance,
        schema_version=result.schema_version,
        kind=result.kind,
        fingerprint_format=result.fingerprint_format,
    )
    if rebuilt.to_dict() != result.to_dict():
        raise FalsificationStrategyError(
            "falsification result content or fingerprint is inconsistent"
        )
    if (
        rebuilt.binding_id != strategy_input.binding_id
        or rebuilt.declared_verifier_id != strategy_input.declared_verifier_id
        or rebuilt.strategy_id != descriptor.strategy_id
        or rebuilt.strategy_version != descriptor.version
        or rebuilt.strategy_kind is not descriptor.strategy_kind
        or rebuilt.strategy_capability_fingerprint != descriptor.fingerprint
        or rebuilt.claim_id != strategy_input.claim.claim_id
        or rebuilt.claim_fingerprint != strategy_input.claim_fingerprint
        or rebuilt.provenance.input_fingerprint != strategy_input.fingerprint
        or rebuilt.provenance.parameters_fingerprint
        != strategy_input.parameters_fingerprint
    ):
        raise FalsificationStrategyError(
            "falsification result identity or provenance does not match exact input"
        )
    return rebuilt


@dataclass(frozen=True)
class _FiniteSequenceSpec:
    corpus: tuple[str, ...]
    needle: str
    predicate_kind: FiniteSequencePredicateKind
    expected_members: tuple[str, ...] | None
    expected_count: int | None
    normalization: str
    casefold: bool
    reverse: bool
    duplicate_semantics: DuplicateSemantics
    max_items: int | None
    transformation: Mapping[str, Any]
    expected_needle_code_points: tuple[int, ...] | None


def _text(value: Any, *, name: str) -> str:
    if not isinstance(value, str):
        raise FalsificationStrategyError(f"{name} must be a string")
    try:
        canonical_utf8_key(value, path=name)
    except CanonicalizationError as exc:
        raise FalsificationStrategyError(str(exc)) from exc
    return value


def _finite_sequence_spec(parameters: Mapping[str, Any]) -> _FiniteSequenceSpec:
    allowed = {
        "input_kind", "corpus", "needle", "predicate", "unicode_unit",
        "normalization", "casefold", "reverse", "duplicate_semantics",
        "max_items", "transformation", "expected_needle_code_points",
    }
    unexpected = set(parameters) - allowed
    if unexpected:
        raise FalsificationStrategyError(
            "unsupported finite sequence parameter fields: "
            + ", ".join(sorted(unexpected))
        )
    if parameters.get("input_kind") != FINITE_TEXT_SEQUENCE_INPUT_KIND:
        raise FalsificationStrategyError(
            f"input_kind must be {FINITE_TEXT_SEQUENCE_INPUT_KIND}"
        )
    corpus_value = parameters.get("corpus")
    if not isinstance(corpus_value, (list, tuple)):
        raise FalsificationStrategyError("corpus must be a finite array of strings")
    corpus = tuple(_text(item, name="corpus item") for item in corpus_value)
    needle = _text(parameters.get("needle"), name="needle")
    if parameters.get("unicode_unit") != "CODE_POINT":
        raise FalsificationStrategyError(
            "unicode_unit must explicitly be CODE_POINT"
        )
    normalization = parameters.get("normalization", "NONE")
    if normalization not in ("NONE", "NFC", "NFD"):
        raise FalsificationStrategyError("normalization must be NONE, NFC, or NFD")
    casefold = parameters.get("casefold", False)
    reverse = parameters.get("reverse", False)
    if not isinstance(casefold, bool) or not isinstance(reverse, bool):
        raise FalsificationStrategyError("casefold and reverse must be booleans")
    duplicate_semantics = _enum(
        parameters.get("duplicate_semantics", "PRESERVE"),
        DuplicateSemantics,
        name="duplicate_semantics",
    )
    max_items = _non_negative(
        parameters.get("max_items"),
        name="max_items",
        optional=True,
    )
    predicate = parameters.get("predicate")
    if not isinstance(predicate, Mapping):
        raise FalsificationStrategyError("predicate must be a mapping")
    predicate_allowed = {"kind", "expected_members", "expected_count"}
    predicate_unexpected = set(predicate) - predicate_allowed
    if predicate_unexpected:
        raise FalsificationStrategyError(
            "unsupported predicate fields: " + ", ".join(sorted(predicate_unexpected))
        )
    predicate_kind = _enum(
        predicate.get("kind"),
        FiniteSequencePredicateKind,
        name="predicate kind",
    )
    expected_members: tuple[str, ...] | None = None
    expected_count: int | None = None
    if predicate_kind is FiniteSequencePredicateKind.EXACT_MEMBERSHIP:
        raw = predicate.get("expected_members")
        if not isinstance(raw, (list, tuple)):
            raise FalsificationStrategyError(
                "EXACT_MEMBERSHIP requires expected_members"
            )
        expected_members = tuple(_text(item, name="expected member") for item in raw)
    elif predicate_kind is FiniteSequencePredicateKind.EXACT_COUNT:
        expected_count = _non_negative(
            predicate.get("expected_count"),
            name="expected_count",
        )
        assert expected_count is not None
    elif set(predicate) != {"kind"}:
        raise FalsificationStrategyError(
            f"{predicate_kind.value} accepts only the kind field"
        )
    transformation_value = parameters.get("transformation", {})
    transformation = _mapping(transformation_value, name="transformation")
    expected_code_points_value = parameters.get("expected_needle_code_points")
    expected_code_points: tuple[int, ...] | None = None
    if expected_code_points_value is not None:
        if not isinstance(expected_code_points_value, (list, tuple)):
            raise FalsificationStrategyError(
                "expected_needle_code_points must be an array"
            )
        normalized_points: list[int] = []
        for point in expected_code_points_value:
            if isinstance(point, bool) or not isinstance(point, int) or point < 0 or point > 0x10FFFF:
                raise FalsificationStrategyError("invalid Unicode code point")
            normalized_points.append(point)
        expected_code_points = tuple(normalized_points)
    return _FiniteSequenceSpec(
        corpus=corpus,
        needle=needle,
        predicate_kind=predicate_kind,
        expected_members=expected_members,
        expected_count=expected_count,
        normalization=str(normalization),
        casefold=casefold,
        reverse=reverse,
        duplicate_semantics=duplicate_semantics,
        max_items=max_items,
        transformation=transformation,
        expected_needle_code_points=expected_code_points,
    )


def _transform_text(
    value: str,
    *,
    normalization: str,
    casefold: bool,
    reverse: bool,
) -> str:
    transformed = value
    if normalization != "NONE":
        transformed = unicodedata.normalize(normalization, transformed)
    if casefold:
        transformed = transformed.casefold()
    if reverse:
        transformed = "".join(reversed(tuple(transformed)))
    return transformed


def _effective_corpus(spec: _FiniteSequenceSpec) -> tuple[str, ...]:
    if spec.duplicate_semantics is DuplicateSemantics.PRESERVE:
        return spec.corpus
    seen: set[str] = set()
    result: list[str] = []
    for item in spec.corpus:
        identity = _transform_text(
            item,
            normalization=spec.normalization,
            casefold=spec.casefold,
            reverse=spec.reverse,
        )
        if identity not in seen:
            seen.add(identity)
            result.append(item)
    return tuple(result)


def _primary_finite_sequence_scan(
    spec: _FiniteSequenceSpec,
) -> tuple[tuple[str, ...], tuple[bool, ...], int, int]:
    corpus = _effective_corpus(spec)
    total = len(corpus)
    examined = total if spec.max_items is None else min(spec.max_items, total)
    selected = corpus[:examined]
    needle = _transform_text(
        spec.needle,
        normalization=spec.normalization,
        casefold=spec.casefold,
        reverse=spec.reverse,
    )
    flags = tuple(
        needle
        in _transform_text(
            item,
            normalization=spec.normalization,
            casefold=spec.casefold,
            reverse=spec.reverse,
        )
        for item in selected
    )
    matches = tuple(item for item, matched in zip(selected, flags) if matched)
    return matches, flags, examined, total


def _independent_finite_sequence_scan(
    spec: _FiniteSequenceSpec,
) -> tuple[tuple[str, ...], tuple[bool, ...], int, int]:
    # Deliberately separate from _primary_finite_sequence_scan and
    # _transform_text. This is an independent implementation path, not a
    # wrapper around the primary scan.
    def independent_transform(value: str) -> str:
        current = value
        if spec.normalization == "NFC":
            current = unicodedata.normalize("NFC", current)
        elif spec.normalization == "NFD":
            current = unicodedata.normalize("NFD", current)
        if spec.casefold:
            current = str.casefold(current)
        if spec.reverse:
            points = [point for point in current]
            points.reverse()
            current = "".join(points)
        return current

    source: list[str] = []
    if spec.duplicate_semantics is DuplicateSemantics.PRESERVE:
        source.extend(spec.corpus)
    else:
        identities: set[str] = set()
        for original in spec.corpus:
            identity = independent_transform(original)
            if identity in identities:
                continue
            identities.add(identity)
            source.append(original)
    total = len(source)
    examined = total if spec.max_items is None else min(spec.max_items, total)
    transformed_needle = independent_transform(spec.needle)
    matches: list[str] = []
    flags: list[bool] = []
    for index in range(examined):
        original = source[index]
        matched = transformed_needle in independent_transform(original)
        flags.append(matched)
        if matched:
            matches.append(original)
    return tuple(matches), tuple(flags), examined, total


def _transformation_definition(spec: _FiniteSequenceSpec) -> Mapping[str, Any]:
    definition: dict[str, Any] = {
        "unicode_unit": "CODE_POINT",
        "normalization": spec.normalization,
        "casefold": spec.casefold,
        "reverse": spec.reverse,
        "duplicate_semantics": spec.duplicate_semantics.value,
        "order": ("NORMALIZE", "CASEFOLD", "REVERSE"),
    }
    if spec.transformation:
        definition["metamorphic"] = spec.transformation
    return _mapping(definition, name="transformation definition")


def _probe_and_outcome(
    *,
    spec: _FiniteSequenceSpec,
    matches: tuple[str, ...],
    flags: tuple[bool, ...],
    examined: int,
    total: int,
) -> tuple[FalsificationOutcome, tuple[FalsificationProbe, ...]]:
    complete = examined == total
    subject = {
        "needle": spec.needle,
        "examined_items": examined,
        "total_items": total,
    }
    if spec.predicate_kind is FiniteSequencePredicateKind.EXACT_MEMBERSHIP:
        expected = spec.expected_members or ()
        if complete:
            counterexample = matches != expected
        else:
            counterexample = matches != expected[:len(matches)]
        if counterexample:
            outcome = FalsificationOutcome.COUNTEREXAMPLE_FOUND
            probe_outcome = FalsificationProbeOutcome.COUNTEREXAMPLE
        elif complete:
            outcome = FalsificationOutcome.NO_COUNTEREXAMPLE_FOUND
            probe_outcome = FalsificationProbeOutcome.SATISFIED
        else:
            outcome = FalsificationOutcome.INCOMPLETE
            probe_outcome = FalsificationProbeOutcome.INCONCLUSIVE
        expected_value: Any = {"members": expected}
        observed: Any = {"members": matches}
    elif spec.predicate_kind is FiniteSequencePredicateKind.EXACT_COUNT:
        expected_count = spec.expected_count or 0
        counterexample = len(matches) > expected_count or (
            complete and len(matches) != expected_count
        )
        if counterexample:
            outcome = FalsificationOutcome.COUNTEREXAMPLE_FOUND
            probe_outcome = FalsificationProbeOutcome.COUNTEREXAMPLE
        elif complete:
            outcome = FalsificationOutcome.NO_COUNTEREXAMPLE_FOUND
            probe_outcome = FalsificationProbeOutcome.SATISFIED
        else:
            outcome = FalsificationOutcome.INCOMPLETE
            probe_outcome = FalsificationProbeOutcome.INCONCLUSIVE
        expected_value = {"count": expected_count}
        observed = {"count": len(matches), "members": matches}
    elif spec.predicate_kind is FiniteSequencePredicateKind.UNIVERSAL:
        nonmatching = tuple(
            index for index, matched in enumerate(flags) if not matched
        )
        if nonmatching:
            outcome = FalsificationOutcome.COUNTEREXAMPLE_FOUND
            probe_outcome = FalsificationProbeOutcome.COUNTEREXAMPLE
        elif complete:
            outcome = FalsificationOutcome.NO_COUNTEREXAMPLE_FOUND
            probe_outcome = FalsificationProbeOutcome.SATISFIED
        else:
            outcome = FalsificationOutcome.INCOMPLETE
            probe_outcome = FalsificationProbeOutcome.INCONCLUSIVE
        expected_value = {"all_items_match": True}
        observed = {"all_examined_match": not nonmatching, "nonmatching_indexes": nonmatching}
    else:
        if matches:
            outcome = FalsificationOutcome.WITNESS_FOUND
            probe_outcome = FalsificationProbeOutcome.WITNESS
        elif complete:
            outcome = FalsificationOutcome.COUNTEREXAMPLE_FOUND
            probe_outcome = FalsificationProbeOutcome.COUNTEREXAMPLE
        else:
            outcome = FalsificationOutcome.INCOMPLETE
            probe_outcome = FalsificationProbeOutcome.INCONCLUSIVE
        expected_value = {"at_least_one_match": True}
        observed = {"members": matches, "witness_found": bool(matches)}
    return outcome, (FalsificationProbe(
        probe_id="finite-sequence-predicate",
        predicate_kind=spec.predicate_kind.value,
        outcome=probe_outcome,
        subject=subject,
        expected=expected_value,
        observed=observed,
    ),)


def _result(
    strategy_input: FalsificationExecutionInput,
    *,
    outcome: FalsificationOutcome,
    probes: tuple[FalsificationProbe, ...],
    examined: int,
    total: int,
    implementation_path: str,
    transformation: Mapping[str, Any],
) -> FalsificationResult:
    completeness = (
        FalsificationCompleteness.COMPLETE
        if examined == total
        else FalsificationCompleteness.PARTIAL
    )
    coverage = FalsificationCoverage(
        completeness=completeness,
        examined_items=examined,
        total_items=total,
        bounds={
            "finite": True,
            "unicode_unit": "CODE_POINT",
            "max_items": (
                None
                if strategy_input.parameters.get("max_items") is None
                else strategy_input.parameters.get("max_items")
            ),
        },
    )
    descriptor = strategy_input.descriptor
    provenance = FalsificationProvenance(
        binding_id=strategy_input.binding_id,
        declared_verifier_id=strategy_input.declared_verifier_id,
        strategy_id=descriptor.strategy_id,
        strategy_version=descriptor.version,
        strategy_capability_fingerprint=descriptor.fingerprint,
        claim_id=strategy_input.claim.claim_id,
        claim_fingerprint=strategy_input.claim_fingerprint,
        input_fingerprint=strategy_input.fingerprint,
        parameters_fingerprint=strategy_input.parameters_fingerprint,
        implementation_path=implementation_path,
        transformation=transformation,
    )
    return FalsificationResult(
        binding_id=strategy_input.binding_id,
        declared_verifier_id=strategy_input.declared_verifier_id,
        strategy_id=descriptor.strategy_id,
        strategy_version=descriptor.version,
        strategy_kind=descriptor.strategy_kind,
        strategy_capability_fingerprint=descriptor.fingerprint,
        claim_id=strategy_input.claim.claim_id,
        claim_fingerprint=strategy_input.claim_fingerprint,
        outcome=outcome,
        probes=probes,
        coverage=coverage,
        provenance=provenance,
    )


def _run_primary(strategy_input: FalsificationExecutionInput) -> FalsificationResult:
    spec = _finite_sequence_spec(strategy_input.parameters)
    matches, flags, examined, total = _primary_finite_sequence_scan(spec)
    outcome, probes = _probe_and_outcome(
        spec=spec,
        matches=matches,
        flags=flags,
        examined=examined,
        total=total,
    )
    return _result(
        strategy_input,
        outcome=outcome,
        probes=probes,
        examined=examined,
        total=total,
        implementation_path="primary_finite_sequence_scan_v1",
        transformation=_transformation_definition(spec),
    )


def _run_independent(strategy_input: FalsificationExecutionInput) -> FalsificationResult:
    spec = _finite_sequence_spec(strategy_input.parameters)
    matches, flags, examined, total = _independent_finite_sequence_scan(spec)
    outcome, probes = _probe_and_outcome(
        spec=spec,
        matches=matches,
        flags=flags,
        examined=examined,
        total=total,
    )
    return _result(
        strategy_input,
        outcome=outcome,
        probes=probes,
        examined=examined,
        total=total,
        implementation_path="independent_finite_sequence_recompute_v1",
        transformation=_transformation_definition(spec),
    )


def _run_metamorphic(strategy_input: FalsificationExecutionInput) -> FalsificationResult:
    spec = _finite_sequence_spec(strategy_input.parameters)
    transformation = spec.transformation
    required = {
        "transformation_id", "version", "operation", "unicode_unit",
    }
    if set(transformation) != required:
        raise FalsificationStrategyError(
            "metamorphic transformation requires exact identity fields"
        )
    _identifier(
        transformation["transformation_id"],
        name="metamorphic transformation_id",
    )
    _identifier(
        transformation["version"],
        name="metamorphic transformation version",
    )
    if transformation["operation"] != "REVERSE_BOTH" or transformation["unicode_unit"] != "CODE_POINT":
        raise FalsificationStrategyError(
            "only explicit Unicode code-point REVERSE_BOTH is supported"
        )
    baseline_spec = _FiniteSequenceSpec(
        corpus=spec.corpus,
        needle=spec.needle,
        predicate_kind=spec.predicate_kind,
        expected_members=spec.expected_members,
        expected_count=spec.expected_count,
        normalization=spec.normalization,
        casefold=spec.casefold,
        reverse=False,
        duplicate_semantics=spec.duplicate_semantics,
        max_items=spec.max_items,
        transformation=spec.transformation,
        expected_needle_code_points=spec.expected_needle_code_points,
    )
    transformed_spec = _FiniteSequenceSpec(
        corpus=spec.corpus,
        needle=spec.needle,
        predicate_kind=spec.predicate_kind,
        expected_members=spec.expected_members,
        expected_count=spec.expected_count,
        normalization=spec.normalization,
        casefold=spec.casefold,
        reverse=True,
        duplicate_semantics=spec.duplicate_semantics,
        max_items=spec.max_items,
        transformation=spec.transformation,
        expected_needle_code_points=spec.expected_needle_code_points,
    )
    baseline_matches, baseline_flags, examined, total = _primary_finite_sequence_scan(baseline_spec)
    transformed_matches, transformed_flags, transformed_examined, transformed_total = _primary_finite_sequence_scan(transformed_spec)
    invariant_holds = (
        baseline_matches == transformed_matches
        and baseline_flags == transformed_flags
        and examined == transformed_examined
        and total == transformed_total
    )
    if invariant_holds:
        predicate_outcome, predicate_probes = _probe_and_outcome(
            spec=baseline_spec,
            matches=baseline_matches,
            flags=baseline_flags,
            examined=examined,
            total=total,
        )
    else:
        predicate_outcome = FalsificationOutcome.COUNTEREXAMPLE_FOUND
        predicate_probes = ()
    meta_probe = FalsificationProbe(
        probe_id="metamorphic-reverse-both",
        predicate_kind="METAMORPHIC_INVARIANT",
        outcome=(
            FalsificationProbeOutcome.SATISFIED
            if invariant_holds
            else FalsificationProbeOutcome.COUNTEREXAMPLE
        ),
        subject={"transformation": transformation},
        expected={"membership_indexes_preserved": True},
        observed={
            "membership_indexes_preserved": invariant_holds,
            "baseline_members": baseline_matches,
            "transformed_members": transformed_matches,
        },
    )
    probes = (meta_probe,) + predicate_probes
    if not invariant_holds:
        outcome = FalsificationOutcome.COUNTEREXAMPLE_FOUND
    elif predicate_outcome is FalsificationOutcome.COUNTEREXAMPLE_FOUND:
        outcome = predicate_outcome
    elif predicate_outcome is FalsificationOutcome.INCOMPLETE:
        outcome = predicate_outcome
    else:
        outcome = FalsificationOutcome.NO_COUNTEREXAMPLE_FOUND
        # A witness probe is evidence for the underlying existential predicate,
        # but the metamorphic result itself reports that no transformation
        # counterexample was found.
        probes = tuple(
            FalsificationProbe(
                probe_id=probe.probe_id,
                predicate_kind=probe.predicate_kind,
                outcome=(
                    FalsificationProbeOutcome.SATISFIED
                    if probe.outcome is FalsificationProbeOutcome.WITNESS
                    else probe.outcome
                ),
                subject=probe.subject,
                expected=probe.expected,
                observed=probe.observed,
            )
            for probe in probes
        )
    return _result(
        strategy_input,
        outcome=outcome,
        probes=probes,
        examined=examined,
        total=total,
        implementation_path="metamorphic_reverse_both_v1",
        transformation=_transformation_definition(transformed_spec),
    )


def _run_representation(strategy_input: FalsificationExecutionInput) -> FalsificationResult:
    spec = _finite_sequence_spec(strategy_input.parameters)
    transformed = _transform_text(
        spec.needle,
        normalization=spec.normalization,
        casefold=spec.casefold,
        reverse=spec.reverse,
    )
    code_points = tuple(ord(character) for character in transformed)
    expected = spec.expected_needle_code_points
    if expected is None:
        raise FalsificationStrategyError(
            "representation checks require expected_needle_code_points"
        )
    if expected == code_points:
        outcome = FalsificationOutcome.NO_COUNTEREXAMPLE_FOUND
        probe_outcome = FalsificationProbeOutcome.SATISFIED
    else:
        outcome = FalsificationOutcome.COUNTEREXAMPLE_FOUND
        probe_outcome = FalsificationProbeOutcome.COUNTEREXAMPLE
    probe = FalsificationProbe(
        probe_id="unicode-code-point-representation",
        predicate_kind="REPRESENTATION_CHECK",
        outcome=probe_outcome,
        subject={"needle": spec.needle},
        expected={"code_points": expected},
        observed={"code_points": code_points},
    )
    return _result(
        strategy_input,
        outcome=outcome,
        probes=(probe,),
        examined=1,
        total=1,
        implementation_path="unicode_code_point_representation_v1",
        transformation=_transformation_definition(spec),
    )


class _GenericFiniteSequenceRuntime:
    def __init__(self, descriptor: FalsificationStrategyDescriptor) -> None:
        self.strategy_id = descriptor.strategy_id
        self.version = descriptor.version
        self.descriptor = descriptor
        self.side_effect_free = True

    def run(self, strategy_input: FalsificationExecutionInput) -> FalsificationResult:
        if self.descriptor.strategy_kind is FalsificationStrategyKind.INDEPENDENT_RECOMPUTE:
            return _run_independent(strategy_input)
        if self.descriptor.strategy_kind is FalsificationStrategyKind.METAMORPHIC_TRANSFORM:
            return _run_metamorphic(strategy_input)
        if self.descriptor.strategy_kind is FalsificationStrategyKind.REPRESENTATION_CHECK:
            return _run_representation(strategy_input)
        return _run_primary(strategy_input)


def _builtin_descriptor(
    strategy_id: str,
    strategy_kind: FalsificationStrategyKind,
    *,
    implementation_path: str,
) -> FalsificationStrategyDescriptor:
    return FalsificationStrategyDescriptor(
        strategy_id=strategy_id,
        version=FALSIFICATION_STRATEGY_VERSION,
        strategy_kind=strategy_kind,
        claim_kinds=("*",),
        input_schema={
            "kind": FINITE_TEXT_SEQUENCE_INPUT_KIND,
            "unicode_unit": "CODE_POINT",
            "normalization": ("NONE", "NFC", "NFD"),
            "casefold": "explicit_boolean",
            "reverse": "explicit_boolean",
            "duplicate_semantics": ("PRESERVE", "DISTINCT"),
            "predicates": (
                "EXACT_COUNT", "EXACT_MEMBERSHIP", "UNIVERSAL", "EXISTENTIAL",
            ),
        },
        output_schema={
            "kind": FALSIFICATION_RESULT_KIND,
            "probe_outcomes": tuple(item.value for item in FalsificationProbeOutcome),
            "result_outcomes": tuple(item.value for item in FalsificationOutcome),
        },
        determinism=VerifierDeterminism.D0,
        side_effect_free=True,
        cost=VerifierCost.LOW,
        bounds={
            "finite_input_required": True,
            "max_items_is_explicit": True,
        },
        coverage={
            "complete_only_when_examined_equals_total": True,
            "absence_never_upgrades_partial_coverage": True,
        },
        description=(
            f"Generic deterministic finite text/sequence {strategy_kind.value.lower()} "
            f"using {implementation_path}."
        ),
    )


_BUILTIN_DESCRIPTORS = (
    _builtin_descriptor(
        WITNESS_SEARCH_STRATEGY_ID,
        FalsificationStrategyKind.WITNESS_SEARCH,
        implementation_path="primary_finite_sequence_scan_v1",
    ),
    _builtin_descriptor(
        COUNTEREXAMPLE_SEARCH_STRATEGY_ID,
        FalsificationStrategyKind.COUNTEREXAMPLE_SEARCH,
        implementation_path="primary_finite_sequence_scan_v1",
    ),
    _builtin_descriptor(
        INVARIANT_CHECK_STRATEGY_ID,
        FalsificationStrategyKind.INVARIANT_CHECK,
        implementation_path="primary_finite_sequence_scan_v1",
    ),
    _builtin_descriptor(
        METAMORPHIC_TRANSFORM_STRATEGY_ID,
        FalsificationStrategyKind.METAMORPHIC_TRANSFORM,
        implementation_path="metamorphic_reverse_both_v1",
    ),
    _builtin_descriptor(
        INDEPENDENT_RECOMPUTE_STRATEGY_ID,
        FalsificationStrategyKind.INDEPENDENT_RECOMPUTE,
        implementation_path="independent_finite_sequence_recompute_v1",
    ),
    _builtin_descriptor(
        REPRESENTATION_CHECK_STRATEGY_ID,
        FalsificationStrategyKind.REPRESENTATION_CHECK,
        implementation_path="unicode_code_point_representation_v1",
    ),
)
BUILTIN_FALSIFICATION_STRATEGY_CAPABILITY_REGISTRY = (
    FalsificationStrategyCapabilityRegistry(_BUILTIN_DESCRIPTORS)
)


def builtin_falsification_strategy_capability_registry(
) -> FalsificationStrategyCapabilityRegistry:
    return BUILTIN_FALSIFICATION_STRATEGY_CAPABILITY_REGISTRY


def builtin_falsification_strategy_runtime_registry(
    capability_registry: FalsificationStrategyCapabilityRegistry | None = None,
) -> FalsificationStrategyRuntimeRegistry:
    registry = (
        BUILTIN_FALSIFICATION_STRATEGY_CAPABILITY_REGISTRY
        if capability_registry is None
        else capability_registry
    )
    if type(registry) is not FalsificationStrategyCapabilityRegistry:
        raise FalsificationStrategyError(
            "capability_registry must be an exact FalsificationStrategyCapabilityRegistry"
        )
    builtins = {
        (item.strategy_id, item.version): item
        for item in BUILTIN_FALSIFICATION_STRATEGY_CAPABILITY_REGISTRY.capabilities
    }
    runtimes: dict[tuple[str, str], FalsificationStrategyRuntime] = {}
    for descriptor in registry.capabilities:
        key = (descriptor.strategy_id, descriptor.version)
        expected = builtins.get(key)
        if expected is None or expected.fingerprint != descriptor.fingerprint:
            raise FalsificationStrategyError(
                f"no builtin runtime for exact strategy {descriptor.strategy_id} "
                f"version {descriptor.version}"
            )
        runtimes[key] = _GenericFiniteSequenceRuntime(descriptor)
    return FalsificationStrategyRuntimeRegistry(
        capability_registry=registry,
        runtime_strategies=runtimes,
    )


# Concise compatibility aliases for callers that use "registry" rather than
# the longer capability-registry name.
FalsificationStrategyRegistry = FalsificationStrategyCapabilityRegistry
FalsificationRuntimeRegistry = FalsificationStrategyRuntimeRegistry
