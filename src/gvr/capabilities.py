from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Iterable, Mapping

from .canonical import (
    CanonicalizationError,
    canonical_fingerprint,
    canonical_transport_value,
    canonical_utf8_key,
)
from .core import (
    EffectSupportVerifier,
    GoalSatisfactionVerifier,
    PreconditionsVerifier,
)
from .session import COMPOSITE_CLAIM_VERIFIER
from .software import FUNCTIONAL_REGRESSION_VERIFIER
from .text_search import TEXT_SEARCH_VERIFIER
from .verifiers.data_flow import DATA_FLOW_VERIFIER

if TYPE_CHECKING:
    from .session import AtomicClaim


VERIFIER_CAPABILITY_SCHEMA_VERSION = 1
VERIFIER_CAPABILITY_KIND = "gvr.verifier_capability"
VERIFIER_CAPABILITY_FINGERPRINT_FORMAT = (
    "gvr.verifier_capability.ieee754-json.v1"
)
VERIFIER_CAPABILITY_REGISTRY_SCHEMA_VERSION = 1
VERIFIER_CAPABILITY_REGISTRY_KIND = "gvr.verifier_capability_registry"
VERIFIER_CAPABILITY_REGISTRY_FINGERPRINT_FORMAT = (
    "gvr.verifier_capability_registry.ieee754-json.v1"
)


class VerifierCapabilityError(ValueError):
    """Raised when a capability descriptor or registry is inconsistent."""


class UnknownVerifierCapabilityError(LookupError):
    """Raised when an exact verifier ID and version are not registered."""


class VerifierDeterminism(str, Enum):
    """How a verifier reaches its result.

    D0 is a pure deterministic computation. D1 deterministically evaluates
    immutable evidence. O1 deterministically evaluates a captured observation.
    M1 is model-generated proposal material and is never authoritative truth.
    """

    D0 = "D0"
    D1 = "D1"
    O1 = "O1"
    M1 = "M1"


class VerifierCost(str, Enum):
    """Stable qualitative execution or acquisition cost."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    EXTERNAL = "EXTERNAL"


DeterminismClass = VerifierDeterminism
CostClass = VerifierCost


class FalsificationStrategyKind(str, Enum):
    """Stable generic categories for deterministic falsification work."""

    WITNESS_SEARCH = "WITNESS_SEARCH"
    COUNTEREXAMPLE_SEARCH = "COUNTEREXAMPLE_SEARCH"
    INVARIANT_CHECK = "INVARIANT_CHECK"
    METAMORPHIC_TRANSFORM = "METAMORPHIC_TRANSFORM"
    INDEPENDENT_RECOMPUTE = "INDEPENDENT_RECOMPUTE"
    REPRESENTATION_CHECK = "REPRESENTATION_CHECK"


class FalsificationRequirement(str, Enum):
    """How a verifier capability treats declared falsification output."""

    NONE = "NONE"
    OPTIONAL = "OPTIONAL"
    REQUIRED_BEFORE_PASS = "REQUIRED_BEFORE_PASS"


def _strict_identifier(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise VerifierCapabilityError(f"{name} must be a non-empty string")
    if value != value.strip() or any(character.isspace() for character in value):
        raise VerifierCapabilityError(f"{name} must not contain whitespace")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise VerifierCapabilityError(f"{name} must not contain control characters")
    try:
        canonical_utf8_key(value, path=name)
    except CanonicalizationError as exc:
        raise VerifierCapabilityError(str(exc)) from exc
    return value


def _string_tuple(values: Iterable[str], *, name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise VerifierCapabilityError(f"{name} must be an iterable of strings")
    try:
        items = tuple(values)
    except TypeError as exc:
        raise VerifierCapabilityError(f"{name} must be an iterable of strings") from exc
    normalized = tuple(
        _strict_identifier(item, name=f"{name} item")
        for item in items
    )
    if len(set(normalized)) != len(normalized):
        raise VerifierCapabilityError(f"{name} contains duplicate values")
    return tuple(sorted(normalized, key=lambda item: canonical_utf8_key(item, path=name)))


def _freeze_validated(value: Any) -> Any:
    if value is None or isinstance(value, (bool, str, int, float)):
        return value
    if isinstance(value, Mapping):
        keys = sorted(
            value,
            key=lambda item: canonical_utf8_key(item, path="mapping key"),
        )
        return MappingProxyType({key: _freeze_validated(value[key]) for key in keys})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_validated(item) for item in value)
    raise VerifierCapabilityError(
        f"unsupported immutable contract value {type(value).__name__}"
    )


def _strict_mapping(value: Any, *, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise VerifierCapabilityError(f"{name} must be a mapping")
    try:
        canonical_transport_value(value, path=name)
    except CanonicalizationError as exc:
        raise VerifierCapabilityError(str(exc)) from exc
    return _freeze_validated(value)


def _export_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _export_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_export_value(item) for item in value]
    return value


def _enum_value(value: Any, enum_type: type[Enum], *, name: str) -> Enum:
    if isinstance(value, enum_type):
        return value
    if not isinstance(value, str):
        raise VerifierCapabilityError(f"{name} must be a string enum value")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise VerifierCapabilityError(f"unsupported {name} {value!r}") from exc


def _falsification_kind_tuple(
    values: Iterable[FalsificationStrategyKind | str],
) -> tuple[FalsificationStrategyKind, ...]:
    if isinstance(values, (str, bytes)):
        raise VerifierCapabilityError(
            "accepted_falsification_strategy_kinds must be an iterable"
        )
    try:
        supplied = tuple(values)
    except TypeError as exc:
        raise VerifierCapabilityError(
            "accepted_falsification_strategy_kinds must be an iterable"
        ) from exc
    normalized: list[FalsificationStrategyKind] = []
    for value in supplied:
        try:
            normalized.append(
                value
                if isinstance(value, FalsificationStrategyKind)
                else FalsificationStrategyKind(str(value))
            )
        except ValueError as exc:
            raise VerifierCapabilityError(
                f"unsupported falsification strategy kind {value!r}"
            ) from exc
    if len(set(normalized)) != len(normalized):
        raise VerifierCapabilityError(
            "accepted_falsification_strategy_kinds contains duplicate values"
        )
    return tuple(sorted(normalized, key=lambda item: item.value.encode("utf-8")))


@dataclass(frozen=True, kw_only=True)
class VerifierCapability:
    """Strict immutable descriptor for one exact verifier implementation."""

    verifier_id: str
    version: str
    claim_kinds: tuple[str, ...]
    accepted_evidence_kinds: tuple[str, ...]
    required_evidence_kinds: tuple[str, ...]
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any]
    determinism: VerifierDeterminism
    side_effect_free: bool
    cost: VerifierCost
    bounds: Mapping[str, Any]
    coverage: Mapping[str, Any]
    authoritative: bool
    accepted_falsification_strategy_kinds: tuple[
        FalsificationStrategyKind, ...
    ] = ()
    falsification_requirement: FalsificationRequirement = (
        FalsificationRequirement.NONE
    )
    description: str | None = None
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "verifier_id",
            _strict_identifier(self.verifier_id, name="verifier_id"),
        )
        object.__setattr__(
            self,
            "version",
            _strict_identifier(self.version, name="version"),
        )
        object.__setattr__(
            self,
            "claim_kinds",
            _string_tuple(self.claim_kinds, name="claim_kinds"),
        )
        object.__setattr__(
            self,
            "accepted_evidence_kinds",
            _string_tuple(
                self.accepted_evidence_kinds,
                name="accepted_evidence_kinds",
            ),
        )
        object.__setattr__(
            self,
            "required_evidence_kinds",
            _string_tuple(
                self.required_evidence_kinds,
                name="required_evidence_kinds",
            ),
        )
        if not set(self.required_evidence_kinds) <= set(self.accepted_evidence_kinds):
            raise VerifierCapabilityError(
                "required_evidence_kinds must be a subset of accepted_evidence_kinds"
            )
        object.__setattr__(
            self,
            "input_schema",
            _strict_mapping(self.input_schema, name="input_schema"),
        )
        object.__setattr__(
            self,
            "output_schema",
            _strict_mapping(self.output_schema, name="output_schema"),
        )
        object.__setattr__(
            self,
            "determinism",
            _enum_value(
                self.determinism,
                VerifierDeterminism,
                name="determinism",
            ),
        )
        object.__setattr__(
            self,
            "cost",
            _enum_value(self.cost, VerifierCost, name="cost"),
        )
        if not isinstance(self.side_effect_free, bool):
            raise VerifierCapabilityError("side_effect_free must be a boolean")
        if not isinstance(self.authoritative, bool):
            raise VerifierCapabilityError("authoritative must be a boolean")
        if self.determinism is VerifierDeterminism.M1 and self.authoritative:
            raise VerifierCapabilityError(
                "M1 proposal-only capabilities cannot be authoritative"
            )
        object.__setattr__(
            self,
            "bounds",
            _strict_mapping(self.bounds, name="bounds"),
        )
        object.__setattr__(
            self,
            "coverage",
            _strict_mapping(self.coverage, name="coverage"),
        )
        object.__setattr__(
            self,
            "accepted_falsification_strategy_kinds",
            _falsification_kind_tuple(
                self.accepted_falsification_strategy_kinds
            ),
        )
        object.__setattr__(
            self,
            "falsification_requirement",
            _enum_value(
                self.falsification_requirement,
                FalsificationRequirement,
                name="falsification_requirement",
            ),
        )
        if (
            self.falsification_requirement
            is not FalsificationRequirement.NONE
            and not self.accepted_falsification_strategy_kinds
        ):
            raise VerifierCapabilityError(
                "a falsification requirement needs accepted strategy kinds"
            )
        if self.description is not None:
            if not isinstance(self.description, str):
                raise VerifierCapabilityError("description must be a string")
            try:
                canonical_utf8_key(self.description, path="description")
            except CanonicalizationError as exc:
                raise VerifierCapabilityError(str(exc)) from exc
        try:
            fingerprint = canonical_fingerprint(
                self.semantic_definition(),
                fingerprint_format=VERIFIER_CAPABILITY_FINGERPRINT_FORMAT,
            )
        except CanonicalizationError as exc:
            raise VerifierCapabilityError(str(exc)) from exc
        object.__setattr__(self, "fingerprint", fingerprint)

    def semantic_definition(self) -> dict[str, Any]:
        """Return fingerprinted content. Human description is intentionally absent."""

        definition = {
            "schema_version": VERIFIER_CAPABILITY_SCHEMA_VERSION,
            "kind": VERIFIER_CAPABILITY_KIND,
            "verifier_id": self.verifier_id,
            "version": self.version,
            "claim_kinds": self.claim_kinds,
            "accepted_evidence_kinds": self.accepted_evidence_kinds,
            "required_evidence_kinds": self.required_evidence_kinds,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "determinism": self.determinism.value,
            "side_effect_free": self.side_effect_free,
            "cost": self.cost.value,
            "bounds": self.bounds,
            "coverage": self.coverage,
            "authoritative": self.authoritative,
        }
        # Keep schema-v1 Task 19 identities byte-for-byte stable when the new
        # optional falsification contract is not used.
        if (
            self.accepted_falsification_strategy_kinds
            or self.falsification_requirement is not FalsificationRequirement.NONE
        ):
            definition.update({
                "accepted_falsification_strategy_kinds": tuple(
                    item.value
                    for item in self.accepted_falsification_strategy_kinds
                ),
                "falsification_requirement": self.falsification_requirement.value,
            })
        return definition

    def to_dict(self) -> dict[str, Any]:
        value = _export_value(self.semantic_definition())
        value.update({
            "fingerprint_format": VERIFIER_CAPABILITY_FINGERPRINT_FORMAT,
            "fingerprint": self.fingerprint,
            "description": self.description,
        })
        return value

    def export(self) -> dict[str, Any]:
        return self.to_dict()

    def supports_claim_kind(self, claim_kind: str) -> bool:
        return claim_kind in self.claim_kinds


@dataclass(frozen=True)
class VerifierCapabilityRegistry:
    """Immutable deterministic registry, distinct from runtime VerifierRegistry."""

    capabilities: tuple[VerifierCapability, ...] = ()
    fingerprint: str = field(init=False)
    _by_key: Mapping[tuple[str, str], VerifierCapability] = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        try:
            supplied = tuple(self.capabilities)
        except TypeError as exc:
            raise VerifierCapabilityError("capabilities must be iterable") from exc
        if any(not isinstance(item, VerifierCapability) for item in supplied):
            raise VerifierCapabilityError(
                "capabilities must contain VerifierCapability descriptors"
            )

        grouped: dict[tuple[str, str], list[VerifierCapability]] = {}
        for capability in supplied:
            key = (capability.verifier_id, capability.version)
            grouped.setdefault(key, []).append(capability)

        normalized: list[VerifierCapability] = []
        for key, duplicates in grouped.items():
            semantic_fingerprints = {item.fingerprint for item in duplicates}
            if len(semantic_fingerprints) != 1:
                raise VerifierCapabilityError(
                    "conflicting verifier capability for "
                    f"{key[0]} version {key[1]}"
                )
            normalized.append(min(duplicates, key=_description_key))

        normalized.sort(key=_capability_key)
        capabilities = tuple(normalized)
        by_key = MappingProxyType({
            (item.verifier_id, item.version): item
            for item in capabilities
        })
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "_by_key", by_key)
        try:
            fingerprint = canonical_fingerprint(
                self.semantic_definition(),
                fingerprint_format=VERIFIER_CAPABILITY_REGISTRY_FINGERPRINT_FORMAT,
            )
        except CanonicalizationError as exc:
            raise VerifierCapabilityError(str(exc)) from exc
        object.__setattr__(self, "fingerprint", fingerprint)

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "schema_version": VERIFIER_CAPABILITY_REGISTRY_SCHEMA_VERSION,
            "kind": VERIFIER_CAPABILITY_REGISTRY_KIND,
            "capabilities": tuple(
                capability.semantic_definition()
                for capability in self.capabilities
            ),
        }

    def list(self) -> tuple[VerifierCapability, ...]:
        return self.capabilities

    def list_capabilities(self) -> tuple[VerifierCapability, ...]:
        return self.list()

    def lookup(self, verifier_id: str, version: str) -> VerifierCapability:
        key = (
            _strict_identifier(verifier_id, name="verifier_id"),
            _strict_identifier(version, name="version"),
        )
        try:
            return self._by_key[key]
        except KeyError as exc:
            raise UnknownVerifierCapabilityError(
                f"unknown verifier capability {key[0]} version {key[1]}"
            ) from exc

    def query(
        self,
        *,
        claim_kind: str | None = None,
        authoritative_only: bool = False,
    ) -> tuple[VerifierCapability, ...]:
        if claim_kind is not None:
            claim_kind = _strict_identifier(claim_kind, name="claim_kind")
        if not isinstance(authoritative_only, bool):
            raise VerifierCapabilityError("authoritative_only must be a boolean")
        return tuple(
            capability
            for capability in self.capabilities
            if (claim_kind is None or capability.supports_claim_kind(claim_kind))
            and (
                not authoritative_only
                or (
                    capability.authoritative
                    and capability.determinism is not VerifierDeterminism.M1
                )
            )
        )

    def capabilities_for_claim_kind(
        self,
        claim_kind: str,
        *,
        authoritative_only: bool = False,
    ) -> tuple[VerifierCapability, ...]:
        return self.query(
            claim_kind=claim_kind,
            authoritative_only=authoritative_only,
        )

    def validate_atomic_claim(
        self,
        claim: AtomicClaim,
        *,
        version: str | None = None,
    ) -> VerifierCapability:
        from .session import AtomicClaim

        if not isinstance(claim, AtomicClaim):
            raise VerifierCapabilityError("claim must be an AtomicClaim")
        if version is None:
            matches = tuple(
                capability
                for capability in self.capabilities
                if capability.verifier_id == claim.verifier
            )
            if not matches:
                raise UnknownVerifierCapabilityError(
                    f"unknown verifier capability {claim.verifier}"
                )
            if len(matches) != 1:
                raise UnknownVerifierCapabilityError(
                    f"verifier capability {claim.verifier} requires an exact version"
                )
            capability = matches[0]
        else:
            capability = self.lookup(claim.verifier, version)
        if not capability.supports_claim_kind(claim.claim_kind):
            raise VerifierCapabilityError(
                f"verifier {capability.verifier_id} version {capability.version} "
                f"does not support claim kind {claim.claim_kind}"
            )
        if not capability.authoritative:
            raise VerifierCapabilityError(
                f"verifier {capability.verifier_id} version {capability.version} "
                "is not authoritative and cannot verify an AtomicClaim"
            )
        return capability

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": VERIFIER_CAPABILITY_REGISTRY_SCHEMA_VERSION,
            "kind": VERIFIER_CAPABILITY_REGISTRY_KIND,
            "fingerprint_format": VERIFIER_CAPABILITY_REGISTRY_FINGERPRINT_FORMAT,
            "fingerprint": self.fingerprint,
            "capabilities": [item.to_dict() for item in self.capabilities],
        }

    def export(self) -> dict[str, Any]:
        return self.to_dict()


def _capability_key(capability: VerifierCapability) -> tuple[bytes, bytes]:
    return (
        canonical_utf8_key(capability.verifier_id, path="verifier_id"),
        canonical_utf8_key(capability.version, path="version"),
    )


def _description_key(capability: VerifierCapability) -> tuple[int, bytes]:
    if capability.description is None:
        return (0, b"")
    return (
        1,
        canonical_utf8_key(capability.description, path="description"),
    )


def _builtin(
    verifier_id: str,
    *,
    determinism: VerifierDeterminism,
    cost: VerifierCost,
    bounds: Mapping[str, Any],
    coverage: Mapping[str, Any],
    description: str,
    claim_kinds: tuple[str, ...] = (),
    accepted_evidence_kinds: tuple[str, ...] = (),
    required_evidence_kinds: tuple[str, ...] = (),
) -> VerifierCapability:
    return VerifierCapability(
        verifier_id=verifier_id,
        version="1",
        claim_kinds=claim_kinds,
        accepted_evidence_kinds=accepted_evidence_kinds,
        required_evidence_kinds=required_evidence_kinds,
        input_schema={},
        output_schema={},
        determinism=determinism,
        side_effect_free=True,
        cost=cost,
        bounds=bounds,
        coverage=coverage,
        authoritative=True,
        description=description,
    )


BUILTIN_VERIFIER_CAPABILITY_REGISTRY = VerifierCapabilityRegistry((
    _builtin(
        PreconditionsVerifier.name,
        determinism=VerifierDeterminism.D0,
        cost=VerifierCost.LOW,
        bounds={"domain": "SUPPLIED_PROPOSAL_AND_CONTEXT", "scaling": "LINEAR_IN_ACTIONS"},
        coverage={"scope": "DECLARED_ACTION_PRECONDITIONS"},
        description="Checks action preconditions by pure deterministic simulation.",
    ),
    _builtin(
        EffectSupportVerifier.name,
        determinism=VerifierDeterminism.D0,
        cost=VerifierCost.LOW,
        bounds={"domain": "SUPPLIED_PROPOSAL_AND_CONTEXT", "scaling": "LINEAR_IN_EFFECTS"},
        coverage={"scope": "DECLARED_ACTION_EFFECTS"},
        description="Checks whether declared action effects are supported.",
    ),
    _builtin(
        GoalSatisfactionVerifier.name,
        determinism=VerifierDeterminism.D0,
        cost=VerifierCost.LOW,
        bounds={"domain": "SUPPLIED_PROPOSAL_AND_CONTEXT", "scaling": "LINEAR_IN_ACTIONS_AND_GOALS"},
        coverage={"scope": "DECLARED_GOAL_PREDICATES"},
        description="Simulates declared actions and checks declared goal predicates.",
    ),
    _builtin(
        TEXT_SEARCH_VERIFIER,
        determinism=VerifierDeterminism.D0,
        cost=VerifierCost.LOW,
        bounds={"domain": "SUPPLIED_CORPUS", "scaling": "LINEAR_IN_CORPUS_TEXT"},
        coverage={"scope": "EVERY_SUPPLIED_CORPUS_ITEM"},
        description="Recomputes exact literal matches over the supplied corpus.",
    ),
    _builtin(
        FUNCTIONAL_REGRESSION_VERIFIER,
        determinism=VerifierDeterminism.D1,
        cost=VerifierCost.MEDIUM,
        bounds={"domain": "SUPPLIED_FUNCTIONAL_SNAPSHOTS", "scaling": "LINEAR_IN_OBSERVABLES"},
        coverage={"pass_requires": "COMPLETE_COVERAGE_FOR_EVERY_REQUIRED_KIND"},
        description="Compares immutable functional snapshots conservatively.",
    ),
    _builtin(
        DATA_FLOW_VERIFIER,
        determinism=VerifierDeterminism.O1,
        cost=VerifierCost.EXTERNAL,
        bounds={"domain": "CAPTURED_GRAPHIFY_TRAVERSAL", "scope": "DECLARED_QUERY_BOUNDS"},
        coverage={"absence_requires": "COMPLETE_FOR_SUPPORTED_CONSTRUCT"},
        claim_kinds=("CAN_FLOW_TO", "NO_SUPPORTED_PATH"),
        accepted_evidence_kinds=(
            "graphify.data_flow_edge",
            "graphify.data_flow_boundary",
            "graphify.data_flow_query_result",
        ),
        required_evidence_kinds=(),
        description="Checks captured Graphify traversal observations without reparsing source.",
    ),
    _builtin(
        COMPOSITE_CLAIM_VERIFIER,
        determinism=VerifierDeterminism.D1,
        cost=VerifierCost.MEDIUM,
        bounds={"domain": "IMMUTABLE_CLAIM_GRAPH_AND_BUNDLES", "budget": "SESSION_BUDGET"},
        coverage={"scope": "REACHABLE_REQUESTED_ROOTS"},
        description="Composes current bundle verdicts with exact tri-state operators.",
    ),
))


def builtin_verifier_capability_registry() -> VerifierCapabilityRegistry:
    """Return the immutable snapshot describing verifier IDs shipped by GVR."""

    return BUILTIN_VERIFIER_CAPABILITY_REGISTRY
