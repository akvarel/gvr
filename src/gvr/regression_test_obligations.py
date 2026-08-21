from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from .bundle import VerificationBundle, build_verification_bundle, validate_verification_bundle
from .canonical import (
    CanonicalizationError,
    canonical_fingerprint,
    canonical_transport_value,
    canonical_utf8_key,
)
from .model import Evidence, VerificationIssue, VerificationReport, VerificationVerdict


REGRESSION_TEST_OBLIGATION_SCHEMA_VERSION = 1
REGRESSION_TEST_OBLIGATION_VERIFIER = "gvr.regression_test_obligation.v1"
TEST_OBLIGATION_GROUNDED = "TEST_OBLIGATION_GROUNDED"

BEHAVIOR_EVIDENCE_INVENTORY_SCHEMA_VERSION = 1
BEHAVIOR_EVIDENCE_INVENTORY_KIND = "gvr.behavior_evidence_inventory"
BEHAVIOR_EVIDENCE_INVENTORY_FINGERPRINT_FORMAT = (
    "gvr.behavior_evidence_inventory.ieee754-json.v1"
)
TEST_OBLIGATION_KIND = "gvr.test_obligation"
TEST_OBLIGATION_FINGERPRINT_FORMAT = "gvr.test_obligation.ieee754-json.v1"
REGRESSION_OBLIGATION_PLAN_SCHEMA_VERSION = 1
REGRESSION_OBLIGATION_PLAN_KIND = "gvr.regression_obligation_plan"
REGRESSION_OBLIGATION_PLAN_FINGERPRINT_FORMAT = (
    "gvr.regression_obligation_plan.ieee754-json.v1"
)

class RegressionObligationError(ValueError):
    """Raised when obligation evidence or plan state is inconsistent."""


class BehaviorEvidenceKind(str, Enum):
    SURFACE = "gvr.test.surface"
    ACTOR_ROLE = "gvr.test.actor_role"
    ACTION = "gvr.test.action"
    FIELD = "gvr.test.field"
    CONSTRAINT = "gvr.test.constraint"
    DATA_PARTITION = "gvr.test.data_partition"
    OBSERVABLE_OUTCOME = "gvr.test.observable_outcome"
    STATE_TRANSITION = "gvr.test.state_transition"
    PERSISTENCE_RELATION = "gvr.test.persistence_relation"
    PERMISSION_RELATION = "gvr.test.permission_relation"
    DEPENDENCY = "gvr.test.dependency"
    ERROR_RECOVERY = "gvr.test.error_recovery"
    EXECUTION_SAFETY = "gvr.test.execution_safety"


# This is a closed schema-v1 vocabulary. New source evidence kinds require a
# schema/version change rather than silently entering an authoritative verifier.
BEHAVIOR_EVIDENCE_KINDS = tuple(item.value for item in BehaviorEvidenceKind)
BEHAVIOR_EVIDENCE_KIND_SET = frozenset(BEHAVIOR_EVIDENCE_KINDS)


class BehaviorFactClass(str, Enum):
    SURFACE = "SURFACE"
    ACTOR_ROLE = "ACTOR_ROLE"
    ACTION = "ACTION"
    FIELD = "FIELD"
    CONSTRAINT = "CONSTRAINT"
    DATA_PARTITION = "DATA_PARTITION"
    OBSERVABLE_OUTCOME = "OBSERVABLE_OUTCOME"
    STATE_TRANSITION = "STATE_TRANSITION"
    PERSISTENCE_RELATION = "PERSISTENCE_RELATION"
    PERMISSION_RELATION = "PERMISSION_RELATION"
    DEPENDENCY = "DEPENDENCY"
    ERROR_RECOVERY = "ERROR_RECOVERY"
    EXECUTION_SAFETY = "EXECUTION_SAFETY"


class FactCoverageCompleteness(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


class TestObligationKind(str, Enum):
    HAPPY_PATH = "HAPPY_PATH"
    REQUIRED_FIELD = "REQUIRED_FIELD"
    INVALID_FORMAT = "INVALID_FORMAT"
    BOUNDARY_VALUE = "BOUNDARY_VALUE"
    STATE_TRANSITION = "STATE_TRANSITION"
    ROLE_PERMISSION = "ROLE_PERMISSION"
    PERSISTENCE_READ_BACK = "PERSISTENCE_READ_BACK"
    ERROR_RECOVERY = "ERROR_RECOVERY"
    DEPENDENCY = "DEPENDENCY"


class TestLevel(str, Enum):
    UNIT = "UNIT"
    INTEGRATION = "INTEGRATION"
    SYSTEM = "SYSTEM"


class RegressionObligationGapCode(str, Enum):
    MISSING_NAVIGATION = "MISSING_NAVIGATION"
    MISSING_PRECONDITION = "MISSING_PRECONDITION"
    MISSING_ACTION = "MISSING_ACTION"
    MISSING_ORACLE = "MISSING_ORACLE"
    MISSING_CONSTRAINT = "MISSING_CONSTRAINT"
    MISSING_TEST_DATA_PARTITION = "MISSING_TEST_DATA_PARTITION"
    MISSING_ROLE_EVIDENCE = "MISSING_ROLE_EVIDENCE"
    MISSING_PERSISTENCE_READ_BACK = "MISSING_PERSISTENCE_READ_BACK"
    AUTHENTICATION_UNPROVEN = "AUTHENTICATION_UNPROVEN"
    EXECUTION_SAFETY_UNKNOWN = "EXECUTION_SAFETY_UNKNOWN"
    COVERAGE_PARTIAL = "COVERAGE_PARTIAL"
    COVERAGE_UNKNOWN = "COVERAGE_UNKNOWN"
    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"
    UNSUPPORTED_INTERACTION = "UNSUPPORTED_INTERACTION"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


class RegressionObligationReadiness(str, Enum):
    READY = "READY"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


class RegressionObligationTermination(str, Enum):
    COMPLETE = "COMPLETE"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


EVIDENCE_FACT_CLASS: Mapping[str, BehaviorFactClass] = MappingProxyType({
    "gvr.test.surface": BehaviorFactClass.SURFACE,
    "gvr.test.actor_role": BehaviorFactClass.ACTOR_ROLE,
    "gvr.test.action": BehaviorFactClass.ACTION,
    "gvr.test.field": BehaviorFactClass.FIELD,
    "gvr.test.constraint": BehaviorFactClass.CONSTRAINT,
    "gvr.test.data_partition": BehaviorFactClass.DATA_PARTITION,
    "gvr.test.observable_outcome": BehaviorFactClass.OBSERVABLE_OUTCOME,
    "gvr.test.state_transition": BehaviorFactClass.STATE_TRANSITION,
    "gvr.test.persistence_relation": BehaviorFactClass.PERSISTENCE_RELATION,
    "gvr.test.permission_relation": BehaviorFactClass.PERMISSION_RELATION,
    "gvr.test.dependency": BehaviorFactClass.DEPENDENCY,
    "gvr.test.error_recovery": BehaviorFactClass.ERROR_RECOVERY,
    "gvr.test.execution_safety": BehaviorFactClass.EXECUTION_SAFETY,
})
EVIDENCE_KIND_BY_FACT_CLASS: Mapping[BehaviorFactClass, tuple[str, ...]] = MappingProxyType({
    fact_class: tuple(
        kind for kind in BEHAVIOR_EVIDENCE_KINDS
        if EVIDENCE_FACT_CLASS[kind] is fact_class
    )
    for fact_class in BehaviorFactClass
})

_TRUTH_LIKE_KEYS = frozenset({
    "approval", "approved", "authorization", "authorized", "can_deploy",
    "can_merge", "decision", "fail", "grounded", "pass", "readiness",
    "ready", "status", "verdict",
})


class _FrozenDict(dict[str, Any]):
    def _immutable(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("regression obligation semantic content is immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable
    __ior__ = _immutable

    def __deepcopy__(self, _memo: dict[int, Any]) -> _FrozenDict:
        return self


def _utf8_key(value: str, *, path: str = "value") -> bytes:
    try:
        return canonical_utf8_key(value, path=path)
    except CanonicalizationError as exc:
        raise RegressionObligationError(str(exc)) from exc


def _identifier(value: Any, *, name: str) -> str:
    if isinstance(value, Enum):
        value = value.value
    if not isinstance(value, str) or not value or value != value.strip():
        raise RegressionObligationError(f"{name} must be a non-empty trimmed string")
    if any(character.isspace() for character in value):
        raise RegressionObligationError(f"{name} must not contain whitespace")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise RegressionObligationError(f"{name} must not contain control characters")
    _utf8_key(value, path=name)
    return value


def _sha256(value: Any, *, name: str) -> str:
    normalized = _identifier(value, name=name)
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise RegressionObligationError(
            f"{name} must be a lowercase SHA-256 fingerprint"
        )
    return normalized


def _text(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RegressionObligationError(f"{name} must be a non-empty string")
    _utf8_key(value, path=name)
    return value.strip()


def _enum(value: Any, enum_type: type[Enum], *, name: str) -> Enum:
    if isinstance(value, enum_type):
        return value
    if not isinstance(value, str):
        raise RegressionObligationError(f"{name} must be a string enum value")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise RegressionObligationError(f"unsupported {name} {value!r}") from exc


def _canonical_value(value: Any, *, path: str) -> Any:
    if isinstance(value, Enum):
        return _canonical_value(value.value, path=path)
    if value is None or isinstance(value, (str, bool, int, float)):
        try:
            canonical_transport_value(value, path=path)
        except CanonicalizationError as exc:
            raise RegressionObligationError(str(exc)) from exc
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key in value:
            if not isinstance(key, str):
                raise RegressionObligationError(f"{path} contains a non-string mapping key")
            _utf8_key(key, path=f"{path} key")
            normalized[key] = _canonical_value(value[key], path=f"{path}.{key}")
        return normalized
    if isinstance(value, (list, tuple)):
        return [
            _canonical_value(item, path=f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    raise RegressionObligationError(
        f"{path} contains unsupported semantic value {type(value).__name__}"
    )


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return _FrozenDict({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _mapping(value: Any, *, name: str, reject_truth: bool = False) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RegressionObligationError(f"{name} must be a mapping")
    normalized = _canonical_value(value, path=name)
    if reject_truth:
        _reject_truth_like_fields(normalized, name=name)
    return _freeze(normalized)


def _export(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {key: _export(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_export(item) for item in value]
    return value


def _reject_truth_like_fields(value: Any, *, name: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = key.strip().lower().replace("-", "_")
            if normalized in _TRUTH_LIKE_KEYS:
                raise RegressionObligationError(
                    f"{name} contains truth-like field {key!r}"
                )
            _reject_truth_like_fields(item, name=f"{name}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_truth_like_fields(item, name=f"{name}[{index}]")


def _string_ids(values: Iterable[str], *, name: str, allow_empty: bool = False) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise RegressionObligationError(f"{name} must be an iterable of strings")
    try:
        items = tuple(_identifier(value, name=f"{name} item") for value in values)
    except TypeError as exc:
        raise RegressionObligationError(f"{name} must be an iterable of strings") from exc
    normalized = tuple(sorted(set(items), key=lambda item: _utf8_key(item, path=name)))
    if not allow_empty and not normalized:
        raise RegressionObligationError(f"{name} must not be empty")
    return normalized


def _fact_classes(values: Iterable[BehaviorFactClass], *, name: str) -> tuple[BehaviorFactClass, ...]:
    if isinstance(values, (str, bytes)):
        raise RegressionObligationError(f"{name} must be an iterable of fact classes")
    try:
        normalized = {
            _enum(value, BehaviorFactClass, name=f"{name} item")
            for value in values
        }
    except TypeError as exc:
        raise RegressionObligationError(f"{name} must be an iterable of fact classes") from exc
    result = tuple(item for item in BehaviorFactClass if item in normalized)
    if not result:
        raise RegressionObligationError(f"{name} must not be empty")
    return result


def _fingerprint(value: Any, *, fingerprint_format: str) -> str:
    try:
        return canonical_fingerprint(_export(value), fingerprint_format=fingerprint_format)
    except CanonicalizationError as exc:
        raise RegressionObligationError(str(exc)) from exc


def _normalize_evidence(record: Evidence) -> Evidence:
    if not isinstance(record, Evidence):
        raise RegressionObligationError("inventory evidence must contain Evidence records")
    evidence_id = _identifier(record.id, name="evidence id")
    if record.kind not in BEHAVIOR_EVIDENCE_KIND_SET:
        raise RegressionObligationError(
            f"unsupported behavior evidence kind {record.kind!r}"
        )
    kind = _identifier(record.kind, name="evidence kind")
    payload = _mapping(record.payload, name=f"evidence[{evidence_id}].payload", reject_truth=True)
    source = None if record.source is None else _text(record.source, name="evidence source")
    fingerprint = (
        None if record.fingerprint is None
        else _identifier(record.fingerprint, name="evidence fingerprint")
    )
    return Evidence(evidence_id, kind, payload, source, fingerprint)


def _evidence_definition(record: Evidence) -> dict[str, Any]:
    return {
        "id": record.id,
        "kind": record.kind,
        "payload": record.payload,
        "source": record.source,
        "fingerprint": record.fingerprint,
    }


@dataclass(frozen=True, kw_only=True)
class FactClassCoverage:
    fact_class: BehaviorFactClass
    completeness: FactCoverageCompleteness
    evidence_ids: tuple[str, ...] = ()
    scope: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "fact_class", _enum(
            self.fact_class, BehaviorFactClass, name="fact_class"
        ))
        object.__setattr__(self, "completeness", _enum(
            self.completeness, FactCoverageCompleteness, name="completeness"
        ))
        object.__setattr__(self, "evidence_ids", _string_ids(
            self.evidence_ids,
            name="coverage evidence_ids",
            allow_empty=True,
        ))
        object.__setattr__(self, "scope", _mapping(self.scope, name="coverage scope", reject_truth=True))
        if self.completeness is FactCoverageCompleteness.UNKNOWN and self.evidence_ids:
            raise RegressionObligationError(
                "unknown coverage cannot cite positive evidence_ids"
            )

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "fact_class": self.fact_class.value,
            "completeness": self.completeness.value,
            "evidence_ids": self.evidence_ids,
            "scope": self.scope,
        }

    def to_dict(self) -> dict[str, Any]:
        return _export(self.semantic_definition())


@dataclass(frozen=True, kw_only=True)
class BehaviorEvidenceInventory:
    evidence: tuple[Evidence, ...]
    coverage: tuple[FactClassCoverage, ...] = ()
    schema_version: int = BEHAVIOR_EVIDENCE_INVENTORY_SCHEMA_VERSION
    kind: str = BEHAVIOR_EVIDENCE_INVENTORY_KIND
    fingerprint_format: str = BEHAVIOR_EVIDENCE_INVENTORY_FINGERPRINT_FORMAT
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        if self.schema_version != BEHAVIOR_EVIDENCE_INVENTORY_SCHEMA_VERSION:
            raise RegressionObligationError(
                f"unsupported behavior evidence inventory schema version {self.schema_version}"
            )
        if self.kind != BEHAVIOR_EVIDENCE_INVENTORY_KIND:
            raise RegressionObligationError(f"unsupported behavior evidence inventory kind {self.kind}")
        if self.fingerprint_format != BEHAVIOR_EVIDENCE_INVENTORY_FINGERPRINT_FORMAT:
            raise RegressionObligationError(
                f"unsupported behavior evidence inventory fingerprint format {self.fingerprint_format}"
            )

        by_id: dict[str, Evidence] = {}
        semantics: dict[str, str] = {}
        for supplied in self.evidence:
            record = _normalize_evidence(supplied)
            semantic = _fingerprint(
                _evidence_definition(record),
                fingerprint_format="gvr.behavior_evidence_record.ieee754-json.v1",
            )
            previous = semantics.get(record.id)
            if previous is not None and previous != semantic:
                raise RegressionObligationError(
                    f"conflicting evidence records for ID {record.id}"
                )
            semantics[record.id] = semantic
            by_id[record.id] = record
        normalized_evidence = tuple(
            by_id[evidence_id]
            for evidence_id in sorted(by_id, key=lambda item: _utf8_key(item, path="evidence id"))
        )

        coverage_by_key: dict[tuple[BehaviorFactClass, str], FactClassCoverage] = {}
        for supplied in self.coverage:
            if not isinstance(supplied, FactClassCoverage):
                raise RegressionObligationError(
                    "inventory coverage must contain FactClassCoverage records"
                )
            scope_fingerprint = _fingerprint(
                supplied.scope,
                fingerprint_format="gvr.fact_class_coverage_scope.ieee754-json.v1",
            )
            key = (supplied.fact_class, scope_fingerprint)
            current = coverage_by_key.get(key)
            if current is None:
                coverage_by_key[key] = supplied
                continue
            if current.completeness is not supplied.completeness:
                raise RegressionObligationError(
                    f"conflicting coverage records for fact class {supplied.fact_class.value} and scope"
                )
            coverage_by_key[key] = FactClassCoverage(
                fact_class=supplied.fact_class,
                completeness=supplied.completeness,
                evidence_ids=current.evidence_ids + supplied.evidence_ids,
                scope=supplied.scope,
            )

        evidence_index = {record.id: record for record in normalized_evidence}
        for item in coverage_by_key.values():
            for evidence_id in item.evidence_ids:
                record = evidence_index.get(evidence_id)
                if record is None:
                    raise RegressionObligationError(
                        f"coverage references unavailable evidence {evidence_id}"
                    )
                if EVIDENCE_FACT_CLASS[record.kind] is not item.fact_class:
                    raise RegressionObligationError(
                        f"evidence {evidence_id} does not support fact class {item.fact_class.value}"
                    )

        normalized_coverage = tuple(sorted(
            coverage_by_key.values(),
            key=lambda item: (
                list(BehaviorFactClass).index(item.fact_class),
                _fingerprint(
                    item.scope,
                    fingerprint_format="gvr.fact_class_coverage_scope.ieee754-json.v1",
                ),
            ),
        ))
        object.__setattr__(self, "evidence", normalized_evidence)
        object.__setattr__(self, "coverage", normalized_coverage)
        object.__setattr__(self, "fingerprint", _fingerprint(
            self.semantic_definition(),
            fingerprint_format=self.fingerprint_format,
        ))

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "evidence": tuple(_evidence_definition(record) for record in self.evidence),
            "coverage": tuple(item.semantic_definition() for item in self.coverage),
        }

    def evidence_by_id(self, evidence_id: str) -> Evidence | None:
        return next((item for item in self.evidence if item.id == evidence_id), None)

    def coverage_for(self, fact_class: BehaviorFactClass) -> FactClassCoverage:
        normalized = _enum(fact_class, BehaviorFactClass, name="fact_class")
        candidates = tuple(item for item in self.coverage if item.fact_class is normalized)
        for item in candidates:
            if not item.scope:
                return item
        if len(candidates) == 1:
            return candidates[0]
        return FactClassCoverage(
            fact_class=normalized,
            completeness=FactCoverageCompleteness.UNKNOWN,
            evidence_ids=(),
            scope={},
        )

    def coverage_for_scope(
        self,
        fact_class: BehaviorFactClass,
        *,
        subject: str,
        surface: str,
        action: str,
    ) -> FactClassCoverage:
        normalized = _enum(fact_class, BehaviorFactClass, name="fact_class")
        semantics = {"subject": subject, "surface": surface, "action": action}
        matches: list[tuple[int, FactClassCoverage]] = []
        for item in self.coverage:
            if item.fact_class is normalized:
                scoped = {
                    key: value for key, value in item.scope.items()
                    if key in semantics
                }
                if all(semantics[key] == value for key, value in scoped.items()):
                    matches.append((len(scoped), item))
        if not matches:
            return FactClassCoverage(
                fact_class=normalized,
                completeness=FactCoverageCompleteness.UNKNOWN,
                evidence_ids=(),
                scope=semantics,
            )
        max_specificity = max(specificity for specificity, _item in matches)
        chosen = [item for specificity, item in matches if specificity == max_specificity]
        completeness = (
            FactCoverageCompleteness.UNKNOWN
            if any(item.completeness is FactCoverageCompleteness.UNKNOWN for item in chosen)
            else FactCoverageCompleteness.PARTIAL
            if any(item.completeness is FactCoverageCompleteness.PARTIAL for item in chosen)
            else FactCoverageCompleteness.COMPLETE
        )
        return FactClassCoverage(
            fact_class=normalized,
            completeness=completeness,
            evidence_ids=tuple(
                evidence_id for item in chosen for evidence_id in item.evidence_ids
            ),
            scope=semantics,
        )

    def to_dict(self) -> dict[str, Any]:
        value = _export(self.semantic_definition())
        value.update({
            "fingerprint_format": self.fingerprint_format,
            "fingerprint": self.fingerprint,
        })
        return value


# Public aliases emphasize that this is the normalized evidence-backed input.
EvidenceInventory = BehaviorEvidenceInventory
RegressionEvidenceInventory = BehaviorEvidenceInventory
FactCoverage = FactClassCoverage
CoverageCompleteness = FactCoverageCompleteness


@dataclass(frozen=True, kw_only=True)
class ObligationRule:
    kind: TestObligationKind
    fact_classes: tuple[BehaviorFactClass, ...]
    test_level: TestLevel
    rationale: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _enum(self.kind, TestObligationKind, name="rule kind"))
        object.__setattr__(self, "fact_classes", _fact_classes(self.fact_classes, name="rule fact_classes"))
        object.__setattr__(self, "test_level", _enum(self.test_level, TestLevel, name="rule test_level"))
        object.__setattr__(self, "rationale", _text(self.rationale, name="rule rationale"))


OBLIGATION_RULES: Mapping[TestObligationKind, ObligationRule] = MappingProxyType({
    TestObligationKind.HAPPY_PATH: ObligationRule(
        kind=TestObligationKind.HAPPY_PATH,
        fact_classes=(
            BehaviorFactClass.SURFACE,
            BehaviorFactClass.ACTION,
            BehaviorFactClass.OBSERVABLE_OUTCOME,
        ),
        test_level=TestLevel.SYSTEM,
        rationale="Navigate to the surface, perform the linked action, and assert its oracle.",
    ),
    TestObligationKind.REQUIRED_FIELD: ObligationRule(
        kind=TestObligationKind.REQUIRED_FIELD,
        fact_classes=(
            BehaviorFactClass.SURFACE,
            BehaviorFactClass.ACTION,
            BehaviorFactClass.FIELD,
            BehaviorFactClass.CONSTRAINT,
            BehaviorFactClass.OBSERVABLE_OUTCOME,
        ),
        test_level=TestLevel.SYSTEM,
        rationale="Omit the linked required field and assert the observable validation behavior.",
    ),
    TestObligationKind.INVALID_FORMAT: ObligationRule(
        kind=TestObligationKind.INVALID_FORMAT,
        fact_classes=(
            BehaviorFactClass.SURFACE,
            BehaviorFactClass.ACTION,
            BehaviorFactClass.FIELD,
            BehaviorFactClass.CONSTRAINT,
            BehaviorFactClass.DATA_PARTITION,
            BehaviorFactClass.OBSERVABLE_OUTCOME,
        ),
        test_level=TestLevel.SYSTEM,
        rationale="Exercise the bounded invalid-format partition and assert the linked oracle.",
    ),
    TestObligationKind.BOUNDARY_VALUE: ObligationRule(
        kind=TestObligationKind.BOUNDARY_VALUE,
        fact_classes=(
            BehaviorFactClass.SURFACE,
            BehaviorFactClass.ACTION,
            BehaviorFactClass.FIELD,
            BehaviorFactClass.CONSTRAINT,
            BehaviorFactClass.DATA_PARTITION,
            BehaviorFactClass.OBSERVABLE_OUTCOME,
        ),
        test_level=TestLevel.SYSTEM,
        rationale="Exercise the bounded boundary-value partition and assert the linked oracle.",
    ),
    TestObligationKind.STATE_TRANSITION: ObligationRule(
        kind=TestObligationKind.STATE_TRANSITION,
        fact_classes=(
            BehaviorFactClass.SURFACE,
            BehaviorFactClass.ACTION,
            BehaviorFactClass.OBSERVABLE_OUTCOME,
            BehaviorFactClass.STATE_TRANSITION,
        ),
        test_level=TestLevel.SYSTEM,
        rationale="Perform the linked action and assert both its oracle and state transition.",
    ),
    TestObligationKind.ROLE_PERMISSION: ObligationRule(
        kind=TestObligationKind.ROLE_PERMISSION,
        fact_classes=(
            BehaviorFactClass.SURFACE,
            BehaviorFactClass.ACTOR_ROLE,
            BehaviorFactClass.ACTION,
            BehaviorFactClass.OBSERVABLE_OUTCOME,
            BehaviorFactClass.PERMISSION_RELATION,
        ),
        test_level=TestLevel.SYSTEM,
        rationale="Authenticate as the linked role and verify its exact permission relation.",
    ),
    TestObligationKind.PERSISTENCE_READ_BACK: ObligationRule(
        kind=TestObligationKind.PERSISTENCE_READ_BACK,
        fact_classes=(
            BehaviorFactClass.SURFACE,
            BehaviorFactClass.ACTION,
            BehaviorFactClass.OBSERVABLE_OUTCOME,
            BehaviorFactClass.PERSISTENCE_RELATION,
        ),
        test_level=TestLevel.INTEGRATION,
        rationale="Write through the action and independently read the persisted result back.",
    ),
    TestObligationKind.ERROR_RECOVERY: ObligationRule(
        kind=TestObligationKind.ERROR_RECOVERY,
        fact_classes=(
            BehaviorFactClass.SURFACE,
            BehaviorFactClass.ACTION,
            BehaviorFactClass.OBSERVABLE_OUTCOME,
            BehaviorFactClass.ERROR_RECOVERY,
        ),
        test_level=TestLevel.INTEGRATION,
        rationale="Trigger the linked error and assert the specified recovery and oracle.",
    ),
    TestObligationKind.DEPENDENCY: ObligationRule(
        kind=TestObligationKind.DEPENDENCY,
        fact_classes=(
            BehaviorFactClass.SURFACE,
            BehaviorFactClass.ACTION,
            BehaviorFactClass.OBSERVABLE_OUTCOME,
            BehaviorFactClass.DEPENDENCY,
        ),
        test_level=TestLevel.INTEGRATION,
        rationale="Exercise the supported dependency interaction and assert the linked oracle.",
    ),
})


@dataclass(frozen=True, kw_only=True)
class TestObligation:
    obligation_id: str
    kind: TestObligationKind
    subject: str
    expected_behavior: str
    rationale: str
    fact_classes: tuple[BehaviorFactClass, ...]
    evidence_ids: tuple[str, ...]
    test_level: TestLevel
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: int = REGRESSION_TEST_OBLIGATION_SCHEMA_VERSION
    record_kind: str = TEST_OBLIGATION_KIND
    fingerprint_format: str = TEST_OBLIGATION_FINGERPRINT_FORMAT
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        if self.schema_version != REGRESSION_TEST_OBLIGATION_SCHEMA_VERSION:
            raise RegressionObligationError(
                f"unsupported test obligation schema version {self.schema_version}"
            )
        if self.record_kind != TEST_OBLIGATION_KIND:
            raise RegressionObligationError(f"unsupported test obligation record kind {self.record_kind}")
        if self.fingerprint_format != TEST_OBLIGATION_FINGERPRINT_FORMAT:
            raise RegressionObligationError(
                f"unsupported test obligation fingerprint format {self.fingerprint_format}"
            )
        object.__setattr__(self, "obligation_id", _identifier(self.obligation_id, name="obligation_id"))
        object.__setattr__(self, "kind", _enum(self.kind, TestObligationKind, name="obligation kind"))
        object.__setattr__(self, "subject", _text(self.subject, name="subject"))
        object.__setattr__(self, "expected_behavior", _text(
            self.expected_behavior, name="expected_behavior"
        ))
        object.__setattr__(self, "rationale", _text(self.rationale, name="rationale"))
        object.__setattr__(self, "fact_classes", _fact_classes(
            self.fact_classes, name="fact_classes"
        ))
        object.__setattr__(self, "evidence_ids", _string_ids(
            self.evidence_ids, name="evidence_ids"
        ))
        object.__setattr__(self, "test_level", _enum(
            self.test_level, TestLevel, name="test_level"
        ))
        object.__setattr__(self, "metadata", _mapping(
            self.metadata, name="metadata", reject_truth=True
        ))
        rule = OBLIGATION_RULES[self.kind]
        if self.fact_classes != rule.fact_classes:
            raise RegressionObligationError(
                f"obligation kind {self.kind.value} requires exact fact_classes "
                + ", ".join(item.value for item in rule.fact_classes)
            )
        if self.test_level is not rule.test_level:
            raise RegressionObligationError(
                f"obligation kind {self.kind.value} requires test_level {rule.test_level.value}"
            )
        object.__setattr__(self, "fingerprint", _fingerprint(
            self.semantic_definition(), fingerprint_format=self.fingerprint_format
        ))

    @property
    def claim_id(self) -> str:
        return f"test-obligation:{self.obligation_id}"

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "record_kind": self.record_kind,
            "obligation_id": self.obligation_id,
            "kind": self.kind.value,
            "subject": self.subject,
            "expected_behavior": self.expected_behavior,
            "rationale": self.rationale,
            "fact_classes": tuple(item.value for item in self.fact_classes),
            "evidence_ids": self.evidence_ids,
            "test_level": self.test_level.value,
            "metadata": self.metadata,
        }

    def to_dict(self) -> dict[str, Any]:
        value = _export(self.semantic_definition())
        value.update({
            "claim_id": self.claim_id,
            "fingerprint_format": self.fingerprint_format,
            "fingerprint": self.fingerprint,
        })
        return value


def _payload_text(record: Evidence, key: str) -> str | None:
    value = record.payload.get(key)
    return value.strip() if isinstance(value, str) and value.strip() else None


def _records_form_exact_obligation(
    kind: TestObligationKind,
    records: tuple[Evidence, ...],
    *,
    subject: str,
    surface: str,
    action: str,
    expected_behavior: str | None = None,
) -> bool:
    by_class: dict[BehaviorFactClass, list[Evidence]] = {}
    for record in records:
        by_class.setdefault(EVIDENCE_FACT_CLASS[record.kind], []).append(record)
    rule = OBLIGATION_RULES[kind]
    if set(by_class) != set(rule.fact_classes):
        return False
    if any(len(by_class[fact_class]) != 1 for fact_class in rule.fact_classes):
        return False

    surface_record = by_class[BehaviorFactClass.SURFACE][0]
    action_record = by_class[BehaviorFactClass.ACTION][0]
    outcome_record = by_class[BehaviorFactClass.OBSERVABLE_OUTCOME][0]
    if not (
        _payload_text(surface_record, "subject") == subject
        and _payload_text(surface_record, "surface") == surface
        and _payload_text(surface_record, "navigation") is not None
        and _payload_text(action_record, "subject") == subject
        and _payload_text(action_record, "surface") == surface
        and _payload_text(action_record, "action") == action
        and action_record.payload.get("surface_id") == surface_record.id
        and _payload_text(action_record, "precondition") is not None
        and _payload_text(outcome_record, "subject") == subject
        and _payload_text(outcome_record, "surface") == surface
        and _payload_text(outcome_record, "action") == action
        and outcome_record.payload.get("surface_id") == surface_record.id
        and outcome_record.payload.get("action_id") == action_record.id
        and _payload_text(outcome_record, "oracle") is not None
        and (
            expected_behavior is None
            or _payload_text(outcome_record, "oracle") == expected_behavior
        )
    ):
        return False

    def exact_context(record: Evidence) -> bool:
        return (
            _payload_text(record, "subject") == subject
            and _payload_text(record, "surface") == surface
            and _payload_text(record, "action") == action
            and record.payload.get("surface_id") == surface_record.id
            and record.payload.get("action_id") == action_record.id
        )

    if kind in {
        TestObligationKind.REQUIRED_FIELD,
        TestObligationKind.INVALID_FORMAT,
        TestObligationKind.BOUNDARY_VALUE,
    }:
        field_record = by_class[BehaviorFactClass.FIELD][0]
        constraint_record = by_class[BehaviorFactClass.CONSTRAINT][0]
        if not exact_context(field_record) or not exact_context(constraint_record):
            return False
        if constraint_record.payload.get("field_id") != field_record.id:
            return False
        constraint = _payload_text(constraint_record, "constraint")
        expected_constraint = {
            TestObligationKind.REQUIRED_FIELD: "required",
            TestObligationKind.INVALID_FORMAT: "format",
            TestObligationKind.BOUNDARY_VALUE: "boundary",
        }[kind]
        if constraint != expected_constraint:
            return False
        if kind is not TestObligationKind.REQUIRED_FIELD:
            partition = by_class[BehaviorFactClass.DATA_PARTITION][0]
            expected_partition = (
                "invalid_format" if kind is TestObligationKind.INVALID_FORMAT
                else "boundary_value"
            )
            if not exact_context(partition):
                return False
            if (
                partition.payload.get("field_id") != field_record.id
                or partition.payload.get("constraint_id") != constraint_record.id
                or _payload_text(partition, "partition") != expected_partition
            ):
                return False
    elif kind is TestObligationKind.STATE_TRANSITION:
        transition = by_class[BehaviorFactClass.STATE_TRANSITION][0]
        if not exact_context(transition) or transition.payload.get("outcome_id") != outcome_record.id:
            return False
        if not _payload_text(transition, "from_state") or not _payload_text(transition, "to_state"):
            return False
    elif kind is TestObligationKind.ROLE_PERMISSION:
        role = by_class[BehaviorFactClass.ACTOR_ROLE][0]
        permission = by_class[BehaviorFactClass.PERMISSION_RELATION][0]
        if not (
            _payload_text(role, "subject") == subject
            and _payload_text(role, "surface") == surface
            and role.payload.get("surface_id") == surface_record.id
            and _payload_text(role, "role") is not None
            and exact_context(permission)
            and permission.payload.get("role_id") == role.id
            and permission.payload.get("outcome_id") == outcome_record.id
            and permission.payload.get("authenticated") is True
            and _payload_text(permission, "permission") in {"allow", "deny"}
        ):
            return False
    elif kind is TestObligationKind.PERSISTENCE_READ_BACK:
        relation = by_class[BehaviorFactClass.PERSISTENCE_RELATION][0]
        if not (
            exact_context(relation)
            and relation.payload.get("outcome_id") == outcome_record.id
            and _payload_text(relation, "relation") == "read_back"
            and _payload_text(relation, "read_surface") is not None
            and _payload_text(relation, "read_action") is not None
        ):
            return False
    elif kind is TestObligationKind.ERROR_RECOVERY:
        recovery = by_class[BehaviorFactClass.ERROR_RECOVERY][0]
        if not (
            exact_context(recovery)
            and recovery.payload.get("outcome_id") == outcome_record.id
            and _payload_text(recovery, "error") is not None
            and _payload_text(recovery, "recovery") is not None
        ):
            return False
    elif kind is TestObligationKind.DEPENDENCY:
        dependency = by_class[BehaviorFactClass.DEPENDENCY][0]
        if not (
            exact_context(dependency)
            and dependency.payload.get("outcome_id") == outcome_record.id
            and dependency.payload.get("supported") is True
            and _payload_text(dependency, "dependency") is not None
            and _payload_text(dependency, "interaction") is not None
        ):
            return False
    return True


def verify_test_obligation_grounding(
    obligation: TestObligation,
    inventory: BehaviorEvidenceInventory,
) -> VerificationReport:
    """Verify exact payload-ID and semantic linkage against current scoped coverage."""

    if not isinstance(obligation, TestObligation):
        raise RegressionObligationError("obligation must be a TestObligation")
    if not isinstance(inventory, BehaviorEvidenceInventory):
        raise RegressionObligationError("inventory must be a BehaviorEvidenceInventory")

    index = {record.id: record for record in inventory.evidence}
    issues: list[VerificationIssue] = []
    dependency_ids: set[str] = set()
    records: list[Evidence] = []
    for evidence_id in obligation.evidence_ids:
        record = index.get(evidence_id)
        if record is None:
            issues.append(VerificationIssue(
                code="OBLIGATION_EVIDENCE_MISSING",
                message=f"Obligation references unavailable evidence {evidence_id}.",
                verdict=VerificationVerdict.UNKNOWN,
            ))
            continue
        dependency_ids.add(evidence_id)
        records.append(record)

    surface = obligation.metadata.get("surface")
    action = obligation.metadata.get("action")
    if not isinstance(surface, str) or not isinstance(action, str) or not _records_form_exact_obligation(
        obligation.kind,
        tuple(records),
        subject=obligation.subject,
        surface=surface if isinstance(surface, str) else "",
        action=action if isinstance(action, str) else "",
        expected_behavior=obligation.expected_behavior,
    ):
        issues.append(VerificationIssue(
            code="OBLIGATION_LINK_MISMATCH",
            message="The cited facts do not form the exact payload-ID and subject/action/surface chain required by the obligation rule.",
            verdict=VerificationVerdict.UNKNOWN,
            evidence_ids=tuple(record.id for record in records),
        ))

    ids_by_class: dict[BehaviorFactClass, set[str]] = {}
    for record in records:
        ids_by_class.setdefault(EVIDENCE_FACT_CLASS[record.kind], set()).add(record.id)
    for fact_class in obligation.fact_classes:
        fact_coverage = inventory.coverage_for_scope(
            fact_class,
            subject=obligation.subject,
            surface=surface if isinstance(surface, str) else "",
            action=action if isinstance(action, str) else "",
        )
        dependency_ids.update(fact_coverage.evidence_ids)
        required_ids = ids_by_class.get(fact_class, set())
        if (
            fact_coverage.completeness is not FactCoverageCompleteness.COMPLETE
            or not required_ids <= set(fact_coverage.evidence_ids)
        ):
            issues.append(VerificationIssue(
                code="OBLIGATION_COVERAGE_INCOMPLETE",
                message=(
                    f"{fact_class.value} lacks COMPLETE local coverage containing the exact obligation facts."
                ),
                verdict=VerificationVerdict.UNKNOWN,
                evidence_ids=fact_coverage.evidence_ids,
            ))

    issues.sort(key=lambda issue: (
        _utf8_key(issue.code, path="issue code"),
        tuple(_utf8_key(item, path="issue evidence id") for item in issue.evidence_ids),
        _utf8_key(issue.message, path="issue message"),
    ))
    verdict = VerificationVerdict.PASS if not issues else VerificationVerdict.UNKNOWN
    return VerificationReport(
        verdict=verdict,
        verifier=REGRESSION_TEST_OBLIGATION_VERIFIER,
        issues=tuple(issues),
        evidence_ids=tuple(sorted(dependency_ids, key=lambda item: _utf8_key(item, path="evidence id"))),
        metadata={
            "claim_kind": TEST_OBLIGATION_GROUNDED,
            "obligation_id": obligation.obligation_id,
            "obligation_fingerprint": obligation.fingerprint,
            "inventory_fingerprint": inventory.fingerprint,
            "fact_classes": tuple(item.value for item in obligation.fact_classes),
        },
    )


def verify_test_obligation_grounding_bundle(
    obligation: TestObligation,
    inventory: BehaviorEvidenceInventory,
) -> VerificationBundle:
    report = verify_test_obligation_grounding(obligation, inventory)
    index = {record.id: record for record in inventory.evidence}
    records = tuple(index[evidence_id] for evidence_id in report.evidence_ids)
    return build_verification_bundle(report, records)


# Concise public aliases for callers that use the claim name directly.
verify_test_obligation = verify_test_obligation_grounding
verify_test_obligation_bundle = verify_test_obligation_grounding_bundle


def _budget_value(value: Any, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RegressionObligationError(f"{name} must be a non-negative integer")
    return value


@dataclass(frozen=True, kw_only=True)
class RegressionObligationBudget:
    max_obligations: int = 256
    max_bundles: int = 256
    max_evidence_records: int = 4096
    max_steps: int = 8192

    def __post_init__(self) -> None:
        for name in ("max_obligations", "max_bundles", "max_evidence_records", "max_steps"):
            object.__setattr__(self, name, _budget_value(getattr(self, name), name=name))

    def to_dict(self) -> dict[str, int]:
        return {
            "max_obligations": self.max_obligations,
            "max_bundles": self.max_bundles,
            "max_evidence_records": self.max_evidence_records,
            "max_steps": self.max_steps,
        }


DEFAULT_REGRESSION_OBLIGATION_BUDGET = RegressionObligationBudget()


@dataclass(frozen=True, kw_only=True)
class RegressionObligationConsumption:
    evidence_records: int = 0
    candidate_obligations: int = 0
    obligations: int = 0
    bundles: int = 0
    steps: int = 0
    deduplicated_obligations: int = 0

    def __post_init__(self) -> None:
        for name in (
            "evidence_records", "candidate_obligations", "obligations", "bundles",
            "steps", "deduplicated_obligations",
        ):
            object.__setattr__(self, name, _budget_value(getattr(self, name), name=name))

    def to_dict(self) -> dict[str, int]:
        return {
            "evidence_records": self.evidence_records,
            "candidate_obligations": self.candidate_obligations,
            "obligations": self.obligations,
            "bundles": self.bundles,
            "steps": self.steps,
            "deduplicated_obligations": self.deduplicated_obligations,
        }


@dataclass(frozen=True, kw_only=True)
class RegressionObligationGap:
    code: RegressionObligationGapCode
    message: str
    fact_class: BehaviorFactClass | None = None
    evidence_ids: tuple[str, ...] = ()
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _enum(self.code, RegressionObligationGapCode, name="gap code"))
        object.__setattr__(self, "message", _text(self.message, name="gap message"))
        if self.fact_class is not None:
            object.__setattr__(self, "fact_class", _enum(
                self.fact_class, BehaviorFactClass, name="gap fact_class"
            ))
        object.__setattr__(self, "evidence_ids", _string_ids(
            self.evidence_ids, name="gap evidence_ids", allow_empty=True
        ))
        object.__setattr__(self, "details", _mapping(
            self.details, name="gap details", reject_truth=True
        ))

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "message": self.message,
            "fact_class": None if self.fact_class is None else self.fact_class.value,
            "evidence_ids": list(self.evidence_ids),
            "details": _export(self.details),
        }


def _report_definition(report: VerificationReport) -> dict[str, Any]:
    return {
        "verdict": report.verdict.value,
        "verifier": report.verifier,
        "issues": tuple({
            "code": issue.code,
            "message": issue.message,
            "verdict": issue.verdict.value,
            "evidence_ids": issue.evidence_ids,
        } for issue in report.issues),
        "evidence_ids": report.evidence_ids,
        "metadata": report.metadata,
    }


def _bundle_definition(bundle: VerificationBundle, *, include_content: bool) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": bundle.schema_version,
        "kind": bundle.kind,
        "fingerprint_format": bundle.fingerprint_format,
        "verifier": bundle.verifier,
        "fingerprint": bundle.fingerprint,
    }
    if include_content:
        value.update({
            "report": _report_definition(bundle.report),
            "evidence": tuple(_evidence_definition(item) for item in bundle.evidence),
            "claim_dependency_ids": bundle.claim_dependency_ids,
        })
    return value


@dataclass(frozen=True, kw_only=True)
class RegressionObligationPlan:
    obligations: tuple[TestObligation, ...]
    bundles: tuple[VerificationBundle, ...]
    coverage: tuple[FactClassCoverage, ...]
    gaps: tuple[RegressionObligationGap, ...]
    budget: RegressionObligationBudget
    consumption: RegressionObligationConsumption
    termination: RegressionObligationTermination
    readiness: RegressionObligationReadiness
    inventory_fingerprint: str
    schema_version: int = REGRESSION_OBLIGATION_PLAN_SCHEMA_VERSION
    kind: str = REGRESSION_OBLIGATION_PLAN_KIND
    fingerprint_format: str = REGRESSION_OBLIGATION_PLAN_FINGERPRINT_FORMAT
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        if self.schema_version != REGRESSION_OBLIGATION_PLAN_SCHEMA_VERSION:
            raise RegressionObligationError(
                f"unsupported regression obligation plan schema version {self.schema_version}"
            )
        if self.kind != REGRESSION_OBLIGATION_PLAN_KIND:
            raise RegressionObligationError(f"unsupported regression obligation plan kind {self.kind}")
        if self.fingerprint_format != REGRESSION_OBLIGATION_PLAN_FINGERPRINT_FORMAT:
            raise RegressionObligationError(
                f"unsupported regression obligation plan fingerprint format {self.fingerprint_format}"
            )
        if not isinstance(self.budget, RegressionObligationBudget):
            raise RegressionObligationError("budget must be a RegressionObligationBudget")
        if not isinstance(self.consumption, RegressionObligationConsumption):
            raise RegressionObligationError("consumption must be RegressionObligationConsumption")
        object.__setattr__(self, "termination", _enum(
            self.termination, RegressionObligationTermination, name="termination"
        ))
        object.__setattr__(self, "readiness", _enum(
            self.readiness, RegressionObligationReadiness, name="readiness"
        ))
        object.__setattr__(self, "inventory_fingerprint", _sha256(
            self.inventory_fingerprint, name="inventory_fingerprint"
        ))

        obligations = tuple(self.obligations)
        bundles = tuple(self.bundles)
        coverage = tuple(self.coverage)
        gaps = tuple(self.gaps)
        if any(not isinstance(item, TestObligation) for item in obligations):
            raise RegressionObligationError("obligations must contain TestObligation records")
        if any(not isinstance(item, VerificationBundle) for item in bundles):
            raise RegressionObligationError("bundles must contain VerificationBundle records")
        if any(not isinstance(item, FactClassCoverage) for item in coverage):
            raise RegressionObligationError("coverage must contain FactClassCoverage records")
        if any(not isinstance(item, RegressionObligationGap) for item in gaps):
            raise RegressionObligationError("gaps must contain RegressionObligationGap records")
        if len(obligations) != len(bundles):
            raise RegressionObligationError("each obligation requires exactly one bundle")
        obligation_ids = tuple(item.obligation_id for item in obligations)
        if len(set(obligation_ids)) != len(obligation_ids):
            raise RegressionObligationError("duplicate obligation IDs are not allowed")
        for obligation, bundle in zip(obligations, bundles):
            validate_verification_bundle(bundle)
            if bundle.report.verifier != REGRESSION_TEST_OBLIGATION_VERIFIER:
                raise RegressionObligationError("plan bundle uses the wrong verifier")
            if bundle.report.metadata.get("obligation_id") != obligation.obligation_id:
                raise RegressionObligationError("plan obligation and bundle are misaligned")
            if bundle.report.metadata.get("obligation_fingerprint") != obligation.fingerprint:
                raise RegressionObligationError("plan obligation fingerprint and bundle are misaligned")
            if bundle.report.metadata.get("inventory_fingerprint") != self.inventory_fingerprint:
                raise RegressionObligationError("plan inventory fingerprint and bundle are misaligned")
        expected_obligation_order = tuple(sorted(
            obligations,
            key=lambda item: (
                list(TestObligationKind).index(item.kind),
                _utf8_key(item.subject, path="obligation subject"),
                _utf8_key(item.expected_behavior, path="expected behavior"),
                _utf8_key(item.obligation_id, path="obligation id"),
            ),
        ))
        if obligations != expected_obligation_order:
            raise RegressionObligationError("plan obligations are not in canonical order")
        if coverage != tuple(sorted(
            coverage,
            key=lambda item: (
                list(BehaviorFactClass).index(item.fact_class),
                _fingerprint(
                    item.scope,
                    fingerprint_format="gvr.fact_class_coverage_scope.ieee754-json.v1",
                ),
            ),
        )):
            raise RegressionObligationError("plan coverage is not in canonical fact-class order")
        if gaps != tuple(sorted(gaps, key=_gap_sort_key)):
            raise RegressionObligationError("plan gaps are not in canonical order")
        if self.consumption.obligations != len(obligations):
            raise RegressionObligationError("consumption obligation count is inconsistent")
        if self.consumption.bundles != len(bundles):
            raise RegressionObligationError("consumption bundle count is inconsistent")
        if len(obligations) > self.budget.max_obligations:
            raise RegressionObligationError("plan exceeds max_obligations")
        if len(bundles) > self.budget.max_bundles:
            raise RegressionObligationError("plan exceeds max_bundles")
        if self.consumption.evidence_records > self.budget.max_evidence_records:
            raise RegressionObligationError("plan exceeds max_evidence_records")
        if self.consumption.steps > self.budget.max_steps:
            raise RegressionObligationError("plan exceeds max_steps")
        has_budget_gap = any(
            item.code is RegressionObligationGapCode.BUDGET_EXHAUSTED for item in gaps
        )
        if (
            self.termination is RegressionObligationTermination.BUDGET_EXHAUSTED
        ) != has_budget_gap:
            raise RegressionObligationError(
                "plan termination and budget-exhausted gap are inconsistent"
            )
        expected_readiness = _readiness(
            obligations=obligations,
            bundles=bundles,
            gaps=gaps,
            termination=self.termination,
        )
        if self.readiness is not expected_readiness:
            raise RegressionObligationError(
                "plan readiness is inconsistent with current obligations, gaps, and termination"
            )

        object.__setattr__(self, "obligations", obligations)
        object.__setattr__(self, "bundles", bundles)
        object.__setattr__(self, "coverage", coverage)
        object.__setattr__(self, "gaps", gaps)
        object.__setattr__(self, "fingerprint", _fingerprint(
            self.semantic_definition(), fingerprint_format=self.fingerprint_format
        ))

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "obligations": tuple(item.to_dict() for item in self.obligations),
            "bundles": tuple(_bundle_definition(item, include_content=False) for item in self.bundles),
            "coverage": tuple(item.semantic_definition() for item in self.coverage),
            "gaps": tuple(item.to_dict() for item in self.gaps),
            "budget": self.budget.to_dict(),
            "consumption": self.consumption.to_dict(),
            "termination": self.termination.value,
            "readiness": self.readiness.value,
            "inventory_fingerprint": self.inventory_fingerprint,
        }

    def to_dict(self) -> dict[str, Any]:
        value = _export(self.semantic_definition())
        value["bundles"] = [
            _export(_bundle_definition(item, include_content=True))
            for item in self.bundles
        ]
        value.update({
            "fingerprint_format": self.fingerprint_format,
            "fingerprint": self.fingerprint,
        })
        return value


@dataclass
class _Candidate:
    rule: ObligationRule
    subject: str
    surface: str
    action: str
    expected_behavior: str
    evidence_ids: set[str]
    discriminator: str


def _obligation_identity(
    rule: ObligationRule,
    subject: str,
    expected_behavior: str,
    *,
    surface: str,
    action: str,
    discriminator: str,
) -> tuple[str, ...]:
    return (
        rule.kind.value,
        subject,
        surface,
        action,
        expected_behavior,
        discriminator,
        rule.test_level.value,
    )


def _obligation_id(identity: tuple[str, ...]) -> str:
    fingerprint = _fingerprint(
        {"identity": identity},
        fingerprint_format="gvr.test_obligation_identity.ieee754-json.v1",
    )
    return f"obl-{fingerprint[:24]}"


def _gap_sort_key(gap: RegressionObligationGap) -> tuple[Any, ...]:
    return (
        list(RegressionObligationGapCode).index(gap.code),
        -1 if gap.fact_class is None else list(BehaviorFactClass).index(gap.fact_class),
        tuple(_utf8_key(item, path="gap evidence id") for item in gap.evidence_ids),
        _utf8_key(gap.message, path="gap message"),
    )


def _readiness(
    *,
    obligations: tuple[TestObligation, ...],
    bundles: tuple[VerificationBundle, ...],
    gaps: tuple[RegressionObligationGap, ...],
    termination: RegressionObligationTermination,
) -> RegressionObligationReadiness:
    if termination is RegressionObligationTermination.BUDGET_EXHAUSTED:
        return RegressionObligationReadiness.BLOCKED
    gap_codes = {gap.code for gap in gaps}
    blocking = {
        RegressionObligationGapCode.MISSING_NAVIGATION,
        RegressionObligationGapCode.MISSING_PRECONDITION,
        RegressionObligationGapCode.MISSING_ACTION,
        RegressionObligationGapCode.MISSING_ORACLE,
        RegressionObligationGapCode.MISSING_CONSTRAINT,
        RegressionObligationGapCode.MISSING_TEST_DATA_PARTITION,
        RegressionObligationGapCode.MISSING_ROLE_EVIDENCE,
        RegressionObligationGapCode.MISSING_PERSISTENCE_READ_BACK,
        RegressionObligationGapCode.COVERAGE_PARTIAL,
        RegressionObligationGapCode.CONTRADICTORY_EVIDENCE,
        RegressionObligationGapCode.UNSUPPORTED_INTERACTION,
        RegressionObligationGapCode.BUDGET_EXHAUSTED,
    }
    if any(gap.code in blocking for gap in gaps):
        return RegressionObligationReadiness.BLOCKED
    unknown = {
        RegressionObligationGapCode.AUTHENTICATION_UNPROVEN,
        RegressionObligationGapCode.EXECUTION_SAFETY_UNKNOWN,
        RegressionObligationGapCode.COVERAGE_UNKNOWN,
    }
    if gap_codes & unknown:
        return RegressionObligationReadiness.UNKNOWN
    if not obligations:
        return RegressionObligationReadiness.UNKNOWN
    if any(bundle.report.verdict is not VerificationVerdict.PASS for bundle in bundles):
        return RegressionObligationReadiness.UNKNOWN
    return RegressionObligationReadiness.READY


def derive_regression_test_obligations(
    inventory: BehaviorEvidenceInventory,
    *,
    budget: RegressionObligationBudget | None = None,
) -> RegressionObligationPlan:
    """Derive finite obligations only from exact linked behavior fact chains."""

    if not isinstance(inventory, BehaviorEvidenceInventory):
        raise RegressionObligationError("inventory must be a BehaviorEvidenceInventory")
    actual_budget = DEFAULT_REGRESSION_OBLIGATION_BUDGET if budget is None else budget
    if not isinstance(actual_budget, RegressionObligationBudget):
        raise RegressionObligationError("budget must be a RegressionObligationBudget")

    max_records = min(actual_budget.max_evidence_records, actual_budget.max_steps)
    available = inventory.evidence[:max_records]
    evidence_records = len(available)
    steps = evidence_records
    exhausted = len(available) < len(inventory.evidence)
    by_class: dict[BehaviorFactClass, list[Evidence]] = {
        fact_class: [] for fact_class in BehaviorFactClass
    }
    for record in available:
        by_class[EVIDENCE_FACT_CLASS[record.kind]].append(record)

    gaps: list[RegressionObligationGap] = []
    gap_keys: set[tuple[Any, ...]] = set()

    def add_gap(
        code: RegressionObligationGapCode,
        message: str,
        *,
        fact_class: BehaviorFactClass | None = None,
        evidence_ids: tuple[str, ...] = (),
        details: Mapping[str, Any] | None = None,
    ) -> None:
        normalized_ids = tuple(sorted(set(evidence_ids), key=lambda value: _utf8_key(value, path="gap evidence id")))
        normalized_details = {} if details is None else details
        key = (
            code,
            fact_class,
            normalized_ids,
            _fingerprint(normalized_details, fingerprint_format="gvr.regression_gap_details.ieee754-json.v1"),
        )
        if key in gap_keys:
            return
        gap_keys.add(key)
        gaps.append(RegressionObligationGap(
            code=code,
            message=message,
            fact_class=fact_class,
            evidence_ids=normalized_ids,
            details=normalized_details,
        ))

    def local_coverage(
        fact_class: BehaviorFactClass,
        subject: str,
        surface: str,
        action: str,
    ) -> FactClassCoverage:
        return inventory.coverage_for_scope(
            fact_class,
            subject=subject,
            surface=surface,
            action=action,
        )

    candidates: dict[tuple[str, ...], _Candidate] = {}
    candidate_count = 0
    deduplicated = 0

    def add_candidate(
        kind: TestObligationKind,
        records: tuple[Evidence, ...],
        *,
        subject: str,
        surface: str,
        action: str,
        oracle: str,
        discriminator: str,
    ) -> None:
        nonlocal candidate_count, deduplicated, exhausted, steps
        rule = OBLIGATION_RULES[kind]
        if steps >= actual_budget.max_steps:
            exhausted = True
            return
        steps += 1
        if not _records_form_exact_obligation(
            kind,
            records,
            subject=subject,
            surface=surface,
            action=action,
            expected_behavior=oracle,
        ):
            return
        identity = _obligation_identity(
            rule,
            subject,
            oracle,
            surface=surface,
            action=action,
            discriminator=discriminator,
        )
        existing = candidates.get(identity)
        if existing is None:
            if (
                len(candidates) >= actual_budget.max_obligations
                or len(candidates) >= actual_budget.max_bundles
            ):
                exhausted = True
                return
            candidate_count += 1
            candidates[identity] = _Candidate(
                rule=rule,
                subject=subject,
                surface=surface,
                action=action,
                expected_behavior=oracle,
                evidence_ids={record.id for record in records},
                discriminator=discriminator,
            )
        else:
            candidate_count += 1
            existing.evidence_ids.update(record.id for record in records)
            deduplicated += 1

    surfaces = by_class[BehaviorFactClass.SURFACE]
    for surface_record in surfaces:
        subject = _payload_text(surface_record, "subject")
        surface = _payload_text(surface_record, "surface")
        if subject is None or surface is None:
            continue
        navigation = _payload_text(surface_record, "navigation")
        if navigation is None:
            add_gap(
                RegressionObligationGapCode.MISSING_NAVIGATION,
                f"Surface evidence {surface_record.id} has no navigation semantics.",
                fact_class=BehaviorFactClass.SURFACE,
                evidence_ids=(surface_record.id,),
                details={"subject": subject, "surface": surface},
            )

        linked_actions = [
            record for record in by_class[BehaviorFactClass.ACTION]
            if record.payload.get("surface_id") == surface_record.id
            and _payload_text(record, "subject") == subject
            and _payload_text(record, "surface") == surface
            and _payload_text(record, "action") is not None
        ]
        if not linked_actions:
            matching_action_coverage = [
                item for item in inventory.coverage
                if item.fact_class is BehaviorFactClass.ACTION
                and item.scope.get("subject") == subject
                and item.scope.get("surface") == surface
            ]
            if any(
                item.completeness is FactCoverageCompleteness.COMPLETE
                and not item.evidence_ids
                for item in matching_action_coverage
            ):
                add_gap(
                    RegressionObligationGapCode.MISSING_ACTION,
                    f"Complete local coverage proves no action for surface {surface}.",
                    fact_class=BehaviorFactClass.ACTION,
                    evidence_ids=(surface_record.id,),
                    details={"subject": subject, "surface": surface},
                )
            else:
                add_gap(
                    RegressionObligationGapCode.COVERAGE_UNKNOWN,
                    f"Action coverage for surface {surface} is not complete in the same scope.",
                    fact_class=BehaviorFactClass.ACTION,
                    evidence_ids=(surface_record.id,),
                    details={"subject": subject, "surface": surface},
                )
            continue

        for action_record in linked_actions:
            action = _payload_text(action_record, "action")
            if action is None:
                continue
            if _payload_text(action_record, "precondition") is None:
                add_gap(
                    RegressionObligationGapCode.MISSING_PRECONDITION,
                    f"Action evidence {action_record.id} has no precondition.",
                    fact_class=BehaviorFactClass.ACTION,
                    evidence_ids=(action_record.id,),
                    details={"subject": subject, "surface": surface, "action": action},
                )

            def exact_context(record: Evidence) -> bool:
                return (
                    _payload_text(record, "subject") == subject
                    and _payload_text(record, "surface") == surface
                    and _payload_text(record, "action") == action
                    and record.payload.get("surface_id") == surface_record.id
                    and record.payload.get("action_id") == action_record.id
                )

            outcomes = [
                record for record in by_class[BehaviorFactClass.OBSERVABLE_OUTCOME]
                if exact_context(record) and _payload_text(record, "oracle") is not None
            ]
            if not outcomes:
                add_gap(
                    RegressionObligationGapCode.MISSING_ORACLE,
                    f"Action evidence {action_record.id} has no exactly linked observable oracle.",
                    fact_class=BehaviorFactClass.OBSERVABLE_OUTCOME,
                    evidence_ids=(action_record.id,),
                    details={"subject": subject, "surface": surface, "action": action},
                )
                continue
            oracle_values = {_payload_text(record, "oracle") for record in outcomes}
            if len(oracle_values) > 1:
                add_gap(
                    RegressionObligationGapCode.CONTRADICTORY_EVIDENCE,
                    f"Action {action} has contradictory observable outcomes.",
                    fact_class=BehaviorFactClass.OBSERVABLE_OUTCOME,
                    evidence_ids=tuple(record.id for record in outcomes),
                    details={"subject": subject, "surface": surface, "action": action},
                )

            safety = [
                record for record in by_class[BehaviorFactClass.EXECUTION_SAFETY]
                if exact_context(record)
                and _payload_text(record, "mode") is not None
                and record.payload.get("bounded") is True
            ]
            if not safety:
                add_gap(
                    RegressionObligationGapCode.EXECUTION_SAFETY_UNKNOWN,
                    f"Execution safety for action {action} is not established by bounded local evidence.",
                    fact_class=BehaviorFactClass.EXECUTION_SAFETY,
                    evidence_ids=(action_record.id,),
                    details={"subject": subject, "surface": surface, "action": action},
                )

            fields = [record for record in by_class[BehaviorFactClass.FIELD] if exact_context(record)]
            roles = [
                record for record in by_class[BehaviorFactClass.ACTOR_ROLE]
                if _payload_text(record, "subject") == subject
                and _payload_text(record, "surface") == surface
                and record.payload.get("surface_id") == surface_record.id
                and _payload_text(record, "role") is not None
            ]

            for outcome in outcomes:
                oracle = _payload_text(outcome, "oracle")
                if oracle is None or navigation is None or _payload_text(action_record, "precondition") is None:
                    continue
                base = (surface_record, action_record, outcome)
                add_candidate(
                    TestObligationKind.HAPPY_PATH,
                    base,
                    subject=subject,
                    surface=surface,
                    action=action,
                    oracle=oracle,
                    discriminator=outcome.id,
                )

                for field_record in fields:
                    constraints = [
                        record for record in by_class[BehaviorFactClass.CONSTRAINT]
                        if exact_context(record)
                        and record.payload.get("field_id") == field_record.id
                        and _payload_text(record, "constraint") is not None
                    ]
                    if not constraints:
                        add_gap(
                            RegressionObligationGapCode.MISSING_CONSTRAINT,
                            f"Field evidence {field_record.id} has no exactly linked constraint.",
                            fact_class=BehaviorFactClass.CONSTRAINT,
                            evidence_ids=(field_record.id,),
                            details={"field_id": field_record.id},
                        )
                    for constraint in constraints:
                        constraint_kind = _payload_text(constraint, "constraint")
                        if constraint_kind == "required":
                            add_candidate(
                                TestObligationKind.REQUIRED_FIELD,
                                base + (field_record, constraint),
                                subject=subject,
                                surface=surface,
                                action=action,
                                oracle=oracle,
                                discriminator=field_record.id,
                            )
                        if constraint_kind not in {"format", "boundary"}:
                            continue
                        partition_kind = "invalid_format" if constraint_kind == "format" else "boundary_value"
                        partitions = [
                            record for record in by_class[BehaviorFactClass.DATA_PARTITION]
                            if exact_context(record)
                            and record.payload.get("field_id") == field_record.id
                            and record.payload.get("constraint_id") == constraint.id
                            and _payload_text(record, "partition") == partition_kind
                        ]
                        if not partitions:
                            add_gap(
                                RegressionObligationGapCode.MISSING_TEST_DATA_PARTITION,
                                f"Constraint evidence {constraint.id} has no bounded linked {partition_kind} partition.",
                                fact_class=BehaviorFactClass.DATA_PARTITION,
                                evidence_ids=(constraint.id,),
                                details={"constraint_id": constraint.id, "partition": partition_kind},
                            )
                        for partition in partitions:
                            obligation_kind = (
                                TestObligationKind.INVALID_FORMAT
                                if constraint_kind == "format"
                                else TestObligationKind.BOUNDARY_VALUE
                            )
                            add_candidate(
                                obligation_kind,
                                base + (field_record, constraint, partition),
                                subject=subject,
                                surface=surface,
                                action=action,
                                oracle=oracle,
                                discriminator=partition.id,
                            )

                for transition in by_class[BehaviorFactClass.STATE_TRANSITION]:
                    if exact_context(transition) and transition.payload.get("outcome_id") == outcome.id:
                        add_candidate(
                            TestObligationKind.STATE_TRANSITION,
                            base + (transition,),
                            subject=subject,
                            surface=surface,
                            action=action,
                            oracle=oracle,
                            discriminator=transition.id,
                        )

                permissions = [
                    record for record in by_class[BehaviorFactClass.PERMISSION_RELATION]
                    if exact_context(record) and record.payload.get("outcome_id") == outcome.id
                ]
                for permission in permissions:
                    role = next((item for item in roles if item.id == permission.payload.get("role_id")), None)
                    if role is None:
                        add_gap(
                            RegressionObligationGapCode.MISSING_ROLE_EVIDENCE,
                            f"Permission evidence {permission.id} references no exact local role.",
                            fact_class=BehaviorFactClass.ACTOR_ROLE,
                            evidence_ids=(permission.id,),
                            details={"role_id": permission.payload.get("role_id")},
                        )
                        continue
                    if permission.payload.get("authenticated") is not True:
                        add_gap(
                            RegressionObligationGapCode.AUTHENTICATION_UNPROVEN,
                            f"Permission evidence {permission.id} does not prove authentication for its role.",
                            fact_class=BehaviorFactClass.PERMISSION_RELATION,
                            evidence_ids=(role.id, permission.id),
                            details={"role_id": role.id},
                        )
                        continue
                    add_candidate(
                        TestObligationKind.ROLE_PERMISSION,
                        base + (role, permission),
                        subject=subject,
                        surface=surface,
                        action=action,
                        oracle=oracle,
                        discriminator=permission.id,
                    )

                persistence_facts = [
                    record for record in by_class[BehaviorFactClass.PERSISTENCE_RELATION]
                    if exact_context(record) and record.payload.get("outcome_id") == outcome.id
                ]
                valid_persistence = [
                    record for record in persistence_facts
                    if _payload_text(record, "relation") == "read_back"
                    and _payload_text(record, "read_surface") is not None
                    and _payload_text(record, "read_action") is not None
                ]
                if persistence_facts and not valid_persistence:
                    add_gap(
                        RegressionObligationGapCode.MISSING_PERSISTENCE_READ_BACK,
                        f"Persistence evidence for action {action} does not establish an independent read back.",
                        fact_class=BehaviorFactClass.PERSISTENCE_RELATION,
                        evidence_ids=tuple(record.id for record in persistence_facts),
                        details={"subject": subject, "surface": surface, "action": action},
                    )
                for relation in valid_persistence:
                    add_candidate(
                        TestObligationKind.PERSISTENCE_READ_BACK,
                        base + (relation,),
                        subject=subject,
                        surface=surface,
                        action=action,
                        oracle=oracle,
                        discriminator=relation.id,
                    )

                for recovery in by_class[BehaviorFactClass.ERROR_RECOVERY]:
                    if exact_context(recovery) and recovery.payload.get("outcome_id") == outcome.id:
                        add_candidate(
                            TestObligationKind.ERROR_RECOVERY,
                            base + (recovery,),
                            subject=subject,
                            surface=surface,
                            action=action,
                            oracle=oracle,
                            discriminator=recovery.id,
                        )

                dependencies = [
                    record for record in by_class[BehaviorFactClass.DEPENDENCY]
                    if exact_context(record) and record.payload.get("outcome_id") == outcome.id
                ]
                for dependency in dependencies:
                    if dependency.payload.get("supported") is not True:
                        add_gap(
                            RegressionObligationGapCode.UNSUPPORTED_INTERACTION,
                            f"Dependency evidence {dependency.id} describes an unsupported interaction.",
                            fact_class=BehaviorFactClass.DEPENDENCY,
                            evidence_ids=(dependency.id,),
                            details={"dependency_id": dependency.id},
                        )
                        continue
                    add_candidate(
                        TestObligationKind.DEPENDENCY,
                        base + (dependency,),
                        subject=subject,
                        surface=surface,
                        action=action,
                        oracle=oracle,
                        discriminator=dependency.id,
                    )

    index = {record.id: record for record in available}
    for candidate in candidates.values():
        ids_by_class: dict[BehaviorFactClass, set[str]] = {}
        for evidence_id in candidate.evidence_ids:
            record = index[evidence_id]
            ids_by_class.setdefault(EVIDENCE_FACT_CLASS[record.kind], set()).add(evidence_id)
        for fact_class in candidate.rule.fact_classes:
            coverage = local_coverage(
                fact_class,
                candidate.subject,
                candidate.surface,
                candidate.action,
            )
            exact_ids = ids_by_class.get(fact_class, set())
            if coverage.completeness is FactCoverageCompleteness.PARTIAL:
                add_gap(
                    RegressionObligationGapCode.COVERAGE_PARTIAL,
                    f"{fact_class.value} has only PARTIAL coverage for the linked journey.",
                    fact_class=fact_class,
                    evidence_ids=coverage.evidence_ids,
                    details={
                        "subject": candidate.subject,
                        "surface": candidate.surface,
                        "action": candidate.action,
                    },
                )
            elif (
                coverage.completeness is not FactCoverageCompleteness.COMPLETE
                or not exact_ids <= set(coverage.evidence_ids)
            ):
                add_gap(
                    RegressionObligationGapCode.COVERAGE_UNKNOWN,
                    f"{fact_class.value} lacks COMPLETE coverage containing the exact linked facts.",
                    fact_class=fact_class,
                    evidence_ids=coverage.evidence_ids,
                    details={
                        "subject": candidate.subject,
                        "surface": candidate.surface,
                        "action": candidate.action,
                    },
                )

    obligations: list[TestObligation] = []
    bundles: list[VerificationBundle] = []
    sorted_candidates = sorted(
        candidates.items(),
        key=lambda item: (
            list(TestObligationKind).index(item[1].rule.kind),
            _utf8_key(item[1].subject, path="subject"),
            _utf8_key(item[1].expected_behavior, path="expected behavior"),
            _utf8_key(_obligation_id(item[0]), path="obligation id"),
        ),
    )
    for identity, candidate in sorted_candidates:
        if (
            len(obligations) >= actual_budget.max_obligations
            or len(bundles) >= actual_budget.max_bundles
            or steps >= actual_budget.max_steps
        ):
            exhausted = True
            break
        steps += 1
        item = TestObligation(
            obligation_id=_obligation_id(identity),
            kind=candidate.rule.kind,
            subject=candidate.subject,
            expected_behavior=candidate.expected_behavior,
            rationale=candidate.rule.rationale,
            fact_classes=candidate.rule.fact_classes,
            evidence_ids=tuple(candidate.evidence_ids),
            test_level=candidate.rule.test_level,
            metadata={
                "derivation_rule": candidate.rule.kind.value,
                "surface": candidate.surface,
                "action": candidate.action,
                "discriminator": candidate.discriminator,
            },
        )
        bundle = verify_test_obligation_grounding_bundle(item, inventory)
        obligations.append(item)
        bundles.append(bundle)

    if exhausted:
        add_gap(
            RegressionObligationGapCode.BUDGET_EXHAUSTED,
            "Regression obligation derivation stopped at a declared budget.",
            details={"budget": actual_budget.to_dict()},
        )

    termination = (
        RegressionObligationTermination.BUDGET_EXHAUSTED
        if exhausted else RegressionObligationTermination.COMPLETE
    )
    normalized_obligations = tuple(obligations)
    normalized_bundles = tuple(bundles)
    normalized_gaps = tuple(sorted(gaps, key=_gap_sort_key))
    plan_readiness = _readiness(
        obligations=normalized_obligations,
        bundles=normalized_bundles,
        gaps=normalized_gaps,
        termination=termination,
    )
    consumption = RegressionObligationConsumption(
        evidence_records=evidence_records,
        candidate_obligations=candidate_count,
        obligations=len(normalized_obligations),
        bundles=len(normalized_bundles),
        steps=steps,
        deduplicated_obligations=deduplicated,
    )
    return RegressionObligationPlan(
        obligations=normalized_obligations,
        bundles=normalized_bundles,
        coverage=inventory.coverage,
        gaps=normalized_gaps,
        budget=actual_budget,
        consumption=consumption,
        termination=termination,
        readiness=plan_readiness,
        inventory_fingerprint=inventory.fingerprint,
    )


__all__ = [
    "REGRESSION_TEST_OBLIGATION_SCHEMA_VERSION",
    "REGRESSION_TEST_OBLIGATION_VERIFIER", "TEST_OBLIGATION_GROUNDED",
    "BEHAVIOR_EVIDENCE_INVENTORY_SCHEMA_VERSION", "BEHAVIOR_EVIDENCE_INVENTORY_KIND",
    "BEHAVIOR_EVIDENCE_INVENTORY_FINGERPRINT_FORMAT", "TEST_OBLIGATION_KIND",
    "TEST_OBLIGATION_FINGERPRINT_FORMAT", "REGRESSION_OBLIGATION_PLAN_SCHEMA_VERSION",
    "REGRESSION_OBLIGATION_PLAN_KIND", "REGRESSION_OBLIGATION_PLAN_FINGERPRINT_FORMAT",
    "BEHAVIOR_EVIDENCE_KINDS", "BEHAVIOR_EVIDENCE_KIND_SET",
    "BehaviorEvidenceKind", "BehaviorFactClass", "FactCoverageCompleteness",
    "TestObligationKind", "TestLevel",
    "RegressionObligationGapCode", "RegressionObligationReadiness",
    "RegressionObligationTermination", "EVIDENCE_FACT_CLASS",
    "EVIDENCE_KIND_BY_FACT_CLASS", "RegressionObligationError", "FactClassCoverage",
    "BehaviorEvidenceInventory", "EvidenceInventory", "RegressionEvidenceInventory",
    "FactCoverage", "CoverageCompleteness", "ObligationRule", "OBLIGATION_RULES",
    "TestObligation", "verify_test_obligation_grounding",
    "verify_test_obligation_grounding_bundle", "verify_test_obligation",
    "verify_test_obligation_bundle", "RegressionObligationBudget",
    "DEFAULT_REGRESSION_OBLIGATION_BUDGET", "RegressionObligationConsumption",
    "RegressionObligationGap", "RegressionObligationPlan",
    "derive_regression_test_obligations",
]
