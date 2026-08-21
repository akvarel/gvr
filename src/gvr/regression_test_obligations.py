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
    BEHAVIOR_CONTRACT = "gvr.test.behavior_contract"
    BEHAVIOR_CHANGE = "gvr.test.behavior_change"
    INPUT_PARTITION = "gvr.test.input_partition"
    OUTPUT_OBSERVATION = "gvr.test.output_observation"
    BRANCH_CONDITION = "gvr.test.branch_condition"
    EXCEPTION_BEHAVIOR = "gvr.test.exception_behavior"
    STATE_TRANSITION = "gvr.test.state_transition"
    SIDE_EFFECT = "gvr.test.side_effect"
    COLLABORATOR_INTERACTION = "gvr.test.collaborator_interaction"
    DATA_FLOW = "gvr.test.data_flow"
    CONCURRENCY_BEHAVIOR = "gvr.test.concurrency_behavior"
    EXISTING_TEST = "gvr.test.existing_test"
    COVERAGE_OBSERVATION = "gvr.test.coverage_observation"


# This is a closed schema-v1 vocabulary. New source evidence kinds require a
# schema/version change rather than silently entering an authoritative verifier.
BEHAVIOR_EVIDENCE_KINDS = tuple(item.value for item in BehaviorEvidenceKind)
BEHAVIOR_EVIDENCE_KIND_SET = frozenset(BEHAVIOR_EVIDENCE_KINDS)


class BehaviorFactClass(str, Enum):
    CONTRACT = "CONTRACT"
    CHANGE = "CHANGE"
    INPUT = "INPUT"
    OUTPUT = "OUTPUT"
    BRANCH = "BRANCH"
    EXCEPTION = "EXCEPTION"
    STATE = "STATE"
    SIDE_EFFECT = "SIDE_EFFECT"
    INTERACTION = "INTERACTION"
    DATA_FLOW = "DATA_FLOW"
    CONCURRENCY = "CONCURRENCY"
    EXISTING_TEST = "EXISTING_TEST"
    COVERAGE = "COVERAGE"


class FactCoverageCompleteness(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


class TestObligationKind(str, Enum):
    CHARACTERIZATION = "CHARACTERIZATION"
    REGRESSION = "REGRESSION"
    BOUNDARY = "BOUNDARY"
    OUTPUT = "OUTPUT"
    BRANCH = "BRANCH"
    EXCEPTION = "EXCEPTION"
    STATE_TRANSITION = "STATE_TRANSITION"
    SIDE_EFFECT = "SIDE_EFFECT"
    INTERACTION = "INTERACTION"

    # Stable source-level aliases. Aliases do not expand the schema-v1 rule set.
    HAPPY_PATH = "CHARACTERIZATION"
    NEGATIVE = "BOUNDARY"
    ERROR_PATH = "EXCEPTION"
    INTEGRATION = "INTERACTION"


class TestLevel(str, Enum):
    UNIT = "UNIT"
    INTEGRATION = "INTEGRATION"
    SYSTEM = "SYSTEM"


class RegressionObligationGapCode(str, Enum):
    PARTIAL_FACT_COVERAGE = "PARTIAL_FACT_COVERAGE"
    UNKNOWN_FACT_COVERAGE = "UNKNOWN_FACT_COVERAGE"
    MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
    NO_DERIVATION_RULE = "NO_DERIVATION_RULE"
    UNGROUNDED_OBLIGATION = "UNGROUNDED_OBLIGATION"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    CONFLICTING_FACTS = "CONFLICTING_FACTS"


class RegressionObligationReadiness(str, Enum):
    READY = "READY"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


class RegressionObligationTermination(str, Enum):
    COMPLETE = "COMPLETE"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


EVIDENCE_FACT_CLASS: Mapping[str, BehaviorFactClass] = MappingProxyType({
    "gvr.test.behavior_contract": BehaviorFactClass.CONTRACT,
    "gvr.test.behavior_change": BehaviorFactClass.CHANGE,
    "gvr.test.input_partition": BehaviorFactClass.INPUT,
    "gvr.test.output_observation": BehaviorFactClass.OUTPUT,
    "gvr.test.branch_condition": BehaviorFactClass.BRANCH,
    "gvr.test.exception_behavior": BehaviorFactClass.EXCEPTION,
    "gvr.test.state_transition": BehaviorFactClass.STATE,
    "gvr.test.side_effect": BehaviorFactClass.SIDE_EFFECT,
    "gvr.test.collaborator_interaction": BehaviorFactClass.INTERACTION,
    "gvr.test.data_flow": BehaviorFactClass.DATA_FLOW,
    "gvr.test.concurrency_behavior": BehaviorFactClass.CONCURRENCY,
    "gvr.test.existing_test": BehaviorFactClass.EXISTING_TEST,
    "gvr.test.coverage_observation": BehaviorFactClass.COVERAGE,
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
        if self.completeness is not FactCoverageCompleteness.UNKNOWN and not self.evidence_ids:
            raise RegressionObligationError(
                "complete or partial coverage must cite evidence_ids"
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

        coverage_by_class: dict[BehaviorFactClass, FactClassCoverage] = {}
        for supplied in self.coverage:
            if not isinstance(supplied, FactClassCoverage):
                raise RegressionObligationError(
                    "inventory coverage must contain FactClassCoverage records"
                )
            current = coverage_by_class.get(supplied.fact_class)
            if current is None:
                coverage_by_class[supplied.fact_class] = supplied
                continue
            if current.completeness is not supplied.completeness or current.scope != supplied.scope:
                raise RegressionObligationError(
                    f"conflicting coverage records for fact class {supplied.fact_class.value}"
                )
            coverage_by_class[supplied.fact_class] = FactClassCoverage(
                fact_class=supplied.fact_class,
                completeness=supplied.completeness,
                evidence_ids=current.evidence_ids + supplied.evidence_ids,
                scope=supplied.scope,
            )

        evidence_index = {record.id: record for record in normalized_evidence}
        for item in coverage_by_class.values():
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

        normalized_coverage = tuple(
            coverage_by_class[fact_class]
            for fact_class in BehaviorFactClass
            if fact_class in coverage_by_class
        )
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
        for item in self.coverage:
            if item.fact_class is normalized:
                return item
        return FactClassCoverage(
            fact_class=normalized,
            completeness=FactCoverageCompleteness.UNKNOWN,
            evidence_ids=(),
            scope={},
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
    TestObligationKind.CHARACTERIZATION: ObligationRule(
        kind=TestObligationKind.CHARACTERIZATION,
        fact_classes=(BehaviorFactClass.CONTRACT,),
        test_level=TestLevel.UNIT,
        rationale="Capture the observable contract before later changes can erase it.",
    ),
    TestObligationKind.REGRESSION: ObligationRule(
        kind=TestObligationKind.REGRESSION,
        fact_classes=(BehaviorFactClass.CHANGE,),
        test_level=TestLevel.UNIT,
        rationale="Lock the changed behavior to prevent recurrence of the prior semantics.",
    ),
    TestObligationKind.BOUNDARY: ObligationRule(
        kind=TestObligationKind.BOUNDARY,
        fact_classes=(BehaviorFactClass.INPUT,),
        test_level=TestLevel.UNIT,
        rationale="Exercise the identified input partition or boundary.",
    ),
    TestObligationKind.OUTPUT: ObligationRule(
        kind=TestObligationKind.OUTPUT,
        fact_classes=(BehaviorFactClass.OUTPUT,),
        test_level=TestLevel.UNIT,
        rationale="Assert the externally observable output.",
    ),
    TestObligationKind.BRANCH: ObligationRule(
        kind=TestObligationKind.BRANCH,
        fact_classes=(BehaviorFactClass.BRANCH,),
        test_level=TestLevel.UNIT,
        rationale="Exercise the identified decision outcome.",
    ),
    TestObligationKind.EXCEPTION: ObligationRule(
        kind=TestObligationKind.EXCEPTION,
        fact_classes=(BehaviorFactClass.EXCEPTION,),
        test_level=TestLevel.UNIT,
        rationale="Assert the identified error or exception behavior.",
    ),
    TestObligationKind.STATE_TRANSITION: ObligationRule(
        kind=TestObligationKind.STATE_TRANSITION,
        fact_classes=(BehaviorFactClass.STATE,),
        test_level=TestLevel.UNIT,
        rationale="Assert both the pre-state and resulting state transition.",
    ),
    TestObligationKind.SIDE_EFFECT: ObligationRule(
        kind=TestObligationKind.SIDE_EFFECT,
        fact_classes=(BehaviorFactClass.SIDE_EFFECT,),
        test_level=TestLevel.INTEGRATION,
        rationale="Observe the identified side effect at its boundary.",
    ),
    TestObligationKind.INTERACTION: ObligationRule(
        kind=TestObligationKind.INTERACTION,
        fact_classes=(
            BehaviorFactClass.INTERACTION,
            BehaviorFactClass.DATA_FLOW,
            BehaviorFactClass.CONCURRENCY,
        ),
        test_level=TestLevel.INTEGRATION,
        rationale="Exercise the identified collaborator, flow, or concurrency interaction.",
    ),
})
_RULE_BY_FACT_CLASS: Mapping[BehaviorFactClass, ObligationRule] = MappingProxyType({
    fact_class: rule
    for rule in OBLIGATION_RULES.values()
    for fact_class in rule.fact_classes
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
        if not set(self.fact_classes) <= set(rule.fact_classes):
            raise RegressionObligationError(
                f"obligation kind {self.kind.value} does not accept fact_classes "
                + ", ".join(item.value for item in self.fact_classes)
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


def verify_test_obligation_grounding(
    obligation: TestObligation,
    inventory: BehaviorEvidenceInventory,
) -> VerificationReport:
    """Verify that one obligation is derived only from compatible current facts."""

    if not isinstance(obligation, TestObligation):
        raise RegressionObligationError("obligation must be a TestObligation")
    if not isinstance(inventory, BehaviorEvidenceInventory):
        raise RegressionObligationError("inventory must be a BehaviorEvidenceInventory")

    index = {record.id: record for record in inventory.evidence}
    issues: list[VerificationIssue] = []
    dependency_ids: set[str] = set()
    compatible_classes: set[BehaviorFactClass] = set()

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
        fact_class = EVIDENCE_FACT_CLASS[record.kind]
        if fact_class not in obligation.fact_classes:
            issues.append(VerificationIssue(
                code="OBLIGATION_EVIDENCE_INCOMPATIBLE",
                message=(
                    f"Evidence {evidence_id} is {fact_class.value}, not one of the "
                    "obligation's declared fact classes."
                ),
                verdict=VerificationVerdict.UNKNOWN,
                evidence_ids=(evidence_id,),
            ))
            continue
        compatible_classes.add(fact_class)
        subject = record.payload.get("subject")
        if subject != obligation.subject:
            issues.append(VerificationIssue(
                code="OBLIGATION_SUBJECT_MISMATCH",
                message=f"Evidence {evidence_id} concerns a different subject.",
                verdict=VerificationVerdict.UNKNOWN,
                evidence_ids=(evidence_id,),
            ))
        behavior = record.payload.get("behavior")
        if behavior != obligation.expected_behavior:
            issues.append(VerificationIssue(
                code="OBLIGATION_BEHAVIOR_MISMATCH",
                message=f"Evidence {evidence_id} does not state the required behavior.",
                verdict=VerificationVerdict.UNKNOWN,
                evidence_ids=(evidence_id,),
            ))

    for fact_class in obligation.fact_classes:
        if fact_class not in compatible_classes:
            continue
        fact_coverage = inventory.coverage_for(fact_class)
        dependency_ids.update(fact_coverage.evidence_ids)
        if fact_coverage.completeness is not FactCoverageCompleteness.COMPLETE:
            issues.append(VerificationIssue(
                code="OBLIGATION_COVERAGE_INCOMPLETE",
                message=(
                    f"{fact_class.value} coverage is {fact_coverage.completeness.value}; "
                    "grounding PASS requires COMPLETE coverage."
                ),
                verdict=VerificationVerdict.UNKNOWN,
                evidence_ids=fact_coverage.evidence_ids,
            ))

    if not compatible_classes and not issues:
        issues.append(VerificationIssue(
            code="OBLIGATION_EVIDENCE_MISSING",
            message="No compatible behavior evidence grounds this obligation.",
            verdict=VerificationVerdict.UNKNOWN,
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
        if coverage != tuple(
            item for fact_class in BehaviorFactClass
            for item in coverage if item.fact_class is fact_class
        ):
            raise RegressionObligationError("plan coverage is not in canonical fact-class order")
        if len({item.fact_class for item in coverage}) != len(coverage):
            raise RegressionObligationError("plan coverage contains duplicate fact classes")
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
    expected_behavior: str
    evidence_ids: set[str]
    fact_classes: set[BehaviorFactClass]


def _obligation_identity(
    rule: ObligationRule,
    subject: str,
    expected_behavior: str,
) -> tuple[str, str, str, str]:
    return (rule.kind.value, subject, expected_behavior, rule.test_level.value)


def _obligation_id(identity: tuple[str, str, str, str]) -> str:
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
    if (
        RegressionObligationGapCode.UNKNOWN_FACT_COVERAGE in gap_codes
        and gap_codes <= {
            RegressionObligationGapCode.UNKNOWN_FACT_COVERAGE,
            RegressionObligationGapCode.UNGROUNDED_OBLIGATION,
        }
    ):
        return RegressionObligationReadiness.UNKNOWN
    blocking = {
        RegressionObligationGapCode.PARTIAL_FACT_COVERAGE,
        RegressionObligationGapCode.MISSING_REQUIRED_FIELD,
        RegressionObligationGapCode.NO_DERIVATION_RULE,
        RegressionObligationGapCode.UNGROUNDED_OBLIGATION,
        RegressionObligationGapCode.BUDGET_EXHAUSTED,
        RegressionObligationGapCode.CONFLICTING_FACTS,
    }
    if any(gap.code in blocking for gap in gaps):
        return RegressionObligationReadiness.BLOCKED
    if RegressionObligationGapCode.UNKNOWN_FACT_COVERAGE in gap_codes:
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
    """Deterministically derive a bounded, evidence-grounded test obligation plan.

    This pure operation does not discover evidence, invoke providers, call a model,
    execute code, generate tests, browse, or authorize merge/deploy actions.
    """

    if not isinstance(inventory, BehaviorEvidenceInventory):
        raise RegressionObligationError("inventory must be a BehaviorEvidenceInventory")
    actual_budget = DEFAULT_REGRESSION_OBLIGATION_BUDGET if budget is None else budget
    if not isinstance(actual_budget, RegressionObligationBudget):
        raise RegressionObligationError("budget must be a RegressionObligationBudget")

    evidence_records = 0
    candidate_count = 0
    steps = 0
    deduplicated = 0
    exhausted = False
    gaps: list[RegressionObligationGap] = []
    candidates: dict[tuple[str, str, str, str], _Candidate] = {}
    conflicting_fact_keys: set[tuple[BehaviorFactClass, str, str]] = set()
    fact_values: dict[tuple[BehaviorFactClass, str, str], str] = {}

    coverage_by_class = {item.fact_class: item for item in inventory.coverage}
    evidenced_classes = {EVIDENCE_FACT_CLASS[item.kind] for item in inventory.evidence}
    for fact_class in BehaviorFactClass:
        if fact_class not in evidenced_classes:
            continue
        supplied = coverage_by_class.get(fact_class)
        completeness = (
            FactCoverageCompleteness.UNKNOWN
            if supplied is None else supplied.completeness
        )
        if completeness is FactCoverageCompleteness.PARTIAL:
            gaps.append(RegressionObligationGap(
                code=RegressionObligationGapCode.PARTIAL_FACT_COVERAGE,
                message=f"{fact_class.value} facts have only PARTIAL coverage.",
                fact_class=fact_class,
                evidence_ids=() if supplied is None else supplied.evidence_ids,
            ))
        elif completeness is FactCoverageCompleteness.UNKNOWN:
            gaps.append(RegressionObligationGap(
                code=RegressionObligationGapCode.UNKNOWN_FACT_COVERAGE,
                message=f"{fact_class.value} fact coverage is UNKNOWN.",
                fact_class=fact_class,
            ))

    for record in inventory.evidence:
        if evidence_records >= actual_budget.max_evidence_records or steps >= actual_budget.max_steps:
            exhausted = True
            break
        evidence_records += 1
        steps += 1
        fact_class = EVIDENCE_FACT_CLASS[record.kind]
        rule = _RULE_BY_FACT_CLASS.get(fact_class)
        if rule is None:
            # Existing-test and coverage observations are supporting inventory;
            # they do not independently manufacture obligations.
            continue
        subject_value = record.payload.get("subject")
        behavior_value = record.payload.get("behavior")
        if not isinstance(subject_value, str) or not subject_value.strip():
            gaps.append(RegressionObligationGap(
                code=RegressionObligationGapCode.MISSING_REQUIRED_FIELD,
                message=f"Evidence {record.id} lacks a non-empty subject.",
                fact_class=fact_class,
                evidence_ids=(record.id,),
                details={"field": "subject"},
            ))
            continue
        if not isinstance(behavior_value, str) or not behavior_value.strip():
            gaps.append(RegressionObligationGap(
                code=RegressionObligationGapCode.MISSING_REQUIRED_FIELD,
                message=f"Evidence {record.id} lacks a non-empty behavior.",
                fact_class=fact_class,
                evidence_ids=(record.id,),
                details={"field": "behavior"},
            ))
            continue
        subject = subject_value.strip()
        expected_behavior = behavior_value.strip()

        fact_key_value = record.payload.get("fact_key", record.id)
        if not isinstance(fact_key_value, str) or not fact_key_value.strip():
            gaps.append(RegressionObligationGap(
                code=RegressionObligationGapCode.MISSING_REQUIRED_FIELD,
                message=f"Evidence {record.id} has an invalid fact_key.",
                fact_class=fact_class,
                evidence_ids=(record.id,),
                details={"field": "fact_key"},
            ))
            continue
        fact_identity = (fact_class, subject, fact_key_value.strip())
        previous_behavior = fact_values.get(fact_identity)
        if previous_behavior is not None and previous_behavior != expected_behavior:
            conflicting_fact_keys.add(fact_identity)
        else:
            fact_values[fact_identity] = expected_behavior

        identity = _obligation_identity(rule, subject, expected_behavior)
        candidate_count += 1
        existing = candidates.get(identity)
        if existing is None:
            candidates[identity] = _Candidate(
                rule=rule,
                subject=subject,
                expected_behavior=expected_behavior,
                evidence_ids={record.id},
                fact_classes={fact_class},
            )
        else:
            existing.evidence_ids.add(record.id)
            existing.fact_classes.add(fact_class)
            deduplicated += 1

    if conflicting_fact_keys:
        for fact_class, subject, fact_key in sorted(
            conflicting_fact_keys,
            key=lambda item: (
                list(BehaviorFactClass).index(item[0]),
                _utf8_key(item[1], path="subject"),
                _utf8_key(item[2], path="fact_key"),
            ),
        ):
            affected = tuple(
                record.id for record in inventory.evidence
                if EVIDENCE_FACT_CLASS[record.kind] is fact_class
                and record.payload.get("subject") == subject
                and record.payload.get("fact_key", record.id) == fact_key
            )
            gaps.append(RegressionObligationGap(
                code=RegressionObligationGapCode.CONFLICTING_FACTS,
                message=f"Conflicting {fact_class.value} facts share fact_key {fact_key}.",
                fact_class=fact_class,
                evidence_ids=affected,
                details={"subject": subject, "fact_key": fact_key},
            ))

    obligations: list[TestObligation] = []
    bundles: list[VerificationBundle] = []
    sorted_candidates = sorted(
        candidates.items(),
        key=lambda item: (
            list(TestObligationKind).index(item[1].rule.kind),
            _utf8_key(item[1].subject, path="subject"),
            _utf8_key(item[1].expected_behavior, path="expected_behavior"),
            tuple(_utf8_key(value, path="evidence id") for value in sorted(item[1].evidence_ids)),
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
            fact_classes=tuple(
                fact_class for fact_class in BehaviorFactClass
                if fact_class in candidate.fact_classes
            ),
            evidence_ids=tuple(candidate.evidence_ids),
            test_level=candidate.rule.test_level,
            metadata={"derivation_rule": candidate.rule.kind.value},
        )
        bundle = verify_test_obligation_grounding_bundle(item, inventory)
        obligations.append(item)
        bundles.append(bundle)
        if bundle.report.verdict is not VerificationVerdict.PASS:
            gaps.append(RegressionObligationGap(
                code=RegressionObligationGapCode.UNGROUNDED_OBLIGATION,
                message=f"Obligation {item.obligation_id} is not fully grounded.",
                evidence_ids=bundle.report.evidence_ids,
                details={"obligation_id": item.obligation_id},
            ))

    if exhausted:
        gaps.append(RegressionObligationGap(
            code=RegressionObligationGapCode.BUDGET_EXHAUSTED,
            message="Regression obligation derivation stopped at a declared budget.",
            details={"budget": actual_budget.to_dict()},
        ))

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
