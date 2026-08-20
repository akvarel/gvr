from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class VerificationVerdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class Freshness(str, Enum):
    FRESH = "FRESH"
    STALE = "STALE"


class EvidenceState(str, Enum):
    ACTIVE = "ACTIVE"
    REMOVED = "REMOVED"


class _MissingValue:
    __slots__ = ()
    def __repr__(self) -> str:
        return "MISSING"


class _IndeterminateValue:
    __slots__ = ()
    def __repr__(self) -> str:
        return "INDETERMINATE"


MISSING = _MissingValue()
INDETERMINATE = _IndeterminateValue()


@dataclass(frozen=True)
class Evidence:
    id: str
    kind: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    source: str | None = None
    fingerprint: str | None = None


@dataclass(frozen=True)
class VerificationIssue:
    code: str
    message: str
    verdict: VerificationVerdict
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class VerificationReport:
    verdict: VerificationVerdict
    verifier: str
    issues: tuple[VerificationIssue, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)


_VERDICT_ORDER = {
    VerificationVerdict.PASS: 0,
    VerificationVerdict.UNKNOWN: 1,
    VerificationVerdict.FAIL: 2,
}


def combine_verdicts(*verdicts: VerificationVerdict) -> VerificationVerdict:
    """Conservative aggregation: FAIL > UNKNOWN > PASS."""
    if not verdicts:
        return VerificationVerdict.UNKNOWN
    return max(verdicts, key=_VERDICT_ORDER.__getitem__)
