from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
from typing import Any, Mapping

from ..model import VerificationVerdict


class Coverage(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


class DeltaKind(str, Enum):
    PRESERVED = "PRESERVED"
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    CHANGED = "CHANGED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class RevisionRef:
    repository: str
    revision: str


@dataclass(frozen=True)
class Observable:
    kind: str
    key: str
    value: Any
    evidence_ids: tuple[str, ...] = ()
    receiver_confidence: str = "PROVEN"
    analysis_completeness: str = "COMPLETE_FOR_SUPPORTED_CONSTRUCT"

    @property
    def exact(self) -> bool:
        return (
            self.receiver_confidence == "PROVEN"
            and self.analysis_completeness == "COMPLETE_FOR_SUPPORTED_CONSTRUCT"
        )

    @property
    def semantic_fingerprint(self) -> str:
        canonical = json.dumps(
            {"kind": self.kind, "key": self.key, "value": self.value},
            sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=repr,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class FunctionalSnapshot:
    revision: RevisionRef
    observables: tuple[Observable, ...]
    coverage_by_kind: Mapping[str, Coverage] = field(default_factory=dict)

    def coverage(self, kind: str) -> Coverage:
        return self.coverage_by_kind.get(kind, Coverage.UNKNOWN)


@dataclass(frozen=True)
class FunctionalDeltaItem:
    kind: str
    key: str
    delta: DeltaKind
    verdict: VerificationVerdict
    baseline: Observable | None
    candidate: Observable | None
    evidence_ids: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class FunctionalDeltaResult:
    baseline: RevisionRef
    candidate: RevisionRef
    items: tuple[FunctionalDeltaItem, ...]

    @property
    def has_proven_regression(self) -> bool:
        return any(
            item.delta in (DeltaKind.REMOVED, DeltaKind.CHANGED)
            and item.verdict is VerificationVerdict.PASS
            for item in self.items
        )


def _index(snapshot: FunctionalSnapshot) -> dict[tuple[str, str], Observable]:
    out: dict[tuple[str, str], Observable] = {}
    for obs in snapshot.observables:
        identity = (obs.kind, obs.key)
        if identity in out:
            raise ValueError(f"duplicate observable identity: {identity}")
        out[identity] = obs
    return out


def _evidence(*observables: Observable | None) -> tuple[str, ...]:
    ids: list[str] = []
    for obs in observables:
        if obs is not None:
            ids.extend(obs.evidence_ids)
    return tuple(dict.fromkeys(sorted(ids)))


def compare_functionality(
    baseline: FunctionalSnapshot,
    candidate: FunctionalSnapshot,
) -> FunctionalDeltaResult:
    """Compare observable behavior conservatively.

    Presence is direct evidence; absence is only evidence when the relevant
    snapshot has COMPLETE coverage for that observable kind. This prevents an
    unsupported/partial analyzer from fabricating REMOVED or ADDED behavior.
    """
    b = _index(baseline)
    c = _index(candidate)
    identities = sorted(set(b) | set(c))
    items: list[FunctionalDeltaItem] = []

    for kind, key in identities:
        before = b.get((kind, key))
        after = c.get((kind, key))

        if before is not None and after is not None:
            exact = before.exact and after.exact
            if before.semantic_fingerprint == after.semantic_fingerprint:
                items.append(FunctionalDeltaItem(
                    kind, key, DeltaKind.PRESERVED,
                    VerificationVerdict.PASS if exact else VerificationVerdict.UNKNOWN,
                    before, after, _evidence(before, after),
                    "semantic observable is equal in both revisions" if exact
                    else "observable is equal but at least one side is MAY/PARTIAL",
                ))
            else:
                items.append(FunctionalDeltaItem(
                    kind, key, DeltaKind.CHANGED if exact else DeltaKind.UNKNOWN,
                    VerificationVerdict.PASS if exact else VerificationVerdict.UNKNOWN,
                    before, after, _evidence(before, after),
                    "semantic observable differs between exact revisions" if exact
                    else "observable differs but at least one side is MAY/PARTIAL",
                ))
            continue

        if before is not None:
            can_prove_absence = candidate.coverage(kind) is Coverage.COMPLETE
            exact = before.exact and can_prove_absence
            items.append(FunctionalDeltaItem(
                kind, key, DeltaKind.REMOVED if exact else DeltaKind.UNKNOWN,
                VerificationVerdict.PASS if exact else VerificationVerdict.UNKNOWN,
                before, None, _evidence(before),
                "candidate complete coverage proves baseline observable is absent" if exact
                else "candidate absence is not proof because coverage/evidence is incomplete",
            ))
            continue

        assert after is not None
        can_prove_baseline_absence = baseline.coverage(kind) is Coverage.COMPLETE
        exact = after.exact and can_prove_baseline_absence
        items.append(FunctionalDeltaItem(
            kind, key, DeltaKind.ADDED if exact else DeltaKind.UNKNOWN,
            VerificationVerdict.PASS if exact else VerificationVerdict.UNKNOWN,
            None, after, _evidence(after),
            "baseline complete coverage proves candidate observable is new" if exact
            else "candidate presence is known but novelty is not proven from incomplete baseline coverage",
        ))

    return FunctionalDeltaResult(baseline.revision, candidate.revision, tuple(items))
