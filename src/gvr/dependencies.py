from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from typing import Any, Iterable, Mapping

from .model import EvidenceState, Freshness, VerificationVerdict


def stable_fingerprint(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=repr)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class EvidenceRecord:
    id: str
    payload: Mapping[str, Any]
    fingerprint: str
    version: int
    state: EvidenceState = EvidenceState.ACTIVE


@dataclass
class ClaimRecord:
    id: str
    verdict: VerificationVerdict
    freshness: Freshness = Freshness.FRESH
    version: int = 0
    dependency_versions: dict[str, int] = field(default_factory=dict)


class DependencyCycleError(ValueError):
    pass


class UnknownDependencyError(KeyError):
    pass


class ClaimDependencyGraph:
    """Deterministic claim/evidence dependency graph with stale propagation.

    Edges point claim -> dependency, where a dependency is either evidence or
    another claim. Evidence changes invalidate all transitive dependent claims.
    Claim dependency cycles are rejected because circular support cannot prove a
    claim.
    """

    def __init__(self) -> None:
        self._evidence: dict[str, EvidenceRecord] = {}
        self._claims: dict[str, ClaimRecord] = {}
        self._deps: dict[str, set[str]] = {}
        self._reverse: dict[str, set[str]] = {}
        self._clock = 0

    @property
    def evidence(self) -> Mapping[str, EvidenceRecord]:
        return dict(self._evidence)

    @property
    def claims(self) -> Mapping[str, ClaimRecord]:
        return {
            k: ClaimRecord(v.id, v.verdict, v.freshness, v.version, dict(v.dependency_versions))
            for k, v in self._claims.items()
        }

    def put_evidence(self, evidence_id: str, payload: Mapping[str, Any]) -> EvidenceRecord:
        fp = stable_fingerprint(payload)
        current = self._evidence.get(evidence_id)
        if current and current.state is EvidenceState.ACTIVE and current.fingerprint == fp:
            return current
        self._clock += 1
        rec = EvidenceRecord(evidence_id, dict(payload), fp, self._clock, EvidenceState.ACTIVE)
        self._evidence[evidence_id] = rec
        if current is not None:
            self._invalidate_dependents(evidence_id)
        return rec

    def remove_evidence(self, evidence_id: str) -> EvidenceRecord:
        current = self._evidence.get(evidence_id)
        self._clock += 1
        rec = EvidenceRecord(
            evidence_id,
            {} if current is None else current.payload,
            "" if current is None else current.fingerprint,
            self._clock,
            EvidenceState.REMOVED,
        )
        self._evidence[evidence_id] = rec
        self._invalidate_dependents(evidence_id)
        return rec

    def put_claim(self, claim_id: str, verdict: VerificationVerdict) -> ClaimRecord:
        rec = self._claims.get(claim_id)
        if rec is None:
            rec = ClaimRecord(claim_id, verdict)
            self._claims[claim_id] = rec
            self._deps.setdefault(claim_id, set())
        else:
            if rec.verdict != verdict:
                rec.verdict = verdict
                self._invalidate_dependents(claim_id)
        return rec

    def add_dependency(self, claim_id: str, dependency_id: str) -> None:
        if claim_id not in self._claims:
            raise UnknownDependencyError(f"unknown claim: {claim_id}")
        if dependency_id not in self._claims and dependency_id not in self._evidence:
            raise UnknownDependencyError(f"unknown dependency: {dependency_id}")
        if dependency_id == claim_id or (dependency_id in self._claims and self._reachable(dependency_id, claim_id)):
            raise DependencyCycleError(f"claim dependency cycle: {claim_id} -> {dependency_id}")
        self._deps.setdefault(claim_id, set()).add(dependency_id)
        self._reverse.setdefault(dependency_id, set()).add(claim_id)
        self._claims[claim_id].freshness = Freshness.STALE

    def set_dependencies(self, claim_id: str, dependency_ids: Iterable[str]) -> None:
        """Atomically replace a claim's support set and mark it stale.

        Replacement is required for re-verification because support may disappear
        as well as appear. A removed dependency must not remain silently attached
        to the claim forever.
        """
        if claim_id not in self._claims:
            raise UnknownDependencyError(f"unknown claim: {claim_id}")
        requested = tuple(sorted(set(dependency_ids)))
        for dep in requested:
            if dep not in self._claims and dep not in self._evidence:
                raise UnknownDependencyError(f"unknown dependency: {dep}")

        old = set(self._deps.get(claim_id, set()))
        for dep in old:
            self._reverse.get(dep, set()).discard(claim_id)
        self._deps[claim_id] = set()
        try:
            for dep in requested:
                if dep == claim_id or (dep in self._claims and self._reachable(dep, claim_id)):
                    raise DependencyCycleError(f"claim dependency cycle: {claim_id} -> {dep}")
                self._deps[claim_id].add(dep)
                self._reverse.setdefault(dep, set()).add(claim_id)
        except Exception:
            for dep in self._deps.get(claim_id, set()):
                self._reverse.get(dep, set()).discard(claim_id)
            self._deps[claim_id] = old
            for dep in old:
                self._reverse.setdefault(dep, set()).add(claim_id)
            raise

        if old != set(requested):
            self._claims[claim_id].freshness = Freshness.STALE
            self._invalidate_dependents(claim_id)

    def dependencies_of(self, claim_id: str) -> tuple[str, ...]:
        return tuple(sorted(self._deps.get(claim_id, ())))

    def dependents_of(self, node_id: str) -> tuple[str, ...]:
        return tuple(sorted(self._reverse.get(node_id, ())))

    def mark_reverified(self, claim_id: str, verdict: VerificationVerdict) -> ClaimRecord:
        claim = self._claims[claim_id]
        versions: dict[str, int] = {}
        for dep in sorted(self._deps.get(claim_id, ())):
            if dep in self._evidence:
                ev = self._evidence[dep]
                if ev.state is not EvidenceState.ACTIVE:
                    raise ValueError(f"cannot freshen {claim_id}: evidence {dep} is removed")
                versions[dep] = ev.version
            else:
                dep_claim = self._claims[dep]
                if dep_claim.freshness is not Freshness.FRESH or not self.is_fresh(dep):
                    raise ValueError(f"cannot freshen {claim_id}: dependent claim {dep} is stale")
                versions[dep] = dep_claim.version

        changed_basis = (claim.verdict != verdict or claim.dependency_versions != versions or claim.version == 0)
        if changed_basis:
            self._clock += 1
            claim.version = self._clock
            self._invalidate_dependents(claim_id)
        claim.verdict = verdict
        claim.dependency_versions = versions
        claim.freshness = Freshness.FRESH
        return claim

    def is_fresh(self, claim_id: str) -> bool:
        claim = self._claims[claim_id]
        if claim.freshness is not Freshness.FRESH:
            return False
        for dep, recorded_version in claim.dependency_versions.items():
            if dep in self._evidence:
                ev = self._evidence[dep]
                if ev.state is not EvidenceState.ACTIVE or ev.version != recorded_version:
                    return False
            elif dep in self._claims:
                dep_claim = self._claims[dep]
                if dep_claim.freshness is not Freshness.FRESH or dep_claim.version != recorded_version:
                    return False
            else:
                return False
        return True

    def stale_claims(self) -> tuple[str, ...]:
        return tuple(sorted(cid for cid, c in self._claims.items() if not self.is_fresh(cid)))

    def _invalidate_dependents(self, node_id: str) -> None:
        stack = list(self._reverse.get(node_id, ()))
        seen: set[str] = set()
        while stack:
            cid = stack.pop()
            if cid in seen:
                continue
            seen.add(cid)
            if cid in self._claims:
                self._claims[cid].freshness = Freshness.STALE
            stack.extend(self._reverse.get(cid, ()))

    def _reachable(self, start: str, target: str) -> bool:
        stack = [start]
        seen: set[str] = set()
        while stack:
            node = stack.pop()
            if node == target:
                return True
            if node in seen:
                continue
            seen.add(node)
            stack.extend(dep for dep in self._deps.get(node, ()) if dep in self._claims)
        return False
