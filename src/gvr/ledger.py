from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Iterable, Mapping

from .bundle import VerificationBundle, validate_verification_bundle
from .dependencies import ClaimDependencyGraph
from .model import Freshness, VerificationReport, VerificationVerdict


@dataclass(frozen=True)
class ClaimDefinition:
    id: str
    statement: str
    verifier: str


@dataclass(frozen=True)
class VerificationSnapshot:
    run_id: int
    claim_id: str
    verdict: VerificationVerdict
    evidence_ids: tuple[str, ...]
    claim_dependency_ids: tuple[str, ...]
    report: VerificationReport
    claim_version: int


@dataclass(frozen=True)
class ClaimStatus:
    claim_id: str
    stored_verdict: VerificationVerdict
    effective_verdict: VerificationVerdict
    freshness: Freshness
    version: int


class ClaimLedger:
    """Claim ledger that prevents stale verdicts from propagating as truth."""

    def __init__(self) -> None:
        self.dependencies = ClaimDependencyGraph()
        self._definitions: dict[str, ClaimDefinition] = {}
        self._history: dict[str, list[VerificationSnapshot]] = {}
        self._run_clock = 0

    def define(self, definition: ClaimDefinition) -> None:
        existing = self._definitions.get(definition.id)
        if existing is not None and existing != definition:
            raise ValueError(f"claim definition {definition.id} already exists with different semantics")
        self._definitions[definition.id] = definition
        self.dependencies.put_claim(definition.id, VerificationVerdict.UNKNOWN)
        self._history.setdefault(definition.id, [])

    def put_evidence(self, evidence_id: str, payload: Mapping[str, object]) -> None:
        self.dependencies.put_evidence(evidence_id, payload)

    def remove_evidence(self, evidence_id: str) -> None:
        self.dependencies.remove_evidence(evidence_id)

    def record_verification(
        self,
        claim_id: str,
        report: VerificationReport,
        *,
        evidence_ids: Iterable[str] | None = None,
        claim_dependency_ids: Iterable[str] = (),
    ) -> VerificationSnapshot:
        if claim_id not in self._definitions:
            raise KeyError(f"undefined claim: {claim_id}")
        definition = self._definitions[claim_id]
        if report.verifier != definition.verifier:
            raise ValueError(
                f"claim {claim_id} requires verifier {definition.verifier}, got {report.verifier}"
            )

        explicit_evidence = tuple(sorted(set(report.evidence_ids if evidence_ids is None else evidence_ids)))
        report_evidence = tuple(sorted(set(report.evidence_ids)))
        if evidence_ids is not None and report_evidence and report_evidence != explicit_evidence:
            raise ValueError("report evidence_ids and supplied evidence_ids disagree")

        for eid in explicit_evidence:
            ev = self.dependencies.evidence.get(eid)
            if ev is None or ev.state.value != "ACTIVE":
                raise ValueError(f"claim {claim_id} references unavailable evidence {eid}")

        claim_deps = tuple(sorted(set(claim_dependency_ids)))
        for dep in claim_deps:
            if dep not in self._definitions:
                raise ValueError(f"claim {claim_id} references undefined claim dependency {dep}")

        all_deps = tuple(sorted(set(explicit_evidence) | set(claim_deps)))
        self.dependencies.set_dependencies(claim_id, all_deps)
        record = self.dependencies.mark_reverified(claim_id, report.verdict)

        self._run_clock += 1
        snapshot = VerificationSnapshot(
            run_id=self._run_clock,
            claim_id=claim_id,
            verdict=report.verdict,
            evidence_ids=explicit_evidence,
            claim_dependency_ids=claim_deps,
            report=report,
            claim_version=record.version,
        )
        self._history[claim_id].append(snapshot)
        return snapshot

    def record_bundle(
        self,
        claim_id: str,
        bundle: VerificationBundle,
    ) -> VerificationSnapshot:
        """Atomically register a bundle's evidence and record its report."""

        validate_verification_bundle(bundle)
        trial = deepcopy(self)
        for evidence in bundle.evidence:
            trial.put_evidence(evidence.id, evidence.payload)
        snapshot = trial.record_verification(
            claim_id,
            bundle.report,
            evidence_ids=bundle.report.evidence_ids,
            claim_dependency_ids=bundle.claim_dependency_ids,
        )
        self.dependencies = trial.dependencies
        self._definitions = trial._definitions
        self._history = trial._history
        self._run_clock = trial._run_clock
        return snapshot

    def status(self, claim_id: str) -> ClaimStatus:
        record = self.dependencies.claims[claim_id]
        fresh = self.dependencies.is_fresh(claim_id)
        freshness = Freshness.FRESH if fresh else Freshness.STALE
        effective = record.verdict if fresh else VerificationVerdict.UNKNOWN
        return ClaimStatus(
            claim_id=claim_id,
            stored_verdict=record.verdict,
            effective_verdict=effective,
            freshness=freshness,
            version=record.version,
        )

    def history(self, claim_id: str) -> tuple[VerificationSnapshot, ...]:
        return tuple(self._history[claim_id])

    def stale_claims(self) -> tuple[str, ...]:
        return self.dependencies.stale_claims()
