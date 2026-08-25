from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from ..canonical import canonical_fingerprint
from ..model import VerificationIssue, VerificationReport, VerificationVerdict
from ..provider_independence import IndependenceTrustState, VerifiedIndependenceFamily

PROVIDER_CORROBORATION_VERIFIER = "gvr.provider_corroboration.v1"
PROVIDER_CORROBORATION_FINGERPRINT_FORMAT = "gvr.provider_corroboration.report.v1"
SNAPSHOT_FINGERPRINT_FORMAT = "gvr.provider_corroboration.snapshot.v1"

_MESSAGES = {
    "PROVIDER_CORROBORATED_PASS": "Independent provider families decisively corroborate the PASS verdict.",
    "PROVIDER_CORROBORATED_FAIL": "Independent provider families decisively corroborate the FAIL verdict.",
    "PROVIDER_SINGLE_FAMILY_DECISIVE_PASS": "One provider family produced a decisive PASS without independent corroboration.",
    "PROVIDER_SINGLE_FAMILY_DECISIVE_FAIL": "One provider family produced a decisive FAIL without independent corroboration.",
    "PROVIDER_CONFLICT": "Independent provider families produced decisive conflicting verdicts.",
    "PROVIDER_FAMILY_CONTRADICTION": "One provider family produced contradictory decisive verdicts and cannot count as independent corroboration.",
    "PROVIDER_ONLY_HEURISTIC": "Provider observations are heuristic or unknown only and are not upgraded by repetition.",
    "PROVIDER_SNAPSHOT_MISMATCH": "Provider observations do not share one source snapshot.",
    "PROVIDER_CLAIM_MISMATCH": "Provider observations do not verify the same claim fingerprint.",
    "PROVIDER_MALFORMED_OBSERVATION": "A provider observation is malformed and was treated as fail-closed UNKNOWN.",
    "PROVIDER_NO_OBSERVATIONS": "No provider observations were supplied.",
    "HEURISTIC_ONLY_SUPPORT": "Provider observations are heuristic or unknown only and are not upgraded by repetition.",
    "SOURCE_SNAPSHOT_MISMATCH": "Provider observations do not share one source snapshot.",
    "CONFLICTING_GRAPH_EVIDENCE": "Independent provider families produced decisive conflicting graph verdicts.",
    "MALFORMED_GRAPH_EVIDENCE": "A provider observation is malformed and was treated as fail-closed UNKNOWN.",
}

_LEGACY_ISSUE_ALIASES = {
    "HEURISTIC_ONLY_SUPPORT": ("PROVIDER_ONLY_HEURISTIC",),
    "SOURCE_SNAPSHOT_MISMATCH": ("PROVIDER_SNAPSHOT_MISMATCH",),
    "CONFLICTING_GRAPH_EVIDENCE": ("PROVIDER_CONFLICT",),
    "MALFORMED_GRAPH_EVIDENCE": ("PROVIDER_MALFORMED_OBSERVATION",),
}


@dataclass(frozen=True)
class ProviderVerificationObservation:
    provider_id: str
    implementation_id: str
    family_id: str
    source_snapshot: Mapping[str, Any]
    claim_fingerprint: str
    report: VerificationReport
    metadata: Mapping[str, Any] = field(default_factory=dict)
    independence: VerifiedIndependenceFamily | None = None

    def __post_init__(self) -> None:
        if not self.provider_id or not self.implementation_id or not self.family_id or not self.claim_fingerprint:
            raise ValueError("provider observations require provider, implementation, family, and claim identity")
        if not isinstance(self.report, VerificationReport):
            raise ValueError("provider observation report must be a VerificationReport")
        object.__setattr__(self, "source_snapshot", _stable(self.source_snapshot))
        object.__setattr__(self, "metadata", _stable(self.metadata))
        if self.independence is None:
            object.__setattr__(
                self,
                "independence",
                VerifiedIndependenceFamily(self.family_id, (), IndependenceTrustState.UNVERIFIED),
            )
        elif not isinstance(self.independence, VerifiedIndependenceFamily):
            raise ValueError("provider observation independence must be registry-resolved")

    @property
    def snapshot_fingerprint(self) -> str:
        return canonical_fingerprint(self.source_snapshot, fingerprint_format=SNAPSHOT_FINGERPRINT_FORMAT)

    @property
    def identity(self) -> tuple[str, str, str, str, str, str]:
        independence_key = (
            self.independence.family_id
            if self.independence.trust_state is IndependenceTrustState.VERIFIED
            else f"UNVERIFIED:{self.family_id}:{self.provider_id}"
        )
        return (
            self.claim_fingerprint,
            self.snapshot_fingerprint,
            independence_key,
            self.implementation_id,
            "" if self.independence.trust_state is IndependenceTrustState.VERIFIED else self.provider_id,
            _report_fingerprint(self.report),
        )


def reconcile_provider_observations(observations: Iterable[ProviderVerificationObservation]) -> VerificationReport:
    valid: list[ProviderVerificationObservation] = []
    issues: list[VerificationIssue] = []
    malformed = 0
    for item in observations:
        if isinstance(item, ProviderVerificationObservation):
            valid.append(item)
        else:
            malformed += 1
    if malformed:
        issues.extend(_issues("MALFORMED_GRAPH_EVIDENCE", VerificationVerdict.UNKNOWN))
    deduped = tuple({obs.identity: obs for obs in sorted(valid, key=lambda o: o.identity)}.values())
    if not deduped:
        return _final(VerificationVerdict.UNKNOWN, issues + [_issue("PROVIDER_NO_OBSERVATIONS", VerificationVerdict.UNKNOWN)], (), (), malformed)

    claim_ids = tuple(sorted({o.claim_fingerprint for o in deduped}))
    snapshot_groups = _snapshot_groups(deduped)
    if len(claim_ids) != 1:
        issues.append(_issue("PROVIDER_CLAIM_MISMATCH", VerificationVerdict.UNKNOWN))
    if len(snapshot_groups) != 1:
        issues.extend(_issues("SOURCE_SNAPSHOT_MISMATCH", VerificationVerdict.UNKNOWN))

    evidence_ids = _evidence_ids(deduped)
    provider_issues = _provider_issues(deduped)
    issues = provider_issues + issues

    hard_mismatch = len(claim_ids) != 1 or len(snapshot_groups) != 1 or malformed
    pass_families = _decisive_families(deduped, VerificationVerdict.PASS)
    fail_families = _decisive_families(deduped, VerificationVerdict.FAIL)
    contradictory_families = tuple(sorted(pass_families & fail_families))
    unknown_only = not pass_families and not fail_families

    decisive_pass = _has_decisive(deduped, VerificationVerdict.PASS)
    decisive_fail = _has_decisive(deduped, VerificationVerdict.FAIL)

    if hard_mismatch:
        verdict = VerificationVerdict.UNKNOWN
    elif contradictory_families:
        issues.append(_issue("PROVIDER_FAMILY_CONTRADICTION", VerificationVerdict.UNKNOWN, evidence_ids))
        verdict = VerificationVerdict.UNKNOWN
    elif pass_families and fail_families:
        issues.extend(_issues("CONFLICTING_GRAPH_EVIDENCE", VerificationVerdict.UNKNOWN, evidence_ids))
        verdict = VerificationVerdict.UNKNOWN
    elif len(pass_families) >= 2:
        issues.append(_issue("PROVIDER_CORROBORATED_PASS", VerificationVerdict.PASS, evidence_ids))
        verdict = VerificationVerdict.PASS
    elif len(fail_families) >= 2:
        issues.append(_issue("PROVIDER_CORROBORATED_FAIL", VerificationVerdict.FAIL, evidence_ids))
        verdict = VerificationVerdict.FAIL
    elif decisive_pass and decisive_fail:
        verdict = VerificationVerdict.UNKNOWN
    elif decisive_pass:
        issues.append(_issue("PROVIDER_SINGLE_FAMILY_DECISIVE_PASS", VerificationVerdict.PASS, evidence_ids))
        verdict = VerificationVerdict.PASS
    elif decisive_fail:
        issues.append(_issue("PROVIDER_SINGLE_FAMILY_DECISIVE_FAIL", VerificationVerdict.FAIL, evidence_ids))
        verdict = VerificationVerdict.FAIL
    else:
        if unknown_only:
            issues.extend(_issues("HEURISTIC_ONLY_SUPPORT", VerificationVerdict.UNKNOWN, evidence_ids))
        verdict = VerificationVerdict.UNKNOWN

    return _final(verdict, issues, evidence_ids, deduped, malformed, claim_ids=claim_ids, snapshot_groups=snapshot_groups)


def _decisive_families(observations: tuple[ProviderVerificationObservation, ...], verdict: VerificationVerdict) -> frozenset[str]:
    families: set[str] = set()
    for obs in observations:
        if (
            obs.report.verdict is verdict
            and not _is_hint_or_heuristic(obs.report)
            and obs.independence.trust_state is IndependenceTrustState.VERIFIED
        ):
            families.add(obs.independence.family_id)
    return frozenset(families)


def _has_decisive(observations: tuple[ProviderVerificationObservation, ...], verdict: VerificationVerdict) -> bool:
    return any(obs.report.verdict is verdict and not _is_hint_or_heuristic(obs.report) for obs in observations)


def _is_hint_or_heuristic(report: VerificationReport) -> bool:
    codes = {issue.code for issue in report.issues}
    if report.verdict is VerificationVerdict.UNKNOWN:
        return True
    return bool(codes & {"EDGE_NOT_EXACT", "NODE_NOT_EXACT", "INFERRED_HINT", "PROVIDER_ONLY_HEURISTIC", "HEURISTIC_ONLY_SUPPORT"})


def _provider_issues(observations: tuple[ProviderVerificationObservation, ...]) -> list[VerificationIssue]:
    seen: set[tuple[str, VerificationVerdict, tuple[str, ...]]] = set()
    out: list[VerificationIssue] = []
    for obs in observations:
        for issue in obs.report.issues:
            key = (issue.code, issue.verdict, tuple(issue.evidence_ids))
            if key not in seen:
                seen.add(key)
                out.append(issue)
    return sorted(out, key=lambda i: (i.code, i.verdict.value, i.evidence_ids))


def _evidence_ids(observations: tuple[ProviderVerificationObservation, ...]) -> tuple[str, ...]:
    ids: set[str] = set()
    for obs in observations:
        ids.update(str(e) for e in obs.report.evidence_ids)
        for issue in obs.report.issues:
            ids.update(str(e) for e in issue.evidence_ids)
    return tuple(sorted(ids))


def _snapshot_groups(observations: tuple[ProviderVerificationObservation, ...]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    groups: dict[str, set[str]] = {}
    for obs in observations:
        groups.setdefault(obs.snapshot_fingerprint, set()).add(obs.provider_id)
    return tuple((fp, tuple(sorted(providers))) for fp, providers in sorted(groups.items()))


def _final(
    verdict: VerificationVerdict,
    issues: list[VerificationIssue],
    evidence_ids: tuple[str, ...],
    observations: tuple[ProviderVerificationObservation, ...],
    malformed: int,
    *,
    claim_ids: tuple[str, ...] = (),
    snapshot_groups: tuple[tuple[str, tuple[str, ...]], ...] = (),
) -> VerificationReport:
    metadata = {
        "claim_fingerprints": claim_ids,
        "snapshot_groups": snapshot_groups,
        "providers": tuple((o.provider_id, o.implementation_id, o.family_id, o.report.verdict.value) for o in observations),
        "verified_independence_families": tuple(sorted({
            o.independence.family_id
            for o in observations
            if o.independence.trust_state is IndependenceTrustState.VERIFIED
        })),
        "unverified_provider_labels": tuple(sorted({
            o.family_id
            for o in observations
            if o.independence.trust_state is IndependenceTrustState.UNVERIFIED
        })),
        "malformed_observations": malformed,
    }
    fp_metadata = {
        "claim_fingerprints": claim_ids,
        "snapshot_fingerprints": tuple(group[0] for group in snapshot_groups),
        "observations": tuple(sorted((
            o.independence.trust_state.value,
            o.independence.family_id,
            o.implementation_id,
            o.report.verdict.value,
            _report_fingerprint(o.report),
        ) for o in observations)),
        "malformed_observations": malformed,
    }
    fp_payload = {"verdict": verdict.value, "issues": [(i.code, i.verdict.value, i.evidence_ids) for i in issues], "evidence_ids": evidence_ids, "metadata": fp_metadata}
    metadata["fingerprint"] = canonical_fingerprint(fp_payload, fingerprint_format=PROVIDER_CORROBORATION_FINGERPRINT_FORMAT)
    return VerificationReport(verdict=verdict, verifier=PROVIDER_CORROBORATION_VERIFIER, issues=tuple(issues), evidence_ids=evidence_ids, metadata=metadata)


def _issue(code: str, verdict: VerificationVerdict, evidence_ids: tuple[str, ...] = ()) -> VerificationIssue:
    return VerificationIssue(code=code, message=_MESSAGES[code], verdict=verdict, evidence_ids=tuple(evidence_ids))


def _issues(code: str, verdict: VerificationVerdict, evidence_ids: tuple[str, ...] = ()) -> list[VerificationIssue]:
    return [_issue(code, verdict, evidence_ids)] + [
        _issue(alias, verdict, evidence_ids) for alias in _LEGACY_ISSUE_ALIASES.get(code, ())
    ]


def _report_fingerprint(report: VerificationReport) -> str:
    return canonical_fingerprint(
        {
            "verdict": report.verdict.value,
            "verifier": report.verifier,
            "issues": [(i.code, i.message, i.verdict.value, i.evidence_ids) for i in report.issues],
            "evidence_ids": report.evidence_ids,
            "metadata": _stable(report.metadata),
        },
        fingerprint_format=PROVIDER_CORROBORATION_FINGERPRINT_FORMAT + ".input",
    )


def _stable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _stable(value[k]) for k in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return tuple(_stable(v) for v in value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)
