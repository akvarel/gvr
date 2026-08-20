from __future__ import annotations

from typing import Iterable

from ..model import VerificationIssue, VerificationReport, VerificationVerdict
from .functional_delta import Coverage, DeltaKind, FunctionalDeltaResult, FunctionalSnapshot, compare_functionality


VERIFIER_NAME = "functional_regression"


def _scope_kinds(
    baseline: FunctionalSnapshot,
    candidate: FunctionalSnapshot,
    required_kinds: Iterable[str] | None,
) -> tuple[str, ...]:
    if required_kinds is not None:
        return tuple(sorted({str(kind) for kind in required_kinds if str(kind)}))
    kinds = set(baseline.coverage_by_kind) | set(candidate.coverage_by_kind)
    kinds.update(obs.kind for obs in baseline.observables)
    kinds.update(obs.kind for obs in candidate.observables)
    return tuple(sorted(kinds))


def verify_functional_regression(
    baseline: FunctionalSnapshot,
    candidate: FunctionalSnapshot,
    *,
    required_kinds: Iterable[str] | None = None,
) -> tuple[FunctionalDeltaResult, VerificationReport]:
    """Verify the claim that *candidate introduces no functional regression*.

    A proven REMOVED or CHANGED observable falsifies the claim immediately.
    Otherwise the claim passes only when every observable in scope is decided and
    both revisions have COMPLETE coverage for every scoped kind. Missing scope,
    partial coverage, MAY/PARTIAL observables, or any UNKNOWN delta keeps the
    result UNKNOWN rather than laundering incomplete analysis into PASS.
    """

    delta = compare_functionality(baseline, candidate)
    scope = _scope_kinds(baseline, candidate, required_kinds)

    regressions = tuple(
        item
        for item in delta.items
        if item.delta in (DeltaKind.REMOVED, DeltaKind.CHANGED)
        and item.verdict is VerificationVerdict.PASS
    )
    unknown_items = tuple(
        item
        for item in delta.items
        if item.delta is DeltaKind.UNKNOWN or item.verdict is VerificationVerdict.UNKNOWN
    )
    incomplete_kinds = tuple(
        kind
        for kind in scope
        if baseline.coverage(kind) is not Coverage.COMPLETE
        or candidate.coverage(kind) is not Coverage.COMPLETE
    )

    if regressions:
        issues = tuple(
            VerificationIssue(
                code="FUNCTIONAL_REGRESSION",
                message=f"{item.kind}:{item.key} is proven {item.delta.value} in the candidate revision.",
                verdict=VerificationVerdict.FAIL,
                evidence_ids=item.evidence_ids,
            )
            for item in regressions
        )
        evidence_ids = tuple(sorted({eid for item in regressions for eid in item.evidence_ids}))
        verdict = VerificationVerdict.FAIL
    elif not scope:
        issues = (
            VerificationIssue(
                code="FUNCTIONAL_SCOPE_UNKNOWN",
                message="No observable kind was supplied or discovered; no-regression cannot be proven.",
                verdict=VerificationVerdict.UNKNOWN,
            ),
        )
        evidence_ids = ()
        verdict = VerificationVerdict.UNKNOWN
    elif unknown_items or incomplete_kinds:
        issue_list = [
            VerificationIssue(
                code="FUNCTIONAL_DELTA_UNKNOWN",
                message=f"{item.kind}:{item.key} is not decidable from exact evidence.",
                verdict=VerificationVerdict.UNKNOWN,
                evidence_ids=item.evidence_ids,
            )
            for item in unknown_items
        ]
        if incomplete_kinds:
            issue_list.append(
                VerificationIssue(
                    code="FUNCTIONAL_COVERAGE_INCOMPLETE",
                    message="Complete baseline and candidate coverage is required for: "
                    + ", ".join(incomplete_kinds),
                    verdict=VerificationVerdict.UNKNOWN,
                )
            )
        issues = tuple(issue_list)
        evidence_ids = tuple(sorted({eid for item in unknown_items for eid in item.evidence_ids}))
        verdict = VerificationVerdict.UNKNOWN
    else:
        issues = ()
        evidence_ids = tuple(sorted({eid for item in delta.items for eid in item.evidence_ids}))
        verdict = VerificationVerdict.PASS

    report = VerificationReport(
        verdict=verdict,
        verifier=VERIFIER_NAME,
        issues=issues,
        evidence_ids=evidence_ids,
        metadata={
            "baseline": {
                "repository": baseline.revision.repository,
                "revision": baseline.revision.revision,
            },
            "candidate": {
                "repository": candidate.revision.repository,
                "revision": candidate.revision.revision,
            },
            "required_kinds": scope,
            "incomplete_kinds": incomplete_kinds,
            "delta_counts": {
                kind.value: sum(1 for item in delta.items if item.delta is kind)
                for kind in DeltaKind
            },
        },
    )
    return delta, report
