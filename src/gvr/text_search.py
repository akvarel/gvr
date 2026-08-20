from __future__ import annotations

from dataclasses import dataclass
import unicodedata

from .model import VerificationIssue, VerificationReport, VerificationVerdict


@dataclass(frozen=True)
class TextSearchAssertion:
    corpus: tuple[str, ...]
    needle: str
    claimed_matches: tuple[str, ...]
    requested_needle: str | None = None
    require_grounding: bool = True
    reverse: bool = False
    normalization: str = "NFC"


@dataclass(frozen=True)
class TextSearchResult:
    executed_needle: str
    requested_needle: str | None
    actual_matches: tuple[str, ...]
    claimed_matches: tuple[str, ...]
    verdict: VerificationVerdict


def _norm(value: str, form: str) -> str:
    return unicodedata.normalize(form, value)


def _prepare(value: str, form: str, reverse: bool) -> str:
    value = _norm(value, form)
    return value[::-1] if reverse else value


def evaluate_text_search(assertion: TextSearchAssertion) -> tuple[TextSearchResult, VerificationReport]:
    issues: list[VerificationIssue] = []

    if assertion.require_grounding and assertion.requested_needle is None:
        result = TextSearchResult(
            executed_needle=assertion.needle,
            requested_needle=None,
            actual_matches=(),
            claimed_matches=assertion.claimed_matches,
            verdict=VerificationVerdict.UNKNOWN,
        )
        return result, VerificationReport(
            verdict=VerificationVerdict.UNKNOWN,
            verifier="text_search",
            issues=(VerificationIssue(
                code="MISSING_SPEC_GROUNDING",
                message="The executed literal is not independently grounded to the requested literal.",
                verdict=VerificationVerdict.UNKNOWN,
            ),),
        )

    if assertion.requested_needle is not None:
        requested = _prepare(assertion.requested_needle, assertion.normalization, assertion.reverse)
        executed = _prepare(assertion.needle, assertion.normalization, assertion.reverse)
        if requested != executed:
            issues.append(VerificationIssue(
                code="SPEC_MISMATCH",
                message="Executed literal differs from independently grounded requested literal.",
                verdict=VerificationVerdict.FAIL,
            ))

    needle = _prepare(assertion.needle, assertion.normalization, assertion.reverse)
    actual: list[str] = []
    for original in assertion.corpus:
        candidate = _prepare(original, assertion.normalization, assertion.reverse)
        if needle in candidate:
            actual.append(original)

    actual_matches = tuple(actual)
    if actual_matches != assertion.claimed_matches:
        issues.append(VerificationIssue(
            code="SEARCH_RESULT_MISMATCH",
            message="Claimed matches differ from independently recomputed literal matches.",
            verdict=VerificationVerdict.FAIL,
        ))

    verdict = VerificationVerdict.FAIL if any(i.verdict is VerificationVerdict.FAIL for i in issues) else VerificationVerdict.PASS
    result = TextSearchResult(
        executed_needle=assertion.needle,
        requested_needle=assertion.requested_needle,
        actual_matches=actual_matches,
        claimed_matches=assertion.claimed_matches,
        verdict=verdict,
    )
    return result, VerificationReport(verdict=verdict, verifier="text_search", issues=tuple(issues))
