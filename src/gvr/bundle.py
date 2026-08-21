from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
import math
from typing import Any, Iterable, Mapping

from .canonical import (
    BUNDLE_FINGERPRINT_FORMAT,
    CanonicalizationError,
    canonical_transport_fingerprint,
)
from .model import (
    INDETERMINATE,
    MISSING,
    Evidence,
    VerificationIssue,
    VerificationReport,
    VerificationVerdict,
)


VERIFICATION_BUNDLE_SCHEMA_VERSION = 1
VERIFICATION_BUNDLE_KIND = "gvr.verification_bundle"
VERIFICATION_BUNDLE_FINGERPRINT_FORMAT = BUNDLE_FINGERPRINT_FORMAT


class BundleValidationError(ValueError):
    """Raised when a verification bundle is incomplete or ambiguous."""


class _FrozenDict(dict[str, Any]):
    """JSON-compatible immutable mapping used inside a frozen bundle."""

    def _immutable(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("verification bundle semantic content is immutable")

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


def _canonical_value(value: Any, *, path: str) -> Any:
    """Return strict JSON-compatible semantic content with sorted mapping keys."""

    if value is MISSING:
        return {"$gvr": "MISSING"}
    if value is INDETERMINATE:
        return {"$gvr": "INDETERMINATE"}
    if isinstance(value, Enum):
        return _canonical_value(value.value, path=path)
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise BundleValidationError(f"{path} contains a non-finite number")
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key in value:
            if not isinstance(key, str):
                raise BundleValidationError(f"{path} contains a non-string mapping key")
            normalized[key] = _canonical_value(value[key], path=f"{path}.{key}")
        return {key: normalized[key] for key in sorted(normalized)}
    if isinstance(value, (list, tuple)):
        return [
            _canonical_value(item, path=f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    raise BundleValidationError(
        f"{path} contains unsupported semantic value {type(value).__name__}"
    )


def _freeze_canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return _FrozenDict({
            key: _freeze_canonical(item)
            for key, item in value.items()
        })
    if isinstance(value, list):
        return tuple(_freeze_canonical(item) for item in value)
    return value


def _freeze_value(value: Any, *, path: str) -> Any:
    return _freeze_canonical(_canonical_value(value, path=path))


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _normalize_ids(values: Iterable[str], *, name: str) -> tuple[str, ...]:
    ids = tuple(values)
    if any(not isinstance(item, str) or not item for item in ids):
        raise BundleValidationError(f"{name} must contain non-empty strings")
    if len(set(ids)) != len(ids):
        raise BundleValidationError(f"{name} contains duplicate IDs")
    return tuple(sorted(ids))


def _canonical_issue(issue: VerificationIssue) -> dict[str, Any]:
    return {
        "code": issue.code,
        "message": issue.message,
        "verdict": issue.verdict.value,
        "evidence_ids": list(issue.evidence_ids),
    }


def _normalize_report(report: VerificationReport) -> VerificationReport:
    if not isinstance(report, VerificationReport):
        raise BundleValidationError("report must be a VerificationReport")
    if not isinstance(report.verdict, VerificationVerdict):
        raise BundleValidationError("report verdict is invalid")
    if not isinstance(report.verifier, str) or not report.verifier:
        raise BundleValidationError("report verifier must be a non-empty string")
    if not isinstance(report.metadata, Mapping):
        raise BundleValidationError("report metadata must be a mapping")
    metadata = _freeze_value(report.metadata, path="report.metadata")

    evidence_ids = _normalize_ids(report.evidence_ids, name="report evidence_ids")
    normalized_issues: list[VerificationIssue] = []
    for issue in report.issues:
        if not isinstance(issue, VerificationIssue):
            raise BundleValidationError("report issues must be VerificationIssue records")
        if not isinstance(issue.verdict, VerificationVerdict):
            raise BundleValidationError("issue verdict is invalid")
        if not isinstance(issue.code, str) or not issue.code:
            raise BundleValidationError("issue code must be a non-empty string")
        if not isinstance(issue.message, str):
            raise BundleValidationError("issue message must be a string")
        issue_ids = _normalize_ids(issue.evidence_ids, name="issue evidence_ids")
        unrelated = set(issue_ids) - set(evidence_ids)
        if unrelated:
            raise BundleValidationError(
                "issue evidence must also be present in report evidence_ids: "
                + ", ".join(sorted(unrelated))
            )
        normalized_issues.append(
            VerificationIssue(
                code=issue.code,
                message=issue.message,
                verdict=issue.verdict,
                evidence_ids=issue_ids,
            )
        )
    normalized_issues.sort(key=lambda item: _canonical_json(_canonical_issue(item)))
    return VerificationReport(
        verdict=report.verdict,
        verifier=report.verifier,
        issues=tuple(normalized_issues),
        evidence_ids=evidence_ids,
        metadata=metadata,
    )


def _canonical_evidence(evidence: Evidence) -> dict[str, Any]:
    return {
        "id": evidence.id,
        "kind": evidence.kind,
        "payload": _canonical_value(evidence.payload, path=f"evidence[{evidence.id}].payload"),
        "source": evidence.source,
        "fingerprint": evidence.fingerprint,
    }


def _normalize_evidence(
    evidence_records: Iterable[Evidence],
) -> tuple[Evidence, ...]:
    by_id: dict[str, Evidence] = {}
    semantics_by_id: dict[str, str] = {}
    for evidence in evidence_records:
        if not isinstance(evidence, Evidence):
            raise BundleValidationError("bundle evidence must contain Evidence records")
        if not isinstance(evidence.id, str) or not evidence.id:
            raise BundleValidationError("evidence ID must be a non-empty string")
        if not isinstance(evidence.kind, str) or not evidence.kind:
            raise BundleValidationError(f"evidence {evidence.id} kind must be non-empty")
        if not isinstance(evidence.payload, Mapping):
            raise BundleValidationError(f"evidence {evidence.id} payload must be a mapping")
        if evidence.source is not None and not isinstance(evidence.source, str):
            raise BundleValidationError(f"evidence {evidence.id} source must be a string")
        if evidence.fingerprint is not None and not isinstance(evidence.fingerprint, str):
            raise BundleValidationError(
                f"evidence {evidence.id} fingerprint must be a string"
            )
        normalized = Evidence(
            id=evidence.id,
            kind=evidence.kind,
            payload=_freeze_value(
                evidence.payload,
                path=f"evidence[{evidence.id}].payload",
            ),
            source=evidence.source,
            fingerprint=evidence.fingerprint,
        )
        semantic = _canonical_json(_canonical_evidence(normalized))
        previous = semantics_by_id.get(evidence.id)
        if previous is not None and previous != semantic:
            raise BundleValidationError(
                f"conflicting evidence records share ID {evidence.id}"
            )
        semantics_by_id[evidence.id] = semantic
        by_id.setdefault(evidence.id, normalized)
    return tuple(by_id[evidence_id] for evidence_id in sorted(by_id))


def _canonical_report(report: VerificationReport) -> dict[str, Any]:
    return {
        "verdict": report.verdict.value,
        "verifier": report.verifier,
        "issues": [_canonical_issue(issue) for issue in report.issues],
        "evidence_ids": list(report.evidence_ids),
        "metadata": _canonical_value(report.metadata, path="report.metadata"),
    }


def _bundle_content(bundle: VerificationBundle) -> dict[str, Any]:
    return {
        "schema_version": bundle.schema_version,
        "kind": bundle.kind,
        "fingerprint_format": bundle.fingerprint_format,
        "verifier": bundle.verifier,
        "report": _canonical_report(bundle.report),
        "evidence": [_canonical_evidence(item) for item in bundle.evidence],
        "claim_dependency_ids": list(bundle.claim_dependency_ids),
    }


@dataclass(frozen=True, kw_only=True)
class VerificationBundle:
    """Versioned, deterministic report plus its exact dependency manifest."""

    schema_version: int = VERIFICATION_BUNDLE_SCHEMA_VERSION
    kind: str = VERIFICATION_BUNDLE_KIND
    fingerprint_format: str = VERIFICATION_BUNDLE_FINGERPRINT_FORMAT
    verifier: str = field(init=False)
    report: VerificationReport
    evidence: tuple[Evidence, ...] = ()
    claim_dependency_ids: tuple[str, ...] = ()
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        if self.schema_version != VERIFICATION_BUNDLE_SCHEMA_VERSION:
            raise BundleValidationError(
                f"unsupported bundle schema version {self.schema_version}"
            )
        if self.kind != VERIFICATION_BUNDLE_KIND:
            raise BundleValidationError(f"unsupported bundle kind {self.kind}")
        if self.fingerprint_format != VERIFICATION_BUNDLE_FINGERPRINT_FORMAT:
            raise BundleValidationError(
                f"unsupported bundle fingerprint format {self.fingerprint_format}"
            )

        report = _normalize_report(self.report)
        evidence = _normalize_evidence(self.evidence)
        claim_dependency_ids = _normalize_ids(
            self.claim_dependency_ids,
            name="claim_dependency_ids",
        )
        evidence_ids = {item.id for item in evidence}
        report_ids = set(report.evidence_ids)
        missing = report_ids - evidence_ids
        extra = evidence_ids - report_ids
        if missing:
            raise BundleValidationError(
                "missing evidence records for report dependencies: "
                + ", ".join(sorted(missing))
            )
        if extra:
            raise BundleValidationError(
                "unreferenced evidence records are not allowed: "
                + ", ".join(sorted(extra))
            )

        object.__setattr__(self, "verifier", report.verifier)
        object.__setattr__(self, "report", report)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "claim_dependency_ids", claim_dependency_ids)
        try:
            fingerprint = canonical_transport_fingerprint(_bundle_content(self))
        except CanonicalizationError as exc:
            raise BundleValidationError(str(exc)) from exc
        object.__setattr__(self, "fingerprint", fingerprint)


def build_verification_bundle(
    report: VerificationReport,
    evidence: Iterable[Evidence],
    *,
    claim_dependency_ids: Iterable[str] = (),
) -> VerificationBundle:
    """Build and validate a self-contained verification dependency package."""

    return VerificationBundle(
        report=report,
        evidence=tuple(evidence),
        claim_dependency_ids=tuple(claim_dependency_ids),
    )


def validate_verification_bundle(bundle: VerificationBundle) -> None:
    """Revalidate a bundle before crossing a mutation or transport boundary."""

    if not isinstance(bundle, VerificationBundle):
        raise BundleValidationError("bundle must be a VerificationBundle")
    expected = VerificationBundle(
        schema_version=bundle.schema_version,
        kind=bundle.kind,
        fingerprint_format=bundle.fingerprint_format,
        report=bundle.report,
        evidence=bundle.evidence,
        claim_dependency_ids=bundle.claim_dependency_ids,
    )
    if expected != bundle:
        raise BundleValidationError("bundle content or fingerprint is inconsistent")
