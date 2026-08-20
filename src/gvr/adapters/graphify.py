from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from ..model import Evidence, VerificationVerdict


@dataclass(frozen=True)
class GraphifyTraversalEvidence:
    evidence: tuple[Evidence, ...]
    complete_supported_search: bool
    search_coverage: str
    termination_reason: str
    blocking_boundary_keys: tuple[str, ...]

    @property
    def absence_verdict(self) -> VerificationVerdict:
        """Whether an empty-path result may support an absence claim."""
        if self.complete_supported_search and self.search_coverage == "COMPLETE_FOR_SUPPORTED_CONSTRUCT":
            return VerificationVerdict.PASS
        return VerificationVerdict.UNKNOWN


def ingest_traversal_result(result: Mapping[str, Any]) -> GraphifyTraversalEvidence:
    evidence: list[Evidence] = []
    for path in result.get("paths", ()) or ():
        for item in path.get("supporting_evidence", ()) or ():
            key = str(item.get("key") or "")
            if not key:
                continue
            evidence.append(Evidence(
                id=key,
                kind="graphify.data_flow_edge",
                payload=dict(item),
                source=str(item.get("source_file") or "") or None,
                fingerprint=key,
            ))
    # preserve order while deduplicating exact evidence keys
    unique = {ev.id: ev for ev in evidence}

    boundaries = tuple(
        sorted(
            str(ev.get("boundary_evidence_key") or ev.get("diagnostic_evidence_key") or "")
            for ev in (result.get("boundary_events", ()) or ())
            if ev.get("boundary_evidence_key") or ev.get("diagnostic_evidence_key")
        )
    )
    return GraphifyTraversalEvidence(
        evidence=tuple(unique[k] for k in sorted(unique)),
        complete_supported_search=bool(result.get("complete_supported_search", False)),
        search_coverage=str(result.get("search_coverage") or "UNKNOWN"),
        termination_reason=str(result.get("termination_reason") or "UNKNOWN"),
        blocking_boundary_keys=boundaries,
    )
