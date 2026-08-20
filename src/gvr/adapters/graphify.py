from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from ..model import Evidence, VerificationVerdict


@dataclass(frozen=True)
class GraphifyTraversalEvidence:
    """Evidence and audit metadata ingested from Graphify's public result contract."""

    evidence: tuple[Evidence, ...]
    complete_supported_search: bool
    search_coverage: str
    termination_reason: str
    blocking_boundary_keys: tuple[str, ...]
    boundary_evidence: tuple[Evidence, ...] = ()
    start: str = ""
    target: str | None = None
    direction: str = "UNKNOWN"
    truncated: bool = False
    input_resolution: str = "UNKNOWN"
    query_validity: bool = False
    start_node_found: bool = False
    target_node_found: bool | None = None
    query_bounds: Mapping[str, Any] = field(default_factory=dict)

    @property
    def absence_verdict(self) -> VerificationVerdict:
        """Whether an empty-path result may support an absence claim."""
        if self.complete_supported_search and self.search_coverage == "COMPLETE_FOR_SUPPORTED_CONSTRUCT":
            return VerificationVerdict.PASS
        return VerificationVerdict.UNKNOWN


def _mapping_items(value: Any) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item for item in value if isinstance(item, Mapping))


def ingest_traversal_result(result: Mapping[str, Any]) -> GraphifyTraversalEvidence:
    """Ingest only Graphify's public traversal-result mapping.

    This adapter does not reparse source or reconstruct a graph. It exposes the
    exact direct and boundary evidence records so a verifier report can be
    recorded in :class:`gvr.ledger.ClaimLedger` without custom dependency logic.
    Validation of whether the payload proves a claim remains the verifier's job.
    """

    direct_by_key: dict[str, Evidence] = {}
    for path in _mapping_items(result.get("paths")):
        for item in _mapping_items(path.get("supporting_evidence")):
            key = str(item.get("key") or "")
            if not key:
                continue
            direct_by_key.setdefault(
                key,
                Evidence(
                    id=key,
                    kind="graphify.data_flow_edge",
                    payload=dict(item),
                    source=str(item.get("source_file") or "") or None,
                    fingerprint=key,
                ),
            )

    boundary_by_key: dict[str, Evidence] = {}
    for event in _mapping_items(result.get("boundary_events")):
        key = str(
            event.get("boundary_evidence_key")
            or event.get("diagnostic_evidence_key")
            or ""
        )
        if not key:
            continue
        boundary_by_key.setdefault(
            key,
            Evidence(
                id=key,
                kind="graphify.data_flow_boundary",
                payload=dict(event),
                source=str(event.get("canonical_caller_file") or "") or None,
                fingerprint=key,
            ),
        )

    boundary_keys = tuple(sorted(boundary_by_key))
    all_evidence = {**direct_by_key, **boundary_by_key}
    return GraphifyTraversalEvidence(
        evidence=tuple(all_evidence[key] for key in sorted(all_evidence)),
        complete_supported_search=bool(result.get("complete_supported_search", False)),
        search_coverage=str(result.get("search_coverage") or "UNKNOWN"),
        termination_reason=str(result.get("termination_reason") or "UNKNOWN"),
        blocking_boundary_keys=boundary_keys,
        boundary_evidence=tuple(boundary_by_key[key] for key in boundary_keys),
        start=str(result.get("start") or ""),
        target=(None if result.get("target") is None else str(result.get("target"))),
        direction=str(result.get("direction") or "UNKNOWN"),
        truncated=bool(result.get("truncated", False)),
        input_resolution=str(result.get("input_resolution") or "UNKNOWN"),
        query_validity=result.get("query_validity") is True,
        start_node_found=result.get("start_node_found") is True,
        target_node_found=(
            None
            if result.get("target_node_found") is None
            else result.get("target_node_found") is True
        ),
        query_bounds=(
            dict(result.get("query_bounds", {}))
            if isinstance(result.get("query_bounds", {}), Mapping)
            else {}
        ),
    )
