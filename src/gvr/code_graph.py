from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from .canonical import canonical_fingerprint
from .model import Evidence, VerificationVerdict

GRAPH_EVIDENCE_FINGERPRINT_FORMAT = "gvr.code_graph.evidence.v1"
GRAPH_MODEL_FINGERPRINT_FORMAT = "gvr.code_graph.model.v1"
CODE_GRAPH_OBSERVATION_EVIDENCE_KIND = "gvr.code_graph.provider_observation"
CODE_GRAPH_OBSERVATION_KIND = "gvr.code_graph.provider_observation"
CODE_GRAPH_OBSERVATION_SCHEMA_VERSION = 1
CODE_GRAPH_OBSERVATION_FINGERPRINT_FORMAT = "gvr.code_graph.provider_observation.v1"
ATOMIC_CLAIM_FINGERPRINT_FORMAT = "gvr.atomic_claim.ieee754-json.v1"


class GraphEvidenceModelError(ValueError):
    """Raised when native graph evidence cannot be safely canonicalized."""


class CodeGraphObservationError(ValueError):
    """Raised when canonical provider observation evidence is malformed."""


class EvidenceConfidence(str, Enum):
    EXACT = "EXACT"
    HEURISTIC = "HEURISTIC"
    INFERRED_HINT = "INFERRED_HINT"


class GraphEvidenceKind(str, Enum):
    NODE = "NODE"
    CALL = "CALL"
    REFERENCE = "REFERENCE"
    ARCHITECTURE = "ARCHITECTURE"


def _snapshot(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _snapshot(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return tuple(_snapshot(v) for v in value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


@dataclass(frozen=True)
class GraphEvidence:
    id: str
    kind: GraphEvidenceKind
    semantic_identity: Mapping[str, Any]
    exact_identity: Mapping[str, Any]
    confidence: EvidenceConfidence
    source: str = ""
    target: str = ""
    label: str = ""
    native: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "semantic_identity", _snapshot(self.semantic_identity))
        object.__setattr__(self, "exact_identity", _snapshot(self.exact_identity))
        object.__setattr__(self, "native", _snapshot(self.native))

    @property
    def semantic_fingerprint(self) -> str:
        return canonical_fingerprint(
            {"kind": self.kind.value, "identity": self.semantic_identity},
            fingerprint_format=GRAPH_EVIDENCE_FINGERPRINT_FORMAT + ".semantic",
        )

    @property
    def exact_fingerprint(self) -> str:
        return canonical_fingerprint(
            {"kind": self.kind.value, "identity": self.exact_identity},
            fingerprint_format=GRAPH_EVIDENCE_FINGERPRINT_FORMAT + ".exact",
        )

    @property
    def fingerprint(self) -> str:
        return canonical_fingerprint(self.to_dict(), fingerprint_format=GRAPH_EVIDENCE_FINGERPRINT_FORMAT)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "semantic_identity": self.semantic_identity,
            "exact_identity": self.exact_identity,
            "semantic_fingerprint": self.semantic_fingerprint,
            "exact_fingerprint": self.exact_fingerprint,
            "confidence": self.confidence.value,
            "source": self.source,
            "target": self.target,
            "label": self.label,
            "native": self.native,
        }


@dataclass(frozen=True)
class GraphBlocker:
    id: str
    reason: str
    scope: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "details", _snapshot(self.details))

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "reason": self.reason, "scope": self.scope, "details": self.details}


@dataclass(frozen=True)
class GraphEvidenceModel:
    provider: str
    nodes: tuple[GraphEvidence, ...]
    edges: tuple[GraphEvidence, ...]
    blockers: tuple[GraphBlocker, ...] = ()
    absence_subjects: tuple[str, ...] = ()
    source_snapshot: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "nodes", tuple(sorted(self.nodes, key=_graph_evidence_sort_key)))
        object.__setattr__(self, "edges", tuple(sorted(self.edges, key=_graph_evidence_sort_key)))
        object.__setattr__(self, "blockers", tuple(sorted(self.blockers, key=_graph_blocker_sort_key)))
        object.__setattr__(self, "absence_subjects", tuple(sorted(str(s) for s in self.absence_subjects)))
        object.__setattr__(self, "source_snapshot", _snapshot(self.source_snapshot))
        seen: dict[str, GraphEvidence] = {}
        for item in self.nodes + self.edges:
            existing = seen.get(item.id)
            if existing is not None and existing != item:
                raise GraphEvidenceModelError(f"conflicting duplicate graph evidence id: {item.id}")
            seen[item.id] = item

    @property
    def evidence(self) -> tuple[GraphEvidence, ...]:
        return self.nodes + self.edges

    @property
    def fingerprint(self) -> str:
        return canonical_fingerprint(self.to_dict(), fingerprint_format=GRAPH_MODEL_FINGERPRINT_FORMAT)

    def absence_verdict(self, subject: str) -> VerificationVerdict:
        if str(subject) in self.absence_subjects:
            return VerificationVerdict.PASS
        return VerificationVerdict.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "source_snapshot": self.source_snapshot,
            "nodes": [item.to_dict() for item in self.nodes],
            "edges": [item.to_dict() for item in self.edges],
            "blockers": [item.to_dict() for item in self.blockers],
            "absence_subjects": self.absence_subjects,
        }


def _graph_evidence_sort_key(item: GraphEvidence) -> tuple[str, ...]:
    return (
        str(_graph_kind_sort_order(item.kind)),
        item.id,
        item.kind.value,
        item.source,
        item.target,
        item.label,
        item.confidence.value,
        item.semantic_fingerprint,
        item.exact_fingerprint,
        item.fingerprint,
    )


def _graph_kind_sort_order(kind: GraphEvidenceKind) -> int:
    order = {
        GraphEvidenceKind.NODE: 0,
        GraphEvidenceKind.CALL: 1,
        GraphEvidenceKind.REFERENCE: 2,
        GraphEvidenceKind.ARCHITECTURE: 3,
    }
    return order.get(kind, 99)


def _graph_blocker_sort_key(item: GraphBlocker) -> tuple[str, ...]:
    return (
        item.id,
        item.reason,
        item.scope,
        canonical_fingerprint(
            item.to_dict(),
            fingerprint_format=GRAPH_MODEL_FINGERPRINT_FORMAT + ".blocker",
        ),
    )


@dataclass(frozen=True)
class CodeGraphProviderObservation:
    """Decoded canonical provider observation consumed by the generic runtime."""

    evidence_id: str
    provider_id: str
    implementation_id: str
    family_id: str
    claim_fingerprint: str
    graph_model: GraphEvidenceModel
    graph_model_fingerprint: str


def claim_fingerprint_for_observation(claim: Any) -> str:
    """Return the exact atomic-claim fingerprint used by execution/planning."""

    semantic_definition = getattr(claim, "semantic_definition", None)
    if not callable(semantic_definition):
        raise CodeGraphObservationError("claim must expose semantic_definition()")
    return canonical_fingerprint(
        semantic_definition(),
        fingerprint_format=ATOMIC_CLAIM_FINGERPRINT_FORMAT,
    )


def encode_code_graph_observation_evidence(
    graph_model: GraphEvidenceModel,
    *,
    evidence_id: str,
    claim: Any | None = None,
    claim_fingerprint: str | None = None,
    implementation_id: str | None = None,
    family_id: str | None = None,
    source_snapshot: Mapping[str, Any] | None = None,
) -> Evidence:
    """Encode a canonical provider graph snapshot as one GVR evidence record.

    Provider adapters are responsible for turning provider-specific output into a
    :class:`GraphEvidenceModel`. This function only seals that canonical model
    with exact provider, implementation, family, claim, and snapshot identities.
    """

    if not isinstance(graph_model, GraphEvidenceModel):
        raise CodeGraphObservationError("graph_model must be a GraphEvidenceModel")
    if source_snapshot is not None:
        graph_model = GraphEvidenceModel(
            provider=graph_model.provider,
            nodes=graph_model.nodes,
            edges=graph_model.edges,
            blockers=graph_model.blockers,
            absence_subjects=graph_model.absence_subjects,
            source_snapshot=source_snapshot,
        )
    if claim_fingerprint is None:
        if claim is None:
            raise CodeGraphObservationError("claim or claim_fingerprint is required")
        claim_fingerprint = claim_fingerprint_for_observation(claim)
    provider_id = str(graph_model.provider or "")
    if not provider_id:
        raise CodeGraphObservationError("graph model provider is required")
    if family_id is not None and str(family_id) != provider_id:
        raise CodeGraphObservationError("provider family is sealed to the graph model provider")
    payload = {
        "schema_version": CODE_GRAPH_OBSERVATION_SCHEMA_VERSION,
        "kind": CODE_GRAPH_OBSERVATION_KIND,
        "provider_id": provider_id,
        "implementation_id": str(implementation_id or provider_id),
        "family_id": provider_id,
        "claim_fingerprint": str(claim_fingerprint),
        "source_snapshot": graph_model.source_snapshot,
        "graph_model_fingerprint": graph_model.fingerprint,
        "graph_model": graph_model.to_dict(),
    }
    return Evidence(
        id=str(evidence_id),
        kind=CODE_GRAPH_OBSERVATION_EVIDENCE_KIND,
        payload=payload,
        source=provider_id,
        fingerprint=canonical_fingerprint(
            payload,
            fingerprint_format=CODE_GRAPH_OBSERVATION_FINGERPRINT_FORMAT,
        ),
    )


def decode_code_graph_observation_evidence(evidence: Evidence) -> CodeGraphProviderObservation:
    """Decode canonical provider-observation evidence without provider parsing."""

    if not isinstance(evidence, Evidence):
        raise CodeGraphObservationError("evidence must be an Evidence record")
    if evidence.kind != CODE_GRAPH_OBSERVATION_EVIDENCE_KIND:
        raise CodeGraphObservationError("unsupported code graph observation evidence kind")
    payload = evidence.payload
    if not isinstance(payload, Mapping):
        raise CodeGraphObservationError("code graph observation payload must be a mapping")
    if payload.get("schema_version") != CODE_GRAPH_OBSERVATION_SCHEMA_VERSION:
        raise CodeGraphObservationError("unsupported code graph observation schema version")
    if payload.get("kind") != CODE_GRAPH_OBSERVATION_KIND:
        raise CodeGraphObservationError("unsupported code graph observation kind")
    graph_model_document = payload.get("graph_model")
    if not isinstance(graph_model_document, Mapping):
        raise CodeGraphObservationError("code graph observation is missing graph_model")
    graph_model = graph_model_from_dict(graph_model_document)
    if payload.get("graph_model_fingerprint") != graph_model.fingerprint:
        raise CodeGraphObservationError("code graph observation graph model fingerprint mismatch")
    if _snapshot(payload.get("source_snapshot", {})) != graph_model.source_snapshot:
        raise CodeGraphObservationError("code graph observation snapshot mismatch")
    provider_id = _required_string(payload, "provider_id")
    family_id = _required_string(payload, "family_id")
    if provider_id != graph_model.provider:
        raise CodeGraphObservationError("code graph observation provider does not match graph model provider")
    if family_id != provider_id:
        raise CodeGraphObservationError("code graph observation provider family is not adapter-sealed")
    return CodeGraphProviderObservation(
        evidence_id=evidence.id,
        provider_id=provider_id,
        implementation_id=_required_string(payload, "implementation_id"),
        family_id=family_id,
        claim_fingerprint=_required_string(payload, "claim_fingerprint"),
        graph_model=graph_model,
        graph_model_fingerprint=graph_model.fingerprint,
    )


def graph_model_from_dict(document: Mapping[str, Any]) -> GraphEvidenceModel:
    """Reconstruct a canonical graph model from its transport dictionary."""

    try:
        return GraphEvidenceModel(
            provider=_required_string(document, "provider"),
            nodes=tuple(_graph_evidence_from_dict(item) for item in _sequence(document.get("nodes", ()), "nodes")),
            edges=tuple(_graph_evidence_from_dict(item) for item in _sequence(document.get("edges", ()), "edges")),
            blockers=tuple(_graph_blocker_from_dict(item) for item in _sequence(document.get("blockers", ()), "blockers")),
            absence_subjects=tuple(str(item) for item in _sequence(document.get("absence_subjects", ()), "absence_subjects")),
            source_snapshot=document.get("source_snapshot", {}),
        )
    except (TypeError, ValueError, KeyError) as exc:
        raise CodeGraphObservationError("graph model document is malformed") from exc


def _graph_evidence_from_dict(document: Mapping[str, Any]) -> GraphEvidence:
    if not isinstance(document, Mapping):
        raise CodeGraphObservationError("graph evidence document must be a mapping")
    return GraphEvidence(
        id=_required_string(document, "id"),
        kind=GraphEvidenceKind(_required_string(document, "kind")),
        semantic_identity=_mapping(document.get("semantic_identity", {}), "semantic_identity"),
        exact_identity=_mapping(document.get("exact_identity", {}), "exact_identity"),
        confidence=EvidenceConfidence(_required_string(document, "confidence")),
        source=str(document.get("source") or ""),
        target=str(document.get("target") or ""),
        label=str(document.get("label") or ""),
        native=_mapping(document.get("native", {}), "native"),
    )


def _graph_blocker_from_dict(document: Mapping[str, Any]) -> GraphBlocker:
    if not isinstance(document, Mapping):
        raise CodeGraphObservationError("graph blocker document must be a mapping")
    return GraphBlocker(
        id=_required_string(document, "id"),
        reason=_required_string(document, "reason"),
        scope=str(document.get("scope") or ""),
        details=_mapping(document.get("details", {}), "details"),
    )


def _required_string(document: Mapping[str, Any], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise CodeGraphObservationError(f"{key} must be a non-empty string")
    return value


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CodeGraphObservationError(f"{name} must be a mapping")
    return value


def _sequence(value: Any, name: str) -> tuple[Any, ...]:
    if not isinstance(value, (list, tuple)):
        raise CodeGraphObservationError(f"{name} must be a sequence")
    return tuple(value)
