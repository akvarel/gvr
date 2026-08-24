from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from .canonical import canonical_fingerprint
from .model import VerificationVerdict

GRAPH_EVIDENCE_FINGERPRINT_FORMAT = "gvr.code_graph.evidence.v1"
GRAPH_MODEL_FINGERPRINT_FORMAT = "gvr.code_graph.model.v1"


class GraphEvidenceModelError(ValueError):
    """Raised when native graph evidence cannot be safely canonicalized."""


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
        object.__setattr__(self, "nodes", tuple(self.nodes))
        object.__setattr__(self, "edges", tuple(self.edges))
        object.__setattr__(self, "blockers", tuple(sorted(self.blockers, key=lambda b: b.id)))
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
