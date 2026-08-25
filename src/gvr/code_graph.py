from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from .canonical import canonical_fingerprint
from .provider_independence import (
    BUILTIN_PROVIDER_IMPLEMENTATION_REGISTRY,
    ProviderImplementationRegistry,
    ProviderOriginAttestation,
    ProviderOriginAuthority,
    VerifiedIndependenceFamily,
)
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
class SourceRevisionIdentity:
    repository: str
    revision: str

    def __post_init__(self) -> None:
        if not str(self.repository) or not str(self.revision):
            raise GraphEvidenceModelError("source revision requires repository and revision")
        object.__setattr__(self, "repository", str(self.repository))
        object.__setattr__(self, "revision", str(self.revision))

    def to_dict(self) -> dict[str, str]:
        return {"repository": self.repository, "revision": self.revision}


@dataclass(frozen=True)
class GraphQueryScope:
    start: str = ""
    target: str | None = None
    direction: str = "FORWARD"
    relations: frozenset[str] = field(default_factory=frozenset)
    requested_relations: frozenset[str] = field(default_factory=frozenset)
    effective_relations: frozenset[str] = field(default_factory=frozenset)
    rejected_relations: frozenset[str] = field(default_factory=frozenset)
    max_depth: int | None = None
    max_paths: int | None = None
    max_expansions: int | None = None
    stop_nodes: frozenset[str] = field(default_factory=frozenset)
    evidence_namespace: str = "default"

    def __post_init__(self) -> None:
        direction = str(self.direction or "FORWARD").upper()
        if direction not in {"FORWARD", "BACKWARD"}:
            raise GraphEvidenceModelError(f"invalid graph query direction: {direction!r}")
        for name in ("max_depth", "max_paths", "max_expansions"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value < 0):
                raise GraphEvidenceModelError(f"graph query {name} must be non-negative")
        if not str(self.evidence_namespace):
            raise GraphEvidenceModelError("graph query evidence_namespace is required")
        object.__setattr__(self, "start", str(self.start))
        object.__setattr__(self, "target", None if self.target is None else str(self.target))
        object.__setattr__(self, "direction", direction)
        legacy_relations = frozenset(str(item) for item in self.relations)
        requested = frozenset(str(item) for item in self.requested_relations)
        effective = frozenset(str(item) for item in self.effective_relations)
        rejected = frozenset(str(item) for item in self.rejected_relations)
        if legacy_relations:
            if effective and legacy_relations != effective:
                raise GraphEvidenceModelError("graph query relations conflict with effective_relations")
            effective = legacy_relations
            if not requested:
                requested = legacy_relations
        object.__setattr__(self, "relations", effective)
        object.__setattr__(self, "requested_relations", requested)
        object.__setattr__(self, "effective_relations", effective)
        object.__setattr__(self, "rejected_relations", rejected)
        object.__setattr__(self, "stop_nodes", frozenset(str(item) for item in self.stop_nodes))
        object.__setattr__(self, "evidence_namespace", str(self.evidence_namespace))

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.start,
            "target": self.target,
            "direction": self.direction,
            "requested_relations": tuple(sorted(self.requested_relations)),
            "effective_relations": tuple(sorted(self.effective_relations)),
            "rejected_relations": tuple(sorted(self.rejected_relations)),
            "max_depth": self.max_depth,
            "max_paths": self.max_paths,
            "max_expansions": self.max_expansions,
            "stop_nodes": tuple(sorted(self.stop_nodes)),
            "evidence_namespace": self.evidence_namespace,
        }


@dataclass(frozen=True)
class CoverageCertificate:
    coverage: str = "UNKNOWN"
    complete_supported_search: bool = False
    termination_reason: str = "UNKNOWN"
    truncated: bool = False
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "coverage", str(self.coverage or "UNKNOWN"))
        object.__setattr__(self, "complete_supported_search", self.complete_supported_search is True)
        object.__setattr__(self, "termination_reason", str(self.termination_reason or "UNKNOWN"))
        object.__setattr__(self, "truncated", self.truncated is True)
        object.__setattr__(self, "details", _snapshot(self.details))

    @property
    def proves_complete_search(self) -> bool:
        return (
            self.complete_supported_search
            and not self.truncated
            and self.coverage == "COMPLETE_FOR_SUPPORTED_CONSTRUCT"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "coverage": self.coverage,
            "complete_supported_search": self.complete_supported_search,
            "termination_reason": self.termination_reason,
            "truncated": self.truncated,
            "details": self.details,
        }


@dataclass(frozen=True)
class ProviderImplementationIdentity:
    provider_id: str
    implementation_id: str
    family_id: str
    implementation_revision: str = "unspecified"
    provider_kind: str = "low-level"

    def __post_init__(self) -> None:
        if not self.provider_id or not self.implementation_id or not self.family_id:
            raise GraphEvidenceModelError("provider identity fields must be non-empty")
        object.__setattr__(self, "provider_id", str(self.provider_id))
        object.__setattr__(self, "implementation_id", str(self.implementation_id))
        object.__setattr__(self, "family_id", str(self.family_id))
        object.__setattr__(self, "implementation_revision", str(self.implementation_revision))
        object.__setattr__(self, "provider_kind", str(self.provider_kind))

    def to_dict(self) -> dict[str, str]:
        value = {
            "provider_id": self.provider_id,
            "implementation_id": self.implementation_id,
            "family_id": self.family_id,
        }
        if self.implementation_revision != "unspecified":
            value["implementation_revision"] = self.implementation_revision
        if self.provider_kind != "low-level":
            value["provider_kind"] = self.provider_kind
        return value


@dataclass(frozen=True)
class GraphFacts:
    nodes: tuple[GraphEvidence, ...] = ()
    edges: tuple[GraphEvidence, ...] = ()
    blockers: tuple[GraphBlocker, ...] = ()
    absence_subjects: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "nodes", tuple(sorted(self.nodes, key=_graph_evidence_sort_key)))
        object.__setattr__(self, "edges", tuple(sorted(self.edges, key=_graph_evidence_sort_key)))
        object.__setattr__(self, "blockers", tuple(sorted(self.blockers, key=_graph_blocker_sort_key)))
        object.__setattr__(self, "absence_subjects", tuple(sorted(str(item) for item in self.absence_subjects)))
        seen: dict[str, GraphEvidence] = {}
        for item in self.nodes + self.edges:
            existing = seen.get(item.id)
            if existing is not None and existing != item:
                raise GraphEvidenceModelError(f"conflicting duplicate graph evidence id: {item.id}")
            seen[item.id] = item

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [item.to_dict() for item in self.nodes],
            "edges": [item.to_dict() for item in self.edges],
            "blockers": [item.to_dict() for item in self.blockers],
            "absence_subjects": self.absence_subjects,
        }


@dataclass(frozen=True, init=False)
class GraphEvidenceModel:
    provider_identity: ProviderImplementationIdentity
    source_revision: SourceRevisionIdentity
    query_scope: GraphQueryScope
    coverage: CoverageCertificate
    facts: GraphFacts
    _legacy_source_snapshot: Mapping[str, Any]
    _typed_authority: bool

    def __init__(
        self,
        provider: str | None = None,
        nodes: tuple[GraphEvidence, ...] = (),
        edges: tuple[GraphEvidence, ...] = (),
        blockers: tuple[GraphBlocker, ...] = (),
        absence_subjects: tuple[str, ...] = (),
        source_snapshot: Mapping[str, Any] | None = None,
        *,
        provider_identity: ProviderImplementationIdentity | None = None,
        source_revision: SourceRevisionIdentity | None = None,
        query_scope: GraphQueryScope | None = None,
        coverage: CoverageCertificate | None = None,
        facts: GraphFacts | None = None,
        _legacy_source_snapshot: Mapping[str, Any] | None = None,
        _typed_authority: bool | None = None,
    ) -> None:
        supplied_typed_authority = any(item is not None for item in (provider_identity, source_revision, query_scope, coverage, facts))
        snapshot = _snapshot(source_snapshot if source_snapshot is not None else (_legacy_source_snapshot or {}))
        if provider_identity is None:
            provider_id = str(provider or "")
            provider_identity = ProviderImplementationIdentity(provider_id, provider_id, provider_id)
        elif provider is not None and str(provider) != provider_identity.provider_id:
            raise GraphEvidenceModelError("provider conflicts with typed provider identity")
        if source_revision is None:
            source_revision = _source_revision_from_legacy(snapshot)
        if query_scope is None:
            query_scope = _query_scope_from_legacy(snapshot)
        if coverage is None:
            coverage = _coverage_from_legacy(snapshot)
        if facts is None:
            facts = GraphFacts(nodes=nodes, edges=edges, blockers=blockers, absence_subjects=absence_subjects)
        elif nodes or edges or blockers or absence_subjects:
            raise GraphEvidenceModelError("facts cannot be combined with legacy graph fact fields")
        object.__setattr__(self, "provider_identity", provider_identity)
        object.__setattr__(self, "source_revision", source_revision)
        object.__setattr__(self, "query_scope", query_scope)
        object.__setattr__(self, "coverage", coverage)
        object.__setattr__(self, "facts", facts)
        object.__setattr__(self, "_legacy_source_snapshot", snapshot)
        object.__setattr__(self, "_typed_authority", supplied_typed_authority if _typed_authority is None else _typed_authority)

    @property
    def provider(self) -> str:
        return self.provider_identity.provider_id

    @property
    def nodes(self) -> tuple[GraphEvidence, ...]:
        return self.facts.nodes

    @property
    def edges(self) -> tuple[GraphEvidence, ...]:
        return self.facts.edges

    @property
    def blockers(self) -> tuple[GraphBlocker, ...]:
        return self.facts.blockers

    @property
    def absence_subjects(self) -> tuple[str, ...]:
        return self.facts.absence_subjects

    @property
    def source_snapshot(self) -> Mapping[str, Any]:
        return self._legacy_source_snapshot or self.source_revision.to_dict()

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
            "provider_identity": self.provider_identity.to_dict(),
            "source_revision": self.source_revision.to_dict(),
            "query_scope": self.query_scope.to_dict(),
            "coverage": self.coverage.to_dict(),
            "facts": self.facts.to_dict(),
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


def _source_revision_from_legacy(snapshot: Mapping[str, Any]) -> SourceRevisionIdentity:
    nested = snapshot.get("source_revision")
    if isinstance(nested, Mapping):
        repository = nested.get("repository")
        revision = nested.get("revision")
    else:
        repository = snapshot.get("repository") or snapshot.get("repo") or "unknown"
        revision = snapshot.get("revision") or snapshot.get("commit") or snapshot.get("sha")
    if revision is None:
        revision = canonical_fingerprint(snapshot, fingerprint_format=GRAPH_MODEL_FINGERPRINT_FORMAT + ".legacy_revision")
    return SourceRevisionIdentity(str(repository or "unknown"), str(revision))


def _query_scope_from_legacy(snapshot: Mapping[str, Any]) -> GraphQueryScope:
    bounds = snapshot.get("query_bounds")
    bounds = bounds if isinstance(bounds, Mapping) else {}
    requested_relations = _legacy_set(bounds.get("requested_relations", bounds.get("relations", ())))
    effective_relations = _legacy_set(bounds.get("effective_allowed_relations", bounds.get("effective_relations", bounds.get("relations", ()))))
    rejected_relations = _legacy_set(bounds.get("rejected_relations", ()))
    stop_nodes = bounds.get("stop_nodes", ())
    if isinstance(stop_nodes, (str, bytes)) or not isinstance(stop_nodes, (list, tuple, set, frozenset)):
        stop_nodes = ()
    return GraphQueryScope(
        start=str(snapshot.get("start") or ""),
        target=None if snapshot.get("target") is None else str(snapshot.get("target")),
        direction=str(snapshot.get("direction") or bounds.get("direction") or "FORWARD"),
        requested_relations=requested_relations,
        effective_relations=effective_relations,
        rejected_relations=rejected_relations,
        max_depth=None if bounds.get("max_depth") is None else int(bounds["max_depth"]),
        max_paths=None if bounds.get("max_paths") is None else int(bounds["max_paths"]),
        max_expansions=None if bounds.get("max_expansions") is None else int(bounds["max_expansions"]),
        stop_nodes=frozenset(str(item) for item in stop_nodes),
        evidence_namespace=str(snapshot.get("evidence_namespace") or "default"),
    )


def _legacy_set(value: Any) -> frozenset[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple, set, frozenset)):
        return frozenset()
    return frozenset(str(item) for item in value)


def _coverage_from_legacy(snapshot: Mapping[str, Any]) -> CoverageCertificate:
    return CoverageCertificate(
        coverage=str(snapshot.get("search_coverage") or "UNKNOWN"),
        complete_supported_search=snapshot.get("complete_supported_search") is True,
        termination_reason=str(snapshot.get("termination_reason") or "UNKNOWN"),
        truncated=snapshot.get("truncated") is True,
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
    independence: VerifiedIndependenceFamily
    origin_attestation: ProviderOriginAttestation

    @property
    def provider_identity(self) -> ProviderImplementationIdentity:
        return self.graph_model.provider_identity

    @property
    def source_revision(self) -> SourceRevisionIdentity:
        return self.graph_model.source_revision

    @property
    def query_scope(self) -> GraphQueryScope:
        return self.graph_model.query_scope

    @property
    def coverage(self) -> CoverageCertificate:
        return self.graph_model.coverage


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
    provider_registry: ProviderImplementationRegistry | None = None,
    provider_authority: ProviderOriginAuthority | None = None,
) -> Evidence:
    return _encode_code_graph_observation_evidence(
        graph_model, evidence_id=evidence_id, claim=claim, claim_fingerprint=claim_fingerprint,
        implementation_id=implementation_id, family_id=family_id, source_snapshot=source_snapshot,
        provider_registry=provider_registry, provider_authority=provider_authority,
    )


def _encode_code_graph_observation_evidence(
    graph_model: GraphEvidenceModel,
    *,
    evidence_id: str,
    claim: Any | None = None,
    claim_fingerprint: str | None = None,
    implementation_id: str | None = None,
    family_id: str | None = None,
    source_snapshot: Mapping[str, Any] | None = None,
    provider_registry: ProviderImplementationRegistry | None = None,
    provider_authority: ProviderOriginAuthority | None = None,
    _adapter_origin: ProviderOriginAttestation | None = None,
) -> Evidence:
    """Encode a canonical provider graph snapshot as one GVR evidence record.

    Provider adapters are responsible for turning provider-specific output into a
    :class:`GraphEvidenceModel`. This function only seals that canonical model
    with exact provider, implementation, family, claim, and snapshot identities.
    """

    if not isinstance(graph_model, GraphEvidenceModel):
        raise CodeGraphObservationError("graph_model must be a GraphEvidenceModel")
    if source_snapshot is not None and _snapshot(source_snapshot) != graph_model.source_snapshot:
        raise CodeGraphObservationError("source snapshot authority override is forbidden")
    if claim_fingerprint is None:
        if claim is None:
            raise CodeGraphObservationError("claim or claim_fingerprint is required")
        claim_fingerprint = claim_fingerprint_for_observation(claim)
    identity = graph_model.provider_identity
    registry = provider_registry or BUILTIN_PROVIDER_IMPLEMENTATION_REGISTRY
    origin = _adapter_origin or registry.attest(identity, authority=provider_authority)
    independence = origin.family
    provider_id = identity.provider_id
    if not provider_id:
        raise CodeGraphObservationError("graph model provider is required")
    if implementation_id is not None and str(implementation_id) != identity.implementation_id:
        if graph_model._typed_authority:
            raise CodeGraphObservationError("provider implementation authority override is forbidden")
        identity = ProviderImplementationIdentity(provider_id, str(implementation_id), provider_id)
    if family_id is not None and str(family_id) != identity.family_id:
        raise CodeGraphObservationError("provider family is sealed to the graph model provider; authority override is forbidden")
    payload = {
        "schema_version": CODE_GRAPH_OBSERVATION_SCHEMA_VERSION,
        "kind": CODE_GRAPH_OBSERVATION_KIND,
        "provider_id": provider_id,
        "implementation_id": identity.implementation_id,
        "family_id": identity.family_id,
        "independence": independence.to_dict(),
        "provider_origin": origin.to_dict(),
        "claim_fingerprint": str(claim_fingerprint),
        "typed_authority": graph_model._typed_authority,
        "source_snapshot": graph_model.source_snapshot,
        "source_revision": graph_model.source_revision.to_dict(),
        "query_scope": graph_model.query_scope.to_dict(),
        "coverage": graph_model.coverage.to_dict(),
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


def decode_code_graph_observation_evidence(
    evidence: Evidence,
    *,
    provider_registry: ProviderImplementationRegistry | None = None,
) -> CodeGraphProviderObservation:
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
    typed_authority = payload.get("typed_authority") is True
    legacy_snapshot = _mapping(payload.get("source_snapshot", {}), "source_snapshot")
    if not typed_authority and (graph_model._typed_authority or graph_model.source_snapshot != legacy_snapshot):
        graph_model = GraphEvidenceModel(
            provider_identity=graph_model.provider_identity,
            source_revision=graph_model.source_revision,
            query_scope=graph_model.query_scope,
            coverage=graph_model.coverage,
            facts=graph_model.facts,
            _legacy_source_snapshot=legacy_snapshot,
            _typed_authority=typed_authority,
        )
    if payload.get("graph_model_fingerprint") != graph_model.fingerprint:
        raise CodeGraphObservationError("code graph observation graph model fingerprint mismatch")
    if _mapping(payload.get("source_revision", {}), "source_revision") != graph_model.source_revision.to_dict():
        raise CodeGraphObservationError("code graph observation source revision mismatch")
    if _snapshot(_mapping(payload.get("query_scope", {}), "query_scope")) != _snapshot(graph_model.query_scope.to_dict()):
        raise CodeGraphObservationError("code graph observation query scope mismatch")
    if _snapshot(_mapping(payload.get("coverage", {}), "coverage")) != _snapshot(graph_model.coverage.to_dict()):
        raise CodeGraphObservationError("code graph observation coverage mismatch")
    provider_id = _required_string(payload, "provider_id")
    family_id = _required_string(payload, "family_id")
    if provider_id != graph_model.provider:
        raise CodeGraphObservationError("code graph observation provider does not match graph model provider")
    registry = provider_registry or BUILTIN_PROVIDER_IMPLEMENTATION_REGISTRY
    recorded_origin = _mapping(payload.get("provider_origin", {}), "provider_origin")
    try:
        if str(recorded_origin.get("configuration_identity", "")) == "untrusted":
            origin = registry.attest(graph_model.provider_identity)
            if _snapshot(recorded_origin) != _snapshot(origin.to_dict()):
                raise ValueError("unverified provider origin mismatch")
        else:
            origin = registry.validate(graph_model.provider_identity, recorded_origin)
    except ValueError as exc:
        raise CodeGraphObservationError(str(exc)) from exc
    independence = origin.family
    recorded_independence = _mapping(payload.get("independence", {}), "independence")
    if _snapshot(recorded_independence) != _snapshot(independence.to_dict()):
        raise CodeGraphObservationError("code graph observation independence resolution mismatch")
    return CodeGraphProviderObservation(
        evidence_id=evidence.id,
        provider_id=provider_id,
        implementation_id=_required_string(payload, "implementation_id"),
        family_id=family_id,
        claim_fingerprint=_required_string(payload, "claim_fingerprint"),
        graph_model=graph_model,
        graph_model_fingerprint=graph_model.fingerprint,
        independence=independence,
        origin_attestation=origin,
    )


def graph_model_from_dict(document: Mapping[str, Any]) -> GraphEvidenceModel:
    """Reconstruct a canonical graph model from its transport dictionary."""

    try:
        required = {"provider_identity", "source_revision", "query_scope", "coverage", "facts"}
        if not required <= set(document):
            raise CodeGraphObservationError("graph model document is missing typed authority fields")
        provider = _mapping(document["provider_identity"], "provider_identity")
        revision = _mapping(document["source_revision"], "source_revision")
        scope = _mapping(document["query_scope"], "query_scope")
        certificate = _mapping(document["coverage"], "coverage")
        facts = _mapping(document["facts"], "facts")
        return GraphEvidenceModel(
            provider_identity=ProviderImplementationIdentity(
                _required_string(provider, "provider_id"),
                _required_string(provider, "implementation_id"),
                _required_string(provider, "family_id"),
                str(provider.get("implementation_revision", "unspecified")),
                str(provider.get("provider_kind", "low-level")),
            ),
            source_revision=SourceRevisionIdentity(
                _required_string(revision, "repository"),
                _required_string(revision, "revision"),
            ),
            query_scope=GraphQueryScope(
                start=str(scope.get("start") or ""),
                target=None if scope.get("target") is None else str(scope.get("target")),
                direction=str(scope.get("direction") or "FORWARD"),
                requested_relations=frozenset(str(item) for item in _sequence(scope.get("requested_relations", scope.get("relations", ())), "requested_relations")),
                effective_relations=frozenset(str(item) for item in _sequence(scope.get("effective_relations", scope.get("relations", ())), "effective_relations")),
                rejected_relations=frozenset(str(item) for item in _sequence(scope.get("rejected_relations", ()), "rejected_relations")),
                max_depth=None if scope.get("max_depth") is None else int(scope["max_depth"]),
                max_paths=None if scope.get("max_paths") is None else int(scope["max_paths"]),
                max_expansions=None if scope.get("max_expansions") is None else int(scope["max_expansions"]),
                stop_nodes=frozenset(str(item) for item in _sequence(scope.get("stop_nodes", ()), "stop_nodes")),
                evidence_namespace=str(scope.get("evidence_namespace") or "default"),
            ),
            coverage=CoverageCertificate(
                coverage=str(certificate.get("coverage") or "UNKNOWN"),
                complete_supported_search=certificate.get("complete_supported_search") is True,
                termination_reason=str(certificate.get("termination_reason") or "UNKNOWN"),
                truncated=certificate.get("truncated") is True,
                details=_mapping(certificate.get("details", {}), "coverage.details"),
            ),
            facts=GraphFacts(
                nodes=tuple(_graph_evidence_from_dict(item) for item in _sequence(facts.get("nodes", ()), "nodes")),
                edges=tuple(_graph_evidence_from_dict(item) for item in _sequence(facts.get("edges", ()), "edges")),
                blockers=tuple(_graph_blocker_from_dict(item) for item in _sequence(facts.get("blockers", ()), "blockers")),
                absence_subjects=tuple(str(item) for item in _sequence(facts.get("absence_subjects", ()), "absence_subjects")),
            ),
        )
    except CodeGraphObservationError:
        raise
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
