from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field, replace
from enum import Enum
import hashlib
import heapq
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Iterable, Mapping

from .bundle import (
    BundleValidationError,
    VerificationBundle,
    _canonical_evidence,
    _canonical_json,
    _canonical_value,
    _freeze_value,
    validate_verification_bundle,
)
from .ledger import ClaimDefinition, ClaimLedger, VerificationSnapshot
from .model import Freshness, VerificationReport, VerificationVerdict

if TYPE_CHECKING:
    from .capabilities import VerifierCapability, VerifierCapabilityRegistry


CLAIM_GRAPH_SCHEMA_VERSION = 1
CLAIM_GRAPH_KIND = "gvr.claim_graph"
VERIFICATION_SESSION_SCHEMA_VERSION = 1
VERIFICATION_SESSION_KIND = "gvr.verification_session"
COMPOSITE_CLAIM_VERIFIER = "gvr.claim_graph.composite.v1"


class ClaimGraphValidationError(ValueError):
    """Raised when a claim graph is ambiguous, incomplete, or cyclic."""


class VerificationSessionError(ValueError):
    """Raised when supplied session state is inconsistent with its ClaimGraph."""


class ClaimOperator(str, Enum):
    AND = "AND"
    OR = "OR"
    NOT = "NOT"


class SessionTermination(str, Enum):
    COMPLETE = "COMPLETE"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    UNSUPPORTED_CLAIM = "UNSUPPORTED_CLAIM"


def _non_empty_string(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ClaimGraphValidationError(f"{name} must be a non-empty string")
    return value


def _dependency_ids(values: Iterable[str], *, owner: str) -> tuple[str, ...]:
    dependencies = tuple(values)
    if any(not isinstance(item, str) or not item for item in dependencies):
        raise ClaimGraphValidationError(
            f"claim {owner} dependencies must contain non-empty strings"
        )
    if len(set(dependencies)) != len(dependencies):
        raise ClaimGraphValidationError(
            f"claim {owner} dependencies contain duplicate IDs"
        )
    return tuple(sorted(dependencies))


def _strict_semantic_mapping(value: Any, *, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ClaimGraphValidationError(f"{path} must be a mapping")
    try:
        return _freeze_value(value, path=path)
    except BundleValidationError as exc:
        raise ClaimGraphValidationError(str(exc)) from exc


@dataclass(frozen=True, kw_only=True)
class AtomicClaim:
    """An immutable verifier-bound atomic claim semantic definition."""

    claim_id: str
    claim_kind: str
    spec: Mapping[str, Any]
    verifier: str
    scope: Mapping[str, Any] = field(default_factory=dict)
    dependencies: tuple[str, ...] = ()
    description: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "claim_id", _non_empty_string(self.claim_id, name="claim_id"))
        object.__setattr__(
            self,
            "claim_kind",
            _non_empty_string(self.claim_kind, name=f"claim {self.claim_id} kind"),
        )
        object.__setattr__(
            self,
            "verifier",
            _non_empty_string(self.verifier, name=f"claim {self.claim_id} verifier"),
        )
        object.__setattr__(
            self,
            "spec",
            _strict_semantic_mapping(self.spec, path=f"claim[{self.claim_id}].spec"),
        )
        object.__setattr__(
            self,
            "scope",
            _strict_semantic_mapping(self.scope, path=f"claim[{self.claim_id}].scope"),
        )
        object.__setattr__(
            self,
            "dependencies",
            _dependency_ids(self.dependencies, owner=self.claim_id),
        )
        if self.description is not None and not isinstance(self.description, str):
            raise ClaimGraphValidationError(
                f"claim {self.claim_id} description must be a string"
            )

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "node_type": "ATOMIC",
            "claim_id": self.claim_id,
            "claim_kind": self.claim_kind,
            "spec": _canonical_value(self.spec, path=f"claim[{self.claim_id}].spec"),
            "verifier": self.verifier,
            "scope": _canonical_value(self.scope, path=f"claim[{self.claim_id}].scope"),
            "dependencies": list(self.dependencies),
        }

    def validate_capability(
        self,
        registry: VerifierCapabilityRegistry,
        *,
        version: str | None = None,
    ) -> VerifierCapability:
        """Validate this exact verifier binding without selecting a substitute."""

        return registry.validate_atomic_claim(self, version=version)


@dataclass(frozen=True, kw_only=True)
class CompositeClaim:
    """A deterministic derived claim using exact tri-state logic."""

    claim_id: str
    operator: ClaimOperator
    dependencies: tuple[str, ...]
    description: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "claim_id", _non_empty_string(self.claim_id, name="claim_id"))
        try:
            operator = (
                self.operator
                if isinstance(self.operator, ClaimOperator)
                else ClaimOperator(str(self.operator))
            )
        except ValueError as exc:
            raise ClaimGraphValidationError(
                f"claim {self.claim_id} operator is not supported"
            ) from exc
        object.__setattr__(self, "operator", operator)
        dependencies = _dependency_ids(self.dependencies, owner=self.claim_id)
        if operator is ClaimOperator.NOT and len(dependencies) != 1:
            raise ClaimGraphValidationError(
                f"NOT claim {self.claim_id} requires exactly one dependency"
            )
        if operator in (ClaimOperator.AND, ClaimOperator.OR) and len(dependencies) < 2:
            raise ClaimGraphValidationError(
                f"{operator.value} claim {self.claim_id} requires at least two dependencies"
            )
        object.__setattr__(self, "dependencies", dependencies)
        if self.description is not None and not isinstance(self.description, str):
            raise ClaimGraphValidationError(
                f"claim {self.claim_id} description must be a string"
            )

    def semantic_definition(self) -> dict[str, Any]:
        return {
            "node_type": "COMPOSITE",
            "claim_id": self.claim_id,
            "operator": self.operator.value,
            "dependencies": list(self.dependencies),
        }


ClaimNode = AtomicClaim | CompositeClaim


@dataclass(frozen=True, kw_only=True)
class ClaimGraph:
    """Canonical immutable atomic/composite claim graph."""

    nodes: tuple[ClaimNode, ...]
    schema_version: int = CLAIM_GRAPH_SCHEMA_VERSION
    kind: str = CLAIM_GRAPH_KIND
    fingerprint: str = field(init=False)
    _by_id: Mapping[str, ClaimNode] = field(init=False, repr=False, compare=False)
    _evaluation_order: tuple[str, ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.schema_version != CLAIM_GRAPH_SCHEMA_VERSION:
            raise ClaimGraphValidationError(
                f"unsupported claim graph schema version {self.schema_version}"
            )
        if self.kind != CLAIM_GRAPH_KIND:
            raise ClaimGraphValidationError(f"unsupported claim graph kind {self.kind}")

        by_id: dict[str, ClaimNode] = {}
        for node in tuple(self.nodes):
            if not isinstance(node, (AtomicClaim, CompositeClaim)):
                raise ClaimGraphValidationError(
                    "claim graph nodes must be AtomicClaim or CompositeClaim records"
                )
            previous = by_id.get(node.claim_id)
            if previous is not None and previous != node:
                raise ClaimGraphValidationError(
                    f"duplicate claim ID {node.claim_id} has different or ambiguous semantics"
                )
            by_id.setdefault(node.claim_id, node)

        canonical_nodes = tuple(by_id[claim_id] for claim_id in sorted(by_id))
        object.__setattr__(self, "nodes", canonical_nodes)
        object.__setattr__(
            self,
            "_by_id",
            MappingProxyType({
                claim_id: by_id[claim_id]
                for claim_id in sorted(by_id)
            }),
        )

        known = set(by_id)
        for node in canonical_nodes:
            for dependency in node.dependencies:
                if dependency == node.claim_id:
                    raise ClaimGraphValidationError(
                        f"claim {node.claim_id} has a self-dependency"
                    )
                if dependency not in known:
                    raise ClaimGraphValidationError(
                        f"claim {node.claim_id} references unknown dependency {dependency}"
                    )

        indegree = {
            node.claim_id: len(node.dependencies)
            for node in canonical_nodes
        }
        dependents: dict[str, list[str]] = {claim_id: [] for claim_id in known}
        for node in canonical_nodes:
            for dependency in node.dependencies:
                dependents[dependency].append(node.claim_id)
        ready = [claim_id for claim_id, count in indegree.items() if count == 0]
        heapq.heapify(ready)
        order: list[str] = []
        while ready:
            claim_id = heapq.heappop(ready)
            order.append(claim_id)
            for dependent in sorted(dependents[claim_id]):
                indegree[dependent] -= 1
                if indegree[dependent] == 0:
                    heapq.heappush(ready, dependent)
        if len(order) != len(canonical_nodes):
            cyclic = ", ".join(sorted(claim_id for claim_id, count in indegree.items() if count))
            raise ClaimGraphValidationError(f"claim dependency cycle detected: {cyclic}")
        object.__setattr__(self, "_evaluation_order", tuple(order))

        canonical = _canonical_json(self.semantic_definition)
        object.__setattr__(
            self,
            "fingerprint",
            hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        )

    @property
    def semantic_definition(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "nodes": [node.semantic_definition() for node in self.nodes],
        }

    @property
    def evaluation_order(self) -> tuple[str, ...]:
        return self._evaluation_order

    @property
    def atomic_claims(self) -> tuple[AtomicClaim, ...]:
        return tuple(node for node in self.nodes if isinstance(node, AtomicClaim))

    @property
    def composite_claims(self) -> tuple[CompositeClaim, ...]:
        return tuple(node for node in self.nodes if isinstance(node, CompositeClaim))

    def claim(self, claim_id: str) -> ClaimNode:
        try:
            return self._by_id[claim_id]
        except KeyError as exc:
            raise KeyError(f"unknown claim: {claim_id}") from exc

    def __deepcopy__(self, _memo: dict[int, Any]) -> ClaimGraph:
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.semantic_definition,
            "fingerprint": self.fingerprint,
        }


def compose_claim_verdict(
    operator: ClaimOperator,
    verdicts: Iterable[VerificationVerdict],
) -> VerificationVerdict:
    """Apply exact GVR PASS/FAIL/UNKNOWN logic without confidence arithmetic."""

    values = tuple(verdicts)
    if operator is ClaimOperator.AND:
        if VerificationVerdict.FAIL in values:
            return VerificationVerdict.FAIL
        if VerificationVerdict.UNKNOWN in values:
            return VerificationVerdict.UNKNOWN
        return VerificationVerdict.PASS
    if operator is ClaimOperator.OR:
        if VerificationVerdict.PASS in values:
            return VerificationVerdict.PASS
        if VerificationVerdict.UNKNOWN in values:
            return VerificationVerdict.UNKNOWN
        return VerificationVerdict.FAIL
    if operator is ClaimOperator.NOT:
        value = values[0]
        if value is VerificationVerdict.PASS:
            return VerificationVerdict.FAIL
        if value is VerificationVerdict.FAIL:
            return VerificationVerdict.PASS
        return VerificationVerdict.UNKNOWN
    raise ValueError(f"unsupported claim operator {operator!r}")


def _budget_value(value: int | None, *, name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise VerificationSessionError(f"{name} must be a non-negative integer or null")
    return value


@dataclass(frozen=True, kw_only=True)
class SessionBudget:
    max_claims: int | None = None
    max_bundles: int | None = None
    max_evidence_records: int | None = None
    max_evidence_bytes: int | None = None
    max_steps: int | None = None

    def __post_init__(self) -> None:
        for name in (
            "max_claims",
            "max_bundles",
            "max_evidence_records",
            "max_evidence_bytes",
            "max_steps",
        ):
            object.__setattr__(self, name, _budget_value(getattr(self, name), name=name))

    def to_dict(self) -> dict[str, int | None]:
        return {
            "max_claims": self.max_claims,
            "max_bundles": self.max_bundles,
            "max_evidence_records": self.max_evidence_records,
            "max_evidence_bytes": self.max_evidence_bytes,
            "max_steps": self.max_steps,
        }


@dataclass(frozen=True, kw_only=True)
class SessionConsumption:
    claims: int = 0
    bundles: int = 0
    evidence_records: int = 0
    evidence_bytes: int = 0
    steps: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "claims": self.claims,
            "bundles": self.bundles,
            "evidence_records": self.evidence_records,
            "evidence_bytes": self.evidence_bytes,
            "steps": self.steps,
        }


@dataclass(frozen=True, kw_only=True)
class SessionClaimState:
    claim_id: str
    stored_verdict: VerificationVerdict
    effective_verdict: VerificationVerdict
    freshness: Freshness
    version: int
    bundle_fingerprint: str | None = None
    evidence_ids: tuple[str, ...] = ()
    claim_dependency_ids: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class _AtomicVerificationRef:
    fingerprint: str
    evidence_ids: tuple[str, ...]
    claim_dependency_ids: tuple[str, ...]


class VerificationSession:
    """Deterministic session state composed from materialized VerificationBundles."""

    __slots__ = (
        "_graph",
        "_roots",
        "_budget",
        "_ledger",
        "_bundle_refs",
        "_operational_versions",
        "_semantic_versions",
        "_budget_exhausted",
        "_consumption",
    )

    schema_version = VERIFICATION_SESSION_SCHEMA_VERSION
    kind = VERIFICATION_SESSION_KIND

    def __init__(
        self,
        *,
        graph: ClaimGraph,
        roots: Iterable[str],
        budget: SessionBudget | None = None,
    ) -> None:
        if not isinstance(graph, ClaimGraph):
            raise VerificationSessionError("graph must be a ClaimGraph")
        root_values = tuple(roots)
        if any(not isinstance(root, str) or not root for root in root_values):
            raise VerificationSessionError("roots must contain non-empty strings")
        if not root_values:
            raise VerificationSessionError("at least one root claim is required")
        if len(set(root_values)) != len(root_values):
            raise VerificationSessionError("roots contain duplicate IDs")
        unknown_roots = set(root_values) - {node.claim_id for node in graph.nodes}
        if unknown_roots:
            raise VerificationSessionError(
                "roots reference unknown claims: " + ", ".join(sorted(unknown_roots))
            )
        if budget is not None and not isinstance(budget, SessionBudget):
            raise VerificationSessionError("budget must be a SessionBudget")

        self._graph = graph
        self._roots = tuple(sorted(root_values))
        self._budget = SessionBudget() if budget is None else budget
        self._ledger = ClaimLedger()
        self._bundle_refs: dict[str, _AtomicVerificationRef] = {}
        self._operational_versions = {
            node.claim_id: 0
            for node in graph.nodes
        }
        self._semantic_versions = {
            node.claim_id: 0
            for node in graph.nodes
        }
        self._budget_exhausted = False
        self._consumption = SessionConsumption()

        for node in graph.nodes:
            verifier = (
                node.verifier
                if isinstance(node, AtomicClaim)
                else COMPOSITE_CLAIM_VERIFIER
            )
            self._ledger.define(ClaimDefinition(
                id=node.claim_id,
                statement=_canonical_json(node.semantic_definition()),
                verifier=verifier,
            ))

        if (
            self.budget.max_claims is not None
            and len(graph.nodes) > self.budget.max_claims
        ):
            self._budget_exhausted = True
        else:
            self._consumption = replace(
                self._consumption,
                claims=len(graph.nodes),
            )

    @property
    def graph(self) -> ClaimGraph:
        return self._graph

    @property
    def roots(self) -> tuple[str, ...]:
        return self._roots

    @property
    def budget(self) -> SessionBudget:
        return self._budget

    @property
    def ledger(self) -> ClaimLedger:
        """Return a defensive ledger snapshot; trusted writes go through session APIs."""

        return deepcopy(self._ledger)

    @classmethod
    def compose(
        cls,
        *,
        graph: ClaimGraph,
        roots: Iterable[str],
        bundles: Mapping[str, VerificationBundle] | None = None,
        budget: SessionBudget | None = None,
    ) -> VerificationSession:
        if bundles is not None and not isinstance(bundles, Mapping):
            raise VerificationSessionError("bundles must be a mapping by atomic claim ID")
        session = cls(graph=graph, roots=roots, budget=budget)
        supplied = {} if bundles is None else dict(bundles)
        for claim_id in sorted(supplied):
            session._validate_bundle(claim_id, supplied[claim_id])

        for claim_id in graph.evaluation_order:
            if session._budget_exhausted:
                break
            node = graph.claim(claim_id)
            if isinstance(node, AtomicClaim):
                bundle = supplied.get(claim_id)
                if bundle is None:
                    session._consume_empty_step()
                else:
                    session.record_bundle(claim_id, bundle)
            else:
                session._recompute_claim(node)
        return session

    @property
    def consumption(self) -> SessionConsumption:
        return self._consumption

    def _step_available(self) -> bool:
        return (
            self.budget.max_steps is None
            or self._consumption.steps + 1 <= self.budget.max_steps
        )

    def _consume_empty_step(self) -> bool:
        if not self._step_available():
            self._budget_exhausted = True
            return False
        self._consumption = replace(
            self._consumption,
            steps=self._consumption.steps + 1,
        )
        return True

    @staticmethod
    def _evidence_bytes(bundle: VerificationBundle) -> int:
        canonical = _canonical_json([
            _canonical_evidence(evidence)
            for evidence in bundle.evidence
        ])
        return len(canonical.encode("utf-8"))

    def _bundle_budget_available(
        self,
        bundle: VerificationBundle,
    ) -> tuple[bool, int]:
        evidence_bytes = self._evidence_bytes(bundle)
        checks = (
            (self.budget.max_bundles, self._consumption.bundles + 1),
            (
                self.budget.max_evidence_records,
                self._consumption.evidence_records + len(bundle.evidence),
            ),
            (
                self.budget.max_evidence_bytes,
                self._consumption.evidence_bytes + evidence_bytes,
            ),
        )
        return all(limit is None or value <= limit for limit, value in checks), evidence_bytes

    def _validate_bundle(
        self,
        claim_id: str,
        bundle: VerificationBundle,
    ) -> AtomicClaim:
        try:
            node = self.graph.claim(claim_id)
        except KeyError as exc:
            raise VerificationSessionError(
                f"bundle references unknown claim {claim_id}"
            ) from exc
        if not isinstance(node, AtomicClaim):
            raise VerificationSessionError(
                f"bundle claim {claim_id} is not atomic"
            )
        validate_verification_bundle(bundle)
        if bundle.verifier != node.verifier:
            raise VerificationSessionError(
                f"bundle verifier {bundle.verifier} does not match claim {claim_id} verifier {node.verifier}"
            )
        if bundle.claim_dependency_ids != node.dependencies:
            raise VerificationSessionError(
                f"bundle claim dependencies for {claim_id} do not match ClaimGraph"
            )
        return node

    def record_bundle(
        self,
        claim_id: str,
        bundle: VerificationBundle,
    ) -> VerificationSnapshot | None:
        self._validate_bundle(claim_id, bundle)
        bundle_available, evidence_bytes = self._bundle_budget_available(bundle)
        if not self._step_available() or not bundle_available:
            self._budget_exhausted = True
            return None

        snapshot = self._ledger.record_bundle(claim_id, bundle)
        self._record_semantic_version(snapshot)
        self._bundle_refs[claim_id] = _AtomicVerificationRef(
            fingerprint=bundle.fingerprint,
            evidence_ids=bundle.report.evidence_ids,
            claim_dependency_ids=bundle.claim_dependency_ids,
        )
        self._consumption = replace(
            self._consumption,
            bundles=self._consumption.bundles + 1,
            evidence_records=self._consumption.evidence_records + len(bundle.evidence),
            evidence_bytes=self._consumption.evidence_bytes + evidence_bytes,
            steps=self._consumption.steps + 1,
        )
        return snapshot

    def _record_semantic_version(self, snapshot: VerificationSnapshot) -> None:
        """Advance a claim-local semantic version from raw ledger operations."""

        claim_id = snapshot.claim_id
        if snapshot.claim_version == self._operational_versions[claim_id]:
            return
        self._operational_versions[claim_id] = snapshot.claim_version
        self._semantic_versions[claim_id] += 1

    def _effective_verdicts(self) -> dict[str, VerificationVerdict]:
        effective: dict[str, VerificationVerdict] = {}
        for claim_id in self.graph.evaluation_order:
            node = self.graph.claim(claim_id)
            status = self._ledger.status(claim_id)
            verdict = status.effective_verdict
            if isinstance(node, AtomicClaim) and verdict is not VerificationVerdict.UNKNOWN:
                if any(
                    effective[dependency] is VerificationVerdict.UNKNOWN
                    for dependency in node.dependencies
                ):
                    verdict = VerificationVerdict.UNKNOWN
            effective[claim_id] = verdict
        return effective

    def _recompute_claim(
        self,
        node: CompositeClaim,
    ) -> VerificationSnapshot | None:
        if not self._step_available():
            self._budget_exhausted = True
            return None

        dependency_statuses = [
            self._ledger.status(dependency)
            for dependency in node.dependencies
        ]
        if any(status.freshness is Freshness.STALE for status in dependency_statuses):
            self._consumption = replace(
                self._consumption,
                steps=self._consumption.steps + 1,
            )
            return None

        effective = self._effective_verdicts()
        verdict = compose_claim_verdict(
            node.operator,
            (effective[dependency] for dependency in node.dependencies),
        )
        snapshot = self._ledger.record_verification(
            node.claim_id,
            VerificationReport(
                verdict=verdict,
                verifier=COMPOSITE_CLAIM_VERIFIER,
                metadata={
                    "operator": node.operator.value,
                    "dependencies": node.dependencies,
                },
            ),
            claim_dependency_ids=node.dependencies,
        )
        self._record_semantic_version(snapshot)
        self._consumption = replace(
            self._consumption,
            steps=self._consumption.steps + 1,
        )
        return snapshot

    def recompute(self) -> None:
        for claim_id in self.graph.evaluation_order:
            if self._budget_exhausted:
                return
            node = self.graph.claim(claim_id)
            if isinstance(node, CompositeClaim):
                self._recompute_claim(node)

    def remove_evidence(self, evidence_id: str) -> None:
        self._ledger.remove_evidence(evidence_id)

    @property
    def claim_states(self) -> tuple[SessionClaimState, ...]:
        effective = self._effective_verdicts()
        states: list[SessionClaimState] = []
        for node in self.graph.nodes:
            status = self._ledger.status(node.claim_id)
            reference = self._bundle_refs.get(node.claim_id)
            states.append(SessionClaimState(
                claim_id=node.claim_id,
                stored_verdict=status.stored_verdict,
                effective_verdict=effective[node.claim_id],
                freshness=status.freshness,
                version=self._semantic_versions[node.claim_id],
                bundle_fingerprint=(None if reference is None else reference.fingerprint),
                evidence_ids=(() if reference is None else reference.evidence_ids),
                claim_dependency_ids=(
                    node.dependencies
                    if reference is None
                    else reference.claim_dependency_ids
                ),
            ))
        return tuple(states)

    def claim_state(self, claim_id: str) -> SessionClaimState:
        for state in self.claim_states:
            if state.claim_id == claim_id:
                return state
        raise KeyError(f"unknown claim: {claim_id}")

    @property
    def root_verdicts(self) -> Mapping[str, VerificationVerdict]:
        states = {state.claim_id: state for state in self.claim_states}
        return {
            root: states[root].effective_verdict
            for root in self.roots
        }

    @property
    def unverified_claim_ids(self) -> tuple[str, ...]:
        return tuple(
            node.claim_id
            for node in self.graph.atomic_claims
            if node.claim_id not in self._bundle_refs
            or self._ledger.status(node.claim_id).freshness is Freshness.STALE
        )

    @property
    def termination_reason(self) -> SessionTermination:
        if self._budget_exhausted:
            return SessionTermination.BUDGET_EXHAUSTED
        if self.unverified_claim_ids or any(
            state.freshness is Freshness.STALE
            for state in self.claim_states
        ):
            return SessionTermination.UNSUPPORTED_CLAIM
        return SessionTermination.COMPLETE

    def _atomic_verifications(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for node in self.graph.atomic_claims:
            reference = self._bundle_refs.get(node.claim_id)
            items.append({
                "claim_id": node.claim_id,
                "bundle_fingerprint": (
                    None if reference is None else reference.fingerprint
                ),
                "evidence_ids": (
                    [] if reference is None else list(reference.evidence_ids)
                ),
                "claim_dependency_ids": (
                    list(node.dependencies)
                    if reference is None
                    else list(reference.claim_dependency_ids)
                ),
                "verified": reference is not None,
            })
        return items

    def _semantic_basis(self) -> dict[str, Any]:
        """Return canonical identity state without operational ledger clocks."""

        return _canonical_value({
            "schema_version": self.schema_version,
            "kind": self.kind,
            "claim_graph": self.graph.to_dict(),
            "roots": list(self.roots),
            "atomic_verifications": self._atomic_verifications(),
            "claims": [
                {
                    "claim_id": state.claim_id,
                    "stored_verdict": state.stored_verdict.value,
                    "effective_verdict": state.effective_verdict.value,
                    "freshness": state.freshness.value,
                    "version": state.version,
                    "bundle_fingerprint": state.bundle_fingerprint,
                    "evidence_ids": list(state.evidence_ids),
                    "claim_dependency_ids": list(state.claim_dependency_ids),
                }
                for state in self.claim_states
            ],
            "root_verdicts": {
                root: verdict.value
                for root, verdict in self.root_verdicts.items()
            },
            "unverified_claim_ids": list(self.unverified_claim_ids),
            "budget": {
                "declaration": self.budget.to_dict(),
                "consumed": self.consumption.to_dict(),
            },
            "termination_reason": self.termination_reason.value,
        }, path="verification_session")

    @property
    def fingerprint(self) -> str:
        canonical = _canonical_json(self._semantic_basis())
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Return the public semantic contract, excluding raw ledger history."""

        document = self._semantic_basis()
        document["fingerprint"] = self.fingerprint
        return document
