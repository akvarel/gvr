from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ContextManager, Mapping, Protocol, runtime_checkable

from .bundle import VerificationBundle
from .falsification import FalsificationResult
from .ledger import ClaimDefinition
from .model import Evidence, VerificationReport, VerificationVerdict
from .session import VerificationSession


DURABLE_STORAGE_SCHEMA_VERSION = 1
DURABLE_STORAGE_SCHEMA_TABLE = "gvr_storage_schema"


class StorageError(RuntimeError):
    """Base class for durable storage failures."""


class StorageNotFoundError(StorageError, KeyError):
    """Raised when a requested durable object does not exist."""


class StorageConflictError(StorageError, ValueError):
    """Raised when one immutable identity is presented with conflicting content."""


class StorageIntegrityError(StorageError, ValueError):
    """Raised when persisted canonical content or links fail verification."""


class StoredTruthError(StorageIntegrityError):
    """Raised when a write could create a PASS without a complete stored basis."""


class StorageSchemaVersionError(StorageError):
    """Raised when the database schema is newer than this implementation."""


class StorageMigrationError(StorageError):
    """Raised when transactional schema bootstrap or migration fails."""


@dataclass(frozen=True)
class EvidenceSlotVersion:
    slot_id: str
    version: int
    evidence_fingerprint: str
    previous_version: int | None
    current: bool

    @property
    def object_key(self) -> str:
        return f"slot-version:{self.slot_id}:{self.version}"


@dataclass(frozen=True)
class StoredEvidence:
    fingerprint: str
    evidence: Evidence
    canonical_payload: str
    provenance: Mapping[str, Any]
    source_snapshot: Mapping[str, Any]
    bounds: Mapping[str, Any]
    coverage: Mapping[str, Any]
    slot_id: str | None = None
    slot_version: int | None = None


@dataclass(frozen=True)
class StoredBundle:
    fingerprint: str
    bundle: VerificationBundle
    evidence_slots: tuple[EvidenceSlotVersion, ...]
    current: bool

    @property
    def object_key(self) -> str:
        return f"bundle:{self.fingerprint}"


@dataclass(frozen=True)
class StoredClaimDefinition:
    definition: ClaimDefinition
    verifier_version: str
    fingerprint: str


@dataclass(frozen=True)
class StoredClaimVersion:
    claim_id: str
    version: int
    verdict: VerificationVerdict
    verifier_id: str
    verifier_version: str
    bundle_fingerprint: str | None
    report: VerificationReport
    basis_fingerprint: str
    evidence_slots: tuple[EvidenceSlotVersion, ...]
    claim_dependency_versions: tuple[tuple[str, int], ...]
    falsification_fingerprints: tuple[str, ...]
    current: bool

    @property
    def object_key(self) -> str:
        return f"claim-version:{self.claim_id}:{self.version}"


@dataclass(frozen=True)
class StoredClaimStatus:
    claim_id: str
    current_version: int
    stored_verdict: VerificationVerdict
    effective_verdict: VerificationVerdict
    current: bool


@dataclass(frozen=True)
class StoredFalsificationResult:
    fingerprint: str
    result: FalsificationResult
    evidence_slots: tuple[EvidenceSlotVersion, ...]
    current: bool

    @property
    def object_key(self) -> str:
        return f"falsification:{self.fingerprint}"


@dataclass(frozen=True)
class StoredSession:
    fingerprint: str
    session_document: Mapping[str, Any]
    graph_fingerprint: str
    plan_fingerprint: str | None
    execution_fingerprint: str | None
    execution_document: Mapping[str, Any] | None
    termination: str
    counters: Mapping[str, Any]
    claim_versions: tuple[tuple[str, int], ...]
    bundle_fingerprints: tuple[str, ...]
    falsification_fingerprints: tuple[str, ...]
    current: bool

    @property
    def object_key(self) -> str:
        return f"session:{self.fingerprint}"


@dataclass(frozen=True)
class InvalidationEvent:
    event_id: str
    kind: str
    cause_object: str
    replacement_object: str
    targets: tuple[str, ...]


@runtime_checkable
class EvidenceStore(Protocol):
    def put_evidence(
        self,
        evidence: Evidence,
        *,
        slot_id: str | None = None,
        provenance: Mapping[str, Any] | None = None,
        source_snapshot: Mapping[str, Any] | None = None,
        bounds: Mapping[str, Any] | None = None,
        coverage: Mapping[str, Any] | None = None,
        expected_fingerprint: str | None = None,
    ) -> StoredEvidence: ...

    def get_evidence(self, fingerprint: str) -> StoredEvidence: ...

    def get_slot(self, slot_id: str) -> EvidenceSlotVersion | None: ...

    def slot_history(self, slot_id: str) -> tuple[EvidenceSlotVersion, ...]: ...


@runtime_checkable
class BundleStore(Protocol):
    def put_bundle(
        self,
        bundle: VerificationBundle,
        *,
        evidence_slots: Mapping[str, EvidenceSlotVersion] | None = None,
    ) -> StoredBundle: ...

    def get_bundle(self, fingerprint: str) -> StoredBundle: ...


@runtime_checkable
class ClaimStore(Protocol):
    def define_claim(
        self,
        definition: ClaimDefinition,
        *,
        verifier_version: str,
    ) -> StoredClaimDefinition: ...

    def record_claim(
        self,
        claim_id: str,
        bundle: VerificationBundle | None,
        *,
        verifier_version: str,
        report: VerificationReport | None = None,
        claim_dependency_ids: tuple[str, ...] | None = None,
        falsification_fingerprints: tuple[str, ...] = (),
    ) -> StoredClaimVersion: ...

    def claim_status(self, claim_id: str) -> StoredClaimStatus: ...

    def claim_history(self, claim_id: str) -> tuple[StoredClaimVersion, ...]: ...


@runtime_checkable
class SessionStore(Protocol):
    def put_session(
        self,
        session: VerificationSession,
        *,
        plan_fingerprint: str | None = None,
        execution_fingerprint: str | None = None,
        execution_document: Mapping[str, Any] | None = None,
        falsification_fingerprints: tuple[str, ...] = (),
    ) -> StoredSession: ...

    def get_session(self, fingerprint: str) -> StoredSession: ...


@runtime_checkable
class DependencyIndex(Protocol):
    def dependents_of(self, object_key: str) -> tuple[str, ...]: ...

    def invalidation_events(self) -> tuple[InvalidationEvent, ...]: ...


@runtime_checkable
class StorageUnitOfWork(
    EvidenceStore,
    BundleStore,
    ClaimStore,
    SessionStore,
    DependencyIndex,
    Protocol,
):
    def record_execution(self, request: Any, result: Any) -> StoredSession: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...


@runtime_checkable
class UnitOfWorkFactory(Protocol):
    def unit_of_work(self) -> ContextManager[StorageUnitOfWork]: ...


def persist_execution_result(target: Any, request: Any, result: Any) -> Any:
    """Persist one completed execution through an explicit store or unit of work.

    The executor deliberately does not discover storage globally. A supplied unit
    of work controls its surrounding transaction. A supplied factory creates one
    transaction covering evidence, bundles, claims, falsification results, and the
    completed session.
    """

    recorder = getattr(target, "record_execution", None)
    if callable(recorder):
        return recorder(request, result)
    factory = getattr(target, "unit_of_work", None)
    if callable(factory):
        with factory() as unit_of_work:
            return unit_of_work.record_execution(request, result)
    raise TypeError("storage must provide record_execution() or unit_of_work()")
