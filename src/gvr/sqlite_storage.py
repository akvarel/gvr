from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from enum import Enum
import hashlib
import json
import math
from pathlib import Path
import sqlite3
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence
import uuid

from .bundle import (
    BundleValidationError,
    VerificationBundle,
    _canonical_json as _bundle_canonical_json,
    validate_verification_bundle,
)
from .canonical import CanonicalizationError, canonical_fingerprint, canonical_json
from .falsification import (
    FalsificationCompleteness,
    FalsificationCoverage,
    FalsificationOutcome,
    FalsificationProbe,
    FalsificationProbeOutcome,
    FalsificationProvenance,
    FalsificationResult,
)
from .evidence_providers import EvidenceSlotIdentity
from .ledger import ClaimDefinition
from .model import (
    INDETERMINATE,
    MISSING,
    Evidence,
    VerificationIssue,
    VerificationReport,
    VerificationVerdict,
)
from .planning import VerificationPlanStepKind
from .session import (
    COMPOSITE_CLAIM_VERIFIER,
    AtomicClaim,
    VerificationSession,
)
from .storage import (
    DURABLE_STORAGE_SCHEMA_TABLE,
    DURABLE_STORAGE_SCHEMA_VERSION,
    EvidenceDependency,
    EvidenceSlotVersion,
    InvalidationEvent,
    StorageConflictError,
    StorageIntegrityError,
    StorageMigrationError,
    StorageNotFoundError,
    StorageSchemaVersionError,
    StoredBundle,
    StoredClaimDefinition,
    StoredClaimStatus,
    StoredClaimVersion,
    StoredEvidence,
    StoredFalsificationResult,
    StoredSession,
    StoredTruthError,
    SessionExecutionObservation,
)


_EVIDENCE_FINGERPRINT_FORMAT = "gvr.storage.evidence.ieee754-json.v1"
_EVIDENCE_PAYLOAD_FORMAT = "gvr.storage.evidence_payload.ieee754-json.v1"
_STORAGE_DOCUMENT_FORMAT = "gvr.storage.document.ieee754-json.v1"
_CLAIM_DEFINITION_FORMAT = "gvr.storage.claim_definition.ieee754-json.v1"
_CLAIM_BASIS_FORMAT = "gvr.storage.claim_basis.ieee754-json.v1"
_INVALIDATION_EVENT_FORMAT = "gvr.storage.invalidation_event.ieee754-json.v1"
_SLOT_IDENTITY_FORMAT = "gvr.storage.evidence_slot_identity.ieee754-json.v1"
_BUNDLE_RECORD_FORMAT = "gvr.storage.bundle_record.ieee754-json.v1"
_FALSIFICATION_RECORD_FORMAT = "gvr.storage.falsification_record.ieee754-json.v1"
_SESSION_RECORD_FORMAT = "gvr.storage.session_record.ieee754-json.v1"
_SESSION_OBSERVATION_FORMAT = "gvr.storage.session_observation.ieee754-json.v1"


_MIGRATION_1: tuple[str, ...] = (
    """
    CREATE TABLE evidence_artifacts (
        fingerprint TEXT PRIMARY KEY,
        content_json TEXT NOT NULL,
        canonical_json TEXT NOT NULL,
        payload_canonical_json TEXT NOT NULL,
        content_digest TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE evidence_slot_versions (
        slot_id TEXT NOT NULL,
        version INTEGER NOT NULL CHECK (version > 0),
        evidence_fingerprint TEXT NOT NULL,
        previous_version INTEGER,
        PRIMARY KEY (slot_id, version),
        FOREIGN KEY (evidence_fingerprint)
            REFERENCES evidence_artifacts(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    """
    CREATE TABLE evidence_slots (
        slot_id TEXT PRIMARY KEY,
        current_version INTEGER NOT NULL CHECK (current_version > 0),
        current_evidence_fingerprint TEXT NOT NULL,
        FOREIGN KEY (slot_id, current_version)
            REFERENCES evidence_slot_versions(slot_id, version)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (current_evidence_fingerprint)
            REFERENCES evidence_artifacts(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    "CREATE INDEX idx_evidence_slot_versions_fingerprint ON evidence_slot_versions(evidence_fingerprint)",
    """
    CREATE TABLE bundles (
        fingerprint TEXT PRIMARY KEY,
        content_json TEXT NOT NULL,
        canonical_json TEXT NOT NULL,
        content_digest TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE bundle_evidence_links (
        bundle_fingerprint TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        evidence_fingerprint TEXT NOT NULL,
        slot_id TEXT NOT NULL,
        slot_version INTEGER NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (bundle_fingerprint, evidence_id),
        UNIQUE (bundle_fingerprint, ordinal),
        FOREIGN KEY (bundle_fingerprint)
            REFERENCES bundles(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (evidence_fingerprint)
            REFERENCES evidence_artifacts(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (slot_id, slot_version)
            REFERENCES evidence_slot_versions(slot_id, version)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    "CREATE INDEX idx_bundle_evidence_slot ON bundle_evidence_links(slot_id, slot_version)",
    """
    CREATE TABLE bundle_claim_links (
        bundle_fingerprint TEXT NOT NULL,
        claim_dependency_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (bundle_fingerprint, claim_dependency_id),
        UNIQUE (bundle_fingerprint, ordinal),
        FOREIGN KEY (bundle_fingerprint)
            REFERENCES bundles(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    """
    CREATE TABLE claim_definitions (
        claim_id TEXT PRIMARY KEY,
        verifier_id TEXT NOT NULL,
        verifier_version TEXT NOT NULL,
        fingerprint TEXT NOT NULL UNIQUE,
        content_json TEXT NOT NULL,
        canonical_json TEXT NOT NULL,
        content_digest TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE claim_versions (
        claim_id TEXT NOT NULL,
        version INTEGER NOT NULL CHECK (version > 0),
        verdict TEXT NOT NULL CHECK (verdict IN ('PASS', 'FAIL', 'UNKNOWN')),
        verifier_id TEXT NOT NULL,
        verifier_version TEXT NOT NULL,
        bundle_fingerprint TEXT,
        basis_fingerprint TEXT NOT NULL,
        content_json TEXT NOT NULL,
        canonical_json TEXT NOT NULL,
        content_digest TEXT NOT NULL,
        PRIMARY KEY (claim_id, version),
        FOREIGN KEY (claim_id)
            REFERENCES claim_definitions(claim_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (bundle_fingerprint)
            REFERENCES bundles(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    """
    CREATE TABLE claims (
        claim_id TEXT PRIMARY KEY,
        current_version INTEGER NOT NULL CHECK (current_version > 0),
        FOREIGN KEY (claim_id)
            REFERENCES claim_definitions(claim_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (claim_id, current_version)
            REFERENCES claim_versions(claim_id, version)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    """
    CREATE TABLE claim_evidence_links (
        claim_id TEXT NOT NULL,
        claim_version INTEGER NOT NULL,
        evidence_fingerprint TEXT NOT NULL,
        slot_id TEXT NOT NULL,
        slot_version INTEGER NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (claim_id, claim_version, slot_id, slot_version),
        UNIQUE (claim_id, claim_version, ordinal),
        FOREIGN KEY (claim_id, claim_version)
            REFERENCES claim_versions(claim_id, version)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (evidence_fingerprint)
            REFERENCES evidence_artifacts(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (slot_id, slot_version)
            REFERENCES evidence_slot_versions(slot_id, version)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    "CREATE INDEX idx_claim_evidence_slot ON claim_evidence_links(slot_id, slot_version)",
    """
    CREATE TABLE claim_dependency_links (
        claim_id TEXT NOT NULL,
        claim_version INTEGER NOT NULL,
        dependency_claim_id TEXT NOT NULL,
        dependency_claim_version INTEGER NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (claim_id, claim_version, dependency_claim_id),
        UNIQUE (claim_id, claim_version, ordinal),
        FOREIGN KEY (claim_id, claim_version)
            REFERENCES claim_versions(claim_id, version)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (dependency_claim_id, dependency_claim_version)
            REFERENCES claim_versions(claim_id, version)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    "CREATE INDEX idx_claim_dependencies_reverse ON claim_dependency_links(dependency_claim_id, dependency_claim_version)",
    """
    CREATE TABLE falsification_results (
        fingerprint TEXT PRIMARY KEY,
        content_json TEXT NOT NULL,
        canonical_json TEXT NOT NULL,
        content_digest TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE falsification_evidence_links (
        falsification_fingerprint TEXT NOT NULL,
        evidence_fingerprint TEXT NOT NULL,
        slot_id TEXT NOT NULL,
        slot_version INTEGER NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (falsification_fingerprint, slot_id, slot_version),
        UNIQUE (falsification_fingerprint, ordinal),
        FOREIGN KEY (falsification_fingerprint)
            REFERENCES falsification_results(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (evidence_fingerprint)
            REFERENCES evidence_artifacts(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (slot_id, slot_version)
            REFERENCES evidence_slot_versions(slot_id, version)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    "CREATE INDEX idx_falsification_evidence_slot ON falsification_evidence_links(slot_id, slot_version)",
    """
    CREATE TABLE claim_falsification_links (
        claim_id TEXT NOT NULL,
        claim_version INTEGER NOT NULL,
        falsification_fingerprint TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (claim_id, claim_version, falsification_fingerprint),
        UNIQUE (claim_id, claim_version, ordinal),
        FOREIGN KEY (claim_id, claim_version)
            REFERENCES claim_versions(claim_id, version)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (falsification_fingerprint)
            REFERENCES falsification_results(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    """
    CREATE TABLE sessions (
        fingerprint TEXT PRIMARY KEY,
        graph_fingerprint TEXT NOT NULL,
        plan_fingerprint TEXT,
        execution_fingerprint TEXT,
        termination TEXT NOT NULL,
        counters_json TEXT NOT NULL,
        session_content_json TEXT NOT NULL,
        session_canonical_json TEXT NOT NULL,
        session_content_digest TEXT NOT NULL,
        execution_content_json TEXT,
        execution_canonical_json TEXT,
        execution_content_digest TEXT
    )
    """,
    """
    CREATE TABLE session_claim_links (
        session_fingerprint TEXT NOT NULL,
        claim_id TEXT NOT NULL,
        claim_version INTEGER NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (session_fingerprint, claim_id),
        UNIQUE (session_fingerprint, ordinal),
        FOREIGN KEY (session_fingerprint)
            REFERENCES sessions(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (claim_id, claim_version)
            REFERENCES claim_versions(claim_id, version)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    "CREATE INDEX idx_session_claim_reverse ON session_claim_links(claim_id, claim_version)",
    """
    CREATE TABLE session_bundle_links (
        session_fingerprint TEXT NOT NULL,
        bundle_fingerprint TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (session_fingerprint, bundle_fingerprint),
        UNIQUE (session_fingerprint, ordinal),
        FOREIGN KEY (session_fingerprint)
            REFERENCES sessions(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (bundle_fingerprint)
            REFERENCES bundles(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    """
    CREATE TABLE session_falsification_links (
        session_fingerprint TEXT NOT NULL,
        falsification_fingerprint TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (session_fingerprint, falsification_fingerprint),
        UNIQUE (session_fingerprint, ordinal),
        FOREIGN KEY (session_fingerprint)
            REFERENCES sessions(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (falsification_fingerprint)
            REFERENCES falsification_results(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    """
    CREATE TABLE documents (
        document_kind TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        content_json TEXT NOT NULL,
        canonical_json TEXT NOT NULL,
        content_digest TEXT NOT NULL,
        PRIMARY KEY (document_kind, fingerprint)
    )
    """,
    """
    CREATE TABLE object_dependencies (
        dependent_key TEXT NOT NULL,
        dependency_key TEXT NOT NULL,
        relation TEXT NOT NULL,
        PRIMARY KEY (dependent_key, dependency_key, relation)
    )
    """,
    "CREATE INDEX idx_object_dependencies_dependency ON object_dependencies(dependency_key, dependent_key)",
    """
    CREATE TABLE invalidation_events (
        event_id TEXT PRIMARY KEY,
        event_kind TEXT NOT NULL,
        cause_object TEXT NOT NULL,
        replacement_object TEXT NOT NULL,
        content_json TEXT NOT NULL,
        canonical_json TEXT NOT NULL,
        content_digest TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE invalidation_targets (
        event_id TEXT NOT NULL,
        target_key TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (event_id, target_key),
        UNIQUE (event_id, ordinal),
        FOREIGN KEY (event_id)
            REFERENCES invalidation_events(event_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    "CREATE INDEX idx_invalidation_targets_target ON invalidation_targets(target_key, event_id)",
)


_MIGRATION_2: tuple[str, ...] = (
    """
    CREATE TABLE evidence_slot_identities (
        slot_id TEXT PRIMARY KEY,
        identity_kind TEXT NOT NULL,
        identity_fingerprint TEXT,
        authoritative INTEGER NOT NULL CHECK (authoritative IN (0, 1)),
        content_json TEXT NOT NULL,
        canonical_json TEXT NOT NULL,
        content_digest TEXT NOT NULL,
        FOREIGN KEY (slot_id)
            REFERENCES evidence_slots(slot_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    "CREATE INDEX idx_evidence_slot_identity_fingerprint ON evidence_slot_identities(identity_fingerprint)",
    """
    CREATE TABLE bundle_records (
        record_fingerprint TEXT PRIMARY KEY,
        bundle_fingerprint TEXT NOT NULL,
        content_json TEXT NOT NULL,
        canonical_json TEXT NOT NULL,
        content_digest TEXT NOT NULL,
        FOREIGN KEY (bundle_fingerprint)
            REFERENCES bundles(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    "CREATE INDEX idx_bundle_records_domain ON bundle_records(bundle_fingerprint)",
    """
    CREATE TABLE bundle_record_evidence_links (
        record_fingerprint TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        evidence_fingerprint TEXT NOT NULL,
        dependency_kind TEXT NOT NULL CHECK (dependency_kind IN ('IMMUTABLE', 'SLOT')),
        slot_id TEXT,
        slot_version INTEGER,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (record_fingerprint, evidence_id),
        UNIQUE (record_fingerprint, ordinal),
        CHECK (
            (dependency_kind = 'IMMUTABLE' AND slot_id IS NULL AND slot_version IS NULL)
            OR
            (dependency_kind = 'SLOT' AND slot_id IS NOT NULL AND slot_version IS NOT NULL)
        ),
        FOREIGN KEY (record_fingerprint)
            REFERENCES bundle_records(record_fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (evidence_fingerprint)
            REFERENCES evidence_artifacts(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (slot_id, slot_version)
            REFERENCES evidence_slot_versions(slot_id, version)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    "CREATE INDEX idx_bundle_record_slot ON bundle_record_evidence_links(slot_id, slot_version)",
    """
    CREATE TABLE falsification_records (
        record_fingerprint TEXT PRIMARY KEY,
        falsification_fingerprint TEXT NOT NULL,
        content_json TEXT NOT NULL,
        canonical_json TEXT NOT NULL,
        content_digest TEXT NOT NULL,
        FOREIGN KEY (falsification_fingerprint)
            REFERENCES falsification_results(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    "CREATE INDEX idx_falsification_records_domain ON falsification_records(falsification_fingerprint)",
    """
    CREATE TABLE falsification_record_evidence_links (
        record_fingerprint TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        evidence_fingerprint TEXT NOT NULL,
        dependency_kind TEXT NOT NULL CHECK (dependency_kind IN ('IMMUTABLE', 'SLOT')),
        slot_id TEXT,
        slot_version INTEGER,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (record_fingerprint, evidence_id),
        UNIQUE (record_fingerprint, ordinal),
        CHECK (
            (dependency_kind = 'IMMUTABLE' AND slot_id IS NULL AND slot_version IS NULL)
            OR
            (dependency_kind = 'SLOT' AND slot_id IS NOT NULL AND slot_version IS NOT NULL)
        ),
        FOREIGN KEY (record_fingerprint)
            REFERENCES falsification_records(record_fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (evidence_fingerprint)
            REFERENCES evidence_artifacts(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (slot_id, slot_version)
            REFERENCES evidence_slot_versions(slot_id, version)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    "CREATE INDEX idx_falsification_record_slot ON falsification_record_evidence_links(slot_id, slot_version)",
    """
    CREATE TABLE claim_bundle_record_links (
        claim_id TEXT NOT NULL,
        claim_version INTEGER NOT NULL,
        bundle_record_fingerprint TEXT NOT NULL,
        PRIMARY KEY (claim_id, claim_version),
        FOREIGN KEY (claim_id, claim_version)
            REFERENCES claim_versions(claim_id, version)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (bundle_record_fingerprint)
            REFERENCES bundle_records(record_fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    """
    CREATE TABLE claim_evidence_dependency_links (
        claim_id TEXT NOT NULL,
        claim_version INTEGER NOT NULL,
        evidence_id TEXT NOT NULL,
        evidence_fingerprint TEXT NOT NULL,
        dependency_kind TEXT NOT NULL CHECK (dependency_kind IN ('IMMUTABLE', 'SLOT')),
        slot_id TEXT,
        slot_version INTEGER,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (claim_id, claim_version, evidence_id),
        UNIQUE (claim_id, claim_version, ordinal),
        CHECK (
            (dependency_kind = 'IMMUTABLE' AND slot_id IS NULL AND slot_version IS NULL)
            OR
            (dependency_kind = 'SLOT' AND slot_id IS NOT NULL AND slot_version IS NOT NULL)
        ),
        FOREIGN KEY (claim_id, claim_version)
            REFERENCES claim_versions(claim_id, version)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (evidence_fingerprint)
            REFERENCES evidence_artifacts(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (slot_id, slot_version)
            REFERENCES evidence_slot_versions(slot_id, version)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    "CREATE INDEX idx_claim_evidence_dependency_slot ON claim_evidence_dependency_links(slot_id, slot_version)",
    """
    CREATE TABLE claim_falsification_record_links (
        claim_id TEXT NOT NULL,
        claim_version INTEGER NOT NULL,
        falsification_fingerprint TEXT NOT NULL,
        falsification_record_fingerprint TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (claim_id, claim_version, falsification_record_fingerprint),
        UNIQUE (claim_id, claim_version, ordinal),
        FOREIGN KEY (claim_id, claim_version)
            REFERENCES claim_versions(claim_id, version)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (falsification_record_fingerprint)
            REFERENCES falsification_records(record_fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    """
    CREATE TABLE session_records (
        record_fingerprint TEXT PRIMARY KEY,
        session_fingerprint TEXT NOT NULL,
        content_json TEXT NOT NULL,
        canonical_json TEXT NOT NULL,
        content_digest TEXT NOT NULL,
        FOREIGN KEY (session_fingerprint)
            REFERENCES sessions(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    "CREATE INDEX idx_session_records_domain ON session_records(session_fingerprint)",
    """
    CREATE TABLE session_record_claim_links (
        record_fingerprint TEXT NOT NULL,
        claim_id TEXT NOT NULL,
        claim_version INTEGER NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (record_fingerprint, claim_id),
        UNIQUE (record_fingerprint, ordinal),
        FOREIGN KEY (record_fingerprint)
            REFERENCES session_records(record_fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (claim_id, claim_version)
            REFERENCES claim_versions(claim_id, version)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    """
    CREATE TABLE session_record_bundle_links (
        record_fingerprint TEXT NOT NULL,
        bundle_fingerprint TEXT NOT NULL,
        bundle_record_fingerprint TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (record_fingerprint, bundle_record_fingerprint),
        UNIQUE (record_fingerprint, ordinal),
        FOREIGN KEY (record_fingerprint)
            REFERENCES session_records(record_fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (bundle_record_fingerprint)
            REFERENCES bundle_records(record_fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    """
    CREATE TABLE session_record_falsification_links (
        record_fingerprint TEXT NOT NULL,
        falsification_fingerprint TEXT NOT NULL,
        falsification_record_fingerprint TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (record_fingerprint, falsification_record_fingerprint),
        UNIQUE (record_fingerprint, ordinal),
        FOREIGN KEY (record_fingerprint)
            REFERENCES session_records(record_fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (falsification_record_fingerprint)
            REFERENCES falsification_records(record_fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    """
    CREATE TABLE session_execution_observations (
        observation_fingerprint TEXT PRIMARY KEY,
        session_fingerprint TEXT NOT NULL,
        session_record_fingerprint TEXT NOT NULL,
        plan_fingerprint TEXT,
        execution_fingerprint TEXT,
        request_ids_json TEXT NOT NULL,
        correlation_id TEXT,
        content_json TEXT NOT NULL,
        canonical_json TEXT NOT NULL,
        content_digest TEXT NOT NULL,
        FOREIGN KEY (session_record_fingerprint)
            REFERENCES session_records(record_fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    "CREATE INDEX idx_session_observations_record ON session_execution_observations(session_record_fingerprint)",
)


_MIGRATION_3: tuple[str, ...] = (
    "DROP INDEX idx_bundle_record_slot",
    "ALTER TABLE bundle_record_evidence_links RENAME TO bundle_record_evidence_links_v2",
    """
    CREATE TABLE bundle_record_evidence_links (
        record_fingerprint TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        evidence_fingerprint TEXT NOT NULL,
        dependency_kind TEXT NOT NULL CHECK (dependency_kind IN ('IMMUTABLE', 'SLOT')),
        slot_id TEXT,
        slot_version INTEGER,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (record_fingerprint, ordinal),
        CHECK (
            (dependency_kind = 'IMMUTABLE' AND slot_id IS NULL AND slot_version IS NULL)
            OR
            (dependency_kind = 'SLOT' AND slot_id IS NOT NULL AND slot_version IS NOT NULL)
        ),
        FOREIGN KEY (record_fingerprint)
            REFERENCES bundle_records(record_fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (evidence_fingerprint)
            REFERENCES evidence_artifacts(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (slot_id, slot_version)
            REFERENCES evidence_slot_versions(slot_id, version)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    """
    INSERT INTO bundle_record_evidence_links(
        record_fingerprint, evidence_id, evidence_fingerprint,
        dependency_kind, slot_id, slot_version, ordinal
    )
    SELECT record_fingerprint, evidence_id, evidence_fingerprint,
           dependency_kind, slot_id, slot_version, ordinal
    FROM bundle_record_evidence_links_v2
    """,
    "DROP TABLE bundle_record_evidence_links_v2",
    "CREATE INDEX idx_bundle_record_slot ON bundle_record_evidence_links(slot_id, slot_version)",
    "DROP INDEX idx_falsification_record_slot",
    "ALTER TABLE falsification_record_evidence_links RENAME TO falsification_record_evidence_links_v2",
    """
    CREATE TABLE falsification_record_evidence_links (
        record_fingerprint TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        evidence_fingerprint TEXT NOT NULL,
        dependency_kind TEXT NOT NULL CHECK (dependency_kind IN ('IMMUTABLE', 'SLOT')),
        slot_id TEXT,
        slot_version INTEGER,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (record_fingerprint, ordinal),
        CHECK (
            (dependency_kind = 'IMMUTABLE' AND slot_id IS NULL AND slot_version IS NULL)
            OR
            (dependency_kind = 'SLOT' AND slot_id IS NOT NULL AND slot_version IS NOT NULL)
        ),
        FOREIGN KEY (record_fingerprint)
            REFERENCES falsification_records(record_fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (evidence_fingerprint)
            REFERENCES evidence_artifacts(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (slot_id, slot_version)
            REFERENCES evidence_slot_versions(slot_id, version)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    """
    INSERT INTO falsification_record_evidence_links(
        record_fingerprint, evidence_id, evidence_fingerprint,
        dependency_kind, slot_id, slot_version, ordinal
    )
    SELECT record_fingerprint, evidence_id, evidence_fingerprint,
           dependency_kind, slot_id, slot_version, ordinal
    FROM falsification_record_evidence_links_v2
    """,
    "DROP TABLE falsification_record_evidence_links_v2",
    "CREATE INDEX idx_falsification_record_slot ON falsification_record_evidence_links(slot_id, slot_version)",
    "DROP INDEX idx_claim_evidence_dependency_slot",
    "ALTER TABLE claim_evidence_dependency_links RENAME TO claim_evidence_dependency_links_v2",
    """
    CREATE TABLE claim_evidence_dependency_links (
        claim_id TEXT NOT NULL,
        claim_version INTEGER NOT NULL,
        evidence_id TEXT NOT NULL,
        evidence_fingerprint TEXT NOT NULL,
        dependency_kind TEXT NOT NULL CHECK (dependency_kind IN ('IMMUTABLE', 'SLOT')),
        slot_id TEXT,
        slot_version INTEGER,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (claim_id, claim_version, ordinal),
        CHECK (
            (dependency_kind = 'IMMUTABLE' AND slot_id IS NULL AND slot_version IS NULL)
            OR
            (dependency_kind = 'SLOT' AND slot_id IS NOT NULL AND slot_version IS NOT NULL)
        ),
        FOREIGN KEY (claim_id, claim_version)
            REFERENCES claim_versions(claim_id, version)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (evidence_fingerprint)
            REFERENCES evidence_artifacts(fingerprint)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (slot_id, slot_version)
            REFERENCES evidence_slot_versions(slot_id, version)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    )
    """,
    """
    INSERT INTO claim_evidence_dependency_links(
        claim_id, claim_version, evidence_id, evidence_fingerprint,
        dependency_kind, slot_id, slot_version, ordinal
    )
    SELECT claim_id, claim_version, evidence_id, evidence_fingerprint,
           dependency_kind, slot_id, slot_version, ordinal
    FROM claim_evidence_dependency_links_v2
    """,
    "DROP TABLE claim_evidence_dependency_links_v2",
    "CREATE INDEX idx_claim_evidence_dependency_slot ON claim_evidence_dependency_links(slot_id, slot_version)",
)


def _identifier(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise StorageIntegrityError(f"{name} must be a non-empty string")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise StorageIntegrityError(f"{name} must be valid UTF-8") from exc
    return value


def _sha256(value: Any, *, name: str) -> str:
    value = _identifier(value, name=name)
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise StorageIntegrityError(f"{name} must be a lowercase SHA-256 fingerprint")
    return value


def _json_value(value: Any, *, path: str = "value") -> Any:
    if value is MISSING:
        return {"$gvr": "MISSING"}
    if value is INDETERMINATE:
        return {"$gvr": "INDETERMINATE"}
    if isinstance(value, Enum):
        return _json_value(value.value, path=path)
    if value is None or isinstance(value, (str, bool, int)):
        if isinstance(value, str):
            try:
                value.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise StorageIntegrityError(f"{path} contains invalid Unicode") from exc
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise StorageIntegrityError(f"{path} contains a non-finite number")
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise StorageIntegrityError(f"{path} contains a non-string mapping key")
            normalized[key] = _json_value(item, path=f"{path}.{key}")
        return normalized
    if isinstance(value, (list, tuple)):
        return [_json_value(item, path=f"{path}[{index}]") for index, item in enumerate(value)]
    raise StorageIntegrityError(f"{path} contains unsupported value {type(value).__name__}")


def _decode_value(value: Any) -> Any:
    if isinstance(value, dict):
        if value == {"$gvr": "MISSING"}:
            return MISSING
        if value == {"$gvr": "INDETERMINATE"}:
            return INDETERMINATE
        return {key: _decode_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_decode_value(item) for item in value]
    return value


def _mapping(value: Mapping[str, Any] | None, *, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise StorageIntegrityError(f"{name} must be a mapping")
    normalized = _json_value(value, path=name)
    assert isinstance(normalized, dict)
    return normalized


def _content_json(document: Any) -> str:
    normalized = _json_value(document, path="document")
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _parts(document: Any, *, fingerprint_format: str = _STORAGE_DOCUMENT_FORMAT) -> tuple[str, str, str]:
    normalized = _json_value(document, path="document")
    try:
        canonical = canonical_json(normalized, fingerprint_format=fingerprint_format)
        digest = canonical_fingerprint(normalized, fingerprint_format=fingerprint_format)
    except CanonicalizationError as exc:
        raise StorageIntegrityError(str(exc)) from exc
    return _content_json(normalized), canonical, digest


def _verified_document(
    *,
    content_json: str,
    canonical_json_value: str,
    content_digest: str,
    fingerprint_format: str = _STORAGE_DOCUMENT_FORMAT,
    identity: str,
) -> dict[str, Any]:
    try:
        document = json.loads(content_json)
    except (TypeError, json.JSONDecodeError) as exc:
        raise StorageIntegrityError(f"{identity} content is not valid JSON") from exc
    if not isinstance(document, dict):
        raise StorageIntegrityError(f"{identity} content must be a mapping")
    expected_content, expected_canonical, expected_digest = _parts(
        document,
        fingerprint_format=fingerprint_format,
    )
    if content_json != expected_content:
        raise StorageIntegrityError(f"{identity} content is not canonical JSON")
    if canonical_json_value != expected_canonical:
        raise StorageIntegrityError(f"{identity} canonical payload is corrupt")
    if content_digest != expected_digest:
        raise StorageIntegrityError(f"{identity} content fingerprint is corrupt")
    return document


def _evidence_document(evidence: Evidence) -> dict[str, Any]:
    if not isinstance(evidence, Evidence):
        raise StorageIntegrityError("evidence must be an Evidence record")
    _identifier(evidence.id, name="evidence id")
    _identifier(evidence.kind, name="evidence kind")
    if not isinstance(evidence.payload, Mapping):
        raise StorageIntegrityError("evidence payload must be a mapping")
    if evidence.source is not None:
        _identifier(evidence.source, name="evidence source")
    if evidence.fingerprint is not None:
        _identifier(evidence.fingerprint, name="producer fingerprint")
    return {
        "id": evidence.id,
        "kind": evidence.kind,
        "payload": _json_value(evidence.payload, path="evidence payload"),
        "source": evidence.source,
        "fingerprint": evidence.fingerprint,
    }


def _evidence_from_document(document: Mapping[str, Any]) -> Evidence:
    try:
        return Evidence(
            id=_identifier(document["id"], name="evidence id"),
            kind=_identifier(document["kind"], name="evidence kind"),
            payload=_decode_value(document["payload"]),
            source=document.get("source"),
            fingerprint=document.get("fingerprint"),
        )
    except KeyError as exc:
        raise StorageIntegrityError("stored evidence is missing required fields") from exc


def _issue_document(issue: VerificationIssue) -> dict[str, Any]:
    return {
        "code": issue.code,
        "message": issue.message,
        "verdict": issue.verdict.value,
        "evidence_ids": list(issue.evidence_ids),
    }


def _report_document(report: VerificationReport) -> dict[str, Any]:
    if not isinstance(report, VerificationReport):
        raise StorageIntegrityError("report must be a VerificationReport")
    return {
        "verdict": report.verdict.value,
        "verifier": report.verifier,
        "issues": [_issue_document(issue) for issue in report.issues],
        "evidence_ids": list(report.evidence_ids),
        "metadata": _json_value(report.metadata, path="report metadata"),
    }


def _report_from_document(document: Mapping[str, Any]) -> VerificationReport:
    try:
        issues = tuple(
            VerificationIssue(
                code=item["code"],
                message=item["message"],
                verdict=VerificationVerdict(item["verdict"]),
                evidence_ids=tuple(item.get("evidence_ids", ())),
            )
            for item in document.get("issues", ())
        )
        return VerificationReport(
            verdict=VerificationVerdict(document["verdict"]),
            verifier=document["verifier"],
            issues=issues,
            evidence_ids=tuple(document.get("evidence_ids", ())),
            metadata=_decode_value(document.get("metadata", {})),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise StorageIntegrityError("stored verification report is invalid") from exc


def _bundle_from_document(document: Mapping[str, Any]) -> VerificationBundle:
    try:
        report = _report_from_document(document["report"])
        evidence = tuple(
            _evidence_from_document(item)
            for item in document.get("evidence", ())
        )
        bundle = VerificationBundle(
            schema_version=document["schema_version"],
            kind=document["kind"],
            fingerprint_format=document["fingerprint_format"],
            report=report,
            evidence=evidence,
            claim_dependency_ids=tuple(document.get("claim_dependency_ids", ())),
        )
    except (KeyError, TypeError, ValueError, BundleValidationError) as exc:
        raise StorageIntegrityError("stored verification bundle is invalid") from exc
    if document.get("fingerprint") != bundle.fingerprint:
        raise StorageIntegrityError("stored verification bundle fingerprint is inconsistent")
    return bundle


def _falsification_from_document(document: Mapping[str, Any]) -> FalsificationResult:
    try:
        coverage_document = document["coverage"]
        coverage = FalsificationCoverage(
            completeness=FalsificationCompleteness(coverage_document["completeness"]),
            examined_items=coverage_document["examined_items"],
            total_items=coverage_document.get("total_items"),
            bounds=_decode_value(coverage_document.get("bounds", {})),
            schema_version=coverage_document["schema_version"],
            kind=coverage_document["kind"],
            fingerprint_format=coverage_document["fingerprint_format"],
        )
        provenance_document = document["provenance"]
        provenance = FalsificationProvenance(
            binding_id=provenance_document["binding_id"],
            declared_verifier_id=provenance_document["declared_verifier_id"],
            strategy_id=provenance_document["strategy_id"],
            strategy_version=provenance_document["strategy_version"],
            strategy_capability_fingerprint=provenance_document["strategy_capability_fingerprint"],
            claim_id=provenance_document["claim_id"],
            claim_fingerprint=provenance_document["claim_fingerprint"],
            input_fingerprint=provenance_document["input_fingerprint"],
            parameters_fingerprint=provenance_document["parameters_fingerprint"],
            implementation_path=provenance_document["implementation_path"],
            transformation=_decode_value(provenance_document.get("transformation", {})),
            schema_version=provenance_document["schema_version"],
            kind=provenance_document["kind"],
            fingerprint_format=provenance_document["fingerprint_format"],
        )
        probes = tuple(
            FalsificationProbe(
                probe_id=item["probe_id"],
                predicate_kind=item["predicate_kind"],
                outcome=FalsificationProbeOutcome(item["outcome"]),
                subject=_decode_value(item.get("subject")),
                expected=_decode_value(item.get("expected")),
                observed=_decode_value(item.get("observed")),
                schema_version=item["schema_version"],
                kind=item["kind"],
                fingerprint_format=item["fingerprint_format"],
            )
            for item in document["probes"]
        )
        result = FalsificationResult(
            binding_id=document["binding_id"],
            declared_verifier_id=document["declared_verifier_id"],
            strategy_id=document["strategy_id"],
            strategy_version=document["strategy_version"],
            strategy_kind=document["strategy_kind"],
            strategy_capability_fingerprint=document["strategy_capability_fingerprint"],
            claim_id=document["claim_id"],
            claim_fingerprint=document["claim_fingerprint"],
            outcome=FalsificationOutcome(document["outcome"]),
            probes=probes,
            coverage=coverage,
            provenance=provenance,
            schema_version=document["schema_version"],
            kind=document["kind"],
            fingerprint_format=document["fingerprint_format"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise StorageIntegrityError("stored falsification result is invalid") from exc
    if document.get("fingerprint") != result.fingerprint:
        raise StorageIntegrityError("stored falsification result fingerprint is inconsistent")
    return result


def _object_key(kind: str, identity: str) -> str:
    return f"{kind}:{identity}"


def _verify_semantic_document_fingerprint(
    document: Mapping[str, Any],
    *,
    identity: str,
) -> None:
    claimed = document.get("fingerprint")
    if not isinstance(claimed, str):
        raise StorageIntegrityError(f"{identity} fingerprint is missing")
    basis = deepcopy(dict(document))
    basis.pop("fingerprint", None)
    expected = hashlib.sha256(
        _bundle_canonical_json(basis).encode("utf-8")
    ).hexdigest()
    if claimed != expected:
        raise StorageIntegrityError(f"{identity} semantic fingerprint is corrupt")


def _execution_semantic_document(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    """Project a transported execution document onto its truth identity."""

    projected = deepcopy(dict(document))
    projected.pop("correlation_id", None)
    provider_results = projected.get("provider_results", ())
    if not isinstance(provider_results, (list, tuple)):
        raise StorageIntegrityError(
            "verification_execution provider results are invalid"
        )
    for entry in provider_results:
        if not isinstance(entry, Mapping):
            raise StorageIntegrityError(
                "verification_execution provider result entry is invalid"
            )
        result = entry.get("result")
        if not isinstance(result, Mapping):
            raise StorageIntegrityError(
                "verification_execution provider result document is invalid"
            )
        coverage = result.get("coverage")
        if not isinstance(coverage, Mapping):
            raise StorageIntegrityError(
                "verification_execution provider coverage document is invalid"
            )
        coverage.pop("audit", None)
    return projected


def _verify_formatted_document_fingerprint(
    document: Mapping[str, Any],
    *,
    identity: str,
    nonsemantic_fields: Iterable[str] = (),
) -> None:
    claimed = document.get("fingerprint")
    fingerprint_format = document.get("fingerprint_format")
    if not isinstance(claimed, str) or not isinstance(fingerprint_format, str):
        raise StorageIntegrityError(
            f"{identity} fingerprint or fingerprint format is missing"
        )
    basis = deepcopy(dict(document))
    basis.pop("fingerprint", None)
    basis.pop("fingerprint_format", None)
    for field in nonsemantic_fields:
        basis.pop(field, None)
    try:
        expected = canonical_fingerprint(
            basis,
            fingerprint_format=fingerprint_format,
        )
    except CanonicalizationError as exc:
        raise StorageIntegrityError(
            f"{identity} fingerprint basis is invalid"
        ) from exc
    if claimed != expected:
        raise StorageIntegrityError(f"{identity} semantic fingerprint is corrupt")


def _migrate_v2_data(connection: sqlite3.Connection) -> None:
    """Fail closed for v1 slots whose creation semantics are unknowable."""

    for row in connection.execute(
        "SELECT slot_id FROM evidence_slots ORDER BY slot_id"
    ).fetchall():
        document = {
            "schema_version": 1,
            "kind": "gvr.legacy_ambiguous_evidence_slot",
            "legacy_slot_id": row["slot_id"],
        }
        content, canonical, digest = _parts(
            document,
            fingerprint_format=_SLOT_IDENTITY_FORMAT,
        )
        connection.execute(
            """
            INSERT INTO evidence_slot_identities(
                slot_id, identity_kind, identity_fingerprint, authoritative,
                content_json, canonical_json, content_digest
            ) VALUES (?, 'LEGACY_AMBIGUOUS', NULL, 0, ?, ?, ?)
            """,
            (row["slot_id"], content, canonical, digest),
        )


class SQLiteStorage:
    """SQLite stdlib reference adapter for the generic durable GVR stores."""

    def __init__(
        self,
        path: str | Path,
        *,
        migration_hooks: Mapping[int, Callable[[sqlite3.Connection], None]] | None = None,
        busy_timeout_ms: int = 30_000,
    ) -> None:
        if type(busy_timeout_ms) is not int or busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms must be a non-negative integer")
        raw_path = str(path)
        self._anchor: sqlite3.Connection | None = None
        if raw_path == ":memory:":
            raw_path = f"file:gvr-storage-{uuid.uuid4().hex}?mode=memory&cache=shared"
            self._uri = True
            self._anchor = sqlite3.connect(
                raw_path,
                uri=True,
                isolation_level=None,
                check_same_thread=False,
            )
        else:
            self._uri = raw_path.startswith("file:")
        self.path = raw_path
        self._busy_timeout_ms = busy_timeout_ms
        self._migration_hooks = dict(migration_hooks or {})
        self._bootstrap()
        self._configure_database()

    @property
    def schema_version(self) -> int:
        connection = self._connect()
        try:
            row = connection.execute(
                f"SELECT version FROM {DURABLE_STORAGE_SCHEMA_TABLE} WHERE singleton = 1"
            ).fetchone()
            if row is None:
                raise StorageIntegrityError("durable storage schema version is missing")
            return int(row[0])
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            uri=self._uri,
            isolation_level=None,
            timeout=max(self._busy_timeout_ms / 1000, 0.001),
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
        return connection

    def _bootstrap(self) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                (DURABLE_STORAGE_SCHEMA_TABLE,),
            ).fetchone()
            if exists is None:
                connection.execute(
                    f"""
                    CREATE TABLE {DURABLE_STORAGE_SCHEMA_TABLE} (
                        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                        version INTEGER NOT NULL CHECK (version >= 0)
                    )
                    """
                )
                connection.execute(
                    f"INSERT INTO {DURABLE_STORAGE_SCHEMA_TABLE}(singleton, version) VALUES (1, 0)"
                )
                current = 0
            else:
                row = connection.execute(
                    f"SELECT version FROM {DURABLE_STORAGE_SCHEMA_TABLE} WHERE singleton = 1"
                ).fetchone()
                if row is None or type(row[0]) is not int:
                    raise StorageIntegrityError("durable storage schema metadata is invalid")
                current = row[0]
            if current > DURABLE_STORAGE_SCHEMA_VERSION:
                raise StorageSchemaVersionError(
                    f"database schema version {current} is newer than supported version "
                    f"{DURABLE_STORAGE_SCHEMA_VERSION}"
                )
            for version in range(current + 1, DURABLE_STORAGE_SCHEMA_VERSION + 1):
                statements = {
                    1: _MIGRATION_1,
                    2: _MIGRATION_2,
                    3: _MIGRATION_3,
                }.get(version, ())
                if not statements:
                    raise StorageMigrationError(f"missing migration for schema version {version}")
                for statement in statements:
                    connection.execute(statement)
                if version == 2:
                    _migrate_v2_data(connection)
                hook = self._migration_hooks.get(version)
                if hook is not None:
                    hook(connection)
                connection.execute(
                    f"UPDATE {DURABLE_STORAGE_SCHEMA_TABLE} SET version = ? WHERE singleton = 1",
                    (version,),
                )
            connection.commit()
        except StorageSchemaVersionError:
            connection.rollback()
            raise
        except Exception as exc:
            connection.rollback()
            if isinstance(exc, StorageMigrationError):
                raise
            raise StorageMigrationError("durable storage bootstrap failed") from exc
        finally:
            connection.close()

    def _configure_database(self) -> None:
        if self._uri and "mode=memory" in self.path:
            return
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = NORMAL")
        finally:
            connection.close()

    def unit_of_work(self) -> SQLiteUnitOfWork:
        return SQLiteUnitOfWork(self)

    def _write(self, method: str, *args: Any, **kwargs: Any) -> Any:
        with self.unit_of_work() as unit_of_work:
            return getattr(unit_of_work, method)(*args, **kwargs)

    def _read(self, method: str, *args: Any, **kwargs: Any) -> Any:
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            unit_of_work = SQLiteUnitOfWork(self, connection=connection, managed=False)
            result = getattr(unit_of_work, method)(*args, **kwargs)
            connection.rollback()
            return result
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def put_evidence(self, evidence: Evidence, **kwargs: Any) -> StoredEvidence:
        return self._write("put_evidence", evidence, **kwargs)

    def get_evidence(self, fingerprint: str) -> StoredEvidence:
        return self._read("get_evidence", fingerprint)

    def get_evidence_by_slot(self, slot_id: str) -> StoredEvidence:
        return self._read("get_evidence_by_slot", slot_id)

    def get_slot(self, slot_id: str) -> EvidenceSlotVersion | None:
        return self._read("get_slot", slot_id)

    def slot_history(self, slot_id: str) -> tuple[EvidenceSlotVersion, ...]:
        return self._read("slot_history", slot_id)

    def put_bundle(self, bundle: VerificationBundle, **kwargs: Any) -> StoredBundle:
        return self._write("put_bundle", bundle, **kwargs)

    def get_bundle(self, fingerprint: str, **kwargs: Any) -> StoredBundle:
        return self._read("get_bundle", fingerprint, **kwargs)

    def bundle_history(self, fingerprint: str) -> tuple[StoredBundle, ...]:
        return self._read("bundle_history", fingerprint)

    def define_claim(self, definition: ClaimDefinition, **kwargs: Any) -> StoredClaimDefinition:
        return self._write("define_claim", definition, **kwargs)

    def record_claim(self, claim_id: str, bundle: VerificationBundle | None, **kwargs: Any) -> StoredClaimVersion:
        return self._write("record_claim", claim_id, bundle, **kwargs)

    def claim_status(self, claim_id: str) -> StoredClaimStatus:
        return self._read("claim_status", claim_id)

    def claim_history(self, claim_id: str) -> tuple[StoredClaimVersion, ...]:
        return self._read("claim_history", claim_id)

    def stale_claims(self) -> tuple[str, ...]:
        return self._read("stale_claims")

    def put_falsification_result(self, result: FalsificationResult, **kwargs: Any) -> StoredFalsificationResult:
        return self._write("put_falsification_result", result, **kwargs)

    def get_falsification_result(
        self,
        fingerprint: str,
        **kwargs: Any,
    ) -> StoredFalsificationResult:
        return self._read("get_falsification_result", fingerprint, **kwargs)

    def falsification_history(
        self,
        fingerprint: str,
    ) -> tuple[StoredFalsificationResult, ...]:
        return self._read("falsification_history", fingerprint)

    def put_session(self, session: VerificationSession, **kwargs: Any) -> StoredSession:
        return self._write("put_session", session, **kwargs)

    def get_session(self, fingerprint: str, **kwargs: Any) -> StoredSession:
        return self._read("get_session", fingerprint, **kwargs)

    def session_record_history(self, fingerprint: str) -> tuple[StoredSession, ...]:
        return self._read("session_record_history", fingerprint)

    def session_execution_observations(
        self,
        fingerprint: str,
    ) -> tuple[SessionExecutionObservation, ...]:
        return self._read("session_execution_observations", fingerprint)

    def session_history(self) -> tuple[StoredSession, ...]:
        return self._read("session_history")

    def current_sessions(self) -> tuple[StoredSession, ...]:
        return tuple(item for item in self.session_history() if item.current)

    def historical_sessions(self) -> tuple[StoredSession, ...]:
        return tuple(item for item in self.session_history() if not item.current)

    def record_execution(self, request: Any, result: Any) -> StoredSession:
        return self._write("record_execution", request, result)

    def dependents_of(self, object_key: str) -> tuple[str, ...]:
        return self._read("dependents_of", object_key)

    def invalidation_events(self) -> tuple[InvalidationEvent, ...]:
        return self._read("invalidation_events")

    def explain_reverse_dependency_lookup(self, object_key: str) -> tuple[str, ...]:
        return self._read("explain_reverse_dependency_lookup", object_key)

    def clear_cache(self) -> None:
        """Compatibility hook. Reads always verify SQLite and never trust a cache."""


class SQLiteUnitOfWork:
    def __init__(
        self,
        storage: SQLiteStorage,
        *,
        connection: sqlite3.Connection | None = None,
        managed: bool = True,
    ) -> None:
        self.storage = storage
        self.connection = connection
        self._managed = managed
        self._active = connection is not None
        self._savepoint_counter = 0

    def __enter__(self) -> SQLiteUnitOfWork:
        if self.connection is not None:
            if not self._active:
                raise RuntimeError("unit of work is closed")
            return self
        self.connection = self.storage._connect()
        self.connection.execute("BEGIN IMMEDIATE")
        self._active = True
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        if not self._managed:
            return False
        if self.connection is None:
            return False
        try:
            if exc_type is None:
                self.commit()
            else:
                self.rollback()
        finally:
            self.connection.close()
            self.connection = None
            self._active = False
        return False

    def _conn(self) -> sqlite3.Connection:
        if not self._active or self.connection is None:
            raise RuntimeError("unit of work is not active")
        return self.connection

    def commit(self) -> None:
        if self.connection is None or not self._active:
            return
        self.connection.commit()
        self._active = False

    def rollback(self) -> None:
        if self.connection is None or not self._active:
            return
        self.connection.rollback()
        self._active = False

    @contextmanager
    def _logical_write(self) -> Iterator[None]:
        connection = self._conn()
        self._savepoint_counter += 1
        name = f"gvr_write_{self._savepoint_counter}"
        connection.execute(f"SAVEPOINT {name}")
        try:
            yield
        except Exception:
            connection.execute(f"ROLLBACK TO {name}")
            connection.execute(f"RELEASE {name}")
            raise
        else:
            connection.execute(f"RELEASE {name}")

    def _put_dependency(self, dependent_key: str, dependency_key: str, relation: str) -> None:
        self._conn().execute(
            """
            INSERT OR IGNORE INTO object_dependencies(dependent_key, dependency_key, relation)
            VALUES (?, ?, ?)
            """,
            (dependent_key, dependency_key, relation),
        )

    def dependents_of(self, object_key: str) -> tuple[str, ...]:
        object_key = _identifier(object_key, name="object key")
        rows = self._conn().execute(
            """
            SELECT DISTINCT dependent_key
            FROM object_dependencies
            WHERE dependency_key = ?
            ORDER BY dependent_key
            """,
            (object_key,),
        ).fetchall()
        return tuple(row[0] for row in rows)

    def explain_reverse_dependency_lookup(self, object_key: str) -> tuple[str, ...]:
        object_key = _identifier(object_key, name="object key")
        rows = self._conn().execute(
            """
            EXPLAIN QUERY PLAN
            SELECT dependent_key
            FROM object_dependencies
            WHERE dependency_key = ?
            ORDER BY dependent_key
            """,
            (object_key,),
        ).fetchall()
        return tuple(" ".join(str(value) for value in row) for row in rows)

    def _is_invalidated(self, object_key: str) -> bool:
        return self._conn().execute(
            "SELECT 1 FROM invalidation_targets WHERE target_key = ? LIMIT 1",
            (object_key,),
        ).fetchone() is not None

    def _invalidate(
        self,
        *,
        kind: str,
        cause_object: str,
        replacement_object: str,
    ) -> InvalidationEvent:
        document = {
            "schema_version": 1,
            "kind": kind,
            "cause_object": cause_object,
            "replacement_object": replacement_object,
        }
        content, canonical, event_id = _parts(
            document,
            fingerprint_format=_INVALIDATION_EVENT_FORMAT,
        )
        existing = self._conn().execute(
            "SELECT * FROM invalidation_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        if existing is not None:
            verified = _verified_document(
                content_json=existing["content_json"],
                canonical_json_value=existing["canonical_json"],
                content_digest=existing["content_digest"],
                fingerprint_format=_INVALIDATION_EVENT_FORMAT,
                identity=f"invalidation event {event_id}",
            )
            if verified != document:
                raise StorageConflictError("invalidation event identity has conflicting content")
            targets = tuple(
                row[0]
                for row in self._conn().execute(
                    "SELECT target_key FROM invalidation_targets WHERE event_id = ? ORDER BY ordinal",
                    (event_id,),
                )
            )
            return InvalidationEvent(event_id, kind, cause_object, replacement_object, targets)

        frontier = [cause_object]
        seen: set[str] = set()
        targets: list[str] = []
        while frontier:
            dependency = frontier.pop()
            for dependent in self.dependents_of(dependency):
                if dependent in seen:
                    continue
                seen.add(dependent)
                targets.append(dependent)
                frontier.append(dependent)
        targets.sort()
        self._conn().execute(
            """
            INSERT INTO invalidation_events(
                event_id, event_kind, cause_object, replacement_object,
                content_json, canonical_json, content_digest
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (event_id, kind, cause_object, replacement_object, content, canonical, event_id),
        )
        for ordinal, target in enumerate(targets):
            self._conn().execute(
                "INSERT INTO invalidation_targets(event_id, target_key, ordinal) VALUES (?, ?, ?)",
                (event_id, target, ordinal),
            )
        return InvalidationEvent(event_id, kind, cause_object, replacement_object, tuple(targets))

    def invalidation_events(self) -> tuple[InvalidationEvent, ...]:
        events: list[InvalidationEvent] = []
        rows = self._conn().execute(
            "SELECT * FROM invalidation_events ORDER BY event_id"
        ).fetchall()
        for row in rows:
            document = _verified_document(
                content_json=row["content_json"],
                canonical_json_value=row["canonical_json"],
                content_digest=row["content_digest"],
                fingerprint_format=_INVALIDATION_EVENT_FORMAT,
                identity=f"invalidation event {row['event_id']}",
            )
            if row["content_digest"] != row["event_id"]:
                raise StorageIntegrityError("invalidation event key does not match content")
            if (
                row["event_kind"] != document["kind"]
                or row["cause_object"] != document["cause_object"]
                or row["replacement_object"] != document["replacement_object"]
            ):
                raise StorageIntegrityError(
                    "invalidation event columns conflict with canonical content"
                )
            targets = tuple(
                target[0]
                for target in self._conn().execute(
                    "SELECT target_key FROM invalidation_targets WHERE event_id = ? ORDER BY ordinal",
                    (row["event_id"],),
                )
            )
            events.append(InvalidationEvent(
                row["event_id"],
                document["kind"],
                document["cause_object"],
                document["replacement_object"],
                targets,
            ))
        return tuple(events)

    def _slot_identity_document(
        self,
        slot_id: str,
        slot_identity: EvidenceSlotIdentity | None,
    ) -> tuple[str, str | None, dict[str, Any]]:
        if slot_identity is None:
            return (
                "CALLER_OWNED",
                None,
                {
                    "schema_version": 1,
                    "kind": "gvr.caller_owned_evidence_slot",
                    "slot_id": slot_id,
                },
            )
        if type(slot_identity) is not EvidenceSlotIdentity:
            raise StorageIntegrityError(
                "slot_identity must be an exact EvidenceSlotIdentity"
            )
        if slot_id != slot_identity.slot_id:
            raise StorageIntegrityError(
                "semantic slot ID does not match its canonical identity"
            )
        return "SEMANTIC", slot_identity.fingerprint, slot_identity.to_dict()

    def _read_slot_identity_row(self, slot_id: str) -> sqlite3.Row:
        row = self._conn().execute(
            "SELECT * FROM evidence_slot_identities WHERE slot_id = ?",
            (slot_id,),
        ).fetchone()
        if row is None:
            raise StorageIntegrityError(
                f"evidence slot {slot_id} is missing identity metadata"
            )
        document = _verified_document(
            content_json=row["content_json"],
            canonical_json_value=row["canonical_json"],
            content_digest=row["content_digest"],
            fingerprint_format=_SLOT_IDENTITY_FORMAT,
            identity=f"evidence slot identity {slot_id}",
        )
        if row["identity_kind"] == "SEMANTIC":
            if (
                document.get("slot_id") != slot_id
                or document.get("fingerprint") != row["identity_fingerprint"]
            ):
                raise StorageIntegrityError(
                    "semantic evidence slot identity metadata is corrupt"
                )
        elif row["identity_kind"] == "CALLER_OWNED":
            if document.get("slot_id") != slot_id:
                raise StorageIntegrityError(
                    "caller-owned evidence slot identity metadata is corrupt"
                )
        elif row["identity_kind"] == "LEGACY_AMBIGUOUS":
            if document.get("legacy_slot_id") != slot_id:
                raise StorageIntegrityError(
                    "legacy evidence slot identity metadata is corrupt"
                )
        else:
            raise StorageIntegrityError("unknown evidence slot identity kind")
        return row

    def _ensure_slot_identity(
        self,
        slot_id: str,
        slot_identity: EvidenceSlotIdentity | None,
    ) -> None:
        identity_kind, identity_fingerprint, document = self._slot_identity_document(
            slot_id,
            slot_identity,
        )
        content, canonical, digest = _parts(
            document,
            fingerprint_format=_SLOT_IDENTITY_FORMAT,
        )
        existing = self._conn().execute(
            "SELECT * FROM evidence_slot_identities WHERE slot_id = ?",
            (slot_id,),
        ).fetchone()
        if existing is None:
            self._conn().execute(
                """
                INSERT INTO evidence_slot_identities(
                    slot_id, identity_kind, identity_fingerprint,
                    authoritative, content_json, canonical_json, content_digest
                ) VALUES (?, ?, ?, 1, ?, ?, ?)
                """,
                (
                    slot_id,
                    identity_kind,
                    identity_fingerprint,
                    content,
                    canonical,
                    digest,
                ),
            )
            return
        self._read_slot_identity_row(slot_id)
        if existing["identity_kind"] == "LEGACY_AMBIGUOUS":
            if slot_identity is None or slot_id != slot_identity.slot_id:
                raise StorageConflictError(
                    "ambiguous legacy evidence slot cannot be adopted implicitly"
                )
            self._conn().execute(
                """
                UPDATE evidence_slot_identities
                SET identity_kind = ?, identity_fingerprint = ?, authoritative = 1,
                    content_json = ?, canonical_json = ?, content_digest = ?
                WHERE slot_id = ?
                """,
                (
                    identity_kind,
                    identity_fingerprint,
                    content,
                    canonical,
                    digest,
                    slot_id,
                ),
            )
            return
        if (
            existing["identity_kind"] != identity_kind
            or existing["identity_fingerprint"] != identity_fingerprint
            or existing["content_json"] != content
            or existing["canonical_json"] != canonical
            or existing["content_digest"] != digest
            or existing["authoritative"] != 1
        ):
            raise StorageConflictError(
                "evidence slot identity conflicts with existing semantic scope"
            )

    def _semantic_slot_identity(
        self,
        slot_id: str,
    ) -> EvidenceSlotIdentity | None:
        row = self._read_slot_identity_row(slot_id)
        if row["identity_kind"] != "SEMANTIC":
            return None
        document = json.loads(row["content_json"])
        try:
            identity = EvidenceSlotIdentity(
                provider_id=document["provider_id"],
                evidence_id=document["evidence_id"],
                source_identity=_decode_value(document["source_identity"]),
                request_identity=_decode_value(document["request_identity"]),
                schema_version=document["schema_version"],
                kind=document["kind"],
                fingerprint_format=document["fingerprint_format"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StorageIntegrityError(
                "semantic evidence slot identity cannot be reconstructed"
            ) from exc
        if identity.fingerprint != row["identity_fingerprint"]:
            raise StorageIntegrityError(
                "semantic evidence slot identity fingerprint is corrupt"
            )
        return identity

    def put_evidence(
        self,
        evidence: Evidence,
        *,
        slot_id: str | None = None,
        slot_identity: EvidenceSlotIdentity | None = None,
        provenance: Mapping[str, Any] | None = None,
        source_snapshot: Mapping[str, Any] | None = None,
        bounds: Mapping[str, Any] | None = None,
        coverage: Mapping[str, Any] | None = None,
        expected_fingerprint: str | None = None,
    ) -> StoredEvidence:
        with self._logical_write():
            if slot_id is not None and slot_identity is not None:
                raise StorageIntegrityError(
                    "slot_id and slot_identity are mutually exclusive"
                )
            evidence_document = _evidence_document(evidence)
            document = {
                "schema_version": 1,
                "kind": "gvr.stored_evidence",
                "evidence": evidence_document,
                "provenance": _mapping(provenance, name="provenance"),
                "source_snapshot": _mapping(source_snapshot, name="source_snapshot"),
                "bounds": _mapping(bounds, name="bounds"),
                "coverage": _mapping(coverage, name="coverage"),
            }
            content, canonical, fingerprint = _parts(
                document,
                fingerprint_format=_EVIDENCE_FINGERPRINT_FORMAT,
            )
            payload_canonical = canonical_json(
                evidence_document["payload"],
                fingerprint_format=_EVIDENCE_PAYLOAD_FORMAT,
            )
            if expected_fingerprint is not None:
                expected = _sha256(expected_fingerprint, name="expected evidence fingerprint")
                if expected != fingerprint:
                    raise StorageConflictError(
                        "supplied evidence identity conflicts with canonical evidence content"
                    )
            existing = self._conn().execute(
                "SELECT * FROM evidence_artifacts WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if existing is None:
                self._conn().execute(
                    """
                    INSERT INTO evidence_artifacts(
                        fingerprint, content_json, canonical_json,
                        payload_canonical_json, content_digest
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (fingerprint, content, canonical, payload_canonical, fingerprint),
                )
            else:
                stored = self._read_evidence_row(existing)
                if (
                    stored.evidence != _evidence_from_document(evidence_document)
                    or dict(stored.provenance) != document["provenance"]
                    or dict(stored.source_snapshot) != document["source_snapshot"]
                    or dict(stored.bounds) != document["bounds"]
                    or dict(stored.coverage) != document["coverage"]
                ):
                    raise StorageConflictError(
                        "immutable evidence fingerprint has conflicting content"
                    )

            selected_slot_id: str | None = None
            selected_version: int | None = None
            if slot_id is not None or slot_identity is not None:
                selected_slot_id = _identifier(
                    (
                        slot_identity.slot_id
                        if slot_identity is not None
                        else slot_id
                    ),
                    name="slot_id",
                )
                current = self._conn().execute(
                    "SELECT current_version, current_evidence_fingerprint FROM evidence_slots WHERE slot_id = ?",
                    (selected_slot_id,),
                ).fetchone()
                if current is not None:
                    self._ensure_slot_identity(selected_slot_id, slot_identity)
                    current_slot = self._slot_version(
                        selected_slot_id,
                        current["current_version"],
                    )
                    if (
                        current_slot.evidence_fingerprint
                        != current["current_evidence_fingerprint"]
                    ):
                        raise StorageIntegrityError(
                            "evidence slot pointer conflicts with its current version"
                        )
                if current is not None and current["current_evidence_fingerprint"] == fingerprint:
                    selected_version = current["current_version"]
                else:
                    previous_version = None if current is None else current["current_version"]
                    selected_version = 1 if previous_version is None else previous_version + 1
                    self._conn().execute(
                        """
                        INSERT INTO evidence_slot_versions(
                            slot_id, version, evidence_fingerprint, previous_version
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (selected_slot_id, selected_version, fingerprint, previous_version),
                    )
                    if current is None:
                        self._conn().execute(
                            """
                            INSERT INTO evidence_slots(slot_id, current_version, current_evidence_fingerprint)
                            VALUES (?, ?, ?)
                            """,
                            (selected_slot_id, selected_version, fingerprint),
                        )
                        self._ensure_slot_identity(selected_slot_id, slot_identity)
                    else:
                        self._conn().execute(
                            """
                            UPDATE evidence_slots
                            SET current_version = ?, current_evidence_fingerprint = ?
                            WHERE slot_id = ?
                            """,
                            (selected_version, fingerprint, selected_slot_id),
                        )
                        old_key = EvidenceSlotVersion(
                            selected_slot_id,
                            previous_version,
                            current["current_evidence_fingerprint"],
                            None,
                            False,
                        ).object_key
                        new_key = EvidenceSlotVersion(
                            selected_slot_id,
                            selected_version,
                            fingerprint,
                            previous_version,
                            True,
                        ).object_key
                        self._invalidate(
                            kind="slot_version_changed",
                            cause_object=old_key,
                            replacement_object=new_key,
                        )
            stored = self.get_evidence(fingerprint)
            return StoredEvidence(
                fingerprint=stored.fingerprint,
                evidence=stored.evidence,
                canonical_payload=stored.canonical_payload,
                provenance=stored.provenance,
                source_snapshot=stored.source_snapshot,
                bounds=stored.bounds,
                coverage=stored.coverage,
                slot_id=selected_slot_id,
                slot_version=selected_version,
                slot_identity=slot_identity,
            )

    def _read_evidence_row(self, row: sqlite3.Row) -> StoredEvidence:
        document = _verified_document(
            content_json=row["content_json"],
            canonical_json_value=row["canonical_json"],
            content_digest=row["content_digest"],
            fingerprint_format=_EVIDENCE_FINGERPRINT_FORMAT,
            identity=f"evidence {row['fingerprint']}",
        )
        if row["fingerprint"] != row["content_digest"]:
            raise StorageIntegrityError("evidence key does not match canonical fingerprint")
        try:
            evidence_document = document["evidence"]
            expected_payload = canonical_json(
                evidence_document["payload"],
                fingerprint_format=_EVIDENCE_PAYLOAD_FORMAT,
            )
        except (KeyError, CanonicalizationError) as exc:
            raise StorageIntegrityError("stored evidence payload is invalid") from exc
        if row["payload_canonical_json"] != expected_payload:
            raise StorageIntegrityError("stored evidence canonical payload is corrupt")
        return StoredEvidence(
            fingerprint=row["fingerprint"],
            evidence=_evidence_from_document(evidence_document),
            canonical_payload=row["payload_canonical_json"],
            provenance=deepcopy(document.get("provenance", {})),
            source_snapshot=deepcopy(document.get("source_snapshot", {})),
            bounds=deepcopy(document.get("bounds", {})),
            coverage=deepcopy(document.get("coverage", {})),
        )

    def get_evidence(self, fingerprint: str) -> StoredEvidence:
        fingerprint = _sha256(fingerprint, name="evidence fingerprint")
        row = self._conn().execute(
            "SELECT * FROM evidence_artifacts WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        if row is None:
            raise StorageNotFoundError(f"unknown evidence fingerprint: {fingerprint}")
        return self._read_evidence_row(row)

    def _slot_from_row(self, row: sqlite3.Row, *, current_version: int | None = None) -> EvidenceSlotVersion:
        identity = self._read_slot_identity_row(row["slot_id"])
        pointer_current = (
            current_version == row["version"]
            if current_version is not None
            else self._conn().execute(
                "SELECT current_version FROM evidence_slots WHERE slot_id = ?",
                (row["slot_id"],),
            ).fetchone()[0] == row["version"]
        )
        authoritative = identity["authoritative"] == 1
        return EvidenceSlotVersion(
            slot_id=row["slot_id"],
            version=row["version"],
            evidence_fingerprint=row["evidence_fingerprint"],
            previous_version=row["previous_version"],
            current=pointer_current and authoritative,
            identity_fingerprint=identity["identity_fingerprint"],
            authoritative=authoritative,
        )

    def get_slot(self, slot_id: str) -> EvidenceSlotVersion | None:
        slot_id = _identifier(slot_id, name="slot_id")
        row = self._conn().execute(
            """
            SELECT v.*, s.current_version,
                   s.current_evidence_fingerprint AS current_pointer_fingerprint
            FROM evidence_slots AS s
            JOIN evidence_slot_versions AS v
              ON v.slot_id = s.slot_id AND v.version = s.current_version
            WHERE s.slot_id = ?
            """,
            (slot_id,),
        ).fetchone()
        if row is None:
            return None
        if row["current_pointer_fingerprint"] != row["evidence_fingerprint"]:
            raise StorageIntegrityError(
                "evidence slot pointer fingerprint conflicts with current version"
            )
        self.get_evidence(row["evidence_fingerprint"])
        return self._slot_from_row(row, current_version=row["current_version"])

    def get_evidence_by_slot(self, slot_id: str) -> StoredEvidence:
        slot = self.get_slot(slot_id)
        if slot is None:
            raise StorageNotFoundError(f"unknown evidence slot: {slot_id}")
        stored = self.get_evidence(slot.evidence_fingerprint)
        return StoredEvidence(
            fingerprint=stored.fingerprint,
            evidence=stored.evidence,
            canonical_payload=stored.canonical_payload,
            provenance=stored.provenance,
            source_snapshot=stored.source_snapshot,
            bounds=stored.bounds,
            coverage=stored.coverage,
            slot_id=slot.slot_id,
            slot_version=slot.version,
            slot_identity=self._semantic_slot_identity(slot.slot_id),
        )

    def slot_history(self, slot_id: str) -> tuple[EvidenceSlotVersion, ...]:
        slot_id = _identifier(slot_id, name="slot_id")
        current = self._conn().execute(
            """
            SELECT current_version, current_evidence_fingerprint
            FROM evidence_slots WHERE slot_id = ?
            """,
            (slot_id,),
        ).fetchone()
        if current is None:
            return ()
        rows = self._conn().execute(
            "SELECT * FROM evidence_slot_versions WHERE slot_id = ? ORDER BY version",
            (slot_id,),
        ).fetchall()
        result: list[EvidenceSlotVersion] = []
        previous: int | None = None
        for row in rows:
            self.get_evidence(row["evidence_fingerprint"])
            if row["previous_version"] != previous:
                raise StorageIntegrityError("evidence slot version chain is corrupt")
            if row["version"] != (1 if previous is None else previous + 1):
                raise StorageIntegrityError("evidence slot versions are not contiguous")
            if (
                row["version"] == current["current_version"]
                and row["evidence_fingerprint"]
                != current["current_evidence_fingerprint"]
            ):
                raise StorageIntegrityError(
                    "evidence slot pointer fingerprint conflicts with current version"
                )
            result.append(self._slot_from_row(row, current_version=current["current_version"]))
            previous = row["version"]
        return tuple(result)

    def _slot_version(self, slot_id: str, version: int) -> EvidenceSlotVersion:
        row = self._conn().execute(
            "SELECT * FROM evidence_slot_versions WHERE slot_id = ? AND version = ?",
            (slot_id, version),
        ).fetchone()
        if row is None:
            raise StorageIntegrityError(
                f"missing evidence slot version {slot_id}:{version}"
            )
        current = self._conn().execute(
            """
            SELECT current_version, current_evidence_fingerprint
            FROM evidence_slots WHERE slot_id = ?
            """,
            (slot_id,),
        ).fetchone()
        if current is None:
            raise StorageIntegrityError(f"missing evidence slot pointer {slot_id}")
        if (
            current["current_version"] == version
            and current["current_evidence_fingerprint"]
            != row["evidence_fingerprint"]
        ):
            raise StorageIntegrityError(
                "evidence slot pointer fingerprint conflicts with current version"
            )
        self.get_evidence(row["evidence_fingerprint"])
        return self._slot_from_row(row, current_version=current["current_version"])

    def _dependency_document(
        self,
        dependency: EvidenceDependency,
    ) -> dict[str, Any]:
        return {
            "evidence_id": dependency.evidence_id,
            "evidence_fingerprint": dependency.evidence_fingerprint,
            "dependency_kind": "SLOT" if dependency.replaceable else "IMMUTABLE",
            "slot_id": None if dependency.slot is None else dependency.slot.slot_id,
            "slot_version": (
                None if dependency.slot is None else dependency.slot.version
            ),
        }

    def _canonical_evidence_dependencies(
        self,
        dependencies: Iterable[EvidenceDependency],
        *,
        noun: str,
    ) -> tuple[EvidenceDependency, ...]:
        try:
            supplied = tuple(dependencies)
        except TypeError as exc:
            raise StorageIntegrityError(
                f"{noun} must be iterable"
            ) from exc
        normalized: list[EvidenceDependency] = []
        for dependency in supplied:
            if type(dependency) is not EvidenceDependency:
                raise StorageIntegrityError(
                    f"{noun} must contain exact EvidenceDependency records"
                )
            evidence_id = _identifier(
                dependency.evidence_id,
                name=f"{noun} evidence ID",
            )
            evidence_fingerprint = _sha256(
                dependency.evidence_fingerprint,
                name=f"{noun} evidence fingerprint",
            )
            artifact = self.get_evidence(evidence_fingerprint)
            if artifact.evidence.id != evidence_id:
                raise StorageIntegrityError(
                    f"{noun} evidence ID conflicts with its exact artifact"
                )
            slot: EvidenceSlotVersion | None = None
            if dependency.slot is not None:
                if type(dependency.slot) is not EvidenceSlotVersion:
                    raise StorageIntegrityError(
                        f"{noun} slots must be exact EvidenceSlotVersion records"
                    )
                slot = self._slot_version(
                    dependency.slot.slot_id,
                    dependency.slot.version,
                )
                if slot.evidence_fingerprint != evidence_fingerprint:
                    raise StorageIntegrityError(
                        f"{noun} slot conflicts with its exact artifact"
                    )
            normalized.append(
                EvidenceDependency(evidence_id, evidence_fingerprint, slot)
            )
        keyed = {
            _content_json(self._dependency_document(item)): item
            for item in normalized
        }
        if len(keyed) != len(normalized):
            raise StorageIntegrityError(
                f"{noun} contain duplicate exact dependencies"
            )
        return tuple(keyed[key] for key in sorted(keyed))

    def _dependency_from_record_link(
        self,
        row: sqlite3.Row,
    ) -> EvidenceDependency:
        artifact = self.get_evidence(row["evidence_fingerprint"])
        if artifact.evidence.id != row["evidence_id"]:
            raise StorageIntegrityError(
                "stored evidence dependency ID conflicts with its artifact"
            )
        if row["dependency_kind"] == "IMMUTABLE":
            if row["slot_id"] is not None or row["slot_version"] is not None:
                raise StorageIntegrityError(
                    "immutable evidence dependency contains slot coordinates"
                )
            return EvidenceDependency(
                row["evidence_id"],
                row["evidence_fingerprint"],
            )
        if row["dependency_kind"] != "SLOT":
            raise StorageIntegrityError("unknown evidence dependency kind")
        if row["slot_id"] is None or row["slot_version"] is None:
            raise StorageIntegrityError(
                "replaceable evidence dependency is missing slot coordinates"
            )
        slot = self._slot_version(row["slot_id"], row["slot_version"])
        if slot.evidence_fingerprint != row["evidence_fingerprint"]:
            raise StorageIntegrityError(
                "evidence dependency slot conflicts with artifact fingerprint"
            )
        return EvidenceDependency(
            row["evidence_id"],
            row["evidence_fingerprint"],
            slot,
        )

    def _read_bundle_domain(self, fingerprint: str) -> VerificationBundle:
        row = self._conn().execute(
            "SELECT * FROM bundles WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        if row is None:
            raise StorageNotFoundError(f"unknown bundle fingerprint: {fingerprint}")
        document = _verified_document(
            content_json=row["content_json"],
            canonical_json_value=row["canonical_json"],
            content_digest=row["content_digest"],
            identity=f"bundle {fingerprint}",
        )
        bundle = _bundle_from_document(document)
        if bundle.fingerprint != fingerprint:
            raise StorageIntegrityError(
                "bundle key does not match bundle fingerprint"
            )
        claim_links = tuple(
            item[0]
            for item in self._conn().execute(
                """
                SELECT claim_dependency_id FROM bundle_claim_links
                WHERE bundle_fingerprint = ? ORDER BY ordinal
                """,
                (fingerprint,),
            )
        )
        if claim_links != bundle.claim_dependency_ids:
            raise StorageIntegrityError("bundle claim dependency links are corrupt")
        return bundle

    def _legacy_bundle_projection(
        self,
        fingerprint: str,
        dependencies: Sequence[EvidenceDependency],
        *,
        create: bool,
    ) -> bool:
        rows = self._conn().execute(
            """
            SELECT evidence_id, evidence_fingerprint, slot_id,
                   slot_version, ordinal
            FROM bundle_evidence_links
            WHERE bundle_fingerprint = ? ORDER BY ordinal
            """,
            (fingerprint,),
        ).fetchall()
        if (
            not all(item.replaceable for item in dependencies)
            or len({item.evidence_id for item in dependencies})
            != len(dependencies)
        ):
            return False
        expected = tuple(
            (
                item.evidence_id,
                item.evidence_fingerprint,
                item.slot.slot_id,
                item.slot.version,
                ordinal,
            )
            for ordinal, item in enumerate(dependencies)
        )
        observed = tuple(
            (
                row["evidence_id"],
                row["evidence_fingerprint"],
                row["slot_id"],
                row["slot_version"],
                row["ordinal"],
            )
            for row in rows
        )
        if rows or not dependencies:
            return observed == expected
        if not create:
            return False
        for ordinal, item in enumerate(dependencies):
            assert item.slot is not None
            self._conn().execute(
                """
                INSERT INTO bundle_evidence_links(
                    bundle_fingerprint, evidence_id, evidence_fingerprint,
                    slot_id, slot_version, ordinal
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    fingerprint,
                    item.evidence_id,
                    item.evidence_fingerprint,
                    item.slot.slot_id,
                    item.slot.version,
                    ordinal,
                ),
            )
        return True

    def put_bundle(
        self,
        bundle: VerificationBundle,
        *,
        evidence_slots: Mapping[str, EvidenceSlotVersion] | None = None,
        evidence_artifacts: Mapping[str, str] | None = None,
        evidence_dependencies: Iterable[EvidenceDependency] | None = None,
    ) -> StoredBundle:
        with self._logical_write():
            try:
                validate_verification_bundle(bundle)
            except BundleValidationError as exc:
                raise StorageIntegrityError(str(exc)) from exc
            supplied_slots = None if evidence_slots is None else dict(evidence_slots)
            supplied_artifacts = (
                None if evidence_artifacts is None else dict(evidence_artifacts)
            )
            supplied_dependencies = (
                None
                if evidence_dependencies is None
                else tuple(evidence_dependencies)
            )
            if supplied_dependencies is not None and (
                supplied_slots is not None or supplied_artifacts is not None
            ):
                raise StorageIntegrityError(
                    "exact bundle evidence dependencies are mutually exclusive "
                    "with evidence slot/artifact mappings"
                )
            record_rows = self._conn().execute(
                "SELECT record_fingerprint FROM bundle_records WHERE bundle_fingerprint = ?",
                (bundle.fingerprint,),
            ).fetchall()
            if (
                supplied_slots is None
                and supplied_artifacts is None
                and supplied_dependencies is None
                and record_rows
            ):
                stored = self.get_bundle(bundle.fingerprint)
                if stored.bundle != bundle:
                    raise StorageConflictError(
                        "immutable bundle fingerprint has conflicting canonical content"
                    )
                return stored

            slot_map = {} if supplied_slots is None else supplied_slots
            artifact_map = {} if supplied_artifacts is None else supplied_artifacts
            if set(slot_map) & set(artifact_map):
                raise StorageIntegrityError(
                    "bundle evidence cannot be both immutable and replaceable"
                )
            expected_ids = {item.id for item in bundle.evidence}
            if (supplied_slots is not None or supplied_artifacts is not None) and (
                set(slot_map) | set(artifact_map)
            ) != expected_ids:
                raise StorageIntegrityError(
                    "bundle evidence dependency mappings must match exact evidence IDs"
                )

            dependencies: list[EvidenceDependency] = []
            if supplied_dependencies is not None:
                dependencies = list(self._canonical_evidence_dependencies(
                    supplied_dependencies,
                    noun="bundle evidence dependencies",
                ))
                if {item.evidence_id for item in dependencies} != expected_ids:
                    raise StorageIntegrityError(
                        "bundle exact dependencies must cover every bundle evidence ID"
                    )
                bundle_evidence = {item.id: item for item in bundle.evidence}
                for dependency in dependencies:
                    artifact = self.get_evidence(
                        dependency.evidence_fingerprint
                    )
                    if artifact.evidence != bundle_evidence[dependency.evidence_id]:
                        raise StorageIntegrityError(
                            f"bundle evidence {dependency.evidence_id} does not "
                            "match an exact dependency artifact"
                        )
            else:
                for evidence in bundle.evidence:
                    if supplied_slots is None and supplied_artifacts is None:
                        written = self.put_evidence(evidence)
                        dependency = EvidenceDependency(
                            evidence.id,
                            written.fingerprint,
                        )
                    elif evidence.id in slot_map:
                        slot = slot_map[evidence.id]
                        if not isinstance(slot, EvidenceSlotVersion):
                            raise StorageIntegrityError(
                                "bundle evidence slots must contain EvidenceSlotVersion records"
                            )
                        slot = self._slot_version(slot.slot_id, slot.version)
                        artifact = self.get_evidence(slot.evidence_fingerprint)
                        if artifact.evidence != evidence:
                            raise StorageIntegrityError(
                                f"bundle evidence {evidence.id} does not match exact slot artifact"
                            )
                        dependency = EvidenceDependency(
                            evidence.id,
                            slot.evidence_fingerprint,
                            slot,
                        )
                    else:
                        fingerprint = _sha256(
                            artifact_map[evidence.id],
                            name="bundle evidence artifact fingerprint",
                        )
                        artifact = self.get_evidence(fingerprint)
                        if artifact.evidence != evidence:
                            raise StorageIntegrityError(
                                f"bundle evidence {evidence.id} does not match exact immutable artifact"
                            )
                        dependency = EvidenceDependency(evidence.id, fingerprint)
                    dependencies.append(dependency)

            document = bundle.to_dict()
            content, canonical, digest = _parts(document)
            existing = self._conn().execute(
                "SELECT * FROM bundles WHERE fingerprint = ?",
                (bundle.fingerprint,),
            ).fetchone()
            if existing is None:
                self._conn().execute(
                    """
                    INSERT INTO bundles(
                        fingerprint, content_json, canonical_json, content_digest
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (bundle.fingerprint, content, canonical, digest),
                )
                for ordinal, claim_id in enumerate(bundle.claim_dependency_ids):
                    self._conn().execute(
                        """
                        INSERT INTO bundle_claim_links(
                            bundle_fingerprint, claim_dependency_id, ordinal
                        ) VALUES (?, ?, ?)
                        """,
                        (bundle.fingerprint, claim_id, ordinal),
                    )
            elif self._read_bundle_domain(bundle.fingerprint) != bundle:
                raise StorageConflictError(
                    "immutable bundle fingerprint has conflicting canonical content"
                )

            legacy_projection = self._legacy_bundle_projection(
                bundle.fingerprint,
                dependencies,
                create=True,
            )
            record_document = {
                "schema_version": 2,
                "kind": "gvr.stored_bundle_record",
                "bundle_fingerprint": bundle.fingerprint,
                "evidence_dependencies": tuple(
                    self._dependency_document(item) for item in dependencies
                ),
                "legacy_projection": legacy_projection,
            }
            record_content, record_canonical, record_fingerprint = _parts(
                record_document,
                fingerprint_format=_BUNDLE_RECORD_FORMAT,
            )
            record = self._conn().execute(
                "SELECT * FROM bundle_records WHERE record_fingerprint = ?",
                (record_fingerprint,),
            ).fetchone()
            if record is None:
                self._conn().execute(
                    """
                    INSERT INTO bundle_records(
                        record_fingerprint, bundle_fingerprint, content_json,
                        canonical_json, content_digest
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        record_fingerprint,
                        bundle.fingerprint,
                        record_content,
                        record_canonical,
                        record_fingerprint,
                    ),
                )
                record_key = _object_key("bundle-record", record_fingerprint)
                for ordinal, dependency in enumerate(dependencies):
                    self._conn().execute(
                        """
                        INSERT INTO bundle_record_evidence_links(
                            record_fingerprint, evidence_id, evidence_fingerprint,
                            dependency_kind, slot_id, slot_version, ordinal
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            record_fingerprint,
                            dependency.evidence_id,
                            dependency.evidence_fingerprint,
                            "SLOT" if dependency.replaceable else "IMMUTABLE",
                            None if dependency.slot is None else dependency.slot.slot_id,
                            None if dependency.slot is None else dependency.slot.version,
                            ordinal,
                        ),
                    )
                    self._put_dependency(
                        record_key,
                        dependency.object_key,
                        (
                            "evidence_slot_version"
                            if dependency.replaceable
                            else "immutable_evidence"
                        ),
                    )
            else:
                verified = _verified_document(
                    content_json=record["content_json"],
                    canonical_json_value=record["canonical_json"],
                    content_digest=record["content_digest"],
                    fingerprint_format=_BUNDLE_RECORD_FORMAT,
                    identity=f"bundle record {record_fingerprint}",
                )
                if verified != _json_value(record_document):
                    raise StorageConflictError(
                        "bundle record identity has conflicting dependencies"
                    )
            return self.get_bundle(
                bundle.fingerprint,
                record_fingerprint=record_fingerprint,
            )

    def _bundle_record_current(self, record_fingerprint: str) -> bool:
        if self._is_invalidated(
            _object_key("bundle-record", record_fingerprint)
        ):
            return False
        links = self._conn().execute(
            """
            SELECT * FROM bundle_record_evidence_links
            WHERE record_fingerprint = ? ORDER BY ordinal
            """,
            (record_fingerprint,),
        ).fetchall()
        return all(
            self._dependency_from_record_link(item).current for item in links
        )

    def _read_bundle_record(
        self,
        bundle: VerificationBundle,
        row: sqlite3.Row,
    ) -> StoredBundle:
        document = _verified_document(
            content_json=row["content_json"],
            canonical_json_value=row["canonical_json"],
            content_digest=row["content_digest"],
            fingerprint_format=_BUNDLE_RECORD_FORMAT,
            identity=f"bundle record {row['record_fingerprint']}",
        )
        if row["content_digest"] != row["record_fingerprint"]:
            raise StorageIntegrityError("bundle record key is corrupt")
        if document.get("bundle_fingerprint") != bundle.fingerprint:
            raise StorageIntegrityError("bundle record domain reference is corrupt")
        links = self._conn().execute(
            """
            SELECT * FROM bundle_record_evidence_links
            WHERE record_fingerprint = ? ORDER BY ordinal
            """,
            (row["record_fingerprint"],),
        ).fetchall()
        dependencies = tuple(
            self._dependency_from_record_link(item) for item in links
        )
        bundle_evidence = {item.id: item for item in bundle.evidence}
        if {item.evidence_id for item in dependencies} != set(bundle_evidence):
            raise StorageIntegrityError(
                "bundle record evidence links do not cover exact bundle evidence"
            )
        if tuple(self._dependency_document(item) for item in dependencies) != tuple(
            document.get("evidence_dependencies", ())
        ):
            raise StorageIntegrityError(
                "bundle record dependency document conflicts with exact links"
            )
        for dependency in dependencies:
            if (
                self.get_evidence(dependency.evidence_fingerprint).evidence
                != bundle_evidence[dependency.evidence_id]
            ):
                raise StorageIntegrityError(
                    "bundle record evidence artifact content is corrupt"
                )
        if document.get("legacy_projection"):
            if not self._legacy_bundle_projection(
                bundle.fingerprint,
                dependencies,
                create=False,
            ):
                raise StorageIntegrityError(
                    "bundle legacy evidence projection is corrupt"
                )
        return StoredBundle(
            fingerprint=bundle.fingerprint,
            bundle=bundle,
            evidence_slots=tuple(
                item.slot for item in dependencies if item.slot is not None
            ),
            current=self._bundle_record_current(row["record_fingerprint"]),
            record_fingerprint=row["record_fingerprint"],
            evidence_dependencies=dependencies,
        )

    def _get_legacy_bundle(self, fingerprint: str) -> StoredBundle:
        bundle = self._read_bundle_domain(fingerprint)
        links = self._conn().execute(
            """
            SELECT * FROM bundle_evidence_links
            WHERE bundle_fingerprint = ? ORDER BY ordinal
            """,
            (fingerprint,),
        ).fetchall()
        if len(links) != len(bundle.evidence):
            raise StorageIntegrityError("bundle evidence links are incomplete")
        dependencies: list[EvidenceDependency] = []
        for evidence, link in zip(bundle.evidence, links):
            if link["evidence_id"] != evidence.id:
                raise StorageIntegrityError(
                    "bundle evidence link order or identity is corrupt"
                )
            slot = self._slot_version(link["slot_id"], link["slot_version"])
            if slot.evidence_fingerprint != link["evidence_fingerprint"]:
                raise StorageIntegrityError(
                    "bundle evidence link fingerprint is corrupt"
                )
            artifact = self.get_evidence(link["evidence_fingerprint"])
            if artifact.evidence != evidence:
                raise StorageIntegrityError(
                    "bundle evidence artifact content is corrupt"
                )
            dependencies.append(
                EvidenceDependency(evidence.id, link["evidence_fingerprint"], slot)
            )
        current = (
            not self._is_invalidated(_object_key("bundle", fingerprint))
            and all(item.current for item in dependencies)
        )
        return StoredBundle(
            fingerprint=fingerprint,
            bundle=bundle,
            evidence_slots=tuple(item.slot for item in dependencies if item.slot),
            current=current,
            evidence_dependencies=tuple(dependencies),
        )

    def get_bundle(
        self,
        fingerprint: str,
        *,
        record_fingerprint: str | None = None,
    ) -> StoredBundle:
        fingerprint = _sha256(fingerprint, name="bundle fingerprint")
        bundle = self._read_bundle_domain(fingerprint)
        if record_fingerprint is not None:
            record_value = _sha256(
                record_fingerprint,
                name="bundle record fingerprint",
            )
            row = self._conn().execute(
                """
                SELECT * FROM bundle_records
                WHERE record_fingerprint = ? AND bundle_fingerprint = ?
                """,
                (record_value, fingerprint),
            ).fetchone()
            if row is None:
                raise StorageNotFoundError(
                    f"unknown bundle record: {record_value}"
                )
            return self._read_bundle_record(bundle, row)
        rows = self._conn().execute(
            """
            SELECT * FROM bundle_records
            WHERE bundle_fingerprint = ? ORDER BY rowid
            """,
            (fingerprint,),
        ).fetchall()
        if not rows:
            return self._get_legacy_bundle(fingerprint)
        records = tuple(self._read_bundle_record(bundle, item) for item in rows)
        return next(
            (item for item in reversed(records) if item.current),
            records[-1],
        )

    def bundle_history(self, fingerprint: str) -> tuple[StoredBundle, ...]:
        fingerprint = _sha256(fingerprint, name="bundle fingerprint")
        bundle = self._read_bundle_domain(fingerprint)
        rows = self._conn().execute(
            """
            SELECT * FROM bundle_records
            WHERE bundle_fingerprint = ? ORDER BY rowid
            """,
            (fingerprint,),
        ).fetchall()
        if not rows:
            return (self._get_legacy_bundle(fingerprint),)
        return tuple(self._read_bundle_record(bundle, item) for item in rows)

    def _bundle_current(
        self,
        fingerprint: str,
        record_fingerprint: str | None = None,
    ) -> bool:
        return self.get_bundle(
            fingerprint,
            record_fingerprint=record_fingerprint,
        ).current

    def define_claim(
        self,
        definition: ClaimDefinition,
        *,
        verifier_version: str,
    ) -> StoredClaimDefinition:
        with self._logical_write():
            if not isinstance(definition, ClaimDefinition):
                raise StorageIntegrityError("definition must be a ClaimDefinition")
            claim_id = _identifier(definition.id, name="claim id")
            statement = _identifier(definition.statement, name="claim statement")
            verifier_id = _identifier(definition.verifier, name="verifier id")
            version = _identifier(verifier_version, name="verifier version")
            document = {
                "schema_version": 1,
                "kind": "gvr.claim_definition",
                "claim_id": claim_id,
                "statement": statement,
                "verifier_id": verifier_id,
                "verifier_version": version,
            }
            content, canonical, fingerprint = _parts(
                document,
                fingerprint_format=_CLAIM_DEFINITION_FORMAT,
            )
            existing = self._conn().execute(
                "SELECT * FROM claim_definitions WHERE claim_id = ?",
                (claim_id,),
            ).fetchone()
            if existing is None:
                self._conn().execute(
                    """
                    INSERT INTO claim_definitions(
                        claim_id, verifier_id, verifier_version, fingerprint,
                        content_json, canonical_json, content_digest
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim_id,
                        verifier_id,
                        version,
                        fingerprint,
                        content,
                        canonical,
                        fingerprint,
                    ),
                )
            else:
                stored = self._read_claim_definition(existing)
                candidate = StoredClaimDefinition(definition, version, fingerprint)
                if stored != candidate:
                    raise StorageConflictError(
                        f"claim definition {claim_id} already exists with different semantics"
                    )
            return StoredClaimDefinition(definition, version, fingerprint)

    def _read_claim_definition(self, row: sqlite3.Row) -> StoredClaimDefinition:
        document = _verified_document(
            content_json=row["content_json"],
            canonical_json_value=row["canonical_json"],
            content_digest=row["content_digest"],
            fingerprint_format=_CLAIM_DEFINITION_FORMAT,
            identity=f"claim definition {row['claim_id']}",
        )
        if row["fingerprint"] != row["content_digest"]:
            raise StorageIntegrityError("claim definition fingerprint is corrupt")
        if (
            document.get("claim_id") != row["claim_id"]
            or document.get("verifier_id") != row["verifier_id"]
            or document.get("verifier_version") != row["verifier_version"]
        ):
            raise StorageIntegrityError("claim definition columns conflict with canonical content")
        definition = ClaimDefinition(
            document["claim_id"],
            document["statement"],
            document["verifier_id"],
        )
        return StoredClaimDefinition(definition, document["verifier_version"], row["fingerprint"])

    def _claim_definition(self, claim_id: str) -> StoredClaimDefinition:
        row = self._conn().execute(
            "SELECT * FROM claim_definitions WHERE claim_id = ?",
            (claim_id,),
        ).fetchone()
        if row is None:
            raise StorageNotFoundError(f"undefined claim: {claim_id}")
        return self._read_claim_definition(row)

    def _would_cycle(self, claim_id: str, dependencies: Sequence[str]) -> bool:
        target = claim_id
        frontier = list(dependencies)
        seen: set[str] = set()
        while frontier:
            current = frontier.pop()
            if current == target:
                return True
            if current in seen:
                continue
            seen.add(current)
            row = self._conn().execute(
                "SELECT current_version FROM claims WHERE claim_id = ?",
                (current,),
            ).fetchone()
            if row is None:
                continue
            frontier.extend(
                item[0]
                for item in self._conn().execute(
                    """
                    SELECT dependency_claim_id
                    FROM claim_dependency_links
                    WHERE claim_id = ? AND claim_version = ?
                    ORDER BY ordinal
                    """,
                    (current, row["current_version"]),
                )
            )
        return False

    def record_claim(
        self,
        claim_id: str,
        bundle: VerificationBundle | None,
        *,
        verifier_version: str,
        report: VerificationReport | None = None,
        claim_dependency_ids: tuple[str, ...] | None = None,
        falsification_fingerprints: tuple[str, ...] = (),
        bundle_record: StoredBundle | None = None,
        falsification_records: tuple[StoredFalsificationResult, ...] | None = None,
    ) -> StoredClaimVersion:
        with self._logical_write():
            claim_id = _identifier(claim_id, name="claim id")
            definition = self._claim_definition(claim_id)
            version_value = _identifier(
                verifier_version,
                name="verifier version",
            )
            if version_value != definition.verifier_version:
                raise StorageConflictError(
                    f"claim {claim_id} requires verifier version "
                    f"{definition.verifier_version}"
                )

            stored_bundle: StoredBundle | None = None
            if bundle is not None:
                if bundle_record is None:
                    existing_bundle = self._conn().execute(
                        "SELECT 1 FROM bundles WHERE fingerprint = ?",
                        (bundle.fingerprint,),
                    ).fetchone()
                    stored_bundle = (
                        self.put_bundle(bundle)
                        if existing_bundle is None
                        else self.get_bundle(bundle.fingerprint)
                    )
                else:
                    if (
                        type(bundle_record) is not StoredBundle
                        or bundle_record.record_fingerprint is None
                    ):
                        raise StorageIntegrityError(
                            "bundle_record must be an exact stored bundle record"
                        )
                    exact_bundle = self.get_bundle(
                        bundle.fingerprint,
                        record_fingerprint=bundle_record.record_fingerprint,
                    )
                    if (
                        exact_bundle.bundle != bundle
                        or exact_bundle.fingerprint != bundle_record.fingerprint
                        or exact_bundle.record_fingerprint
                        != bundle_record.record_fingerprint
                        or exact_bundle.evidence_dependencies
                        != bundle_record.evidence_dependencies
                    ):
                        raise StorageIntegrityError(
                            "bundle_record conflicts with the exact durable bundle"
                        )
                    stored_bundle = exact_bundle
                if stored_bundle.bundle != bundle:
                    raise StorageConflictError(
                        "bundle fingerprint has conflicting canonical content"
                    )
                if not stored_bundle.current:
                    raise StoredTruthError(
                        "cannot record a claim from a stale bundle"
                    )
                if report is not None and report != bundle.report:
                    raise StorageConflictError(
                        "supplied report disagrees with bundle report"
                    )
                report_value = bundle.report
                expected_dependencies = bundle.claim_dependency_ids
            else:
                if bundle_record is not None:
                    raise StorageIntegrityError("bundle_record requires a bundle")
                if report is None:
                    raise StorageIntegrityError(
                        "a claim record requires a bundle or report"
                    )
                report_value = report
                expected_dependencies = ()
            if report_value.verifier != definition.definition.verifier:
                raise StorageConflictError(
                    f"claim {claim_id} requires verifier "
                    f"{definition.definition.verifier}"
                )

            supplied_dependencies = (
                expected_dependencies
                if claim_dependency_ids is None
                else tuple(claim_dependency_ids)
            )
            dependencies = tuple(sorted(set(supplied_dependencies)))
            if tuple(supplied_dependencies) != dependencies:
                raise StorageIntegrityError(
                    "claim dependency IDs must be unique and sorted"
                )
            if bundle is not None and dependencies != expected_dependencies:
                raise StorageConflictError(
                    "claim dependency IDs disagree with bundle"
                )
            if self._would_cycle(claim_id, dependencies):
                from .dependencies import DependencyCycleError

                raise DependencyCycleError(
                    f"claim dependency cycle for {claim_id}"
                )

            dependency_versions: list[tuple[str, int]] = []
            for dependency_id in dependencies:
                _identifier(dependency_id, name="claim dependency id")
                pointer = self._conn().execute(
                    "SELECT current_version FROM claims WHERE claim_id = ?",
                    (dependency_id,),
                ).fetchone()
                if pointer is None:
                    raise StoredTruthError(
                        f"claim {claim_id} references unverified dependency "
                        f"{dependency_id}"
                    )
                dependency_version = pointer["current_version"]
                if not self._claim_current(
                    dependency_id,
                    dependency_version,
                    set(),
                ):
                    raise StoredTruthError(
                        f"claim {claim_id} references stale dependency "
                        f"{dependency_id}"
                    )
                dependency_versions.append(
                    (dependency_id, dependency_version)
                )

            if falsification_records is not None and falsification_fingerprints:
                raise StorageIntegrityError(
                    "exact falsification records are mutually exclusive with "
                    "falsification fingerprints"
                )
            selected_falsification_records: list[StoredFalsificationResult] = []
            if falsification_records is None:
                falsification_ids = tuple(sorted(set(falsification_fingerprints)))
                if tuple(falsification_fingerprints) != falsification_ids:
                    raise StorageIntegrityError(
                        "falsification fingerprints must be unique and sorted"
                    )
                candidates = tuple(
                    self.get_falsification_result(fingerprint)
                    for fingerprint in falsification_ids
                )
            else:
                supplied_records = tuple(falsification_records)
                if any(
                    type(item) is not StoredFalsificationResult
                    or item.record_fingerprint is None
                    for item in supplied_records
                ):
                    raise StorageIntegrityError(
                        "falsification_records must contain exact stored records"
                    )
                ordered_records = tuple(
                    sorted(
                        supplied_records,
                        key=lambda item: (
                            item.fingerprint,
                            item.record_fingerprint or "",
                        ),
                    )
                )
                if supplied_records != ordered_records or len({
                    item.fingerprint for item in supplied_records
                }) != len(supplied_records):
                    raise StorageIntegrityError(
                        "falsification_records must be unique by domain and sorted"
                    )
                candidates = tuple(
                    self.get_falsification_result(
                        item.fingerprint,
                        record_fingerprint=item.record_fingerprint,
                    )
                    for item in supplied_records
                )
                for supplied, exact in zip(supplied_records, candidates):
                    if (
                        exact.result != supplied.result
                        or exact.record_fingerprint != supplied.record_fingerprint
                        or exact.evidence_dependencies
                        != supplied.evidence_dependencies
                    ):
                        raise StorageIntegrityError(
                            "falsification record conflicts with exact durable content"
                        )
                falsification_ids = tuple(item.fingerprint for item in candidates)
            for stored_falsification in candidates:
                if not stored_falsification.current:
                    raise StoredTruthError(
                        f"claim {claim_id} references stale falsification result"
                    )
                if (
                    stored_falsification.result.claim_id != claim_id
                    or stored_falsification.result.declared_verifier_id
                    != definition.definition.verifier
                ):
                    raise StoredTruthError(
                        f"claim {claim_id} references falsification for a "
                        "different claim or verifier"
                    )
                selected_falsification_records.append(stored_falsification)

            evidence_dependencies = (
                ()
                if stored_bundle is None
                else stored_bundle.evidence_dependencies
            )
            evidence_slots = tuple(
                item.slot
                for item in evidence_dependencies
                if item.slot is not None
            )
            if (
                report_value.verdict is VerificationVerdict.PASS
                and not evidence_dependencies
                and not dependency_versions
                and not falsification_ids
            ):
                raise StoredTruthError(
                    "PASS requires stored evidence, claim, or falsification basis"
                )

            basis_document = {
                "schema_version": 2,
                "kind": "gvr.claim_verification_basis",
                "claim_id": claim_id,
                "definition_fingerprint": definition.fingerprint,
                "verifier_id": definition.definition.verifier,
                "verifier_version": version_value,
                "verdict": report_value.verdict.value,
                "report": _report_document(report_value),
                "bundle_fingerprint": (
                    None if bundle is None else bundle.fingerprint
                ),
                "bundle_record_fingerprint": (
                    None
                    if stored_bundle is None
                    else stored_bundle.record_fingerprint
                ),
                "evidence_slots": [
                    {
                        "slot_id": slot.slot_id,
                        "slot_version": slot.version,
                        "evidence_fingerprint": slot.evidence_fingerprint,
                    }
                    for slot in evidence_slots
                ],
                "evidence_dependencies": [
                    self._dependency_document(item)
                    for item in evidence_dependencies
                ],
                "claim_dependency_versions": [
                    {"claim_id": item, "version": version}
                    for item, version in dependency_versions
                ],
                "falsification_fingerprints": list(falsification_ids),
                "falsification_record_fingerprints": [
                    item.record_fingerprint
                    for item in selected_falsification_records
                ],
            }
            content, canonical, basis_fingerprint = _parts(
                basis_document,
                fingerprint_format=_CLAIM_BASIS_FORMAT,
            )
            current = self._conn().execute(
                "SELECT current_version FROM claims WHERE claim_id = ?",
                (claim_id,),
            ).fetchone()
            if current is not None:
                current_row = self._conn().execute(
                    """
                    SELECT basis_fingerprint FROM claim_versions
                    WHERE claim_id = ? AND version = ?
                    """,
                    (claim_id, current["current_version"]),
                ).fetchone()
                if current_row is None:
                    raise StorageIntegrityError(
                        "claim current pointer is corrupt"
                    )
                if current_row["basis_fingerprint"] == basis_fingerprint:
                    return self._read_claim_version(
                        claim_id,
                        current["current_version"],
                    )
                next_version = current["current_version"] + 1
                previous_key = _object_key(
                    "claim-version",
                    f"{claim_id}:{current['current_version']}",
                )
            else:
                next_version = 1
                previous_key = None

            self._conn().execute(
                """
                INSERT INTO claim_versions(
                    claim_id, version, verdict, verifier_id, verifier_version,
                    bundle_fingerprint, basis_fingerprint,
                    content_json, canonical_json, content_digest
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    claim_id,
                    next_version,
                    report_value.verdict.value,
                    definition.definition.verifier,
                    version_value,
                    None if bundle is None else bundle.fingerprint,
                    basis_fingerprint,
                    content,
                    canonical,
                    basis_fingerprint,
                ),
            )
            if current is None:
                self._conn().execute(
                    "INSERT INTO claims(claim_id, current_version) VALUES (?, ?)",
                    (claim_id, next_version),
                )
            else:
                self._conn().execute(
                    "UPDATE claims SET current_version = ? WHERE claim_id = ?",
                    (next_version, claim_id),
                )

            claim_key = _object_key(
                "claim-version",
                f"{claim_id}:{next_version}",
            )
            if stored_bundle is not None:
                if stored_bundle.record_fingerprint is not None:
                    self._conn().execute(
                        """
                        INSERT INTO claim_bundle_record_links(
                            claim_id, claim_version, bundle_record_fingerprint
                        ) VALUES (?, ?, ?)
                        """,
                        (
                            claim_id,
                            next_version,
                            stored_bundle.record_fingerprint,
                        ),
                    )
                    self._put_dependency(
                        claim_key,
                        stored_bundle.object_key,
                        "bundle_record",
                    )
                else:
                    self._put_dependency(
                        claim_key,
                        _object_key("bundle", bundle.fingerprint),
                        "bundle",
                    )

            for ordinal, dependency in enumerate(evidence_dependencies):
                self._conn().execute(
                    """
                    INSERT INTO claim_evidence_dependency_links(
                        claim_id, claim_version, evidence_id,
                        evidence_fingerprint, dependency_kind,
                        slot_id, slot_version, ordinal
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim_id,
                        next_version,
                        dependency.evidence_id,
                        dependency.evidence_fingerprint,
                        "SLOT" if dependency.replaceable else "IMMUTABLE",
                        None if dependency.slot is None else dependency.slot.slot_id,
                        None if dependency.slot is None else dependency.slot.version,
                        ordinal,
                    ),
                )
                if dependency.slot is not None:
                    self._conn().execute(
                        """
                        INSERT INTO claim_evidence_links(
                            claim_id, claim_version, evidence_fingerprint,
                            slot_id, slot_version, ordinal
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            claim_id,
                            next_version,
                            dependency.evidence_fingerprint,
                            dependency.slot.slot_id,
                            dependency.slot.version,
                            ordinal,
                        ),
                    )
                self._put_dependency(
                    claim_key,
                    dependency.object_key,
                    (
                        "evidence_slot_version"
                        if dependency.replaceable
                        else "immutable_evidence"
                    ),
                )

            for ordinal, (dependency_id, dependency_version) in enumerate(
                dependency_versions
            ):
                self._conn().execute(
                    """
                    INSERT INTO claim_dependency_links(
                        claim_id, claim_version, dependency_claim_id,
                        dependency_claim_version, ordinal
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        claim_id,
                        next_version,
                        dependency_id,
                        dependency_version,
                        ordinal,
                    ),
                )
                self._put_dependency(
                    claim_key,
                    _object_key(
                        "claim-version",
                        f"{dependency_id}:{dependency_version}",
                    ),
                    "claim_version",
                )

            for ordinal, stored_falsification in enumerate(
                selected_falsification_records
            ):
                fingerprint = stored_falsification.fingerprint
                self._conn().execute(
                    """
                    INSERT INTO claim_falsification_links(
                        claim_id, claim_version,
                        falsification_fingerprint, ordinal
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (claim_id, next_version, fingerprint, ordinal),
                )
                if stored_falsification.record_fingerprint is not None:
                    self._conn().execute(
                        """
                        INSERT INTO claim_falsification_record_links(
                            claim_id, claim_version, falsification_fingerprint,
                            falsification_record_fingerprint, ordinal
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            claim_id,
                            next_version,
                            fingerprint,
                            stored_falsification.record_fingerprint,
                            ordinal,
                        ),
                    )
                    self._put_dependency(
                        claim_key,
                        stored_falsification.object_key,
                        "falsification_record",
                    )
                else:
                    self._put_dependency(
                        claim_key,
                        _object_key("falsification", fingerprint),
                        "falsification_result",
                    )

            if previous_key is not None:
                self._invalidate(
                    kind="claim_version_changed",
                    cause_object=previous_key,
                    replacement_object=claim_key,
                )
            return self._read_claim_version(claim_id, next_version)

    def _claim_evidence_dependencies(
        self,
        claim_id: str,
        version: int,
    ) -> tuple[EvidenceDependency, ...]:
        rows = self._conn().execute(
            """
            SELECT * FROM claim_evidence_dependency_links
            WHERE claim_id = ? AND claim_version = ? ORDER BY ordinal
            """,
            (claim_id, version),
        ).fetchall()
        if rows:
            return tuple(
                self._dependency_from_record_link(item) for item in rows
            )
        legacy = self._conn().execute(
            """
            SELECT e.content_json, l.*
            FROM claim_evidence_links AS l
            JOIN evidence_artifacts AS e
              ON e.fingerprint = l.evidence_fingerprint
            WHERE l.claim_id = ? AND l.claim_version = ? ORDER BY l.ordinal
            """,
            (claim_id, version),
        ).fetchall()
        result: list[EvidenceDependency] = []
        for item in legacy:
            evidence_id = json.loads(item["content_json"])["evidence"]["id"]
            slot = self._slot_version(item["slot_id"], item["slot_version"])
            if slot.evidence_fingerprint != item["evidence_fingerprint"]:
                raise StorageIntegrityError(
                    "claim evidence link fingerprint is corrupt"
                )
            result.append(
                EvidenceDependency(
                    evidence_id,
                    item["evidence_fingerprint"],
                    slot,
                )
            )
        return tuple(result)

    def _claim_current(
        self,
        claim_id: str,
        version: int,
        seen: set[tuple[str, int]],
    ) -> bool:
        identity = (claim_id, version)
        if identity in seen:
            raise StorageIntegrityError(
                "stored claim dependency cycle detected"
            )
        seen.add(identity)
        try:
            key = _object_key("claim-version", f"{claim_id}:{version}")
            if self._is_invalidated(key):
                return False
            pointer = self._conn().execute(
                "SELECT current_version FROM claims WHERE claim_id = ?",
                (claim_id,),
            ).fetchone()
            if pointer is None or pointer["current_version"] != version:
                return False
            row = self._conn().execute(
                """
                SELECT bundle_fingerprint, content_json FROM claim_versions
                WHERE claim_id = ? AND version = ?
                """,
                (claim_id, version),
            ).fetchone()
            if row is None:
                raise StorageIntegrityError("claim version is missing")
            try:
                basis_document = json.loads(row["content_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise StorageIntegrityError(
                    "claim current basis is not valid JSON"
                ) from exc
            bundle_record = self._conn().execute(
                """
                SELECT bundle_record_fingerprint
                FROM claim_bundle_record_links
                WHERE claim_id = ? AND claim_version = ?
                """,
                (claim_id, version),
            ).fetchone()
            if (
                basis_document.get("schema_version") == 2
                and row["bundle_fingerprint"] is not None
                and bundle_record is None
            ):
                raise StorageIntegrityError(
                    "v2 claim basis is missing its exact bundle record link"
                )
            if row["bundle_fingerprint"] is not None:
                if not self._bundle_current(
                    row["bundle_fingerprint"],
                    None if bundle_record is None else bundle_record[0],
                ):
                    return False
            evidence_dependencies = self._claim_evidence_dependencies(
                claim_id,
                version,
            )
            if (
                "evidence_dependencies" in basis_document
                and basis_document["evidence_dependencies"]
                != [
                    self._dependency_document(item)
                    for item in evidence_dependencies
                ]
            ):
                raise StorageIntegrityError(
                    "v2 claim evidence dependency links are missing or corrupt"
                )
            if any(not item.current for item in evidence_dependencies):
                return False
            dependency_rows = self._conn().execute(
                """
                SELECT dependency_claim_id, dependency_claim_version
                FROM claim_dependency_links
                WHERE claim_id = ? AND claim_version = ?
                """,
                (claim_id, version),
            ).fetchall()
            for item in dependency_rows:
                if not self._claim_current(
                    item["dependency_claim_id"],
                    item["dependency_claim_version"],
                    seen,
                ):
                    return False
            falsification_rows = self._conn().execute(
                """
                SELECT f.falsification_fingerprint,
                       r.falsification_record_fingerprint
                FROM claim_falsification_links AS f
                LEFT JOIN claim_falsification_record_links AS r
                  ON r.claim_id = f.claim_id
                 AND r.claim_version = f.claim_version
                 AND r.falsification_fingerprint = f.falsification_fingerprint
                WHERE f.claim_id = ? AND f.claim_version = ?
                ORDER BY f.ordinal
                """,
                (claim_id, version),
            ).fetchall()
            if "falsification_record_fingerprints" in basis_document and tuple(
                basis_document["falsification_record_fingerprints"]
            ) != tuple(
                item["falsification_record_fingerprint"]
                for item in falsification_rows
            ):
                raise StorageIntegrityError(
                    "v2 claim falsification record links are missing or corrupt"
                )
            return all(
                self._falsification_current(
                    item["falsification_fingerprint"],
                    item["falsification_record_fingerprint"],
                )
                for item in falsification_rows
            )
        finally:
            seen.remove(identity)

    def _read_claim_version(
        self,
        claim_id: str,
        version: int,
    ) -> StoredClaimVersion:
        row = self._conn().execute(
            """
            SELECT * FROM claim_versions
            WHERE claim_id = ? AND version = ?
            """,
            (claim_id, version),
        ).fetchone()
        if row is None:
            raise StorageNotFoundError(
                f"unknown claim version: {claim_id}:{version}"
            )
        document = _verified_document(
            content_json=row["content_json"],
            canonical_json_value=row["canonical_json"],
            content_digest=row["content_digest"],
            fingerprint_format=_CLAIM_BASIS_FORMAT,
            identity=f"claim version {claim_id}:{version}",
        )
        if (
            row["basis_fingerprint"] != row["content_digest"]
            or row["basis_fingerprint"]
            != canonical_fingerprint(
                document,
                fingerprint_format=_CLAIM_BASIS_FORMAT,
            )
        ):
            raise StorageIntegrityError("claim basis fingerprint is corrupt")
        definition = self._claim_definition(claim_id)
        report = _report_from_document(document["report"])
        if (
            document.get("claim_id") != claim_id
            or document.get("definition_fingerprint") != definition.fingerprint
            or document.get("verifier_id") != row["verifier_id"]
            or document.get("verifier_version") != row["verifier_version"]
            or document.get("verdict") != row["verdict"]
            or report.verdict.value != row["verdict"]
            or report.verifier != row["verifier_id"]
            or document.get("bundle_fingerprint") != row["bundle_fingerprint"]
        ):
            raise StorageIntegrityError(
                "claim basis columns or definition conflict with canonical content"
            )

        bundle_record_row = self._conn().execute(
            """
            SELECT bundle_record_fingerprint
            FROM claim_bundle_record_links
            WHERE claim_id = ? AND claim_version = ?
            """,
            (claim_id, version),
        ).fetchone()
        bundle_record_fingerprint = (
            None if bundle_record_row is None else bundle_record_row[0]
        )
        if row["bundle_fingerprint"] is not None:
            stored_bundle = self.get_bundle(
                row["bundle_fingerprint"],
                record_fingerprint=bundle_record_fingerprint,
            )
            if stored_bundle.bundle.report != report:
                raise StorageIntegrityError(
                    "claim report conflicts with exact stored bundle"
                )
        if document.get("bundle_record_fingerprint") not in (
            None,
            bundle_record_fingerprint,
        ):
            raise StorageIntegrityError(
                "claim bundle record reference is corrupt"
            )

        evidence_dependencies = self._claim_evidence_dependencies(
            claim_id,
            version,
        )
        expected_slot_document = [
            {
                "slot_id": item.slot.slot_id,
                "slot_version": item.slot.version,
                "evidence_fingerprint": item.evidence_fingerprint,
            }
            for item in evidence_dependencies
            if item.slot is not None
        ]
        if document.get("evidence_slots", []) != expected_slot_document:
            raise StorageIntegrityError(
                "claim evidence slot basis conflicts with exact links"
            )
        if "evidence_dependencies" in document and document[
            "evidence_dependencies"
        ] != [
            self._dependency_document(item)
            for item in evidence_dependencies
        ]:
            raise StorageIntegrityError(
                "claim evidence dependency basis conflicts with exact links"
            )

        dependency_versions = tuple(
            (item["dependency_claim_id"], item["dependency_claim_version"])
            for item in self._conn().execute(
                """
                SELECT dependency_claim_id, dependency_claim_version
                FROM claim_dependency_links
                WHERE claim_id = ? AND claim_version = ? ORDER BY ordinal
                """,
                (claim_id, version),
            )
        )
        if document.get("claim_dependency_versions", []) != [
            {"claim_id": item, "version": dependency_version}
            for item, dependency_version in dependency_versions
        ]:
            raise StorageIntegrityError(
                "claim dependency basis conflicts with exact links"
            )

        falsification_rows = self._conn().execute(
            """
            SELECT f.falsification_fingerprint,
                   r.falsification_record_fingerprint
            FROM claim_falsification_links AS f
            LEFT JOIN claim_falsification_record_links AS r
              ON r.claim_id = f.claim_id
             AND r.claim_version = f.claim_version
             AND r.falsification_fingerprint = f.falsification_fingerprint
            WHERE f.claim_id = ? AND f.claim_version = ? ORDER BY f.ordinal
            """,
            (claim_id, version),
        ).fetchall()
        falsification_ids = tuple(
            item["falsification_fingerprint"]
            for item in falsification_rows
        )
        falsification_record_fingerprints = tuple(
            item["falsification_record_fingerprint"]
            for item in falsification_rows
            if item["falsification_record_fingerprint"] is not None
        )
        if tuple(document.get("falsification_fingerprints", ())) != falsification_ids:
            raise StorageIntegrityError(
                "claim falsification basis conflicts with exact links"
            )
        if "falsification_record_fingerprints" in document and tuple(
            document["falsification_record_fingerprints"]
        ) != tuple(
            item["falsification_record_fingerprint"]
            for item in falsification_rows
        ):
            raise StorageIntegrityError(
                "claim falsification record basis conflicts with exact links"
            )
        for item in falsification_rows:
            stored = self.get_falsification_result(
                item["falsification_fingerprint"],
                record_fingerprint=item["falsification_record_fingerprint"],
            )
            if (
                stored.result.claim_id != claim_id
                or stored.result.declared_verifier_id != row["verifier_id"]
            ):
                raise StorageIntegrityError(
                    "claim falsification basis references a different claim or verifier"
                )

        return StoredClaimVersion(
            claim_id=claim_id,
            version=version,
            verdict=VerificationVerdict(row["verdict"]),
            verifier_id=row["verifier_id"],
            verifier_version=row["verifier_version"],
            bundle_fingerprint=row["bundle_fingerprint"],
            report=report,
            basis_fingerprint=row["basis_fingerprint"],
            evidence_slots=tuple(
                item.slot
                for item in evidence_dependencies
                if item.slot is not None
            ),
            claim_dependency_versions=dependency_versions,
            falsification_fingerprints=falsification_ids,
            current=self._claim_current(claim_id, version, set()),
            bundle_record_fingerprint=bundle_record_fingerprint,
            evidence_dependencies=evidence_dependencies,
            falsification_record_fingerprints=falsification_record_fingerprints,
        )

    def claim_status(self, claim_id: str) -> StoredClaimStatus:
        claim_id = _identifier(claim_id, name="claim id")
        row = self._conn().execute(
            "SELECT current_version FROM claims WHERE claim_id = ?",
            (claim_id,),
        ).fetchone()
        if row is None:
            raise StorageNotFoundError(f"claim has no verification history: {claim_id}")
        stored = self._read_claim_version(claim_id, row["current_version"])
        return StoredClaimStatus(
            claim_id=claim_id,
            current_version=stored.version,
            stored_verdict=stored.verdict,
            effective_verdict=(
                stored.verdict if stored.current else VerificationVerdict.UNKNOWN
            ),
            current=stored.current,
        )

    def claim_history(self, claim_id: str) -> tuple[StoredClaimVersion, ...]:
        claim_id = _identifier(claim_id, name="claim id")
        versions = tuple(
            row[0]
            for row in self._conn().execute(
                "SELECT version FROM claim_versions WHERE claim_id = ? ORDER BY version",
                (claim_id,),
            )
        )
        if not versions and self._conn().execute(
            "SELECT 1 FROM claim_definitions WHERE claim_id = ?",
            (claim_id,),
        ).fetchone() is None:
            raise StorageNotFoundError(f"undefined claim: {claim_id}")
        return tuple(self._read_claim_version(claim_id, version) for version in versions)

    def stale_claims(self) -> tuple[str, ...]:
        claim_ids = tuple(
            row[0]
            for row in self._conn().execute("SELECT claim_id FROM claims ORDER BY claim_id")
        )
        return tuple(claim_id for claim_id in claim_ids if not self.claim_status(claim_id).current)

    def _read_falsification_domain(
        self,
        fingerprint: str,
    ) -> FalsificationResult:
        row = self._conn().execute(
            "SELECT * FROM falsification_results WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        if row is None:
            raise StorageNotFoundError(
                f"unknown falsification result: {fingerprint}"
            )
        document = _verified_document(
            content_json=row["content_json"],
            canonical_json_value=row["canonical_json"],
            content_digest=row["content_digest"],
            identity=f"falsification result {fingerprint}",
        )
        result = _falsification_from_document(document)
        if result.fingerprint != fingerprint:
            raise StorageIntegrityError("falsification result key is corrupt")
        return result

    def _legacy_falsification_projection(
        self,
        fingerprint: str,
        dependencies: Sequence[EvidenceDependency],
        *,
        create: bool,
    ) -> bool:
        rows = self._conn().execute(
            """
            SELECT evidence_fingerprint, slot_id, slot_version, ordinal
            FROM falsification_evidence_links
            WHERE falsification_fingerprint = ? ORDER BY ordinal
            """,
            (fingerprint,),
        ).fetchall()
        if not all(item.replaceable for item in dependencies):
            return False
        expected = tuple(
            (
                item.evidence_fingerprint,
                item.slot.slot_id,
                item.slot.version,
                ordinal,
            )
            for ordinal, item in enumerate(dependencies)
        )
        observed = tuple(
            (
                row["evidence_fingerprint"],
                row["slot_id"],
                row["slot_version"],
                row["ordinal"],
            )
            for row in rows
        )
        if rows or not dependencies:
            return observed == expected
        if not create:
            return False
        for ordinal, item in enumerate(dependencies):
            assert item.slot is not None
            self._conn().execute(
                """
                INSERT INTO falsification_evidence_links(
                    falsification_fingerprint, evidence_fingerprint,
                    slot_id, slot_version, ordinal
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    fingerprint,
                    item.evidence_fingerprint,
                    item.slot.slot_id,
                    item.slot.version,
                    ordinal,
                ),
            )
        return True

    def put_falsification_result(
        self,
        result: FalsificationResult,
        *,
        evidence_slots: Iterable[EvidenceSlotVersion] | None = None,
        evidence_artifacts: Iterable[str] | None = None,
        evidence_dependencies: Iterable[EvidenceDependency] | None = None,
    ) -> StoredFalsificationResult:
        with self._logical_write():
            if not isinstance(result, FalsificationResult):
                raise StorageIntegrityError("result must be a FalsificationResult")
            if evidence_dependencies is not None and (
                evidence_slots is not None or evidence_artifacts is not None
            ):
                raise StorageIntegrityError(
                    "exact falsification dependencies are mutually exclusive "
                    "with evidence slot/artifact iterables"
                )
            if (
                evidence_slots is None
                and evidence_artifacts is None
                and evidence_dependencies is None
            ):
                rows = self._conn().execute(
                    """
                    SELECT record_fingerprint FROM falsification_records
                    WHERE falsification_fingerprint = ?
                    """,
                    (result.fingerprint,),
                ).fetchall()
                if rows:
                    stored = self.get_falsification_result(result.fingerprint)
                    if stored.result != result:
                        raise StorageConflictError(
                            "immutable falsification result has conflicting content"
                        )
                    return stored
            if evidence_dependencies is not None:
                dependencies = list(self._canonical_evidence_dependencies(
                    evidence_dependencies,
                    noun="falsification evidence dependencies",
                ))
            else:
                slots = () if evidence_slots is None else tuple(evidence_slots)
                artifacts = () if evidence_artifacts is None else tuple(evidence_artifacts)
                dependencies = []
                seen_ids: set[str] = set()
                for supplied in slots:
                    if not isinstance(supplied, EvidenceSlotVersion):
                        raise StorageIntegrityError(
                            "falsification evidence slots must be EvidenceSlotVersion records"
                        )
                    slot = self._slot_version(supplied.slot_id, supplied.version)
                    artifact = self.get_evidence(slot.evidence_fingerprint)
                    evidence_id = artifact.evidence.id
                    if evidence_id in seen_ids:
                        raise StorageIntegrityError(
                            "falsification evidence dependencies contain duplicate evidence IDs"
                        )
                    seen_ids.add(evidence_id)
                    dependencies.append(
                        EvidenceDependency(
                            evidence_id,
                            slot.evidence_fingerprint,
                            slot,
                        )
                    )
                for supplied in artifacts:
                    fingerprint = _sha256(
                        supplied,
                        name="falsification evidence artifact fingerprint",
                    )
                    artifact = self.get_evidence(fingerprint)
                    evidence_id = artifact.evidence.id
                    if evidence_id in seen_ids:
                        raise StorageIntegrityError(
                            "falsification evidence dependencies contain duplicate evidence IDs"
                        )
                    seen_ids.add(evidence_id)
                    dependencies.append(EvidenceDependency(evidence_id, fingerprint))

            document = result.to_dict()
            content, canonical, digest = _parts(document)
            existing = self._conn().execute(
                "SELECT * FROM falsification_results WHERE fingerprint = ?",
                (result.fingerprint,),
            ).fetchone()
            if existing is None:
                self._conn().execute(
                    """
                    INSERT INTO falsification_results(
                        fingerprint, content_json, canonical_json, content_digest
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (result.fingerprint, content, canonical, digest),
                )
            elif self._read_falsification_domain(result.fingerprint) != result:
                raise StorageConflictError(
                    "immutable falsification result has conflicting content"
                )

            legacy_projection = self._legacy_falsification_projection(
                result.fingerprint,
                dependencies,
                create=True,
            )
            record_document = {
                "schema_version": 2,
                "kind": "gvr.stored_falsification_record",
                "falsification_fingerprint": result.fingerprint,
                "evidence_dependencies": tuple(
                    self._dependency_document(item) for item in dependencies
                ),
                "legacy_projection": legacy_projection,
            }
            record_content, record_canonical, record_fingerprint = _parts(
                record_document,
                fingerprint_format=_FALSIFICATION_RECORD_FORMAT,
            )
            record = self._conn().execute(
                "SELECT * FROM falsification_records WHERE record_fingerprint = ?",
                (record_fingerprint,),
            ).fetchone()
            if record is None:
                self._conn().execute(
                    """
                    INSERT INTO falsification_records(
                        record_fingerprint, falsification_fingerprint,
                        content_json, canonical_json, content_digest
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        record_fingerprint,
                        result.fingerprint,
                        record_content,
                        record_canonical,
                        record_fingerprint,
                    ),
                )
                record_key = _object_key(
                    "falsification-record",
                    record_fingerprint,
                )
                for ordinal, dependency in enumerate(dependencies):
                    self._conn().execute(
                        """
                        INSERT INTO falsification_record_evidence_links(
                            record_fingerprint, evidence_id, evidence_fingerprint,
                            dependency_kind, slot_id, slot_version, ordinal
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            record_fingerprint,
                            dependency.evidence_id,
                            dependency.evidence_fingerprint,
                            "SLOT" if dependency.replaceable else "IMMUTABLE",
                            None if dependency.slot is None else dependency.slot.slot_id,
                            None if dependency.slot is None else dependency.slot.version,
                            ordinal,
                        ),
                    )
                    self._put_dependency(
                        record_key,
                        dependency.object_key,
                        (
                            "evidence_slot_version"
                            if dependency.replaceable
                            else "immutable_evidence"
                        ),
                    )
            else:
                verified = _verified_document(
                    content_json=record["content_json"],
                    canonical_json_value=record["canonical_json"],
                    content_digest=record["content_digest"],
                    fingerprint_format=_FALSIFICATION_RECORD_FORMAT,
                    identity=f"falsification record {record_fingerprint}",
                )
                if verified != _json_value(record_document):
                    raise StorageConflictError(
                        "falsification record identity has conflicting dependencies"
                    )
            return self.get_falsification_result(
                result.fingerprint,
                record_fingerprint=record_fingerprint,
            )

    def _falsification_record_current(self, record_fingerprint: str) -> bool:
        if self._is_invalidated(
            _object_key("falsification-record", record_fingerprint)
        ):
            return False
        rows = self._conn().execute(
            """
            SELECT * FROM falsification_record_evidence_links
            WHERE record_fingerprint = ? ORDER BY ordinal
            """,
            (record_fingerprint,),
        ).fetchall()
        return all(
            self._dependency_from_record_link(item).current for item in rows
        )

    def _read_falsification_record(
        self,
        result: FalsificationResult,
        row: sqlite3.Row,
    ) -> StoredFalsificationResult:
        document = _verified_document(
            content_json=row["content_json"],
            canonical_json_value=row["canonical_json"],
            content_digest=row["content_digest"],
            fingerprint_format=_FALSIFICATION_RECORD_FORMAT,
            identity=f"falsification record {row['record_fingerprint']}",
        )
        if row["content_digest"] != row["record_fingerprint"]:
            raise StorageIntegrityError("falsification record key is corrupt")
        if document.get("falsification_fingerprint") != result.fingerprint:
            raise StorageIntegrityError(
                "falsification record domain reference is corrupt"
            )
        links = self._conn().execute(
            """
            SELECT * FROM falsification_record_evidence_links
            WHERE record_fingerprint = ? ORDER BY ordinal
            """,
            (row["record_fingerprint"],),
        ).fetchall()
        dependencies = tuple(
            self._dependency_from_record_link(item) for item in links
        )
        if tuple(self._dependency_document(item) for item in dependencies) != tuple(
            document.get("evidence_dependencies", ())
        ):
            raise StorageIntegrityError(
                "falsification dependency document conflicts with exact links"
            )
        if document.get("legacy_projection") and not self._legacy_falsification_projection(
            result.fingerprint,
            dependencies,
            create=False,
        ):
            raise StorageIntegrityError(
                "falsification legacy evidence projection is corrupt"
            )
        return StoredFalsificationResult(
            fingerprint=result.fingerprint,
            result=result,
            evidence_slots=tuple(
                item.slot for item in dependencies if item.slot is not None
            ),
            current=self._falsification_record_current(row["record_fingerprint"]),
            record_fingerprint=row["record_fingerprint"],
            evidence_dependencies=dependencies,
        )

    def _get_legacy_falsification_result(
        self,
        fingerprint: str,
    ) -> StoredFalsificationResult:
        result = self._read_falsification_domain(fingerprint)
        links = self._conn().execute(
            """
            SELECT * FROM falsification_evidence_links
            WHERE falsification_fingerprint = ? ORDER BY ordinal
            """,
            (fingerprint,),
        ).fetchall()
        dependencies: list[EvidenceDependency] = []
        for item in links:
            slot = self._slot_version(item["slot_id"], item["slot_version"])
            if slot.evidence_fingerprint != item["evidence_fingerprint"]:
                raise StorageIntegrityError(
                    "falsification evidence link fingerprint is corrupt"
                )
            artifact = self.get_evidence(item["evidence_fingerprint"])
            dependencies.append(
                EvidenceDependency(
                    artifact.evidence.id,
                    item["evidence_fingerprint"],
                    slot,
                )
            )
        current = (
            not self._is_invalidated(_object_key("falsification", fingerprint))
            and all(item.current for item in dependencies)
        )
        return StoredFalsificationResult(
            fingerprint=fingerprint,
            result=result,
            evidence_slots=tuple(item.slot for item in dependencies if item.slot),
            current=current,
            evidence_dependencies=tuple(dependencies),
        )

    def get_falsification_result(
        self,
        fingerprint: str,
        *,
        record_fingerprint: str | None = None,
    ) -> StoredFalsificationResult:
        fingerprint = _sha256(fingerprint, name="falsification fingerprint")
        result = self._read_falsification_domain(fingerprint)
        if record_fingerprint is not None:
            record_value = _sha256(
                record_fingerprint,
                name="falsification record fingerprint",
            )
            row = self._conn().execute(
                """
                SELECT * FROM falsification_records
                WHERE record_fingerprint = ? AND falsification_fingerprint = ?
                """,
                (record_value, fingerprint),
            ).fetchone()
            if row is None:
                raise StorageNotFoundError(
                    f"unknown falsification record: {record_value}"
                )
            return self._read_falsification_record(result, row)
        rows = self._conn().execute(
            """
            SELECT * FROM falsification_records
            WHERE falsification_fingerprint = ? ORDER BY rowid
            """,
            (fingerprint,),
        ).fetchall()
        if not rows:
            return self._get_legacy_falsification_result(fingerprint)
        records = tuple(
            self._read_falsification_record(result, item) for item in rows
        )
        return next(
            (item for item in reversed(records) if item.current),
            records[-1],
        )

    def falsification_history(
        self,
        fingerprint: str,
    ) -> tuple[StoredFalsificationResult, ...]:
        fingerprint = _sha256(fingerprint, name="falsification fingerprint")
        result = self._read_falsification_domain(fingerprint)
        rows = self._conn().execute(
            """
            SELECT * FROM falsification_records
            WHERE falsification_fingerprint = ? ORDER BY rowid
            """,
            (fingerprint,),
        ).fetchall()
        if not rows:
            return (self._get_legacy_falsification_result(fingerprint),)
        return tuple(
            self._read_falsification_record(result, item) for item in rows
        )

    def _falsification_current(
        self,
        fingerprint: str,
        record_fingerprint: str | None = None,
    ) -> bool:
        return self.get_falsification_result(
            fingerprint,
            record_fingerprint=record_fingerprint,
        ).current

    def _put_document(self, kind: str, fingerprint: str, document: Mapping[str, Any]) -> None:
        kind = _identifier(kind, name="document kind")
        fingerprint = _sha256(fingerprint, name="document fingerprint")
        if document.get("fingerprint") != fingerprint:
            raise StorageIntegrityError(
                f"{kind} document fingerprint does not match its reference"
            )
        if kind == "claim_graph":
            _verify_semantic_document_fingerprint(document, identity=kind)
        elif kind == "verification_plan":
            _verify_formatted_document_fingerprint(document, identity=kind)
        elif kind == "verification_execution":
            _verify_formatted_document_fingerprint(
                _execution_semantic_document(document),
                identity=kind,
            )
        content, canonical, digest = _parts(document)
        existing = self._conn().execute(
            "SELECT * FROM documents WHERE document_kind = ? AND fingerprint = ?",
            (kind, fingerprint),
        ).fetchone()
        if existing is None:
            self._conn().execute(
                """
                INSERT INTO documents(
                    document_kind, fingerprint, content_json, canonical_json, content_digest
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (kind, fingerprint, content, canonical, digest),
            )
            return
        stored = _verified_document(
            content_json=existing["content_json"],
            canonical_json_value=existing["canonical_json"],
            content_digest=existing["content_digest"],
            identity=f"{kind} document {fingerprint}",
        )
        candidate = _json_value(document)
        if kind == "verification_execution":
            stored = _execution_semantic_document(stored)
            candidate = _execution_semantic_document(candidate)
        if stored != candidate:
            raise StorageConflictError(f"{kind} document identity has conflicting content")

    def _read_document(self, kind: str, fingerprint: str) -> dict[str, Any]:
        row = self._conn().execute(
            """
            SELECT * FROM documents
            WHERE document_kind = ? AND fingerprint = ?
            """,
            (kind, fingerprint),
        ).fetchone()
        if row is None:
            raise StorageIntegrityError(
                f"missing exact {kind} document {fingerprint}"
            )
        document = _verified_document(
            content_json=row["content_json"],
            canonical_json_value=row["canonical_json"],
            content_digest=row["content_digest"],
            identity=f"{kind} document {fingerprint}",
        )
        if document.get("fingerprint") != fingerprint:
            raise StorageIntegrityError(
                f"{kind} document key conflicts with its fingerprint"
            )
        if kind == "claim_graph":
            _verify_semantic_document_fingerprint(document, identity=kind)
        elif kind == "verification_plan":
            _verify_formatted_document_fingerprint(document, identity=kind)
        elif kind == "verification_execution":
            _verify_formatted_document_fingerprint(
                _execution_semantic_document(document),
                identity=kind,
            )
        return document

    def _read_session_domain(
        self,
        fingerprint: str,
    ) -> tuple[sqlite3.Row, dict[str, Any], dict[str, Any]]:
        row = self._conn().execute(
            "SELECT * FROM sessions WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        if row is None:
            raise StorageNotFoundError(f"unknown session: {fingerprint}")
        document = _verified_document(
            content_json=row["session_content_json"],
            canonical_json_value=row["session_canonical_json"],
            content_digest=row["session_content_digest"],
            identity=f"session {fingerprint}",
        )
        if document.get("fingerprint") != fingerprint:
            raise StorageIntegrityError(
                "session document fingerprint is corrupt"
            )
        _verify_semantic_document_fingerprint(
            document,
            identity=f"session {fingerprint}",
        )
        graph_document = document.get("claim_graph")
        if not isinstance(graph_document, Mapping):
            raise StorageIntegrityError(
                "session claim graph document is missing"
            )
        _verify_semantic_document_fingerprint(
            graph_document,
            identity=f"session {fingerprint} claim graph",
        )
        exact_graph = self._read_document(
            "claim_graph",
            row["graph_fingerprint"],
        )
        if exact_graph != graph_document:
            raise StorageIntegrityError(
                "session embedded graph conflicts with exact stored graph document"
            )
        if document.get("termination_reason") != row["termination"]:
            raise StorageIntegrityError(
                "session termination column is corrupt"
            )
        try:
            counters = json.loads(row["counters_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise StorageIntegrityError(
                "session counters are not valid JSON"
            ) from exc
        if _content_json(counters) != row["counters_json"]:
            raise StorageIntegrityError(
                "session counters are not canonical JSON"
            )
        if counters != document.get("budget", {}).get("consumed", {}):
            raise StorageIntegrityError(
                "session counters conflict with session document"
            )
        return row, document, counters

    def _session_record_document(
        self,
        session_fingerprint: str,
        claim_versions: Sequence[tuple[str, int]],
        bundles: Sequence[StoredBundle],
        falsifications: Sequence[StoredFalsificationResult],
    ) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "kind": "gvr.stored_session_record",
            "session_fingerprint": session_fingerprint,
            "claim_versions": tuple(
                {"claim_id": claim_id, "version": version}
                for claim_id, version in claim_versions
            ),
            "bundle_records": tuple(
                {
                    "bundle_fingerprint": item.fingerprint,
                    "record_fingerprint": item.record_fingerprint,
                }
                for item in bundles
            ),
            "falsification_records": tuple(
                {
                    "falsification_fingerprint": item.fingerprint,
                    "record_fingerprint": item.record_fingerprint,
                }
                for item in falsifications
            ),
        }

    def _execution_request_ids(
        self,
        execution_document: Mapping[str, Any] | None,
    ) -> tuple[str, ...]:
        if execution_document is None:
            return ()
        values = {
            item.get("request_id")
            for item in execution_document.get("provider_results", ())
            if isinstance(item, Mapping)
            and isinstance(item.get("request_id"), str)
        }
        return tuple(sorted(values))

    def _put_session_observation(
        self,
        *,
        session_fingerprint: str,
        session_record_fingerprint: str,
        plan_fingerprint: str | None,
        execution_fingerprint: str | None,
        execution_document: Mapping[str, Any] | None,
    ) -> SessionExecutionObservation:
        request_ids = self._execution_request_ids(execution_document)
        correlation_id = (
            None
            if execution_document is None
            else execution_document.get("correlation_id")
        )
        document = {
            "schema_version": 2,
            "kind": "gvr.session_execution_observation",
            "session_fingerprint": session_fingerprint,
            "session_record_fingerprint": session_record_fingerprint,
            "plan_fingerprint": plan_fingerprint,
            "execution_fingerprint": execution_fingerprint,
            "request_ids": request_ids,
            "correlation_id": correlation_id,
            "execution_document": (
                None
                if execution_document is None
                else _json_value(execution_document)
            ),
        }
        content, canonical, observation_fingerprint = _parts(
            document,
            fingerprint_format=_SESSION_OBSERVATION_FORMAT,
        )
        existing = self._conn().execute(
            """
            SELECT * FROM session_execution_observations
            WHERE observation_fingerprint = ?
            """,
            (observation_fingerprint,),
        ).fetchone()
        if existing is None:
            self._conn().execute(
                """
                INSERT INTO session_execution_observations(
                    observation_fingerprint, session_fingerprint,
                    session_record_fingerprint, plan_fingerprint,
                    execution_fingerprint, request_ids_json,
                    correlation_id, content_json, canonical_json,
                    content_digest
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    observation_fingerprint,
                    session_fingerprint,
                    session_record_fingerprint,
                    plan_fingerprint,
                    execution_fingerprint,
                    _content_json(request_ids),
                    correlation_id,
                    content,
                    canonical,
                    observation_fingerprint,
                ),
            )
        else:
            verified = _verified_document(
                content_json=existing["content_json"],
                canonical_json_value=existing["canonical_json"],
                content_digest=existing["content_digest"],
                fingerprint_format=_SESSION_OBSERVATION_FORMAT,
                identity=f"session observation {observation_fingerprint}",
            )
            if verified != _json_value(document):
                raise StorageConflictError(
                    "session observation identity has conflicting content"
                )
        return SessionExecutionObservation(
            observation_fingerprint=observation_fingerprint,
            session_fingerprint=session_fingerprint,
            session_record_fingerprint=session_record_fingerprint,
            plan_fingerprint=plan_fingerprint,
            execution_fingerprint=execution_fingerprint,
            request_ids=request_ids,
            correlation_id=correlation_id,
            execution_document=(
                None
                if execution_document is None
                else deepcopy(dict(execution_document))
            ),
        )

    def put_session(
        self,
        session: VerificationSession,
        *,
        plan_fingerprint: str | None = None,
        execution_fingerprint: str | None = None,
        execution_document: Mapping[str, Any] | None = None,
        falsification_fingerprints: tuple[str, ...] = (),
        claim_records: tuple[StoredClaimVersion, ...] | None = None,
        bundle_records: tuple[StoredBundle, ...] | None = None,
        falsification_records: tuple[StoredFalsificationResult, ...] | None = None,
    ) -> StoredSession:
        with self._logical_write():
            if type(session) is not VerificationSession or not session.sealed:
                raise StorageIntegrityError(
                    "session must be an exact sealed VerificationSession"
                )
            session_document = session.to_dict()
            session_fingerprint = _sha256(
                session.fingerprint,
                name="session fingerprint",
            )
            graph_fingerprint = _sha256(
                session.graph.fingerprint,
                name="graph fingerprint",
            )
            if session_document.get("fingerprint") != session_fingerprint:
                raise StorageIntegrityError(
                    "session fingerprint is inconsistent"
                )
            self._put_document(
                "claim_graph",
                graph_fingerprint,
                session.graph.to_dict(),
            )
            plan_value = (
                None
                if plan_fingerprint is None
                else _sha256(plan_fingerprint, name="plan fingerprint")
            )
            execution_value = (
                None
                if execution_fingerprint is None
                else _sha256(
                    execution_fingerprint,
                    name="execution fingerprint",
                )
            )
            if execution_document is not None:
                if execution_value is None:
                    raise StorageIntegrityError(
                        "execution_document requires execution_fingerprint"
                    )
                if not isinstance(execution_document, Mapping):
                    raise StorageIntegrityError(
                        "execution_document must be a mapping"
                    )
                if execution_document.get("fingerprint") != execution_value:
                    raise StorageIntegrityError(
                        "execution document fingerprint does not match exact reference"
                    )
                self._put_document(
                    "verification_execution",
                    execution_value,
                    execution_document,
                )

            if falsification_records is not None and falsification_fingerprints:
                raise StorageIntegrityError(
                    "exact session falsification records are mutually exclusive "
                    "with falsification fingerprints"
                )
            if falsification_records is None:
                falsification_ids = tuple(sorted(set(falsification_fingerprints)))
                if tuple(falsification_fingerprints) != falsification_ids:
                    raise StorageIntegrityError(
                        "session falsification fingerprints must be unique and sorted"
                    )
                falsifications = tuple(
                    self.get_falsification_result(item)
                    for item in falsification_ids
                )
            else:
                supplied_falsifications = tuple(falsification_records)
                if any(
                    type(item) is not StoredFalsificationResult
                    or item.record_fingerprint is None
                    for item in supplied_falsifications
                ):
                    raise StorageIntegrityError(
                        "session falsification records must be exact stored records"
                    )
                ordered_falsifications = tuple(
                    sorted(
                        supplied_falsifications,
                        key=lambda item: (
                            item.fingerprint,
                            item.record_fingerprint or "",
                        ),
                    )
                )
                if supplied_falsifications != ordered_falsifications or len({
                    item.fingerprint for item in supplied_falsifications
                }) != len(supplied_falsifications):
                    raise StorageIntegrityError(
                        "session falsification records must be unique by domain and sorted"
                    )
                falsifications = tuple(
                    self.get_falsification_result(
                        item.fingerprint,
                        record_fingerprint=item.record_fingerprint,
                    )
                    for item in supplied_falsifications
                )
                for supplied, exact in zip(
                    supplied_falsifications,
                    falsifications,
                ):
                    if (
                        exact.result != supplied.result
                        or exact.record_fingerprint != supplied.record_fingerprint
                        or exact.evidence_dependencies
                        != supplied.evidence_dependencies
                        or not exact.current
                    ):
                        raise StorageIntegrityError(
                            "session falsification record conflicts with exact durable content"
                        )
                falsification_ids = tuple(
                    item.fingerprint for item in falsifications
                )

            claim_ids = tuple(
                item["claim_id"]
                for item in session_document.get("claims", ())
            )
            if len(set(claim_ids)) != len(claim_ids):
                raise StorageIntegrityError(
                    "session contains duplicate claim states"
                )
            if claim_records is None:
                current_claim_records: list[StoredClaimVersion] = []
                for claim_id in claim_ids:
                    pointer = self._conn().execute(
                        "SELECT current_version FROM claims WHERE claim_id = ?",
                        (claim_id,),
                    ).fetchone()
                    if pointer is None:
                        raise StorageIntegrityError(
                            "session references claim without durable history: "
                            f"{claim_id}"
                        )
                    current_claim_records.append(
                        self._read_claim_version(
                            claim_id,
                            pointer["current_version"],
                        )
                    )
                selected_claim_records = tuple(current_claim_records)
            else:
                supplied_claim_records = tuple(claim_records)
                if (
                    any(
                        type(item) is not StoredClaimVersion
                        for item in supplied_claim_records
                    )
                    or tuple(item.claim_id for item in supplied_claim_records)
                    != claim_ids
                ):
                    raise StorageIntegrityError(
                        "session claim records must be exact and match claim order"
                    )
                selected_claim_records = tuple(
                    self._read_claim_version(item.claim_id, item.version)
                    for item in supplied_claim_records
                )
                for supplied, exact in zip(
                    supplied_claim_records,
                    selected_claim_records,
                ):
                    if exact != supplied or not exact.current:
                        raise StorageIntegrityError(
                            "session claim record conflicts with exact durable content"
                        )
            claim_versions: list[tuple[str, int]] = []
            for claim_id, stored_claim in zip(claim_ids, selected_claim_records):
                state = next(
                    item
                    for item in session_document["claims"]
                    if item["claim_id"] == claim_id
                )
                if (
                    state["stored_verdict"] != stored_claim.verdict.value
                    or state["bundle_fingerprint"]
                    != stored_claim.bundle_fingerprint
                ):
                    raise StorageIntegrityError(
                        f"session claim state for {claim_id} does not match durable basis"
                    )
                claim_versions.append((claim_id, stored_claim.version))

            bundle_ids = tuple(sorted({
                item["bundle_fingerprint"]
                for item in session_document.get("atomic_verifications", ())
                if item.get("bundle_fingerprint") is not None
            }))
            if bundle_records is None:
                bundles = tuple(self.get_bundle(item) for item in bundle_ids)
            else:
                supplied_bundles = tuple(bundle_records)
                if (
                    any(
                        type(item) is not StoredBundle
                        or item.record_fingerprint is None
                        for item in supplied_bundles
                    )
                    or tuple(item.fingerprint for item in supplied_bundles)
                    != bundle_ids
                ):
                    raise StorageIntegrityError(
                        "session bundle records must be exact and sorted by domain"
                    )
                bundles = tuple(
                    self.get_bundle(
                        item.fingerprint,
                        record_fingerprint=item.record_fingerprint,
                    )
                    for item in supplied_bundles
                )
                for supplied, exact in zip(supplied_bundles, bundles):
                    if (
                        exact.bundle != supplied.bundle
                        or exact.record_fingerprint != supplied.record_fingerprint
                        or exact.evidence_dependencies
                        != supplied.evidence_dependencies
                        or not exact.current
                    ):
                        raise StorageIntegrityError(
                            "session bundle record conflicts with exact durable content"
                        )
            session_content, session_canonical, session_digest = _parts(
                session_document
            )
            counters = session.consumption.to_dict()
            counters_json = _content_json(counters)
            execution_content = None
            execution_canonical = None
            execution_digest = None
            if execution_document is not None:
                execution_content, execution_canonical, execution_digest = _parts(
                    execution_document
                )

            existing = self._conn().execute(
                "SELECT * FROM sessions WHERE fingerprint = ?",
                (session_fingerprint,),
            ).fetchone()
            if existing is None:
                self._conn().execute(
                    """
                    INSERT INTO sessions(
                        fingerprint, graph_fingerprint, plan_fingerprint,
                        execution_fingerprint, termination, counters_json,
                        session_content_json, session_canonical_json,
                        session_content_digest, execution_content_json,
                        execution_canonical_json, execution_content_digest
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_fingerprint,
                        graph_fingerprint,
                        plan_value,
                        execution_value,
                        session.termination_reason.value,
                        counters_json,
                        session_content,
                        session_canonical,
                        session_digest,
                        execution_content,
                        execution_canonical,
                        execution_digest,
                    ),
                )
                legacy_session_key = _object_key(
                    "session",
                    session_fingerprint,
                )
                for ordinal, (claim_id, claim_version) in enumerate(
                    claim_versions
                ):
                    self._conn().execute(
                        """
                        INSERT INTO session_claim_links(
                            session_fingerprint, claim_id,
                            claim_version, ordinal
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (
                            session_fingerprint,
                            claim_id,
                            claim_version,
                            ordinal,
                        ),
                    )
                    self._put_dependency(
                        legacy_session_key,
                        _object_key(
                            "claim-version",
                            f"{claim_id}:{claim_version}",
                        ),
                        "claim_version",
                    )
                for ordinal, stored_bundle in enumerate(bundles):
                    self._conn().execute(
                        """
                        INSERT INTO session_bundle_links(
                            session_fingerprint, bundle_fingerprint, ordinal
                        ) VALUES (?, ?, ?)
                        """,
                        (
                            session_fingerprint,
                            stored_bundle.fingerprint,
                            ordinal,
                        ),
                    )
                    self._put_dependency(
                        legacy_session_key,
                        _object_key("bundle", stored_bundle.fingerprint),
                        "bundle",
                    )
                for ordinal, stored_falsification in enumerate(falsifications):
                    self._conn().execute(
                        """
                        INSERT INTO session_falsification_links(
                            session_fingerprint,
                            falsification_fingerprint, ordinal
                        ) VALUES (?, ?, ?)
                        """,
                        (
                            session_fingerprint,
                            stored_falsification.fingerprint,
                            ordinal,
                        ),
                    )
                    self._put_dependency(
                        legacy_session_key,
                        _object_key(
                            "falsification",
                            stored_falsification.fingerprint,
                        ),
                        "falsification_result",
                    )
            else:
                _, stored_document, stored_counters = self._read_session_domain(
                    session_fingerprint
                )
                if (
                    stored_document != _json_value(session_document)
                    or existing["graph_fingerprint"] != graph_fingerprint
                    or existing["termination"]
                    != session.termination_reason.value
                    or stored_counters != counters
                ):
                    raise StorageConflictError(
                        "immutable session fingerprint has conflicting semantic content"
                    )

            record_document = self._session_record_document(
                session_fingerprint,
                claim_versions,
                bundles,
                falsifications,
            )
            record_content, record_canonical, record_fingerprint = _parts(
                record_document,
                fingerprint_format=_SESSION_RECORD_FORMAT,
            )
            record = self._conn().execute(
                "SELECT * FROM session_records WHERE record_fingerprint = ?",
                (record_fingerprint,),
            ).fetchone()
            if record is None:
                self._conn().execute(
                    """
                    INSERT INTO session_records(
                        record_fingerprint, session_fingerprint,
                        content_json, canonical_json, content_digest
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        record_fingerprint,
                        session_fingerprint,
                        record_content,
                        record_canonical,
                        record_fingerprint,
                    ),
                )
                record_key = _object_key(
                    "session-record",
                    record_fingerprint,
                )
                for ordinal, (claim_id, claim_version) in enumerate(
                    claim_versions
                ):
                    self._conn().execute(
                        """
                        INSERT INTO session_record_claim_links(
                            record_fingerprint, claim_id,
                            claim_version, ordinal
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (
                            record_fingerprint,
                            claim_id,
                            claim_version,
                            ordinal,
                        ),
                    )
                    self._put_dependency(
                        record_key,
                        _object_key(
                            "claim-version",
                            f"{claim_id}:{claim_version}",
                        ),
                        "claim_version",
                    )
                for ordinal, stored_bundle in enumerate(bundles):
                    if stored_bundle.record_fingerprint is None:
                        continue
                    self._conn().execute(
                        """
                        INSERT INTO session_record_bundle_links(
                            record_fingerprint, bundle_fingerprint,
                            bundle_record_fingerprint, ordinal
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (
                            record_fingerprint,
                            stored_bundle.fingerprint,
                            stored_bundle.record_fingerprint,
                            ordinal,
                        ),
                    )
                    self._put_dependency(
                        record_key,
                        stored_bundle.object_key,
                        "bundle_record",
                    )
                for ordinal, stored_falsification in enumerate(falsifications):
                    if stored_falsification.record_fingerprint is None:
                        continue
                    self._conn().execute(
                        """
                        INSERT INTO session_record_falsification_links(
                            record_fingerprint, falsification_fingerprint,
                            falsification_record_fingerprint, ordinal
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (
                            record_fingerprint,
                            stored_falsification.fingerprint,
                            stored_falsification.record_fingerprint,
                            ordinal,
                        ),
                    )
                    self._put_dependency(
                        record_key,
                        stored_falsification.object_key,
                        "falsification_record",
                    )
            else:
                verified = _verified_document(
                    content_json=record["content_json"],
                    canonical_json_value=record["canonical_json"],
                    content_digest=record["content_digest"],
                    fingerprint_format=_SESSION_RECORD_FORMAT,
                    identity=f"session record {record_fingerprint}",
                )
                if verified != _json_value(record_document):
                    raise StorageConflictError(
                        "session record identity has conflicting dependencies"
                    )

            self._put_session_observation(
                session_fingerprint=session_fingerprint,
                session_record_fingerprint=record_fingerprint,
                plan_fingerprint=plan_value,
                execution_fingerprint=execution_value,
                execution_document=execution_document,
            )
            return self.get_session(
                session_fingerprint,
                record_fingerprint=record_fingerprint,
            )

    def _session_record_current(self, record_fingerprint: str) -> bool:
        if self._is_invalidated(
            _object_key("session-record", record_fingerprint)
        ):
            return False
        claims = self._conn().execute(
            """
            SELECT claim_id, claim_version FROM session_record_claim_links
            WHERE record_fingerprint = ?
            """,
            (record_fingerprint,),
        ).fetchall()
        if any(
            not self._claim_current(
                item["claim_id"],
                item["claim_version"],
                set(),
            )
            for item in claims
        ):
            return False
        bundles = self._conn().execute(
            """
            SELECT bundle_fingerprint, bundle_record_fingerprint
            FROM session_record_bundle_links
            WHERE record_fingerprint = ?
            """,
            (record_fingerprint,),
        ).fetchall()
        if any(
            not self._bundle_current(
                item["bundle_fingerprint"],
                item["bundle_record_fingerprint"],
            )
            for item in bundles
        ):
            return False
        falsifications = self._conn().execute(
            """
            SELECT falsification_fingerprint,
                   falsification_record_fingerprint
            FROM session_record_falsification_links
            WHERE record_fingerprint = ?
            """,
            (record_fingerprint,),
        ).fetchall()
        return all(
            self._falsification_current(
                item["falsification_fingerprint"],
                item["falsification_record_fingerprint"],
            )
            for item in falsifications
        )

    def _read_session_observation_row(
        self,
        row: sqlite3.Row,
    ) -> SessionExecutionObservation:
        document = _verified_document(
            content_json=row["content_json"],
            canonical_json_value=row["canonical_json"],
            content_digest=row["content_digest"],
            fingerprint_format=_SESSION_OBSERVATION_FORMAT,
            identity=f"session observation {row['observation_fingerprint']}",
        )
        if row["content_digest"] != row["observation_fingerprint"]:
            raise StorageIntegrityError(
                "session observation key is corrupt"
            )
        request_ids = tuple(document.get("request_ids", ()))
        if row["request_ids_json"] != _content_json(request_ids):
            raise StorageIntegrityError(
                "session observation request IDs are corrupt"
            )
        if (
            document.get("session_fingerprint")
            != row["session_fingerprint"]
            or document.get("session_record_fingerprint")
            != row["session_record_fingerprint"]
            or document.get("plan_fingerprint") != row["plan_fingerprint"]
            or document.get("execution_fingerprint")
            != row["execution_fingerprint"]
            or document.get("correlation_id") != row["correlation_id"]
        ):
            raise StorageIntegrityError(
                "session observation columns conflict with canonical content"
            )
        execution_document = document.get("execution_document")
        if execution_document is not None:
            if not isinstance(execution_document, Mapping):
                raise StorageIntegrityError(
                    "session observation execution document is invalid"
                )
            if execution_document.get("fingerprint") != row["execution_fingerprint"]:
                raise StorageIntegrityError(
                    "session observation execution fingerprint is corrupt"
                )
            _verify_formatted_document_fingerprint(
                _execution_semantic_document(execution_document),
                identity="verification_execution",
            )
        return SessionExecutionObservation(
            observation_fingerprint=row["observation_fingerprint"],
            session_fingerprint=row["session_fingerprint"],
            session_record_fingerprint=row["session_record_fingerprint"],
            plan_fingerprint=row["plan_fingerprint"],
            execution_fingerprint=row["execution_fingerprint"],
            request_ids=request_ids,
            correlation_id=row["correlation_id"],
            execution_document=deepcopy(execution_document),
        )

    def _read_session_record(
        self,
        domain_row: sqlite3.Row,
        session_document: Mapping[str, Any],
        counters: Mapping[str, Any],
        row: sqlite3.Row,
    ) -> StoredSession:
        document = _verified_document(
            content_json=row["content_json"],
            canonical_json_value=row["canonical_json"],
            content_digest=row["content_digest"],
            fingerprint_format=_SESSION_RECORD_FORMAT,
            identity=f"session record {row['record_fingerprint']}",
        )
        if row["content_digest"] != row["record_fingerprint"]:
            raise StorageIntegrityError("session record key is corrupt")
        if document.get("session_fingerprint") != row["session_fingerprint"]:
            raise StorageIntegrityError(
                "session record domain reference is corrupt"
            )
        claim_versions = tuple(
            (item["claim_id"], item["claim_version"])
            for item in self._conn().execute(
                """
                SELECT claim_id, claim_version
                FROM session_record_claim_links
                WHERE record_fingerprint = ? ORDER BY ordinal
                """,
                (row["record_fingerprint"],),
            )
        )
        states = {
            item["claim_id"]: item
            for item in session_document.get("claims", ())
        }
        for claim_id, claim_version in claim_versions:
            stored_claim = self._read_claim_version(claim_id, claim_version)
            state = states.get(claim_id)
            if state is None or (
                state.get("stored_verdict") != stored_claim.verdict.value
                or state.get("bundle_fingerprint")
                != stored_claim.bundle_fingerprint
                or tuple(state.get("evidence_ids", ()))
                != stored_claim.report.evidence_ids
            ):
                raise StorageIntegrityError(
                    f"session claim state for {claim_id} conflicts with durable basis"
                )
        bundle_rows = self._conn().execute(
            """
            SELECT bundle_fingerprint, bundle_record_fingerprint
            FROM session_record_bundle_links
            WHERE record_fingerprint = ? ORDER BY ordinal
            """,
            (row["record_fingerprint"],),
        ).fetchall()
        bundle_fingerprints = tuple(
            item["bundle_fingerprint"] for item in bundle_rows
        )
        bundle_record_fingerprints = tuple(
            item["bundle_record_fingerprint"] for item in bundle_rows
        )
        for item in bundle_rows:
            self.get_bundle(
                item["bundle_fingerprint"],
                record_fingerprint=item["bundle_record_fingerprint"],
            )
        falsification_rows = self._conn().execute(
            """
            SELECT falsification_fingerprint,
                   falsification_record_fingerprint
            FROM session_record_falsification_links
            WHERE record_fingerprint = ? ORDER BY ordinal
            """,
            (row["record_fingerprint"],),
        ).fetchall()
        falsification_fingerprints = tuple(
            item["falsification_fingerprint"]
            for item in falsification_rows
        )
        falsification_record_fingerprints = tuple(
            item["falsification_record_fingerprint"]
            for item in falsification_rows
        )
        for item in falsification_rows:
            self.get_falsification_result(
                item["falsification_fingerprint"],
                record_fingerprint=item["falsification_record_fingerprint"],
            )
        expected_record = self._session_record_document(
            row["session_fingerprint"],
            claim_versions,
            tuple(
                self.get_bundle(
                    item["bundle_fingerprint"],
                    record_fingerprint=item["bundle_record_fingerprint"],
                )
                for item in bundle_rows
            ),
            tuple(
                self.get_falsification_result(
                    item["falsification_fingerprint"],
                    record_fingerprint=item[
                        "falsification_record_fingerprint"
                    ],
                )
                for item in falsification_rows
            ),
        )
        if document != _json_value(expected_record):
            raise StorageIntegrityError(
                "session record document conflicts with exact links"
            )
        observation_row = self._conn().execute(
            """
            SELECT * FROM session_execution_observations
            WHERE session_record_fingerprint = ? ORDER BY rowid DESC LIMIT 1
            """,
            (row["record_fingerprint"],),
        ).fetchone()
        observation = (
            None
            if observation_row is None
            else self._read_session_observation_row(observation_row)
        )
        return StoredSession(
            fingerprint=row["session_fingerprint"],
            session_document=deepcopy(dict(session_document)),
            graph_fingerprint=domain_row["graph_fingerprint"],
            plan_fingerprint=(
                None if observation is None else observation.plan_fingerprint
            ),
            execution_fingerprint=(
                None
                if observation is None
                else observation.execution_fingerprint
            ),
            execution_document=(
                None
                if observation is None
                else observation.execution_document
            ),
            termination=domain_row["termination"],
            counters=deepcopy(dict(counters)),
            claim_versions=claim_versions,
            bundle_fingerprints=bundle_fingerprints,
            falsification_fingerprints=falsification_fingerprints,
            current=self._session_record_current(row["record_fingerprint"]),
            record_fingerprint=row["record_fingerprint"],
            bundle_record_fingerprints=bundle_record_fingerprints,
            falsification_record_fingerprints=(
                falsification_record_fingerprints
            ),
        )

    def _get_legacy_session(self, fingerprint: str) -> StoredSession:
        row, document, counters = self._read_session_domain(fingerprint)
        claim_versions = tuple(
            (item["claim_id"], item["claim_version"])
            for item in self._conn().execute(
                """
                SELECT claim_id, claim_version FROM session_claim_links
                WHERE session_fingerprint = ? ORDER BY ordinal
                """,
                (fingerprint,),
            )
        )
        states = {
            item["claim_id"]: item
            for item in document.get("claims", ())
        }
        for claim_id, claim_version in claim_versions:
            stored_claim = self._read_claim_version(claim_id, claim_version)
            state = states.get(claim_id)
            if state is None or (
                state.get("stored_verdict") != stored_claim.verdict.value
                or state.get("bundle_fingerprint")
                != stored_claim.bundle_fingerprint
            ):
                raise StorageIntegrityError(
                    f"session claim state for {claim_id} conflicts with durable basis"
                )
        bundle_fingerprints = tuple(
            item[0]
            for item in self._conn().execute(
                """
                SELECT bundle_fingerprint FROM session_bundle_links
                WHERE session_fingerprint = ? ORDER BY ordinal
                """,
                (fingerprint,),
            )
        )
        falsification_fingerprints = tuple(
            item[0]
            for item in self._conn().execute(
                """
                SELECT falsification_fingerprint
                FROM session_falsification_links
                WHERE session_fingerprint = ? ORDER BY ordinal
                """,
                (fingerprint,),
            )
        )
        execution_document = None
        if row["execution_content_json"] is not None:
            execution_document = _verified_document(
                content_json=row["execution_content_json"],
                canonical_json_value=row["execution_canonical_json"],
                content_digest=row["execution_content_digest"],
                identity=f"session execution {row['execution_fingerprint']}",
            )
            if execution_document.get("fingerprint") != row["execution_fingerprint"]:
                raise StorageIntegrityError(
                    "session execution document fingerprint is corrupt"
                )
        current = (
            not self._is_invalidated(_object_key("session", fingerprint))
            and all(
                self._claim_current(claim_id, version, set())
                for claim_id, version in claim_versions
            )
            and all(self._bundle_current(item) for item in bundle_fingerprints)
            and all(
                self._falsification_current(item)
                for item in falsification_fingerprints
            )
        )
        return StoredSession(
            fingerprint=fingerprint,
            session_document=deepcopy(document),
            graph_fingerprint=row["graph_fingerprint"],
            plan_fingerprint=row["plan_fingerprint"],
            execution_fingerprint=row["execution_fingerprint"],
            execution_document=deepcopy(execution_document),
            termination=row["termination"],
            counters=deepcopy(counters),
            claim_versions=claim_versions,
            bundle_fingerprints=bundle_fingerprints,
            falsification_fingerprints=falsification_fingerprints,
            current=current,
        )

    def get_session(
        self,
        fingerprint: str,
        *,
        record_fingerprint: str | None = None,
    ) -> StoredSession:
        fingerprint = _sha256(fingerprint, name="session fingerprint")
        domain_row, document, counters = self._read_session_domain(fingerprint)
        if record_fingerprint is not None:
            record_value = _sha256(
                record_fingerprint,
                name="session record fingerprint",
            )
            row = self._conn().execute(
                """
                SELECT * FROM session_records
                WHERE record_fingerprint = ? AND session_fingerprint = ?
                """,
                (record_value, fingerprint),
            ).fetchone()
            if row is None:
                raise StorageNotFoundError(
                    f"unknown session record: {record_value}"
                )
            return self._read_session_record(
                domain_row,
                document,
                counters,
                row,
            )
        rows = self._conn().execute(
            """
            SELECT * FROM session_records
            WHERE session_fingerprint = ? ORDER BY rowid
            """,
            (fingerprint,),
        ).fetchall()
        if not rows:
            return self._get_legacy_session(fingerprint)
        records = tuple(
            self._read_session_record(domain_row, document, counters, item)
            for item in rows
        )
        return next(
            (item for item in reversed(records) if item.current),
            records[-1],
        )

    def session_record_history(
        self,
        fingerprint: str,
    ) -> tuple[StoredSession, ...]:
        fingerprint = _sha256(fingerprint, name="session fingerprint")
        domain_row, document, counters = self._read_session_domain(fingerprint)
        rows = self._conn().execute(
            """
            SELECT * FROM session_records
            WHERE session_fingerprint = ? ORDER BY rowid
            """,
            (fingerprint,),
        ).fetchall()
        if not rows:
            return (self._get_legacy_session(fingerprint),)
        return tuple(
            self._read_session_record(domain_row, document, counters, item)
            for item in rows
        )

    def session_execution_observations(
        self,
        fingerprint: str,
    ) -> tuple[SessionExecutionObservation, ...]:
        fingerprint = _sha256(fingerprint, name="session fingerprint")
        self._read_session_domain(fingerprint)
        rows = self._conn().execute(
            """
            SELECT * FROM session_execution_observations
            WHERE session_fingerprint = ? ORDER BY rowid
            """,
            (fingerprint,),
        ).fetchall()
        return tuple(self._read_session_observation_row(item) for item in rows)

    def session_history(self) -> tuple[StoredSession, ...]:
        fingerprints = tuple(
            row[0]
            for row in self._conn().execute(
                "SELECT fingerprint FROM sessions ORDER BY rowid"
            )
        )
        return tuple(self.get_session(fingerprint) for fingerprint in fingerprints)

    def record_execution(self, request: Any, result: Any) -> StoredSession:
        with self._logical_write():
            if result.request_fingerprint != request.fingerprint:
                raise StorageIntegrityError(
                    "execution result does not match exact request fingerprint"
                )
            if result.plan_fingerprint != request.plan.fingerprint:
                raise StorageIntegrityError(
                    "execution result does not match exact plan fingerprint"
                )
            if result.claim_graph_fingerprint != request.claim_graph.fingerprint:
                raise StorageIntegrityError(
                    "execution result does not match exact claim graph fingerprint"
                )
            self._put_document("claim_graph", request.claim_graph.fingerprint, request.claim_graph.to_dict())
            self._put_document("verification_plan", request.plan.fingerprint, request.plan.to_dict())

            acquisition_dependencies: dict[
                str,
                tuple[EvidenceDependency, ...],
            ] = {}
            steps_by_request: dict[tuple[str, str], str] = {}
            plan_steps = {step.step_id: step for step in request.plan.steps}
            verify_step_by_claim: dict[str, Any] = {}
            for step in request.plan.steps:
                if step.kind is VerificationPlanStepKind.ACQUIRE_EVIDENCE:
                    assert (
                        step.request_id is not None
                        and step.request_fingerprint is not None
                    )
                    steps_by_request[
                        (step.request_id, step.request_fingerprint)
                    ] = step.step_id
                elif step.kind is VerificationPlanStepKind.VERIFY_ATOMIC_CLAIM:
                    assert step.claim_id is not None
                    verify_step_by_claim[step.claim_id] = step

            for key, provider_result in result.provider_results.items():
                coverage = provider_result.coverage
                exact_request = request.evidence_requests[key]
                slot_identities = {
                    item.evidence_id: item
                    for item in provider_result.evidence_slot_identities
                }
                for item in provider_result.evidence_slot_identities:
                    expected_identity = exact_request.evidence_slot_identity(
                        item.evidence_id,
                        source_identity=coverage.source_identity,
                    )
                    if item != expected_identity:
                        raise StorageIntegrityError(
                            "provider result semantic slot identity conflicts with exact request and source"
                        )
                dependencies: list[EvidenceDependency] = []
                for evidence in provider_result.evidence:
                    slot_identity = slot_identities.get(evidence.id)
                    written = self.put_evidence(
                        evidence,
                        slot_identity=slot_identity,
                        provenance={
                            "provider_id": provider_result.provider_id,
                            "provider_version": provider_result.provider_version,
                            "request_fingerprint": (
                                provider_result.request_fingerprint
                            ),
                            "capability_fingerprint": (
                                provider_result.capability_fingerprint
                            ),
                            "source_identity": coverage.source_identity,
                        },
                        source_snapshot=coverage.snapshot_identity,
                        bounds=coverage.declared_bounds,
                        coverage=coverage.semantic_transport(),
                    )
                    if slot_identity is None:
                        dependency = EvidenceDependency(
                            evidence.id,
                            written.fingerprint,
                        )
                    else:
                        if written.slot_version is None:
                            raise StorageIntegrityError(
                                "semantic slot write did not publish a version"
                            )
                        slot = self._slot_version(
                            slot_identity.slot_id,
                            written.slot_version,
                        )
                        dependency = EvidenceDependency(
                            evidence.id,
                            written.fingerprint,
                            slot,
                        )
                    dependencies.append(dependency)
                step_id = steps_by_request.get(key)
                if step_id is None:
                    raise StorageIntegrityError(
                        "provider result has no exact acquisition plan step"
                    )
                if exact_request.request_id != provider_result.request_id:
                    raise StorageIntegrityError(
                        "provider result audit request ID conflicts with exact request"
                    )
                acquisition_dependencies[step_id] = tuple(dependencies)

            falsification_records_by_step: dict[
                str,
                StoredFalsificationResult,
            ] = {}
            for step_id, falsification_result in result.falsification_results.items():
                step = plan_steps[step_id]
                dependencies = self._canonical_evidence_dependencies(
                    tuple(
                        dependency
                        for dependency_step_id in step.dependency_step_ids
                        for dependency in acquisition_dependencies.get(
                            dependency_step_id,
                            (),
                        )
                    ),
                    noun="execution falsification dependencies",
                )
                stored_falsification = self.put_falsification_result(
                    falsification_result,
                    evidence_dependencies=dependencies,
                )
                if (
                    stored_falsification.result != falsification_result
                    or stored_falsification.record_fingerprint is None
                    or stored_falsification.evidence_dependencies != dependencies
                ):
                    raise StorageIntegrityError(
                        "stored falsification record does not match exact execution dependencies"
                    )
                falsification_records_by_step[step_id] = stored_falsification

            stored_bundles: dict[str, StoredBundle] = {}
            for claim_id, bundle in result.bundles.items():
                step = verify_step_by_claim.get(claim_id)
                candidates: dict[str, list[EvidenceDependency]] = {}
                if step is not None:
                    for dependency_step_id in step.dependency_step_ids:
                        for dependency in acquisition_dependencies.get(
                            dependency_step_id,
                            (),
                        ):
                            candidates.setdefault(
                                dependency.evidence_id,
                                [],
                            ).append(dependency)
                exact_dependencies: list[EvidenceDependency] = []
                for evidence in bundle.evidence:
                    matches = [
                        item
                        for item in candidates.get(evidence.id, ())
                        if self.get_evidence(
                            item.evidence_fingerprint
                        ).evidence
                        == evidence
                    ]
                    unique = {
                        _content_json(self._dependency_document(item)): item
                        for item in matches
                    }
                    if unique:
                        exact_dependencies.extend(
                            unique[key] for key in sorted(unique)
                        )
                    else:
                        written = self.put_evidence(evidence)
                        exact_dependencies.append(EvidenceDependency(
                            evidence.id,
                            written.fingerprint,
                        ))
                canonical_dependencies = self._canonical_evidence_dependencies(
                    exact_dependencies,
                    noun="execution bundle dependencies",
                )
                stored_bundle = self.put_bundle(
                    bundle,
                    evidence_dependencies=canonical_dependencies,
                )
                if (
                    stored_bundle.bundle != bundle
                    or stored_bundle.record_fingerprint is None
                    or stored_bundle.evidence_dependencies
                    != canonical_dependencies
                ):
                    raise StorageIntegrityError(
                        "stored bundle record does not match exact execution dependencies"
                    )
                stored_bundles[claim_id] = stored_bundle

            verifier_versions: dict[str, str] = {}
            falsification_by_claim: dict[
                str,
                tuple[StoredFalsificationResult, ...],
            ] = {}
            for step in request.plan.steps:
                if step.kind is not VerificationPlanStepKind.VERIFY_ATOMIC_CLAIM:
                    continue
                assert step.claim_id is not None and step.verifier_version is not None
                verifier_versions[step.claim_id] = step.verifier_version
                falsification_by_claim[step.claim_id] = tuple(sorted(
                    [
                        falsification_records_by_step[dependency]
                        for dependency in step.dependency_step_ids
                        if dependency in falsification_records_by_step
                    ],
                    key=lambda item: (
                        item.fingerprint,
                        item.record_fingerprint or "",
                    ),
                ))

            for node in request.claim_graph.nodes:
                if isinstance(node, AtomicClaim):
                    verifier_id = node.verifier
                    verifier_version = verifier_versions[node.claim_id]
                else:
                    verifier_id = COMPOSITE_CLAIM_VERIFIER
                    verifier_version = "1"
                statement = _content_json(node.semantic_definition())
                self.define_claim(
                    ClaimDefinition(node.claim_id, statement, verifier_id),
                    verifier_version=verifier_version,
                )

            session_states = {
                state.claim_id: state
                for state in result.session.claim_states
            }
            stored_claims: dict[str, StoredClaimVersion] = {}
            for claim_id in request.claim_graph.evaluation_order:
                node = request.claim_graph.claim(claim_id)
                if isinstance(node, AtomicClaim):
                    bundle = result.bundles.get(claim_id)
                    if bundle is None:
                        raise StorageIntegrityError(
                            f"completed execution is missing bundle for atomic claim {claim_id}"
                        )
                    stored_claims[claim_id] = self.record_claim(
                        claim_id,
                        bundle,
                        verifier_version=verifier_versions[claim_id],
                        bundle_record=stored_bundles[claim_id],
                        falsification_records=falsification_by_claim.get(
                            claim_id,
                            (),
                        ),
                    )
                else:
                    state = session_states[claim_id]
                    report = VerificationReport(
                        verdict=state.stored_verdict,
                        verifier=COMPOSITE_CLAIM_VERIFIER,
                    )
                    stored_claims[claim_id] = self.record_claim(
                        claim_id,
                        None,
                        verifier_version="1",
                        report=report,
                        claim_dependency_ids=node.dependencies,
                    )

            execution_document = result.to_dict()
            self._put_document("verification_execution", result.fingerprint, execution_document)
            session_bundle_records: dict[str, StoredBundle] = {}
            for stored_bundle in stored_bundles.values():
                previous = session_bundle_records.setdefault(
                    stored_bundle.fingerprint,
                    stored_bundle,
                )
                if previous.record_fingerprint != stored_bundle.record_fingerprint:
                    raise StorageIntegrityError(
                        "one session cannot substitute conflicting exact bundle records"
                    )
            session_falsification_records: dict[
                str,
                StoredFalsificationResult,
            ] = {}
            for stored_falsification in falsification_records_by_step.values():
                previous = session_falsification_records.setdefault(
                    stored_falsification.fingerprint,
                    stored_falsification,
                )
                if (
                    previous.record_fingerprint
                    != stored_falsification.record_fingerprint
                ):
                    raise StorageIntegrityError(
                        "one session cannot substitute conflicting exact falsification records"
                    )
            return self.put_session(
                result.session,
                plan_fingerprint=result.plan_fingerprint,
                execution_fingerprint=result.fingerprint,
                execution_document=execution_document,
                claim_records=tuple(
                    stored_claims[state.claim_id]
                    for state in result.session.claim_states
                ),
                bundle_records=tuple(
                    session_bundle_records[key]
                    for key in sorted(session_bundle_records)
                ),
                falsification_records=tuple(
                    session_falsification_records[key]
                    for key in sorted(session_falsification_records)
                ),
            )


SQLiteDurableStorage = SQLiteStorage
SQLiteLedgerStorage = SQLiteStorage
