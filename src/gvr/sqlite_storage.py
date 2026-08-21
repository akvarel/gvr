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
)


_EVIDENCE_FINGERPRINT_FORMAT = "gvr.storage.evidence.ieee754-json.v1"
_EVIDENCE_PAYLOAD_FORMAT = "gvr.storage.evidence_payload.ieee754-json.v1"
_STORAGE_DOCUMENT_FORMAT = "gvr.storage.document.ieee754-json.v1"
_CLAIM_DEFINITION_FORMAT = "gvr.storage.claim_definition.ieee754-json.v1"
_CLAIM_BASIS_FORMAT = "gvr.storage.claim_basis.ieee754-json.v1"
_INVALIDATION_EVENT_FORMAT = "gvr.storage.invalidation_event.ieee754-json.v1"


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
                statements = _MIGRATION_1 if version == 1 else ()
                if not statements:
                    raise StorageMigrationError(f"missing migration for schema version {version}")
                for statement in statements:
                    connection.execute(statement)
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

    def get_bundle(self, fingerprint: str) -> StoredBundle:
        return self._read("get_bundle", fingerprint)

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

    def get_falsification_result(self, fingerprint: str) -> StoredFalsificationResult:
        return self._read("get_falsification_result", fingerprint)

    def put_session(self, session: VerificationSession, **kwargs: Any) -> StoredSession:
        return self._write("put_session", session, **kwargs)

    def get_session(self, fingerprint: str) -> StoredSession:
        return self._read("get_session", fingerprint)

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
    ) -> StoredEvidence:
        with self._logical_write():
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
            if slot_id is not None:
                selected_slot_id = _identifier(slot_id, name="slot_id")
                current = self._conn().execute(
                    "SELECT current_version, current_evidence_fingerprint FROM evidence_slots WHERE slot_id = ?",
                    (selected_slot_id,),
                ).fetchone()
                if current is not None:
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
        is_current = (
            current_version == row["version"]
            if current_version is not None
            else self._conn().execute(
                "SELECT current_version FROM evidence_slots WHERE slot_id = ?",
                (row["slot_id"],),
            ).fetchone()[0] == row["version"]
        )
        return EvidenceSlotVersion(
            slot_id=row["slot_id"],
            version=row["version"],
            evidence_fingerprint=row["evidence_fingerprint"],
            previous_version=row["previous_version"],
            current=is_current,
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

    def put_bundle(
        self,
        bundle: VerificationBundle,
        *,
        evidence_slots: Mapping[str, EvidenceSlotVersion] | None = None,
    ) -> StoredBundle:
        with self._logical_write():
            try:
                validate_verification_bundle(bundle)
            except BundleValidationError as exc:
                raise StorageIntegrityError(str(exc)) from exc
            supplied = None if evidence_slots is None else dict(evidence_slots)
            if supplied is not None and set(supplied) != {item.id for item in bundle.evidence}:
                raise StorageIntegrityError(
                    "bundle evidence slot mapping must match exact bundle evidence IDs"
                )
            existing = self._conn().execute(
                "SELECT 1 FROM bundles WHERE fingerprint = ?",
                (bundle.fingerprint,),
            ).fetchone()
            if existing is not None and supplied is None:
                stored = self.get_bundle(bundle.fingerprint)
                if stored.bundle != bundle:
                    raise StorageConflictError(
                        "immutable bundle fingerprint has conflicting canonical content"
                    )
                return stored
            resolved: list[tuple[Evidence, EvidenceSlotVersion]] = []
            for evidence in bundle.evidence:
                slot: EvidenceSlotVersion | None
                if supplied is None:
                    slot = self.get_slot(evidence.id)
                    if slot is not None:
                        artifact = self.get_evidence(slot.evidence_fingerprint)
                        if artifact.evidence != evidence:
                            slot = None
                    if slot is None:
                        written = self.put_evidence(evidence, slot_id=evidence.id)
                        assert written.slot_version is not None
                        slot = self._slot_version(evidence.id, written.slot_version)
                else:
                    slot = supplied[evidence.id]
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
                resolved.append((evidence, slot))

            document = bundle.to_dict()
            content, canonical, digest = _parts(document)
            existing = self._conn().execute(
                "SELECT * FROM bundles WHERE fingerprint = ?",
                (bundle.fingerprint,),
            ).fetchone()
            if existing is None:
                self._conn().execute(
                    """
                    INSERT INTO bundles(fingerprint, content_json, canonical_json, content_digest)
                    VALUES (?, ?, ?, ?)
                    """,
                    (bundle.fingerprint, content, canonical, digest),
                )
                for ordinal, (evidence, slot) in enumerate(resolved):
                    self._conn().execute(
                        """
                        INSERT INTO bundle_evidence_links(
                            bundle_fingerprint, evidence_id, evidence_fingerprint,
                            slot_id, slot_version, ordinal
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            bundle.fingerprint,
                            evidence.id,
                            slot.evidence_fingerprint,
                            slot.slot_id,
                            slot.version,
                            ordinal,
                        ),
                    )
                    self._put_dependency(
                        _object_key("bundle", bundle.fingerprint),
                        slot.object_key,
                        "evidence_slot_version",
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
            else:
                stored = self.get_bundle(bundle.fingerprint)
                if stored.bundle != bundle or stored.evidence_slots != tuple(slot for _, slot in resolved):
                    raise StorageConflictError(
                        "immutable bundle fingerprint has conflicting content or evidence links"
                    )
            return self.get_bundle(bundle.fingerprint)

    def _bundle_current(self, fingerprint: str) -> bool:
        key = _object_key("bundle", fingerprint)
        if self._is_invalidated(key):
            return False
        rows = self._conn().execute(
            "SELECT slot_id, slot_version FROM bundle_evidence_links WHERE bundle_fingerprint = ?",
            (fingerprint,),
        ).fetchall()
        return all(self._slot_version(row["slot_id"], row["slot_version"]).current for row in rows)

    def get_bundle(self, fingerprint: str) -> StoredBundle:
        fingerprint = _sha256(fingerprint, name="bundle fingerprint")
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
            raise StorageIntegrityError("bundle key does not match bundle fingerprint")
        links = self._conn().execute(
            """
            SELECT * FROM bundle_evidence_links
            WHERE bundle_fingerprint = ?
            ORDER BY ordinal
            """,
            (fingerprint,),
        ).fetchall()
        if len(links) != len(bundle.evidence):
            raise StorageIntegrityError("bundle evidence links are incomplete")
        slots: list[EvidenceSlotVersion] = []
        for evidence, link in zip(bundle.evidence, links):
            if link["evidence_id"] != evidence.id:
                raise StorageIntegrityError("bundle evidence link order or identity is corrupt")
            slot = self._slot_version(link["slot_id"], link["slot_version"])
            if slot.evidence_fingerprint != link["evidence_fingerprint"]:
                raise StorageIntegrityError("bundle evidence link fingerprint is corrupt")
            artifact = self.get_evidence(link["evidence_fingerprint"])
            if artifact.evidence != evidence:
                raise StorageIntegrityError("bundle evidence artifact content is corrupt")
            slots.append(slot)
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
        return StoredBundle(
            fingerprint=fingerprint,
            bundle=bundle,
            evidence_slots=tuple(slots),
            current=self._bundle_current(fingerprint),
        )

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
    ) -> StoredClaimVersion:
        with self._logical_write():
            claim_id = _identifier(claim_id, name="claim id")
            definition = self._claim_definition(claim_id)
            version_value = _identifier(verifier_version, name="verifier version")
            if version_value != definition.verifier_version:
                raise StorageConflictError(
                    f"claim {claim_id} requires verifier version {definition.verifier_version}"
                )
            stored_bundle: StoredBundle | None = None
            if bundle is not None:
                existing_bundle = self._conn().execute(
                    "SELECT 1 FROM bundles WHERE fingerprint = ?",
                    (bundle.fingerprint,),
                ).fetchone()
                if existing_bundle is None:
                    stored_bundle = self.put_bundle(bundle)
                else:
                    stored_bundle = self.get_bundle(bundle.fingerprint)
                    if stored_bundle.bundle != bundle:
                        raise StorageConflictError(
                            "bundle fingerprint has conflicting canonical content"
                        )
                if not stored_bundle.current:
                    raise StoredTruthError("cannot record a claim from a stale bundle")
                if report is not None and report != bundle.report:
                    raise StorageConflictError("supplied report disagrees with bundle report")
                report_value = bundle.report
                expected_dependencies = bundle.claim_dependency_ids
            else:
                if report is None:
                    raise StorageIntegrityError("a claim record requires a bundle or report")
                report_value = report
                expected_dependencies = ()
            if report_value.verifier != definition.definition.verifier:
                raise StorageConflictError(
                    f"claim {claim_id} requires verifier {definition.definition.verifier}"
                )
            supplied_dependencies = (
                expected_dependencies
                if claim_dependency_ids is None
                else tuple(claim_dependency_ids)
            )
            dependencies = tuple(sorted(set(supplied_dependencies)))
            if tuple(supplied_dependencies) != dependencies:
                raise StorageIntegrityError("claim dependency IDs must be unique and sorted")
            if bundle is not None and dependencies != expected_dependencies:
                raise StorageConflictError("claim dependency IDs disagree with bundle")
            if self._would_cycle(claim_id, dependencies):
                from .dependencies import DependencyCycleError

                raise DependencyCycleError(f"claim dependency cycle for {claim_id}")

            dependency_versions: list[tuple[str, int]] = []
            for dependency_id in dependencies:
                _identifier(dependency_id, name="claim dependency id")
                row = self._conn().execute(
                    "SELECT current_version FROM claims WHERE claim_id = ?",
                    (dependency_id,),
                ).fetchone()
                if row is None:
                    raise StoredTruthError(
                        f"claim {claim_id} references unverified dependency {dependency_id}"
                    )
                dependency_version = row["current_version"]
                if not self._claim_current(dependency_id, dependency_version, set()):
                    raise StoredTruthError(
                        f"claim {claim_id} references stale dependency {dependency_id}"
                    )
                dependency_versions.append((dependency_id, dependency_version))

            falsification_ids = tuple(sorted(set(falsification_fingerprints)))
            if tuple(falsification_fingerprints) != falsification_ids:
                raise StorageIntegrityError(
                    "falsification fingerprints must be unique and sorted"
                )
            for fingerprint in falsification_ids:
                stored_falsification = self.get_falsification_result(fingerprint)
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
                        f"claim {claim_id} references falsification for a different claim or verifier"
                    )

            evidence_slots = () if stored_bundle is None else stored_bundle.evidence_slots
            if (
                report_value.verdict is VerificationVerdict.PASS
                and not evidence_slots
                and not dependency_versions
                and not falsification_ids
            ):
                raise StoredTruthError(
                    "PASS requires stored evidence, claim, or falsification basis"
                )
            basis_document = {
                "schema_version": 1,
                "kind": "gvr.claim_verification_basis",
                "claim_id": claim_id,
                "definition_fingerprint": definition.fingerprint,
                "verifier_id": definition.definition.verifier,
                "verifier_version": version_value,
                "verdict": report_value.verdict.value,
                "report": _report_document(report_value),
                "bundle_fingerprint": None if bundle is None else bundle.fingerprint,
                "evidence_slots": [
                    {
                        "slot_id": slot.slot_id,
                        "slot_version": slot.version,
                        "evidence_fingerprint": slot.evidence_fingerprint,
                    }
                    for slot in evidence_slots
                ],
                "claim_dependency_versions": [
                    {"claim_id": dependency_id, "version": dependency_version}
                    for dependency_id, dependency_version in dependency_versions
                ],
                "falsification_fingerprints": list(falsification_ids),
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
                    raise StorageIntegrityError("claim current pointer is corrupt")
                if current_row["basis_fingerprint"] == basis_fingerprint:
                    return self._read_claim_version(claim_id, current["current_version"])
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
            claim_key = _object_key("claim-version", f"{claim_id}:{next_version}")
            if bundle is not None:
                self._put_dependency(
                    claim_key,
                    _object_key("bundle", bundle.fingerprint),
                    "bundle",
                )
            for ordinal, slot in enumerate(evidence_slots):
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
                        slot.evidence_fingerprint,
                        slot.slot_id,
                        slot.version,
                        ordinal,
                    ),
                )
                self._put_dependency(
                    claim_key,
                    slot.object_key,
                    "evidence_slot_version",
                )
            for ordinal, (dependency_id, dependency_version) in enumerate(dependency_versions):
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
                    _object_key("claim-version", f"{dependency_id}:{dependency_version}"),
                    "claim_version",
                )
            for ordinal, fingerprint in enumerate(falsification_ids):
                self._conn().execute(
                    """
                    INSERT INTO claim_falsification_links(
                        claim_id, claim_version, falsification_fingerprint, ordinal
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (claim_id, next_version, fingerprint, ordinal),
                )
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

    def _claim_current(self, claim_id: str, version: int, seen: set[tuple[str, int]]) -> bool:
        identity = (claim_id, version)
        if identity in seen:
            raise StorageIntegrityError("stored claim dependency cycle detected")
        seen.add(identity)
        key = _object_key("claim-version", f"{claim_id}:{version}")
        if self._is_invalidated(key):
            seen.remove(identity)
            return False
        pointer = self._conn().execute(
            "SELECT current_version FROM claims WHERE claim_id = ?",
            (claim_id,),
        ).fetchone()
        if pointer is None or pointer["current_version"] != version:
            seen.remove(identity)
            return False
        row = self._conn().execute(
            "SELECT bundle_fingerprint FROM claim_versions WHERE claim_id = ? AND version = ?",
            (claim_id, version),
        ).fetchone()
        if row is None:
            raise StorageIntegrityError("claim version is missing")
        if row["bundle_fingerprint"] is not None and not self._bundle_current(row["bundle_fingerprint"]):
            seen.remove(identity)
            return False
        evidence_links = self._conn().execute(
            "SELECT slot_id, slot_version FROM claim_evidence_links WHERE claim_id = ? AND claim_version = ?",
            (claim_id, version),
        ).fetchall()
        if any(
            not self._slot_version(item["slot_id"], item["slot_version"]).current
            for item in evidence_links
        ):
            seen.remove(identity)
            return False
        dependencies = self._conn().execute(
            """
            SELECT dependency_claim_id, dependency_claim_version
            FROM claim_dependency_links
            WHERE claim_id = ? AND claim_version = ?
            ORDER BY ordinal
            """,
            (claim_id, version),
        ).fetchall()
        for dependency in dependencies:
            if not self._claim_current(
                dependency["dependency_claim_id"],
                dependency["dependency_claim_version"],
                seen,
            ):
                seen.remove(identity)
                return False
        falsification_links = self._conn().execute(
            """
            SELECT falsification_fingerprint
            FROM claim_falsification_links
            WHERE claim_id = ? AND claim_version = ?
            """,
            (claim_id, version),
        ).fetchall()
        if any(
            not self._falsification_current(item["falsification_fingerprint"])
            for item in falsification_links
        ):
            seen.remove(identity)
            return False
        seen.remove(identity)
        return True

    def _read_claim_version(self, claim_id: str, version: int) -> StoredClaimVersion:
        row = self._conn().execute(
            "SELECT * FROM claim_versions WHERE claim_id = ? AND version = ?",
            (claim_id, version),
        ).fetchone()
        if row is None:
            raise StorageNotFoundError(f"unknown claim version: {claim_id}:{version}")
        document = _verified_document(
            content_json=row["content_json"],
            canonical_json_value=row["canonical_json"],
            content_digest=row["content_digest"],
            fingerprint_format=_CLAIM_BASIS_FORMAT,
            identity=f"claim version {claim_id}:{version}",
        )
        if row["basis_fingerprint"] != row["content_digest"]:
            raise StorageIntegrityError("claim basis fingerprint is corrupt")
        if (
            document.get("claim_id") != row["claim_id"]
            or document.get("verdict") != row["verdict"]
            or document.get("verifier_id") != row["verifier_id"]
            or document.get("verifier_version") != row["verifier_version"]
            or document.get("bundle_fingerprint") != row["bundle_fingerprint"]
        ):
            raise StorageIntegrityError("claim columns conflict with canonical basis")
        report = _report_from_document(document["report"])
        if report.verdict.value != row["verdict"] or report.verifier != row["verifier_id"]:
            raise StorageIntegrityError("claim report conflicts with stored verdict or verifier")
        definition = self._claim_definition(claim_id)
        if document.get("definition_fingerprint") != definition.fingerprint:
            raise StorageIntegrityError(
                "claim basis does not reference the exact stored definition"
            )
        evidence_rows = self._conn().execute(
            """
            SELECT * FROM claim_evidence_links
            WHERE claim_id = ? AND claim_version = ? ORDER BY ordinal
            """,
            (claim_id, version),
        ).fetchall()
        evidence_slots = tuple(
            self._slot_version(item["slot_id"], item["slot_version"])
            for item in evidence_rows
        )
        expected_evidence = tuple(
            (
                item["slot_id"],
                item["slot_version"],
                item["evidence_fingerprint"],
            )
            for item in document.get("evidence_slots", ())
        )
        actual_evidence = tuple(
            (slot.slot_id, slot.version, slot.evidence_fingerprint)
            for slot in evidence_slots
        )
        if actual_evidence != expected_evidence:
            raise StorageIntegrityError("claim evidence basis links are corrupt")
        dependency_versions = tuple(
            (item["dependency_claim_id"], item["dependency_claim_version"])
            for item in self._conn().execute(
                """
                SELECT * FROM claim_dependency_links
                WHERE claim_id = ? AND claim_version = ? ORDER BY ordinal
                """,
                (claim_id, version),
            )
        )
        expected_dependencies = tuple(
            (item["claim_id"], item["version"])
            for item in document.get("claim_dependency_versions", ())
        )
        if dependency_versions != expected_dependencies:
            raise StorageIntegrityError("claim dependency basis links are corrupt")
        falsification_ids = tuple(
            item[0]
            for item in self._conn().execute(
                """
                SELECT falsification_fingerprint FROM claim_falsification_links
                WHERE claim_id = ? AND claim_version = ? ORDER BY ordinal
                """,
                (claim_id, version),
            )
        )
        if falsification_ids != tuple(document.get("falsification_fingerprints", ())):
            raise StorageIntegrityError("claim falsification basis links are corrupt")
        if row["bundle_fingerprint"] is None:
            if evidence_slots:
                raise StorageIntegrityError(
                    "claim without a bundle cannot have evidence links"
                )
        else:
            stored_bundle = self.get_bundle(row["bundle_fingerprint"])
            if stored_bundle.bundle.report != report:
                raise StorageIntegrityError(
                    "claim report does not match its exact bundle report"
                )
            if stored_bundle.evidence_slots != evidence_slots:
                raise StorageIntegrityError(
                    "claim evidence links do not match its exact bundle links"
                )
            if stored_bundle.bundle.claim_dependency_ids != tuple(
                dependency_id for dependency_id, _version in dependency_versions
            ):
                raise StorageIntegrityError(
                    "claim dependencies do not match its exact bundle dependencies"
                )
        for fingerprint in falsification_ids:
            stored_falsification = self.get_falsification_result(fingerprint)
            if (
                stored_falsification.result.claim_id != claim_id
                or stored_falsification.result.declared_verifier_id
                != row["verifier_id"]
            ):
                raise StorageIntegrityError(
                    "claim falsification basis belongs to a different claim or verifier"
                )
        if (
            report.verdict is VerificationVerdict.PASS
            and not evidence_slots
            and not dependency_versions
            and not falsification_ids
        ):
            raise StoredTruthError(
                "stored PASS has no evidence, claim, or falsification basis"
            )
        current = self._claim_current(claim_id, version, set())
        return StoredClaimVersion(
            claim_id=claim_id,
            version=version,
            verdict=VerificationVerdict(row["verdict"]),
            verifier_id=row["verifier_id"],
            verifier_version=row["verifier_version"],
            bundle_fingerprint=row["bundle_fingerprint"],
            report=report,
            basis_fingerprint=row["basis_fingerprint"],
            evidence_slots=evidence_slots,
            claim_dependency_versions=dependency_versions,
            falsification_fingerprints=falsification_ids,
            current=current,
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

    def put_falsification_result(
        self,
        result: FalsificationResult,
        *,
        evidence_slots: Iterable[EvidenceSlotVersion] | None = None,
    ) -> StoredFalsificationResult:
        with self._logical_write():
            if not isinstance(result, FalsificationResult):
                raise StorageIntegrityError("result must be a FalsificationResult")
            document = result.to_dict()
            content, canonical, digest = _parts(document)
            slots = () if evidence_slots is None else tuple(evidence_slots)
            resolved = tuple(self._slot_version(item.slot_id, item.version) for item in slots)
            if len({(item.slot_id, item.version) for item in resolved}) != len(resolved):
                raise StorageIntegrityError("falsification evidence slots contain duplicates")
            existing = self._conn().execute(
                "SELECT * FROM falsification_results WHERE fingerprint = ?",
                (result.fingerprint,),
            ).fetchone()
            if existing is not None and evidence_slots is None:
                stored = self.get_falsification_result(result.fingerprint)
                if stored.result != result:
                    raise StorageConflictError(
                        "immutable falsification result has conflicting content"
                    )
                return stored
            if existing is None:
                self._conn().execute(
                    """
                    INSERT INTO falsification_results(
                        fingerprint, content_json, canonical_json, content_digest
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (result.fingerprint, content, canonical, digest),
                )
                for ordinal, slot in enumerate(resolved):
                    self._conn().execute(
                        """
                        INSERT INTO falsification_evidence_links(
                            falsification_fingerprint, evidence_fingerprint,
                            slot_id, slot_version, ordinal
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            result.fingerprint,
                            slot.evidence_fingerprint,
                            slot.slot_id,
                            slot.version,
                            ordinal,
                        ),
                    )
                    self._put_dependency(
                        _object_key("falsification", result.fingerprint),
                        slot.object_key,
                        "evidence_slot_version",
                    )
            else:
                stored = self.get_falsification_result(result.fingerprint)
                if stored.result != result or stored.evidence_slots != resolved:
                    raise StorageConflictError(
                        "immutable falsification result has conflicting content or links"
                    )
            return self.get_falsification_result(result.fingerprint)

    def _falsification_current(self, fingerprint: str) -> bool:
        key = _object_key("falsification", fingerprint)
        if self._is_invalidated(key):
            return False
        rows = self._conn().execute(
            """
            SELECT slot_id, slot_version FROM falsification_evidence_links
            WHERE falsification_fingerprint = ?
            """,
            (fingerprint,),
        ).fetchall()
        return all(self._slot_version(row["slot_id"], row["slot_version"]).current for row in rows)

    def get_falsification_result(self, fingerprint: str) -> StoredFalsificationResult:
        fingerprint = _sha256(fingerprint, name="falsification fingerprint")
        row = self._conn().execute(
            "SELECT * FROM falsification_results WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        if row is None:
            raise StorageNotFoundError(f"unknown falsification result: {fingerprint}")
        document = _verified_document(
            content_json=row["content_json"],
            canonical_json_value=row["canonical_json"],
            content_digest=row["content_digest"],
            identity=f"falsification result {fingerprint}",
        )
        result = _falsification_from_document(document)
        if result.fingerprint != fingerprint:
            raise StorageIntegrityError("falsification result key is corrupt")
        links = self._conn().execute(
            """
            SELECT * FROM falsification_evidence_links
            WHERE falsification_fingerprint = ? ORDER BY ordinal
            """,
            (fingerprint,),
        ).fetchall()
        slots: list[EvidenceSlotVersion] = []
        for link in links:
            slot = self._slot_version(link["slot_id"], link["slot_version"])
            if slot.evidence_fingerprint != link["evidence_fingerprint"]:
                raise StorageIntegrityError("falsification evidence link is corrupt")
            slots.append(slot)
        return StoredFalsificationResult(
            fingerprint=fingerprint,
            result=result,
            evidence_slots=tuple(slots),
            current=self._falsification_current(fingerprint),
        )

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
                document,
                identity=kind,
                nonsemantic_fields=("correlation_id",),
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
        if stored != _json_value(document):
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
                document,
                identity=kind,
                nonsemantic_fields=("correlation_id",),
            )
        return document

    def put_session(
        self,
        session: VerificationSession,
        *,
        plan_fingerprint: str | None = None,
        execution_fingerprint: str | None = None,
        execution_document: Mapping[str, Any] | None = None,
        falsification_fingerprints: tuple[str, ...] = (),
    ) -> StoredSession:
        with self._logical_write():
            if type(session) is not VerificationSession or not session.sealed:
                raise StorageIntegrityError("session must be an exact sealed VerificationSession")
            session_document = session.to_dict()
            session_fingerprint = _sha256(session.fingerprint, name="session fingerprint")
            graph_fingerprint = _sha256(session.graph.fingerprint, name="graph fingerprint")
            if session_document.get("fingerprint") != session_fingerprint:
                raise StorageIntegrityError("session fingerprint is inconsistent")
            self._put_document(
                "claim_graph",
                graph_fingerprint,
                session.graph.to_dict(),
            )
            plan_value = None if plan_fingerprint is None else _sha256(
                plan_fingerprint,
                name="plan fingerprint",
            )
            execution_value = None if execution_fingerprint is None else _sha256(
                execution_fingerprint,
                name="execution fingerprint",
            )
            if execution_document is not None:
                if execution_value is None:
                    raise StorageIntegrityError(
                        "execution_document requires execution_fingerprint"
                    )
                if not isinstance(execution_document, Mapping):
                    raise StorageIntegrityError("execution_document must be a mapping")
                if execution_document.get("fingerprint") != execution_value:
                    raise StorageIntegrityError(
                        "execution document fingerprint does not match exact reference"
                    )
                self._put_document(
                    "verification_execution",
                    execution_value,
                    execution_document,
                )
            falsification_ids = tuple(sorted(set(falsification_fingerprints)))
            if tuple(falsification_fingerprints) != falsification_ids:
                raise StorageIntegrityError(
                    "session falsification fingerprints must be unique and sorted"
                )
            for fingerprint in falsification_ids:
                self.get_falsification_result(fingerprint)

            claim_ids = tuple(item["claim_id"] for item in session_document.get("claims", ()))
            if len(set(claim_ids)) != len(claim_ids):
                raise StorageIntegrityError("session contains duplicate claim states")
            claim_versions: list[tuple[str, int]] = []
            for claim_id in claim_ids:
                pointer = self._conn().execute(
                    "SELECT current_version FROM claims WHERE claim_id = ?",
                    (claim_id,),
                ).fetchone()
                if pointer is None:
                    raise StorageIntegrityError(
                        f"session references claim without durable history: {claim_id}"
                    )
                stored_claim = self._read_claim_version(claim_id, pointer["current_version"])
                state = next(
                    item for item in session_document["claims"] if item["claim_id"] == claim_id
                )
                if (
                    state["stored_verdict"] != stored_claim.verdict.value
                    or state["bundle_fingerprint"] != stored_claim.bundle_fingerprint
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
            for fingerprint in bundle_ids:
                self.get_bundle(fingerprint)
            session_content, session_canonical, session_digest = _parts(session_document)
            counters = session.consumption.to_dict()
            counters_json = _content_json(counters)
            execution_content: str | None = None
            execution_canonical: str | None = None
            execution_digest: str | None = None
            if execution_document is not None:
                execution_content, execution_canonical, execution_digest = _parts(execution_document)
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
                session_key = _object_key("session", session_fingerprint)
                for ordinal, (claim_id, claim_version) in enumerate(claim_versions):
                    self._conn().execute(
                        """
                        INSERT INTO session_claim_links(
                            session_fingerprint, claim_id, claim_version, ordinal
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (session_fingerprint, claim_id, claim_version, ordinal),
                    )
                    self._put_dependency(
                        session_key,
                        _object_key("claim-version", f"{claim_id}:{claim_version}"),
                        "claim_version",
                    )
                for ordinal, fingerprint in enumerate(bundle_ids):
                    self._conn().execute(
                        """
                        INSERT INTO session_bundle_links(
                            session_fingerprint, bundle_fingerprint, ordinal
                        ) VALUES (?, ?, ?)
                        """,
                        (session_fingerprint, fingerprint, ordinal),
                    )
                    self._put_dependency(
                        session_key,
                        _object_key("bundle", fingerprint),
                        "bundle",
                    )
                for ordinal, fingerprint in enumerate(falsification_ids):
                    self._conn().execute(
                        """
                        INSERT INTO session_falsification_links(
                            session_fingerprint, falsification_fingerprint, ordinal
                        ) VALUES (?, ?, ?)
                        """,
                        (session_fingerprint, fingerprint, ordinal),
                    )
                    self._put_dependency(
                        session_key,
                        _object_key("falsification", fingerprint),
                        "falsification_result",
                    )
            else:
                stored = self.get_session(session_fingerprint)
                candidate = (
                    _json_value(session_document),
                    graph_fingerprint,
                    plan_value,
                    execution_value,
                    None if execution_document is None else _json_value(execution_document),
                    tuple(claim_versions),
                    bundle_ids,
                    falsification_ids,
                )
                observed = (
                    _json_value(stored.session_document),
                    stored.graph_fingerprint,
                    stored.plan_fingerprint,
                    stored.execution_fingerprint,
                    None if stored.execution_document is None else _json_value(stored.execution_document),
                    stored.claim_versions,
                    stored.bundle_fingerprints,
                    stored.falsification_fingerprints,
                )
                if observed != candidate:
                    raise StorageConflictError(
                        "immutable session fingerprint has conflicting content or references"
                    )
            return self.get_session(session_fingerprint)

    def _session_current(self, fingerprint: str) -> bool:
        if self._is_invalidated(_object_key("session", fingerprint)):
            return False
        claims = self._conn().execute(
            "SELECT claim_id, claim_version FROM session_claim_links WHERE session_fingerprint = ?",
            (fingerprint,),
        ).fetchall()
        if any(
            not self._claim_current(item["claim_id"], item["claim_version"], set())
            for item in claims
        ):
            return False
        bundles = self._conn().execute(
            "SELECT bundle_fingerprint FROM session_bundle_links WHERE session_fingerprint = ?",
            (fingerprint,),
        ).fetchall()
        if any(not self._bundle_current(item[0]) for item in bundles):
            return False
        falsification = self._conn().execute(
            "SELECT falsification_fingerprint FROM session_falsification_links WHERE session_fingerprint = ?",
            (fingerprint,),
        ).fetchall()
        return all(self._falsification_current(item[0]) for item in falsification)

    def get_session(self, fingerprint: str) -> StoredSession:
        fingerprint = _sha256(fingerprint, name="session fingerprint")
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
            raise StorageIntegrityError("session document fingerprint is corrupt")
        _verify_semantic_document_fingerprint(document, identity=f"session {fingerprint}")
        claim_graph_document = document.get("claim_graph")
        if not isinstance(claim_graph_document, Mapping):
            raise StorageIntegrityError("session claim graph document is missing")
        _verify_semantic_document_fingerprint(
            claim_graph_document,
            identity=f"session {fingerprint} claim graph",
        )
        exact_graph_document = self._read_document(
            "claim_graph",
            row["graph_fingerprint"],
        )
        if exact_graph_document != claim_graph_document:
            raise StorageIntegrityError(
                "session embedded graph conflicts with exact stored graph document"
            )
        if row["plan_fingerprint"] is not None:
            plan_row = self._conn().execute(
                """
                SELECT 1 FROM documents
                WHERE document_kind = 'verification_plan' AND fingerprint = ?
                """,
                (row["plan_fingerprint"],),
            ).fetchone()
            if plan_row is None and row["execution_content_json"] is not None:
                raise StorageIntegrityError(
                    "executor-produced session is missing its exact plan document"
                )
            if plan_row is not None:
                plan_document = self._read_document(
                    "verification_plan",
                    row["plan_fingerprint"],
                )
                if plan_document.get("claim_graph_fingerprint") != row["graph_fingerprint"]:
                    raise StorageIntegrityError(
                        "session plan references a different claim graph"
                    )
        if document.get("claim_graph", {}).get("fingerprint") != row["graph_fingerprint"]:
            raise StorageIntegrityError("session graph reference is corrupt")
        if document.get("termination_reason") != row["termination"]:
            raise StorageIntegrityError("session termination column is corrupt")
        counters = json.loads(row["counters_json"])
        if _content_json(counters) != row["counters_json"]:
            raise StorageIntegrityError("session counters are not canonical JSON")
        expected_counters = document.get("budget", {}).get("consumed", {})
        if counters != expected_counters:
            raise StorageIntegrityError("session counters conflict with session document")
        execution_document: dict[str, Any] | None = None
        if row["execution_content_json"] is not None:
            if (
                row["execution_canonical_json"] is None
                or row["execution_content_digest"] is None
                or row["execution_fingerprint"] is None
            ):
                raise StorageIntegrityError("session execution reference is incomplete")
            execution_document = _verified_document(
                content_json=row["execution_content_json"],
                canonical_json_value=row["execution_canonical_json"],
                content_digest=row["execution_content_digest"],
                identity=f"session execution {row['execution_fingerprint']}",
            )
            if execution_document.get("fingerprint") != row["execution_fingerprint"]:
                raise StorageIntegrityError("session execution document fingerprint is corrupt")
            exact_execution_document = self._read_document(
                "verification_execution",
                row["execution_fingerprint"],
            )
            if exact_execution_document != execution_document:
                raise StorageIntegrityError(
                    "session execution document conflicts with exact stored execution"
                )
            if (
                execution_document.get("session", {}).get("fingerprint") != fingerprint
                or execution_document.get("claim_graph_fingerprint")
                != row["graph_fingerprint"]
                or execution_document.get("plan_fingerprint")
                != row["plan_fingerprint"]
            ):
                raise StorageIntegrityError(
                    "session execution references conflict with session identity"
                )
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
        document_claim_ids = tuple(item["claim_id"] for item in document.get("claims", ()))
        if tuple(item[0] for item in claim_versions) != document_claim_ids:
            raise StorageIntegrityError("session claim links are corrupt")
        states_by_id = {
            item["claim_id"]: item
            for item in document.get("claims", ())
        }
        for claim_id, claim_version in claim_versions:
            stored_claim = self._read_claim_version(claim_id, claim_version)
            state = states_by_id[claim_id]
            if (
                state.get("stored_verdict") != stored_claim.verdict.value
                or state.get("bundle_fingerprint")
                != stored_claim.bundle_fingerprint
                or tuple(state.get("evidence_ids", ()))
                != stored_claim.report.evidence_ids
                or tuple(state.get("claim_dependency_ids", ()))
                != tuple(
                    dependency_id
                    for dependency_id, _version
                    in stored_claim.claim_dependency_versions
                )
            ):
                raise StorageIntegrityError(
                    f"session claim state for {claim_id} conflicts with its durable basis"
                )
        for root, verdict in document.get("root_verdicts", {}).items():
            state = states_by_id.get(root)
            if state is None or state.get("effective_verdict") != verdict:
                raise StorageIntegrityError(
                    "session root verdicts conflict with stored claim states"
                )
        bundle_ids = tuple(
            item[0]
            for item in self._conn().execute(
                """
                SELECT bundle_fingerprint FROM session_bundle_links
                WHERE session_fingerprint = ? ORDER BY ordinal
                """,
                (fingerprint,),
            )
        )
        expected_bundles = tuple(sorted({
            item["bundle_fingerprint"]
            for item in document.get("atomic_verifications", ())
            if item.get("bundle_fingerprint") is not None
        }))
        if bundle_ids != expected_bundles:
            raise StorageIntegrityError("session bundle links are corrupt")
        for bundle_id in bundle_ids:
            self.get_bundle(bundle_id)
        falsification_ids = tuple(
            item[0]
            for item in self._conn().execute(
                """
                SELECT falsification_fingerprint FROM session_falsification_links
                WHERE session_fingerprint = ? ORDER BY ordinal
                """,
                (fingerprint,),
            )
        )
        for falsification_id in falsification_ids:
            self.get_falsification_result(falsification_id)
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
            bundle_fingerprints=bundle_ids,
            falsification_fingerprints=falsification_ids,
            current=self._session_current(fingerprint),
        )

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

            acquisition_slots: dict[str, tuple[EvidenceSlotVersion, ...]] = {}
            steps_by_request: dict[tuple[str, str], str] = {}
            for step in request.plan.steps:
                if step.kind is VerificationPlanStepKind.ACQUIRE_EVIDENCE:
                    assert step.request_id is not None and step.request_fingerprint is not None
                    steps_by_request[(step.request_id, step.request_fingerprint)] = step.step_id
            evidence_slots_by_semantics: dict[str, EvidenceSlotVersion] = {}
            for key, provider_result in result.provider_results.items():
                coverage = provider_result.coverage
                slots: list[EvidenceSlotVersion] = []
                for evidence in provider_result.evidence:
                    written = self.put_evidence(
                        evidence,
                        slot_id=evidence.id,
                        provenance={
                            "provider_id": provider_result.provider_id,
                            "provider_version": provider_result.provider_version,
                            "request_id": provider_result.request_id,
                            "request_fingerprint": provider_result.request_fingerprint,
                            "result_fingerprint": provider_result.fingerprint,
                            "source_identity": coverage.source_identity,
                        },
                        source_snapshot=coverage.snapshot_identity,
                        bounds=coverage.declared_bounds,
                        coverage=coverage.to_dict(),
                    )
                    assert written.slot_version is not None
                    slot = self._slot_version(evidence.id, written.slot_version)
                    slots.append(slot)
                    evidence_slots_by_semantics[_content_json(_evidence_document(evidence))] = slot
                step_id = steps_by_request.get(key)
                if step_id is not None:
                    acquisition_slots[step_id] = tuple(slots)

            plan_steps = {step.step_id: step for step in request.plan.steps}
            falsification_ids_by_step: dict[str, str] = {}
            for step_id, falsification_result in result.falsification_results.items():
                step = plan_steps[step_id]
                slots = tuple(
                    slot
                    for dependency_step_id in step.dependency_step_ids
                    for slot in acquisition_slots.get(dependency_step_id, ())
                )
                self.put_falsification_result(
                    falsification_result,
                    evidence_slots=slots,
                )
                falsification_ids_by_step[step_id] = falsification_result.fingerprint

            stored_bundles: dict[str, StoredBundle] = {}
            for claim_id, bundle in result.bundles.items():
                exact_slots: dict[str, EvidenceSlotVersion] = {}
                for evidence in bundle.evidence:
                    slot = evidence_slots_by_semantics.get(
                        _content_json(_evidence_document(evidence))
                    )
                    if slot is None:
                        written = self.put_evidence(evidence, slot_id=evidence.id)
                        assert written.slot_version is not None
                        slot = self._slot_version(evidence.id, written.slot_version)
                    exact_slots[evidence.id] = slot
                stored_bundles[claim_id] = self.put_bundle(
                    bundle,
                    evidence_slots=exact_slots,
                )

            verifier_versions: dict[str, str] = {}
            falsification_by_claim: dict[str, tuple[str, ...]] = {}
            for step in request.plan.steps:
                if step.kind is not VerificationPlanStepKind.VERIFY_ATOMIC_CLAIM:
                    continue
                assert step.claim_id is not None and step.verifier_version is not None
                verifier_versions[step.claim_id] = step.verifier_version
                falsification_by_claim[step.claim_id] = tuple(sorted(
                    falsification_ids_by_step[dependency]
                    for dependency in step.dependency_step_ids
                    if dependency in falsification_ids_by_step
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
            for claim_id in request.claim_graph.evaluation_order:
                node = request.claim_graph.claim(claim_id)
                if isinstance(node, AtomicClaim):
                    bundle = result.bundles.get(claim_id)
                    if bundle is None:
                        raise StorageIntegrityError(
                            f"completed execution is missing bundle for atomic claim {claim_id}"
                        )
                    self.record_claim(
                        claim_id,
                        bundle,
                        verifier_version=verifier_versions[claim_id],
                        falsification_fingerprints=falsification_by_claim.get(claim_id, ()),
                    )
                else:
                    state = session_states[claim_id]
                    report = VerificationReport(
                        verdict=state.stored_verdict,
                        verifier=COMPOSITE_CLAIM_VERIFIER,
                    )
                    self.record_claim(
                        claim_id,
                        None,
                        verifier_version="1",
                        report=report,
                        claim_dependency_ids=node.dependencies,
                    )

            execution_document = result.to_dict()
            self._put_document("verification_execution", result.fingerprint, execution_document)
            return self.put_session(
                result.session,
                plan_fingerprint=result.plan_fingerprint,
                execution_fingerprint=result.fingerprint,
                execution_document=execution_document,
                falsification_fingerprints=tuple(sorted(
                    item.fingerprint for item in result.falsification_results.values()
                )),
            )


SQLiteDurableStorage = SQLiteStorage
SQLiteLedgerStorage = SQLiteStorage
