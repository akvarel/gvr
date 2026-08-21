# Durable storage

GVR's in-memory `ClaimLedger` and `VerificationSession` remain useful for one process and one execution. The durable storage layer preserves the same truth semantics across process restarts and concurrent SQLite callers.

The reference implementation uses only Python's standard-library `sqlite3` module.

## Public interfaces

The storage contract is split into five small, generic protocols:

- `EvidenceStore` stores immutable evidence artifacts and replaceable evidence slots;
- `BundleStore` stores immutable `VerificationBundle` objects and their exact evidence-version links;
- `ClaimStore` stores claim definitions, versioned verification bases, and reconstructible history;
- `SessionStore` stores sealed `VerificationSession` artifacts and exact graph, plan, execution, claim, bundle, and falsification references;
- `DependencyIndex` provides indexed reverse dependency lookup and durable invalidation events.

`StorageUnitOfWork` combines those interfaces for callers that need one explicit transaction. `UnitOfWorkFactory` is the minimal factory contract used by adapters.

The standard-library reference adapter is:

```python
from gvr import SQLiteStorage

storage = SQLiteStorage("verification.sqlite3")
```

`SQLiteDurableStorage` and `SQLiteLedgerStorage` are aliases for the same adapter.

## Immutable evidence and replaceable slots

An immutable stored evidence artifact includes:

- the complete `Evidence` record;
- canonical payload bytes;
- provenance;
- source snapshot identity;
- declared bounds;
- coverage;
- a canonical storage fingerprint.

Writing identical canonical content is idempotent:

```python
stored = storage.put_evidence(
    evidence,
    provenance={"provider_id": "example.provider", "provider_version": "1"},
    source_snapshot={"revision": "abc123"},
    bounds={"max_items": 100},
    coverage={"completeness": "COMPLETE"},
)
```

Immutable artifacts never become stale because time passed. GVR does not use a TTL for verification truth.

A slot gives a stable logical name to a replaceable artifact:

```python
stored = storage.put_evidence(
    evidence,
    slot_id="repository:main:snapshot",
    source_snapshot={"revision": "abc123"},
)

current = storage.get_slot("repository:main:snapshot")
history = storage.slot_history("repository:main:snapshot")
```

When a slot changes, SQLite atomically:

1. inserts or reuses the immutable artifact;
2. appends the next slot version;
3. advances the slot pointer;
4. records one idempotent invalidation event;
5. traverses the indexed reverse dependency graph.

Old slot versions and old artifacts remain available for audit and history reconstruction.

## Bundles

`put_bundle()` stores a `VerificationBundle` under its existing bundle fingerprint. The durable record links every bundle evidence ID to one exact immutable artifact and one exact slot version.

```python
slot = storage.get_slot("repository:main:snapshot")
stored_bundle = storage.put_bundle(
    bundle,
    evidence_slots={bundle.evidence[0].id: slot},
)
```

A historical bundle is immutable. Its `current` state is derived structurally:

- every linked slot version must still be the current slot version;
- the bundle must not be downstream of a durable invalidation cause.

There is no age-based freshness rule.

Every read verifies canonical JSON, storage digests, the domain bundle fingerprint, exact evidence links, exact artifact content, and exact claim dependency links. Missing or substituted links fail closed with `StorageIntegrityError`.

## Claims and stored truth

Define a durable claim before recording a verification:

```python
from gvr import ClaimDefinition

storage.define_claim(
    ClaimDefinition("claim-A", "A is ready", "example.verifier"),
    verifier_version="1",
)
```

Then record the exact bundle basis:

```python
claim_version = storage.record_claim(
    "claim-A",
    bundle,
    verifier_version="1",
)
```

Each immutable claim version preserves:

- claim definition fingerprint;
- verifier ID and exact version;
- stored verdict and full report;
- bundle fingerprint;
- exact evidence slot versions;
- exact upstream claim versions;
- exact falsification result fingerprints;
- canonical basis fingerprint.

A `PASS` cannot be recorded without at least one stored evidence, claim, or falsification basis. A stale bundle, stale claim dependency, stale falsification result, wrong verifier, wrong version, mismatched report, or cross-claim falsification result is rejected.

```python
status = storage.claim_status("claim-A")

status.stored_verdict     # historical verdict, for example PASS
status.effective_verdict  # UNKNOWN when the current basis is stale
status.current            # structural current/stale state
```

Claim dependency cycles are rejected before the current pointer changes. Reverification appends a new claim version and retains every old version:

```python
for version in storage.claim_history("claim-A"):
    print(version.version, version.verdict, version.current)
```

## Sessions

A sealed `VerificationSession` can be stored after its claim bases exist:

```python
stored_session = storage.put_session(
    session,
    plan_fingerprint=plan.fingerprint,
    execution_fingerprint=result.fingerprint,
    execution_document=result.to_dict(),
)
```

The durable session record preserves:

- exact session document and semantic fingerprint;
- exact claim graph fingerprint;
- optional exact plan fingerprint;
- optional exact execution fingerprint and execution document;
- exact claim-version links;
- exact bundle links;
- exact falsification links;
- claim statuses, root verdicts, termination, and counters from the session document.

A session remains in history after an input changes. `current_sessions()` returns structurally current sessions. `historical_sessions()` returns noncurrent session artifacts.

## Falsification results

`FalsificationResult` artifacts are immutable and fingerprint-verified on read:

```python
stored = storage.put_falsification_result(
    result,
    evidence_slots=(input_slot,),
)
```

A claim may use a falsification result only when the result belongs to that exact claim and declared verifier. If a linked evidence slot changes, invalidation flows through:

```text
slot version
  -> falsification result
  -> claim version
  -> downstream claim versions
  -> sessions
```

Falsification still does not decide truth. The stored falsification result is part of the verifier's exact basis, not a replacement verifier.

## Explicit transactions

Use a unit of work for several logical writes:

```python
with storage.unit_of_work() as uow:
    evidence_record = uow.put_evidence(evidence, slot_id="slot-A")
    uow.put_bundle(bundle, evidence_slots={evidence.id: uow.get_slot("slot-A")})
    uow.define_claim(definition, verifier_version="1")
    uow.record_claim(definition.id, bundle, verifier_version="1")
```

An exception rolls back the transaction. High-level logical writes also use SQLite savepoints, so a failed bundle, claim, session, or completed-execution record cannot leave a partial current `PASS` basis.

Do not share one active unit of work across threads. Independent SQLite-supported callers may use separate `SQLiteStorage` instances against the same database. Writes use `BEGIN IMMEDIATE`, foreign keys, a busy timeout, and deterministic conflict checks. Identical concurrent inserts converge on one canonical object. Conflicting immutable identities reject one caller instead of silently choosing content.

## Executor integration

Task 19 execution and Task 20 falsification can persist through an explicitly supplied store:

```python
result = execute_verification_plan(request, storage=storage)
```

Or through a caller-owned unit of work:

```python
with storage.unit_of_work() as uow:
    result = execute_verification_plan(request, unit_of_work=uow)
```

`storage` and `unit_of_work` are mutually exclusive. GVR never discovers storage globally.

The executor first completes its normal fail-closed in-memory semantics. Before returning, durable recording atomically writes the exact provider evidence metadata, slot versions, falsification results, bundles, claim versions, graph and plan documents, execution document, and sealed session. If durable recording fails, `execute_verification_plan()` raises `VerificationExecutionError`; it does not return an unstored `PASS`.

Supplying no storage preserves the Task 19 and Task 20 behavior and fingerprints.

## Schema and migrations

The current durable schema version is exposed as:

```python
DURABLE_STORAGE_SCHEMA_VERSION
DURABLE_STORAGE_SCHEMA_TABLE
```

Bootstrap and every migration run in one SQLite transaction. The adapter never drops or resets an existing database. A database with a newer schema version fails closed with `StorageSchemaVersionError`.

Migration failure raises `StorageMigrationError` and rolls back schema creation or upgrade. `migration_hooks` exists for controlled adapter extensions and migration testing; a hook runs inside the same transaction.

## Integrity and corruption behavior

Reads do not trust an in-memory cache. `clear_cache()` is a compatibility no-op because SQLite remains authoritative.

Reads verify multiple independent layers:

- canonical JSON representation;
- canonical storage digest;
- domain fingerprints for evidence-linked bundles, falsification results, claim graphs, and sessions;
- relational columns against canonical documents;
- exact foreign links and slot pointers;
- claim report, bundle, definition, dependency, and falsification consistency;
- session claim and root state against exact durable claim bases.

Corruption, missing links, conflicting content, or an impossible stored truth state fails closed. The adapter does not repair or reset data automatically.

## Indexed invalidation

Reverse edges are stored in `object_dependencies` with the `idx_object_dependencies_dependency` index. Invalidation walks only reachable dependents. It does not deserialize or scan every stored session.

The main dependency shapes are:

```text
bundle -> slot version
falsification result -> slot version
claim version -> bundle / slot version / claim version / falsification result
session -> claim version / bundle / falsification result
```

`explain_reverse_dependency_lookup()` is a diagnostic helper for checking the SQLite query plan.

## Protocol boundary

Durable storage is currently a Python API, not a raw SQL or generic database JSON protocol. The schema-v1 CLI and JSON protocol do not accept SQL and do not expose database paths. Applications should wrap storage in their own authenticated service boundary when remote access is required.

## Operational notes

- Back up the SQLite database and its WAL consistently using normal SQLite backup practices.
- Treat storage fingerprints as content identities, not signatures or authentication.
- Keep the database file permissions appropriate for the evidence it contains.
- Do not edit rows manually. Manual corruption is detected rather than repaired.
- Do not infer freshness from file timestamps, row order, or wall-clock time.
