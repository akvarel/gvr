# Durable storage

GVR's in-memory `ClaimLedger` and `VerificationSession` remain useful for one process and one execution. The durable storage layer preserves the same truth semantics across process restarts and concurrent SQLite callers.

The reference implementation uses only Python's standard-library `sqlite3` module.

## Public interfaces

The storage contract is split into five small, generic protocols:

- `EvidenceStore` stores immutable evidence artifacts and explicitly replaceable evidence slots;
- `BundleStore` stores immutable `VerificationBundle` objects plus versioned durable records for their exact mutable or immutable evidence basis;
- `ClaimStore` stores claim definitions, versioned verification bases, and reconstructible history;
- `SessionStore` stores sealed `VerificationSession` artifacts, exact semantic dependency records, and separate plan/execution audit observations;
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

Only semantic coverage is stored in that content-addressed artifact. Provider `AuditObservation` metadata is excluded from the artifact fingerprint and retained in the session execution observation that records the completed acquisition.

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

Immutable artifacts never become stale because time passed. GVR does not use a TTL for verification truth. When no replaceable semantics are declared, bundles and claims link directly to the immutable artifact. Storage does not manufacture a mutable slot from `Evidence.id`.

A low-level caller may explicitly own an opaque slot name:

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

### Semantic acquisition slots

Provider-backed executor recording uses the smaller, canonical `EvidenceSlotIdentity` contract instead of a global string derived from raw `Evidence.id`:

```python
slot_identity = request.evidence_slot_identity(
    evidence.id,
    source_identity=coverage.source_identity,
)

result = EvidenceProviderResult(
    # ... exact request, provider, status, coverage, and evidence ...
    evidence_slot_identities=(slot_identity,),
)
```

Declaring an identity is the explicit opt-in to replacement semantics. An omitted identity means immutable evidence.

The slot fingerprint includes canonical:

- provider ID;
- source identity;
- stable request kind, requested evidence kinds, subject, spec, semantic scope, source context, bounds, and source/snapshot classes;
- the evidence ID scoped inside that provider/source/request namespace.

It deliberately excludes:

- correlation `request_id`;
- provider version;
- snapshot context or snapshot identity;
- evidence payload, source snapshot, producer fingerprint, and other immutable artifact content;
- execution, result, or session fingerprints.

Provider version, snapshot, genuine semantic coverage, provenance, or evidence content changes therefore advance the same semantic slot. Correlation-only or audit-observation-only changes reuse the same artifact and slot version. A different provider, source, or semantic request gets a different slot even when it emits the same raw `Evidence.id`.

## Bundles

`put_bundle()` stores a `VerificationBundle` under its existing domain fingerprint. A separate durable bundle-record fingerprint links every exact acquisition dependency to either one immutable artifact or one semantic slot version.

```python
slot = storage.get_slot("repository:main:snapshot")
stored_bundle = storage.put_bundle(
    bundle,
    evidence_slots={bundle.evidence[0].id: slot},
)
```

Direct immutable dependencies use `evidence_artifacts={evidence_id: fingerprint}`. If neither mapping is supplied for a new bundle, `put_bundle()` stores its evidence immutably. It never infers slots from evidence IDs.

The advanced `evidence_dependencies=` form accepts canonical `EvidenceDependency` records directly. It is used by executor recording when several independent acquisitions emit the same raw evidence ID. A bundle may contain one deduplicated immutable `Evidence` value while its durable record retains both exact provider/source/request slot dependencies. Dependency identity and ordering are canonical, not inferred from raw IDs.

One domain bundle may have several historical durable records. This is necessary when a new snapshot, provider version, or independent semantic source changes storage provenance while the language-level `VerificationBundle` content remains identical:

```python
current = storage.get_bundle(bundle.fingerprint)
history = storage.bundle_history(bundle.fingerprint)
exact = storage.get_bundle(
    bundle.fingerprint,
    record_fingerprint=stored_bundle.record_fingerprint,
)
```

A domain-only lookup is convenient for interactive inspection, but callers that are constructing truth bases must pass the exact record returned by the current write. `record_claim(..., bundle_record=stored_bundle)` and its exact falsification-record counterpart prevent substitution by another still-current same-domain record.

A historical bundle is immutable. Its `current` state is derived structurally:

- every replaceable dependency must still reference its slot's authoritative current version;
- immutable dependencies remain current permanently unless their record is corrupt;
- the exact bundle record must not be downstream of a durable invalidation cause.

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
    bundle_record=stored_bundle,
    falsification_records=(stored_falsification,),
)
```

The exact-record parameters are optional for backward-compatible low-level use. Executor recording always supplies them. Each supplied record is reread by record fingerprint, checked against canonical content and exact dependencies, required to be current, and rejected if it conflicts with the current execution.

Each immutable claim version preserves:

- claim definition fingerprint;
- verifier ID and exact version;
- stored verdict and full report;
- bundle fingerprint and exact durable bundle-record fingerprint;
- exact mutable slot versions and direct immutable evidence fingerprints;
- exact upstream claim versions;
- exact falsification result and durable record fingerprints;
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
    claim_records=(claim_version,),
    bundle_records=(stored_bundle,),
    falsification_records=(stored_falsification,),
)
```

Exact claim, bundle, and falsification records are validated again before the session record is created. This keeps the session basis tied to the current execution even when another exact record with the same domain fingerprint is also structurally current.

The durable session layer separates semantic truth basis from audit correlation. A session record preserves:

- exact session document and semantic fingerprint;
- exact claim graph fingerprint;
- exact claim-version links;
- exact bundle-record links;
- exact falsification-record links;
- claim statuses, root verdicts, termination, and counters from the session document.

Plan fingerprints, execution fingerprints, exact execution documents, request IDs, execution correlation IDs, and nested provider `AuditObservation` documents are stored as `SessionExecutionObservation` audit records. They do not create a new semantic session basis or affect currentness. Two executions with one semantic fingerprint may therefore have distinct observation fingerprints and remain independently retrievable.

```python
records = storage.session_record_history(session.fingerprint)
observations = storage.session_execution_observations(session.fingerprint)
```

A session remains in history after an input changes. `current_sessions()` returns structurally current sessions. `historical_sessions()` returns noncurrent session artifacts.

## Falsification results

`FalsificationResult` domain artifacts are immutable and fingerprint-verified on read. Their exact evidence basis is a separate durable record, so a result can retain historical mutable-slot or immutable-artifact links:

```python
stored = storage.put_falsification_result(
    result,
    evidence_slots=(input_slot,),
)
```

A claim may use a falsification result only when the result belongs to that exact claim and declared verifier. If a linked evidence slot changes, invalidation flows through:

```text
slot version
  -> falsification record
  -> claim version
  -> downstream claim versions
  -> sessions
```

Falsification still does not decide truth. The stored falsification result is part of the verifier's exact basis, not a replacement verifier.

## Explicit transactions

Use a unit of work for several logical writes. Opaque `slot_id` is an explicit caller-owned low-level slot; provider acquisition should use `EvidenceSlotIdentity`:

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

The executor first completes its normal fail-closed in-memory semantics. Before returning, durable recording atomically writes exact provider evidence metadata, explicit semantic slot versions or direct immutable dependencies, falsification records, bundle records, claim versions, graph and plan documents, execution audit observations, and sealed session records. Every acquisition dependency is retained, including multiple source/request slots that emitted one identical raw evidence ID. Each returned bundle and falsification record is matched against the canonical dependency tuple computed for the current execution, then threaded directly through the claim and session write. A to B to reopen to replay A therefore restores A's exact basis instead of selecting B by a shared domain fingerprint or row order. `record_execution()` never uses raw `Evidence.id` as a global mutable slot. If any exact record mismatches, is stale, or is corrupt, the outer transaction rolls back and `execute_verification_plan()` raises `VerificationExecutionError`; it does not return an unstored `PASS`.

Supplying no storage preserves the Task 19 and Task 20 behavior and fingerprints.

## Schema and migrations

The current durable schema version is exposed as:

```python
DURABLE_STORAGE_SCHEMA_VERSION
DURABLE_STORAGE_SCHEMA_TABLE
```

Bootstrap and every migration run in one SQLite transaction. The adapter never drops or resets an existing database. A database with a newer schema version fails closed with `StorageSchemaVersionError`.

Migration failure raises `StorageMigrationError` and rolls back schema creation or upgrade. `migration_hooks` exists for controlled adapter extensions and migration testing; a hook runs inside the same transaction.

Schema version 2 added canonical slot identity metadata, mutable-or-immutable evidence dependency links, versioned bundle/falsification/session records, and nonsemantic session execution observations.

Schema version 3 changes bundle-record, falsification-record, and claim dependency-link keys from raw evidence ID to canonical dependency ordinal. This is required because independent acquisitions may legitimately share one raw evidence ID. Migration from version 2 rebuilds only those link tables, copies every authoritative row transactionally, and preserves record fingerprints, slot authority, currentness, history, and replay behavior. Task 24 exact-record threading requires no schema change because schema v3 already stores every bundle, falsification, claim, session, and observation record fingerprint needed for exact selection.

Version 1 did not record whether a slot string was caller-owned or inferred by the old executor from raw `Evidence.id`. Migration still marks every pre-v2 slot `LEGACY_AMBIGUOUS` and non-authoritative before the version-3 link migration runs. Its artifacts and history remain readable, but any dependent bundle, claim, falsification result, or session is structurally stale. A new explicit semantic identity uses its canonical namespaced slot and can establish a new authoritative basis; an ambiguous raw slot is never silently adopted.

## Integrity and corruption behavior

Reads do not trust an in-memory cache. `clear_cache()` is a compatibility no-op because SQLite remains authoritative.

Reads verify multiple independent layers:

- canonical JSON representation;
- canonical storage digest;
- domain fingerprints for evidence-linked bundles, falsification results, claim graphs, and sessions;
- relational columns against canonical documents;
- exact foreign links, slot identity metadata, authority flags, and slot pointers;
- exact bundle, falsification, claim, and session record fingerprints;
- claim report, bundle, definition, dependency, and falsification consistency;
- session claim and root state against exact durable claim bases.

Corruption, missing links, conflicting content, or an impossible stored truth state fails closed. The adapter does not repair or reset data automatically.

## Indexed invalidation

Reverse edges are stored in `object_dependencies` with the `idx_object_dependencies_dependency` index. Invalidation walks only reachable dependents. It does not deserialize or scan every stored session.

The main dependency shapes are:

```text
bundle record -> slot version or immutable evidence artifact
falsification record -> slot version or immutable evidence artifact
claim version -> bundle record / evidence dependency / claim version / falsification record
session record -> claim version / bundle record / falsification record
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
