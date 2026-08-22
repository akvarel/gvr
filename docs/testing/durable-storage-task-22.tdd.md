# Task 22 durable semantic evidence slot identity TDD evidence

## Source and boundary

This remediation starts from approved remote base `fefc7736d72fbd411893522fd7ffdd8421645c3c` on `feature/gvr-durable-slot-identity-remediation-v1`.

The specification is derived from the authorized Task 22 request. It is intentionally limited to the generic evidence acquisition and durable storage boundary. It does not add product-specific schema, TTL freshness, a deployment, a push, or a Drive report.

## User journeys

1. As a durable GVR caller, I can explicitly declare that one acquired evidence record occupies a replaceable semantic slot, so later snapshots replace only that provider/source/request slot.
2. As an auditor, I can retain request and execution correlation without allowing those IDs to change durable truth identity or currentness.
3. As a verifier, I can depend directly on immutable evidence when no replaceable semantics were declared, without a fabricated mutable slot.
4. As an operator, I can reopen, migrate, replay, or roll back SQLite recording without false freshness, cross-source invalidation, partial writes, or silent trust in ambiguous legacy slots.

## Required matrix A-E

| Matrix | Boundary | Required invariant |
|---|---|---|
| A | Correlation | `request_id` and execution correlation remain audit data. They do not change semantic slot identity, slot version, claim basis, invalidation, or currentness. |
| B | Namespace isolation | Raw `Evidence.id` is never a global slot. Canonical provider, source, and request semantics scope every explicit replaceable slot. |
| C | Replacement | Snapshot, provider version, or immutable content changes are excluded from the slot ID but advance that same slot once and stale only exact transitive dependents. |
| D | Immutability | Evidence without an explicit replaceable declaration remains a direct immutable dependency and never becomes a fake mutable slot. |
| E | Durability | Recording is atomic, restart replay is idempotent, schema migration is transactional, and ambiguous v1 slots are non-authoritative until replaced by an explicit semantic identity. |

## Approved-base reproduction before production changes

Baseline command:

```text
python -m pytest -q -p no:cacheprovider
554 passed
```

A standalone real-path probe executed `execute_verification_plan(..., storage=SQLiteStorage(...))`, which reaches `SQLiteStorage.record_execution`.

### Correlation-only request change

Only `EvidenceRequest.request_id` changed from `corr-a` to `corr-b`; provider, source, snapshot, request semantics, evidence ID, evidence content, and claim were unchanged.

Observed approved-base result:

```text
first slot: shared-raw-id version 1
second recording: VerificationExecutionError: durable storage recording failed closed
underlying cause: StorageConflictError: immutable bundle fingerprint has conflicting content or evidence links
after rollback: slot history [1], invalidation events 0, original claim/session current
```

The second audit observation could not be recorded because `record_execution` included `request_id` in the stored evidence artifact provenance, attempted to advance the raw-ID slot, and then collided with the immutable bundle identity.

### Unrelated requests reusing one raw evidence ID

Two real executions used raw `Evidence.id == "shared-raw-id"` but different repositories, request IDs, claims, snapshots, and content.

Observed approved-base result:

```text
slot history: shared-raw-id versions [1, 2]
invalidation event cause: slot-version:shared-raw-id:1
targets: first bundle, first claim version, first session
claim-a current: false
session-a current: false
claim-b current: true
session-b current: true
```

This is the confirmed global-slot collision: an unrelated request invalidated the first source solely because `record_execution` used raw `Evidence.id` as `slot_id`.

## Mandatory adversarial specification

All tests use the real provider runtime, verifier runtime, executor, and SQLite recording path. No mock storage is used.

| # | Matrix | Guarantee | Test |
|---:|:---:|---|---|
| 1 | A | Correlation-only `request_id` changes reuse one semantic slot/version, create no invalidation, retain one current claim/session basis, and remain auditable. | `test_task22_01_request_id_only_change_is_same_slot_version_and_current_basis` |
| 2 | A | Top-level execution correlation changes are audit observations, not slot or session truth versions. | `test_task22_02_execution_correlation_only_is_audit_not_slot_or_session_basis` |
| 3 | B | Same raw evidence ID from different canonical sources never collides. | `test_task22_03_same_raw_id_in_different_sources_never_collides` |
| 4 | B | Same raw evidence ID under different semantic request parameters never collides. | `test_task22_04_same_raw_id_in_different_request_parameters_never_collides` |
| 5 | B | Reusing one correlation request ID cannot alias different semantic sources. | `test_task22_05_same_request_id_cannot_alias_different_semantic_sources` |
| 6 | B/C | Provider identity scopes slots; provider version is excluded from slot identity but advances the same slot and exact basis. | `test_task22_06_provider_identity_scopes_slots_but_provider_version_advances_same_slot` |
| 7 | C | Snapshot-only change with identical `Evidence` content versions the same slot, bundle basis, claim basis, and session basis once; replay is idempotent. | `test_task22_07_snapshot_change_with_identical_content_versions_bundle_claim_and_session_once` |
| 8 | C | Content change advances once and leaves an unrelated source's bundle, claim, and session current. | `test_task22_08_content_change_stales_exact_only_and_leaves_unrelated_current` |
| 9 | C | Falsification records preserve and invalidate the exact semantic slot version transitively, whether the snapshot also changes the domain result fingerprint or only its durable basis. | `test_task22_09_falsification_tracks_exact_semantic_slot_version_transitively` |
| 10 | D | Undeclared evidence remains immutable, creates no slot, and persists direct immutable bundle dependencies. | `test_task22_10_undeclared_evidence_remains_immutable_without_fake_slots` |
| 11 | E | An outer transaction rollback removes artifact/slot advances, invalidation, bundle/falsification records, claim versions, session records, and audit observations together. | `test_task22_11_outer_rollback_removes_slot_advance_and_all_transitive_records` |
| 12 | E | v1 migration marks ambiguous raw-ID slots stale; explicit semantic replacement and restart replay are safe and idempotent. | `test_task22_12_v1_migration_marks_ambiguous_raw_slots_stale_and_restart_replay_is_idempotent` |

## RED evidence

Command:

```text
python -m pytest -q -p no:cacheprovider --tb=line tests/test_durable_storage_slot_identity.py
```

Observed result before any production change:

```text
12 failed
```

Exact failure classes reached the intended boundaries:

- `StorageConflictError: immutable bundle fingerprint has conflicting content or evidence links` for correlation, source/request namespace, provider version, snapshot, content, and falsification variants;
- `StorageConflictError: verification_execution document identity has conflicting content` for execution-correlation replay;
- missing `EvidenceProviderResult.evidence_slot_identities` for the explicit acquisition contract and immutable/direct-dependency cases;
- `DURABLE_STORAGE_SCHEMA_VERSION == 1`, not required migration version 2.

The full repository now collects 566 tests: the approved-base 554 plus these 12 mandatory adversarial tests.

## GREEN evidence

Implementation:

- `EvidenceSlotIdentity` is a frozen public provider/storage contract with a canonical fingerprint and derived `slot_id`.
- `EvidenceRequest.slot_request_identity()` and `evidence_slot_identity()` deliberately exclude correlation request ID, provider version, snapshot, and evidence content while including provider/source/stable-request semantics.
- `EvidenceProviderResult.evidence_slot_identities` is optional, fingerprinted, protocol-round-trippable, and revalidated both after provider execution and again at durable recording.
- `record_execution()` writes a semantic slot only for an explicit declaration. Otherwise it records a direct immutable dependency. No production path infers a slot from raw `Evidence.id`.
- Evidence provenance excludes audit `request_id` and aggregate result fingerprint. Exact request/execution/session correlation remains available in session execution observations.
- Domain bundles, falsification results, and sessions now have separate durable record fingerprints for exact dependency bases. This permits snapshot or provider-version changes to advance the same slot even when the language-level domain artifact remains identical.
- Claims link exact bundle records, mutable or immutable evidence dependencies, upstream claim versions, and exact falsification records. Missing or substituted v2 links fail closed during reads and currentness checks.
- Session semantic records are separate from `SessionExecutionObservation` audit records, so correlation-only replay does not create a new truth basis or invalidation.
- Provider-backed falsification inputs now expose canonical acquisition serialization and use the public `Evidence` fields correctly.
- Durable schema version 2 adds slot authority metadata, mutable-or-immutable dependency records, versioned bundle/falsification/session records, and audit observations. Transactional v1 migration marks every ambiguous old slot non-authoritative without deleting history.

Validation commands and observed results:

```text
python -m pytest -q -p no:cacheprovider tests/test_durable_storage_slot_identity.py
12 passed

python -m pytest -q -p no:cacheprovider \
  tests/test_durable_storage.py \
  tests/test_durable_storage_impossible_states.py \
  tests/test_durable_storage_slot_identity.py
50 passed

python -m pytest -q -p no:cacheprovider \
  tests/test_evidence_providers.py \
  tests/test_evidence_provider_hardening.py \
  tests/test_evidence_provider_task_17b.py \
  tests/test_evidence_provider_task_17c.py \
  tests/test_verification_execution.py \
  tests/test_falsification.py
217 passed

python -m pytest -q -p no:cacheprovider
566 passed

python -m compileall -q src tests
passed

git diff --check
passed
```

Wheel and installed-package evidence:

```text
wheel: gvr-0.2.0-py3-none-any.whl
sha256: 4f239ed2a111f603f5ad868037b9a52f3d4a12e2da774a73d9ae79a1336801f1
installed DURABLE_STORAGE_SCHEMA_VERSION: 2
installed public slot contract: EvidenceSlotIdentity
fresh installed Task 22 SQLite matrix: 12 passed
```

The installed test ran outside the source tree with `PYTHONPATH` removed. It exercised correlation-only replay, raw-ID namespace isolation, request/provider/source/version/snapshot/content variation, direct immutable evidence, exact falsification invalidation, transaction rollback, migration rollback, successful migration/reopen, and restart replay against the built wheel.

## Post-GREEN adversarial alias review

After the GREEN checkpoint, a separate real provider/executor/SQLite probe varied provider request correlation, execution correlation, canonical mapping insertion order, raw evidence IDs, provider identity, source identity, request parameters, provider version, snapshot, immutable content, claim/session identity, replay, and two database reopens.

Observed results:

```text
correlation + canonical key order: 1 slot version, 0 slot events,
  2 current claims/sessions, 2 separate audit observations
provider version + snapshot + correlation replay: 2 slot versions,
  1 slot event, 2 claim/session records, 3 audit observations
same raw ID + same request ID across provider/source/request variants:
  4 distinct semantic slots, 0 slot events, 4 current claims
undeclared immutable evidence across version/snapshot/content changes:
  0 slot rows, 0 slot events, 2 current claims
content-only replacement plus unrelated source: 2 target slot versions,
  1 slot event, unrelated claim/session still current
two reopen/replay cycles: 2 slot versions, 1 slot event,
  2 claim/session records, 4 audit observations
POST_GREEN_ADVERSARIAL_REVIEW=PASS
```

A second transitive fingerprint audit proved that a correlation-only change keeps the `EvidenceRequest`, `EvidenceProviderResult`, semantic slot, stored evidence version, bundle record, claim version, and session record identical while adding only an audit observation. A snapshot change kept the slot identity stable, produced a distinct immutable artifact and exact bundle/claim/session basis, emitted one slot-version event, and staled the exact old falsification record. It completed with `TRANSITIVE_FINGERPRINT_AUDIT=PASS`.

No remaining alias or correlation leakage was found, so the review required no production-code correction.

## Coverage and known gaps

The local `coverage` module is unavailable, so no percentage is claimed. Acceptance-aligned integration coverage is provided by the 12 real executor/provider/SQLite tests, 50 durable storage tests, 217 touched-boundary tests, the 566-test full suite, and the fresh installed-wheel matrix.

No product-specific schema, TTL policy, remote database protocol, deployment, push, PR, or Drive report is included. The required post-GREEN adversarial alias review completed without finding another alias.
