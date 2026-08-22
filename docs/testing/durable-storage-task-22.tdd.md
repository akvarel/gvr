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
| 9 | C | Falsification records preserve and invalidate the exact semantic slot version transitively. | `test_task22_09_falsification_tracks_exact_semantic_slot_version_transitively` |
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

Pending implementation and rerun from the RED checkpoint.

## Coverage and known gaps

Pending GREEN validation, full-suite execution, compileall, wheel build/install, migration/reopen smoke, and separate post-GREEN adversarial review.
