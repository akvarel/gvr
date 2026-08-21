# Task 21 durable storage TDD evidence

## Source and boundaries

The user supplied the Task 21 requirements directly. No separate plan file was used.

Implementation started from Task 20 final commit `38a24395bcc68b34a0f72ab75208ee95cfc21b4b` on `feature/gvr-durable-ledger-evidence-store-v1`.

The task explicitly excluded pushing, Drive reporting, protected branches, Graphify, BugZero, and ICE changes. No subagents were used. The untracked `probe_false_freshness.py` remained byte-for-byte unchanged at SHA-256 `3473d65d38558ff6ab484268f0dd455d3842198542f364ecf2aa882cb0266f89`.

## User journeys

1. As an OSS integrator, I can target small generic evidence, bundle, claim, session, dependency, and unit-of-work interfaces without depending on SQLite details.
2. As an operator, I can restart a process and recover exact evidence, provenance, slots, bundles, claim history, sessions, falsification results, and invalidation state.
3. As an auditor, I can distinguish immutable historical truth artifacts from structurally current truth without a TTL or authoritative cache.
4. As a verifier caller, I cannot observe a current `PASS` without an exact, fingerprint-verified evidence, claim, or falsification basis.
5. As an executor caller, I can explicitly supply durable storage or my own unit of work, and persistence failure cannot return an unstored `PASS`.
6. As a concurrent SQLite caller, identical writes converge idempotently and conflicting immutable identities fail closed.
7. As a maintainer, I can migrate the schema transactionally, reject future versions without reset, and verify that invalidation uses an indexed reverse lookup rather than scanning serialized sessions.

## RED evidence

Commit: `f91b33b786a09922a075ab7742c2376292d63e81` (`test: define Task 21 durable storage contract`)

Command:

```bash
PYTHONPATH=src python -m pytest -o addopts='' -q tests/test_durable_storage.py
```

Observed result before production changes:

```text
ImportError: cannot import name 'BundleStore' from 'gvr'
1 error during collection
exit status 2
```

This was the intended compile-time RED signal. The generic durable interfaces, records, errors, SQLite adapter, schema, invalidation, and executor persistence API did not exist.

## GREEN evidence

The GREEN checkpoint is the implementation commit containing this document.

Focused command:

```bash
PYTHONPATH=src python -m pytest -o addopts='' -q \
  tests/test_durable_storage.py \
  tests/test_durable_storage_impossible_states.py
```

Observed result:

```text
38 passed in 4.56s
```

This comprises 32 mandatory numbered adversarial cases, one explicit caller-owned executor unit-of-work rollback case, and five separate impossible-state review cases.

Full command:

```bash
PYTHONPATH=src python -m pytest -o addopts='' -q
```

Observed result:

```text
554 passed in 6.38s
```

Additional validation:

```text
PYTHONPATH=src python -m compileall -q src/gvr tests: passed
git diff --check: passed
documentation links: ok (26 markdown files)
public durable exports: ok (11 checked)
sqlite foreign_key_check: ok
sqlite integrity_check: ok
```

Wheel validation:

```text
python -m pip wheel . --no-deps --no-build-isolation
wheel: gvr-0.2.0-py3-none-any.whl
SHA-256: 79481f8cdf6b9b128b7d4dda32aab49d638dc26932433ddd33b6518301237fcc
```

The wheel was installed without dependencies into a fresh virtual environment. With `PYTHONPATH` removed and the working directory outside the repository, the installed package created schema version 1 in a temporary SQLite database, stored canonical evidence metadata, recorded a current `PASS` bundle and claim, reopened the database successfully, advanced the evidence slot to version 2, and observed the old claim's effective verdict become `UNKNOWN`. The imported module path was the fresh environment's `site-packages/gvr/__init__.py`.

## Mandatory adversarial specification

| # | Guarantee | Test |
| --- | --- | --- |
| 1 | Public generic store protocols and the SQLite reference adapter are exported and schema-versioned. | `test_01_public_generic_store_interfaces_and_sqlite_reference_adapter` |
| 2 | Restart preserves immutable evidence plus provenance, source snapshot, bounds, coverage, and slot pointer. | `test_02_restart_preserves_immutable_evidence_and_complete_metadata` |
| 3 | Identical canonical evidence and slot writes are idempotent and emit no invalidation. | `test_03_identical_evidence_and_slot_writes_are_idempotent` |
| 4 | A supplied immutable identity cannot be reused for conflicting canonical content. | `test_04_conflicting_content_for_supplied_immutable_identity_is_rejected` |
| 5 | Corrupt canonical evidence content or fingerprints fail closed on read. | `test_05_corrupt_canonical_payload_or_fingerprint_fails_closed_on_read` |
| 6 | Missing or substituted exact bundle evidence links fail closed. | `test_06_bundle_read_rejects_missing_or_substituted_exact_evidence_links` |
| 7 | A durable `PASS` preserves exact bundle, evidence slot, verifier, and verifier-version basis across restart. | `test_07_pass_basis_persists_exact_bundle_evidence_and_verifier_version` |
| 8 | `PASS` without evidence, claim, or falsification basis is rejected. | `test_08_pass_without_evidence_claim_or_falsification_basis_is_rejected` |
| 9 | Slot replacement retains old immutable artifacts and append-only versions while atomically advancing the pointer. | `test_09_slot_replacement_retains_history_and_atomically_advances_pointer` |
| 10 | A slot change invalidates the exact dependent bundle, claim, and session. | `test_10_slot_change_invalidates_exact_bundle_claim_and_session` |
| 11 | Invalidation propagates transitively through downstream claim versions. | `test_11_transitive_claim_invalidation_reaches_all_downstream_claims` |
| 12 | Unrelated bundles, claims, and sessions remain current. | `test_12_unrelated_bundle_claim_and_session_remain_current` |
| 13 | Idempotent invalidation events and stale state survive restart. | `test_13_invalidation_events_and_stale_state_survive_restart_idempotently` |
| 14 | Slot, bundle, claim, and session history remains reconstructible after reverification. | `test_14_slot_bundle_claim_and_session_histories_are_reconstructible` |
| 15 | Immutable evidence and current truth do not expire with wall-clock time. | `test_15_immutable_evidence_and_current_state_do_not_expire_by_time` |
| 16 | Unit-of-work rollback removes artifacts, slot pointers, and invalidation side effects. | `test_16_unit_of_work_rolls_back_artifact_slot_pointer_and_invalidation` |
| 17 | A failed logical claim write cannot leave a current `PASS`. | `test_17_failed_logical_write_cannot_leave_a_current_pass_claim` |
| 18 | Concurrent identical SQLite inserts converge deterministically on one artifact and slot version. | `test_18_concurrent_identical_inserts_are_deterministic_and_idempotent` |
| 19 | Concurrent conflicting claim identities produce one winner and one explicit conflict, not silent corruption. | `test_19_concurrent_conflicting_identity_has_one_winner_and_one_rejection` |
| 20 | A future schema version fails closed without resetting unrelated or existing data. | `test_20_future_schema_fails_closed_without_resetting_existing_data` |
| 21 | Bootstrap or migration failure rolls back the complete schema transaction. | `test_21_failed_migration_rolls_back_bootstrap_transaction` |
| 22 | Claim dependency cycles are rejected without changing the current basis. | `test_22_claim_dependency_cycles_are_rejected_without_changing_current_basis` |
| 23 | Sessions preserve exact graph, plan, execution, statuses, termination, counters, and current state. | `test_23_sessions_persist_exact_graph_plan_execution_statuses_termination_and_counters` |
| 24 | Session history distinguishes historical from current after reverification. | `test_24_sessions_distinguish_historical_from_current_after_reverification` |
| 25 | Task 19 executor recording atomically persists completed evidence, bundle, claim, and session state. | `test_25_task19_executor_records_completed_session_bundle_claim_atomically` |
| 26 | Executor persistence failure raises and cannot return an unstored `PASS`. | `test_26_executor_storage_failure_raises_and_never_returns_unstored_pass` |
| 27 | Task 20 falsification results and exact claim-basis links persist across restart. | `test_27_task20_falsification_result_and_claim_basis_persist_exactly` |
| 28 | Evidence-linked falsification invalidation reaches its claim and session. | `test_28_falsification_evidence_dependency_invalidates_claim_and_session` |
| 29 | Cache clearing cannot hide SQLite corruption because reads always verify the database. | `test_29_cache_clear_is_not_authoritative_and_cannot_hide_database_corruption` |
| 30 | A corrupted claim report basis cannot be observed as `PASS`. | `test_30_corrupted_claim_report_basis_cannot_be_observed_as_pass` |
| 31 | The schema and public records remain generic and contain no product or TTL fields. | `test_31_schema_and_records_are_generic_without_product_or_ttl_fields` |
| 32 | Reverse invalidation lookup uses `idx_object_dependencies_dependency` and does not scan serialized sessions. | `test_32_reverse_dependency_lookup_uses_index_without_serialized_session_scan` |

Additional explicit unit-of-work integration:

| Guarantee | Test |
| --- | --- |
| The executor can record through a caller-owned `SQLiteUnitOfWork`, and a later outer rollback removes the entire completed execution basis. | `test_33_executor_uses_explicit_caller_owned_unit_of_work_and_outer_rollback` |

## Separate impossible stored truth state review

The first review execution intentionally failed all five cases:

```text
5 failed in 0.48s
```

The review exposed and fixed these structural gaps, even when a test recomputed the storage-layer digest after tampering:

| Review finding | Fix | Regression test |
| --- | --- | --- |
| A slot pointer fingerprint could disagree with its selected current version. | Reads now cross-check pointer version and artifact fingerprint, enforce contiguous history, and fail closed. | `test_review_01_slot_pointer_fingerprint_must_match_current_version` |
| A rehashed `PASS` claim document could disagree with an exact `UNKNOWN` bundle report. | Claim reads now verify the exact bundle report, evidence links, and claim dependency links. | `test_review_02_rehashed_pass_claim_cannot_disagree_with_unknown_bundle` |
| A rehashed claim basis could substitute another definition fingerprint. | Claim reads now bind every version to the exact stored claim definition. | `test_review_03_rehashed_claim_basis_cannot_substitute_definition` |
| A falsification result for another claim could be used as a `PASS` basis. | Claim writes and reads now require exact claim ID and declared verifier identity. | `test_review_04_falsification_basis_must_match_exact_claim_identity` |
| A rehashed session document could disagree with exact durable claim state. | Session and claim-graph semantic fingerprints plus claim/root structural state are now revalidated on read. | `test_review_05_rehashed_session_state_cannot_disagree_with_claim_basis` |

Post-fix review result:

```text
5 passed in 0.47s
```

## Implementation summary

- `src/gvr/storage.py` defines the generic protocols, durable records, errors, and explicit completed-execution persistence hook.
- `src/gvr/sqlite_storage.py` implements the stdlib SQLite schema, migrations, transactions, immutable artifacts, slots, bundle/claim/session/falsification persistence, reverse dependencies, invalidation, read verification, and executor recording.
- `src/gvr/execution.py` accepts mutually exclusive explicit `storage` or `unit_of_work` parameters and fails closed when durable completion recording fails.
- `src/gvr/__init__.py` exports the public durable API.
- `docs/DURABLE_STORAGE.md` documents the model and operational contract. The architecture, concepts, design rules, provider, falsification, execution, session, protocol, workflow, code map, indexes, and root README link to it.

## Coverage and known limitations

The repository does not define a coverage command or coverage dependency. Behavioral coverage is supplied by 38 focused storage tests plus the 554-test full suite.

Known boundaries are intentional:

- SQLite supports many readers and one serialized writer. Independent callers should use separate `SQLiteStorage` instances; one active unit of work must not be shared across threads.
- Schema version 1 has a real migration framework but no historical upgrade beyond bootstrap yet.
- Durable storage is a Python API. No raw SQL or generic database JSON protocol was added.
- Content fingerprints are not signatures, authentication, or remote attestation.
- `clear_cache()` is intentionally a no-op because no cache is authoritative.
- Time-based expiry is intentionally absent from truth semantics.
