# Task 24 exact durable record replay hardening TDD evidence

## Authorized source and boundary

Task 24 starts from exact verified base `b1a4989f53843cde1c4edfbe0f5ded4e8cdbca14` on `feature/gvr-exact-record-replay-hardening-v1`.

The work is limited to exact durable record selection and threading across bundle, falsification, claim, session, and execution recording, plus removal of the lexical semantic-field blacklist. Explicit `AuditObservation` remains the only generic nonsemantic operational channel. Durable schema v3 should be preserved if the existing exact-record tables can express the repair.

The untracked `probe_false_freshness.py` is preserved. The task does not edit `graphify-out`, push, deploy, or write a Drive report.

## Required outcomes

1. If exact durable basis A is recorded, independent exact basis B is recorded, the database is reopened, and A is replayed, the current claim and session must thread A's exact bundle record rather than whichever same-domain record was most recently current.
2. The same guarantee holds for B to A to reopen to replay B and for acquisition-order permutations.
3. Exact falsification records returned by the current execution must thread through the claim and session. A competing current record with the same falsification domain fingerprint must not be substituted.
4. A returned exact record that does not match the acquisition dependencies computed for the current execution must fail closed inside the outer transaction.
5. Persisted bundle, falsification, or session exact-record corruption must fail closed without partial claims, sessions, observations, invalidations, or pointer movement.
6. Valid semantic fields named `run_id`, `trace_id`, `execution_id`, and `request_count` must be accepted and fingerprinted. Only data placed in explicit `AuditObservation` is excluded from semantic fingerprints.
7. Task 22 semantic slot identity, Task 23 same-raw-ID independence, exact dependency links, audit transport, transactional migration, and rollback guarantees remain intact.

## Six-scenario specification

| # | Scenario | Test |
|---:|---|---|
| 1 | Record A, record independent same-domain B, reopen, replay A in reverse acquisition order, and prove claim/session use A's exact bundle record and dependencies. | `test_task24_01_reopen_replay_substitutes_the_exact_a_record_after_b` |
| 2 | Exercise A/B and B/A directions with both acquisition orders and prove exact record and execution invariance. | `test_task24_02_reverse_and_request_order_permutations_are_exactly_invariant` |
| 3 | Add a competing current exact record for A's falsification domain, replay A, and prove A's returned falsification record threads through claim and session together with A's bundle record. | `test_task24_03_exact_falsification_record_threads_through_claim_and_session` |
| 4 | Accept and fingerprint semantic identifier-like field names while proving explicit audit-only changes leave the semantic fingerprint unchanged. | `test_task24_04_semantic_identifier_names_are_valid_and_audit_is_explicitly_nonsemantic` |
| 5 | Inject a wrong exact bundle record return after the correct write and prove the execution fails closed with atomic rollback. | `test_task24_05_exact_record_mismatch_fails_closed_and_rolls_back` |
| 6 | Corrupt exact bundle, falsification, and session links one at a time and prove replay fails closed with unchanged durable counts. | `test_task24_06_exact_record_corruption_fails_closed_and_rolls_back` |

## Exact-base baseline

Before adding Task 24 tests, the exact base full suite completed successfully:

```text
python -m pytest -q -p no:cacheprovider --tb=short
572 passed
```

## Exact-base RED evidence

The six-scenario Task 24 specification was added and run before any production source changed.

Command:

```text
python -m pytest -q -p no:cacheprovider --tb=short \
  tests/test_durable_storage_task_24.py
```

Observed exact-base result:

```text
5 failed, 1 passed
```

The failures reached the intended missing boundaries:

- scenarios 1 and 2 replayed A but selected B's most recently current same-domain bundle record;
- scenario 3 likewise substituted B's bundle basis before exact falsification/session threading could be trusted;
- scenario 4 raised `EvidenceProviderError` solely because the valid semantic key was named `run_id`;
- scenario 5 accepted an injected wrong exact record return and committed instead of failing closed.

Scenario 6 passed on the base because existing canonical record/link verification already rejects directly persisted corruption and the outer execution transaction rolls back. Task 24 retains that guarantee while making exact in-memory record selection equally strict.

## GREEN evidence

Pending implementation.

## Post-GREEN adversarial review

Pending independent post-GREEN review.
