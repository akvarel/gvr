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

The RED specification was committed as `abd7a18e9f5ca0bd30285126faee636cf264b997`
before production changes.

The implementation now:

- retains each `StoredBundle` and `StoredFalsificationResult` returned while
  recording the current execution, verifies its canonical content and exact
  acquisition dependencies, and rejects substituted records before claim or
  session publication;
- passes exact bundle and falsification records into `record_claim`, which
  rereads the selected durable records by record fingerprint before recording
  the claim basis;
- passes exact claim, bundle, and falsification records into `put_session`,
  which rereads and verifies each selected record before creating or reusing
  the exact session record;
- preserves the outer execution transaction so mismatch or corruption leaves
  no partial durable writes or pointer movement; and
- removes the lexical semantic-field blacklist. Identifier-like names in
  semantic coverage maps are valid and fingerprinted, while only the explicit
  `AuditObservation` channel remains outside semantic identity.

Focused Task 24 validation:

```text
python -m pytest -q -p no:cacheprovider --tb=short \
  tests/test_durable_storage_task_24.py
6 passed
```

Task 22, 23, and 24 compatibility validation:

```text
python -m pytest -q -p no:cacheprovider --tb=short \
  tests/test_durable_storage_slot_identity.py \
  tests/test_durable_storage_task_23.py \
  tests/test_durable_storage_task_24.py
24 passed
```

Full source validation:

```text
python -m pytest -q -p no:cacheprovider --tb=short
578 passed

python -m compileall -q src tests
PASS

git diff --check
PASS
```

Wheel validation used `python -m pip wheel --no-deps` because the environment
does not expose an executable `python -m build` frontend. The resulting pure
Python wheel was installed into an isolated virtual environment, the source
tree was outside the test working directory, and `PYTHONPATH` was removed from
both the import check and test process:

```text
gvr-0.2.0-py3-none-any.whl
sha256 5e81e94d116f0b8d4bbb834263d2fcd7aa061d1c1aaf8f062d6f481b2f59af6b
INSTALLED_GVR=<isolated-venv>/site-packages/gvr/__init__.py
6 passed in 6.30s
```

Durable storage remains schema v3. Existing exact-record tables and links
express the repair, so no migration or schema-version bump was required.
Existing schema-v2 canonical claim, bundle, falsification, and session record
documents and existing wire/domain schemas are unchanged.

## Post-GREEN adversarial review

After the GREEN commit, an independent generated matrix exercised 64 fresh
databases across both A/B recording directions, both acquisition orders for
each initial execution, both replay orders, replay of either recorded basis,
and runs with and without exact falsification records. Every reopened replay
recovered the expected execution, bundle record, acquisition dependencies,
claim links, session links, and, when present, falsification record links.

A separate 14-case semantic-name matrix covered nested and scalar run, trace,
execution, request, correlation, span, and transport aliases across all generic
semantic coverage maps. Each semantic value affected semantic identity, while
changes confined to explicit `AuditObservation` changed only the audit
fingerprint. The exact adversarial output was:

```text
REPLAY_MATRIX_CASES=64
SEMANTIC_IDENTIFIER_CASES=14
REPLAY_ORDER_INVARIANCE=PASS
SEMANTIC_AUDIT_CHANNEL_SEPARATION=PASS
```

The exact falsification-threading, injected-record mismatch rollback, and all
three persisted-corruption rollback scenarios were then rerun together:

```text
3 passed
```

No adversarial finding required a post-GREEN production change.
