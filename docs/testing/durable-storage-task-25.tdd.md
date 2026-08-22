# Task 25 session exact-record multiplicity TDD evidence

## Authorized source and boundary

Task 25 starts from exact verified base
`822d4d31205850eac2f182d1d1d7da788f2218d6` on
`feature/gvr-session-record-multiplicity-v1`.

The repair is limited to exact session record multiplicity when multiple atomic
claims produce the same semantic `VerificationBundle` fingerprint from
different exact evidence records or semantic slots. Task 22 through Task 24
semantics, transaction atomicity, schema v3, and exact replay guarantees remain
the compatibility boundary. The untracked `probe_false_freshness.py` is
preserved. The task does not edit `graphify-out`, push, or create a Drive
report.

## RED specification

The first executable specification invokes the real
`execute_verification_plan` path against SQLite with atomic claims A and B.
Both claims intentionally produce the same semantic bundle content and domain
fingerprint. Their identical evidence content is acquired through different
authoritative semantic slots, so the durable exact bundle record fingerprints
must differ and both records must be retained by the exact session record.

The exact base currently rejects this valid session before publication because
`record_execution` deduplicates bundle records by domain fingerprint and treats
the second exact record as a substitution conflict.

RED command:

```text
python -m pytest -q -p no:cacheprovider --tb=short \
  tests/test_durable_storage_task_25.py
```

Observed exact-base result:

```text
1 failed
StorageIntegrityError: one session cannot substitute conflicting exact bundle records
VerificationExecutionError: durable storage recording failed closed
```

The failure reached the intended missing boundary at
`SQLiteUnitOfWork.record_execution`: both exact records had already been
created for claims A and B, but the session collector keyed them by the shared
bundle domain fingerprint and rejected the second record before session
publication. No production source had changed when this result was captured.

## Required adversarial coverage

The completed Task 25 suite will contain twelve scenarios covering the real
multiplicity path, order invariance, reopen and replay, idempotency, independent
A-only and B-only invalidation, same-exact-record deduplication, wrong-record
substitution, corrupt exact links, falsification exact-record uniqueness, and
execution from an isolated installed wheel with `PYTHONPATH` removed.

## GREEN implementation

The implementation preserves durable schema v3. Existing
`session_record_bundle_links` already use the exact bundle record fingerprint
as part of their primary key, so several links may share one bundle domain
without a migration.

Completed-execution recording now obtains the session bundle and falsification
collections from the exact stored claim versions. Session creation independently
rereads those claim versions, derives their exact record references, deduplicates
only equal exact record fingerprints, and sorts by exact record fingerprint.
Caller-supplied exact records must equal that derived collection. Session reads
repeat the same derivation and reject links that do not match the claim records.
The legacy semantic-domain link projection remains unique by domain and is not
used as an exact truth collection.

The exact-record audit found one unsafe domain-keyed collection: session bundle
records. It is now record-keyed. Claim-level exact falsification records remain
unique by domain intentionally. A `FalsificationResult` domain includes its
claim ID, binding, declared verifier, strategy identity, and semantic outcome,
so two same-domain records inside one claim version would be alternative bases
for one claim-specific semantic result rather than distinct results. A later
claim version may select a different exact record, and the session derives that
selection from the claim.

The RED specification was committed as
`5c77a0f216d1dd50606e904a84eda74bdbc10929` before production source
changed. The GREEN implementation was committed as
`763c1f47bccd201c55a2fb2633a8c3572e8c0499` before the adversarial
matrix was added.

## Twelve-scenario adversarial matrix

| # | Boundary | Test |
|---:|---|---|
| 1 | Real `execute_verification_plan` plus SQLite accepts two atomic claims with one bundle domain and different exact slot-backed records. | `test_task25_01_real_execution_allows_same_domain_bundle_multiplicity` |
| 2 | Reversing claim and root order preserves execution, session, and exact-record identity. | `test_task25_02_claim_reorder_preserves_exact_session_identity` |
| 3 | Reopening SQLite reconstructs both same-domain exact records and currentness. | `test_task25_03_reopen_reads_both_same_domain_exact_records` |
| 4 | Exact replay is idempotent for bundle records, claim versions, session records, links, and observations. | `test_task25_04_replay_is_idempotent_for_exact_records_and_observation` |
| 5 | Advancing only A's semantic slot invalidates A's old exact bundle and the dependent session, while B remains current. | `test_task25_05_advancing_only_a_invalidates_only_a_exact_bundle` |
| 6 | Advancing only B's semantic slot has the symmetric isolated effect. | `test_task25_06_advancing_only_b_invalidates_only_b_exact_bundle` |
| 7 | Two claims that truly share one exact record produce one canonical session exact link. | `test_task25_07_same_exact_record_is_deduplicated_by_record_fingerprint` |
| 8 | A caller-supplied current same-domain record that is not linked by the exact claims is rejected without partial session writes. | `test_task25_08_wrong_exact_bundle_substitution_rolls_back` |
| 9 | A missing exact session bundle link fails closed after reopen. | `test_task25_09_missing_exact_session_link_fails_closed` |
| 10 | A persisted same-domain exact-record substitution fails closed even though the replacement record is valid and current. | `test_task25_10_corrupt_same_domain_link_substitution_fails_closed` |
| 11 | Claim-level same-domain falsification-record multiplicity remains intentionally rejected. | `test_task25_11_falsification_same_domain_uniqueness_remains_fail_closed` |
| 12 | Omitting bundle/falsification arguments causes the session to derive the exact canonical collection from claim records. | `test_task25_12_session_derives_exact_records_when_arguments_are_omitted` |

## Final validation

Focused Task 25:

```text
python -m pytest -p no:cacheprovider --tb=short \
  tests/test_durable_storage_task_25.py
12 passed in 4.99s
```

Task 22 through Task 25 compatibility:

```text
python -m pytest -p no:cacheprovider --tb=short \
  tests/test_durable_storage_slot_identity.py \
  tests/test_durable_storage_task_23.py \
  tests/test_durable_storage_task_24.py \
  tests/test_durable_storage_task_25.py
36 passed in 18.73s
```

Full source suite and static checks:

```text
python -m pytest -p no:cacheprovider --tb=short
590 passed in 24.66s

python -m compileall -q src tests
PASS

git diff --check
PASS
```

Wheel validation used `python -m pip wheel --no-deps`. The wheel was installed
into a temporary virtual environment, the tests ran from a directory outside
the source tree, and `PYTHONPATH` was removed from both the import check and the
pytest process:

```text
gvr-0.2.0-py3-none-any.whl
sha256 5c54f85da4c858b5fc6f752214d27d310531c603bb60a84b3dd1838bd2b2c373
INSTALLED_GVR=<temporary-venv>/site-packages/gvr/__init__.py
12 passed in 4.82s
```

No remote CI result exists for this task because the authorized boundary
forbids pushing. All reported evidence is local and executable. The environment
does not provide the optional `python -m build` frontend, so the standard pip
wheel builder was used instead. No schema migration, deployment, Drive report,
or `graphify-out` change was performed.
