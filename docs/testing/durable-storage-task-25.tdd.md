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
