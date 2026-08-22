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
