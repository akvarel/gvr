# Task 26 durable storage acceptance matrix TDD evidence

## Boundary

Drive Task 26 was executed on `feature/gvr-task25-acceptance-matrix-v1` from the verified exact remote base `4abeee56bccf8441a769bb59cacd6fd4f96ed257`. The remote base was fetched and matched exactly before branching. The preserved user file `probe_false_freshness.py` remains untracked.

The final implementation changes tests and evidence only. A speculative production change was independently checked by running the compliant falsification scenario against untouched Task 25 production, where it passed, and was reverted.

## Acceptance matrix

| Test | Matrix and durable invariant |
| --- | --- |
| `test_task26_01_real_executor_allows_three_distinct_same_domain_exact_records` | A/B/C execute together with one language-level bundle domain and three semantic source/request slots. Three exact bundle records and three claim links persist and reopen as current. |
| `test_task26_02_four_claims_deduplicate_ab_exact_and_keep_cd_distinct` | A/B genuinely share one exact semantic slot while C and D are distinct. Four claim associations produce exactly three unique exact session bundle links without conflict or loss. |
| `test_task26_03_order_reopen_and_replay_are_invariant` | Claim/root construction order is reversed, storage is reopened, and execution is replayed. Execution/session identity, claim associations, exact link set, and table counts remain invariant. |
| `test_task26_04_advancing_a_then_c_preserves_b_replay_isolation` | A advances, then C advances, then B replays unchanged. A/C old exact bases and the dependent old session become stale, B remains current, and B replay creates no new claim version. |
| `test_task26_05_immutable_evidence_without_slot_identities_supports_three_claims` | A/B/C emit immutable evidence without `evidence_slot_identities`. No evidence-slot rows or raw `Evidence.id` slot inference appear. Independent immutable provenance yields three exact bundle records. Reopen/reordered replay is idempotent and historical immutable bases remain current. |
| `test_task26_06_two_claim_same_domain_multiplicity_with_required_falsification` | One real executor request contains A/B, equal bundle domain fingerprints, distinct exact bundle records, and required falsification for both. Each claim references its own exact bundle and falsification records; the session derives both exact collections; reopen/reordered replay preserves them; advancing A does not substitute B's bundle or falsification record. |
| `test_task26_07_missing_exact_link_fails_closed_and_rolls_back` | Removing one exact session bundle link makes read fail closed. |
| `test_task26_08_substituted_exact_link_fails_closed_and_put_session_rolls_back` | Supplying a current same-domain exact record belonging to another association is rejected and the attempted write leaves table counts unchanged. |
| `test_task26_09_extra_exact_link_fails_closed_and_rolls_back` | Adding an unreferenced exact link makes read fail closed. |
| `test_task26_10_corrupt_exact_link_fails_closed_and_rolls_back` | Corrupting an exact session link to another same-domain record makes read fail closed. |

## Tests-first result

The first draft test harness was committed as `ed48d0003b2beb3760f6c81de2df7a7998b8451a`; its nine failures were harness expectation/helper defects, not production defects. The corrected core matrix was committed as `98838b5614afb0ef0015583540e4dd7c6d9b6763`.

The final compliant one-execution falsification matrix and strengthened immutable matrix were added in `9cec35246f923d0adb5138807186938925d254fd`. The compliant falsification test was then run with `src/gvr/sqlite_storage.py` restored to untouched Task 25 production and passed (`1 passed in 1.06s`). Therefore the speculative production edit in that commit was not justified and was reverted by `e02913a`. No production fix is part of the final diff.

## Structural audit

The larger matrix confirms that exact bundle multiplicity belongs at exact-record scope:

- claim versions store exact bundle and falsification references in `SQLiteUnitOfWork.record_claim` and reconstruct/validate them in `_read_claim_version` (`src/gvr/sqlite_storage.py`);
- `put_session` derives the canonical exact bundle/falsification collections from stored claim versions and rejects caller substitution;
- `_read_session_record` independently reconstructs those collections from claims and compares them with persisted session links;
- `_session_record_current`, `_claim_current`, and exact dependency traversal determine currentness without relying on SQLite row order;
- `record_execution` persists claims first, derives the session exact collections from those stored claims, and retains transaction rollback and replay idempotency.

The existing session bundle collection is correctly keyed/deduplicated by exact `record_fingerprint`. Claim-level falsification domain uniqueness remains contract-safe. `FalsificationProvenance.semantic_definition` includes `input_fingerprint` (`src/gvr/falsification.py:610-627`), runtime result construction writes `strategy_input.fingerprint` (`1590-1648`), and `validate_falsification_result` requires the rebuilt provenance `input_fingerprint` to equal the exact `FalsificationExecutionInput.fingerprint` (`1197-1253`). That input fingerprint binds claim/acquisition/evidence/dependency semantics. Consequently, two valid executor-produced falsification records in one claim version cannot share a semantic result domain while representing different exact semantic inputs; equal semantic input is the same valid basis rather than missing multiplicity.

No additional unsafe domain-keyed collection was found after exercising bundle records, claim links, falsification records/links, session links, session document construction/read reconstruction, currentness traversal, and replay.

## Validation

```text
python -m pytest -o addopts='' -q tests/test_durable_storage_task_26.py
10 passed in 4.80s

python -m pytest -o addopts='' -q tests/test_durable_storage_slot_identity.py tests/test_durable_storage_task_23.py tests/test_durable_storage_task_24.py tests/test_durable_storage_task_25.py tests/test_durable_storage_task_26.py
46 passed in 21.86s

python -m pytest -o addopts='' -q
600 passed in 27.68s

python -m compileall -q src tests
PASS

git diff --check
PASS

python -m pip wheel . --no-deps
Successfully built gvr-0.2.0-py3-none-any.whl
sha256 9a6e76543bf7e766a6a63736e13a8047bc55b12024a9b80c77ac26bddedda6f8
```

Installed-wheel validation ran from `/home/sergey/.jcode/scratch/gvr-task26-wheel/run`, outside the repository, with `PYTHONPATH` removed. `gvr` resolved from the temporary virtual environment's `site-packages`. The complete Task 26 suite, including 3/4-claim matrices, immutable evidence, falsification, reopen/replay, and all corruption cases, passed:

```text
10 passed in 4.90s
```

Remote CI evidence is recorded separately after the feature branch push. No local pytest result is presented as CI evidence.
