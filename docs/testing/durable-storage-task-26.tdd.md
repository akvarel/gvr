# Task 26 durable storage acceptance matrix TDD evidence

## Boundary

Drive Task 26 was executed tests-first on branch `feature/gvr-task25-acceptance-matrix-v1` from base `4abeee56bccf8441a769bb59cacd6fd4f96ed257`.

Production code was not modified. The new Task 26 acceptance file was first run against untouched production.

## Acceptance matrices

| Test | Matrix | Expected durable-storage behavior |
| --- | --- | --- |
| `test_task26_01_real_executor_allows_three_distinct_same_domain_exact_records` | Claims A/B/C, same bundle fingerprint, distinct repository domains. | The real executor persists three claim records and three distinct exact bundle records. The session stores the sorted exact record set and preserves bundle fingerprint multiplicity. |
| `test_task26_02_four_claims_deduplicate_ab_exact_and_keep_cd_distinct` | Claims A/B/C/D, A and B share the exact repository domain, C and D are distinct. | A/B deduplicate to one exact bundle record, C and D keep separate exact records, and the session records exactly three exact links. |
| `test_task26_03_order_reopen_and_replay_are_invariant` | First run A/B/C, then C/B/A, then reopen storage and replay A/B/C. | Execution/session fingerprints and exact session record links are invariant to order, reopen, and replay. Replay does not add durable rows. |
| `test_task26_04_advancing_a_then_c_preserves_b_replay_isolation` | Run A/B/C, advance A to revision 2, advance C to revision 2, replay B only. | A and C original exact bundle records become non-current. B remains current and replaying B does not create a new B claim version. |
| `test_task26_05_immutable_evidence_without_slot_identities_supports_three_claims` | Claims A/B/C produce immutable evidence without `evidence_slot_identities`. | The executor persists three claims with no dependency slots and exact session links for all three record identities. |
| `test_task26_06_two_claim_same_domain_multiplicity_with_required_falsification` | Two Task 24 style executions with required falsification over distinct same-domain evidence, then replay the first. | Bundle and falsification record multiplicity is preserved, and replay reuses the first exact bundle and falsification record identities. |
| `test_task26_07_missing_exact_link_fails_closed_and_rolls_back` | Delete one session exact bundle link. | Reading the corrupted exact session fails closed with `StorageIntegrityError`. |
| `test_task26_08_substituted_exact_link_fails_closed_and_put_session_rolls_back` | Supply `put_session` with one substituted exact bundle record. | `put_session` rejects the substituted exact bundle set and table counts remain unchanged. |
| `test_task26_09_extra_exact_link_fails_closed_and_rolls_back` | Insert an extra exact bundle link into a session record. | Reading the corrupted exact session fails closed with `StorageIntegrityError`. |
| `test_task26_10_corrupt_exact_link_fails_closed_and_rolls_back` | Replace one session exact bundle link with another record for the same bundle fingerprint. | Reading the corrupted exact session fails closed with `StorageIntegrityError`, with table counts unchanged by the read failure. |

## TDD run log

1. Initial RED run against untouched production after adding `tests/test_durable_storage_task_26.py`:

   ```text
   python -m pytest tests/test_durable_storage_task_26.py
   F.FFFFFFFF [100%]
   9 failed, 1 passed in 4.15s
   ```

   The initial failures were in the new test harness expectations and table-count helper, not production code. Per boundary, the failing test file was committed first as `ed48d00`.

2. Corrected the Task 26 tests to match existing exact-record storage semantics while retaining the mandatory matrices:

   ```text
   python -m pytest tests/test_durable_storage_task_26.py
   .......... [100%]
   10 passed in 5.07s
   ```

## Result

Task 26 is GREEN with tests only. No generic production fix was required because the corrected mandatory real-executor scenarios pass on existing production code.
