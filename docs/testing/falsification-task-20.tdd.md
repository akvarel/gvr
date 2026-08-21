# Task 20 falsification layer TDD evidence

## Source and boundaries

The user supplied the authorized Task 20 requirements directly. The implementation starts from Task 19 final commit `5e810cfb7808299d7887ca2a798bc7cde316f4a8` on `feature/gvr-counterexample-falsification-v1`.

The task explicitly excludes Graphify, BugZero, ICE, protected branches, deployment, pushing, and Drive reporting. `probe_false_freshness.py` is preserved outside the committed change set.

## RED evidence

Commit: `b6314b520d86a6a309013bf46887bbf1eef073e8` (`test: define Task 20 falsification contract`)

Command reproduced from the committed RED tree:

```bash
PYTHONPATH=src pytest -q tests/test_falsification.py
```

Observed result before production changes:

```text
ImportError: cannot import name 'COUNTEREXAMPLE_SEARCH_STRATEGY_ID' from 'gvr'
1 error during collection
exit status 2
```

This is the intended compile-time RED signal. The 26 requested falsification APIs and behaviors did not yet exist.

## GREEN evidence

Commit: `15d4db39e6199098c6150b43b90d87ae2e08d45a` (`feat: add exact falsification execution layer`)

The exact archived GREEN commit was revalidated independently:

```text
tests/test_falsification.py: 26 passed
full suite: 510 passed
compileall: passed
```

The archived count is authoritative for the committed GREEN tree. It corrects the earlier `528 full-suite tests` figure embedded in the GREEN commit message.

The GREEN implementation adds exact immutable descriptors and registries, explicit planning bindings, canonical `RUN_FALSIFICATION` steps, exact executor orchestration, verifier gates, six generic built-in strategies, the Latvian weekday regression corpus, schema-v1 protocol support, and public documentation.

## Requested adversarial specification

| # | Guarantee | Test |
| --- | --- | --- |
| 1 | Descriptors are strict, deeply immutable, and canonical. | `test_01_descriptor_is_strict_deeply_immutable_and_canonical` |
| 2 | The built-in registry publishes exactly six kinds, IDs, and version `1`. | `test_02_builtin_registry_publishes_exactly_six_kinds_ids_and_version_one` |
| 3 | Capability registries require exact versions and semantic fingerprints. | `test_03_capability_registry_requires_exact_version_and_fingerprints_semantics` |
| 4 | Runtime registries fingerprint exact keys and reject side-effecting runtimes. | `test_04_runtime_registry_fingerprints_exact_keys_and_rejects_side_effecting_runtime` |
| 5 | Atomic bindings without falsification preserve the Task 19 shape. | `test_05_atomic_binding_without_falsification_preserves_task19_shape` |
| 6 | Planning never auto-selects and required missing bindings fail closed. | `test_06_planner_never_auto_selects_and_required_binding_fails_closed` |
| 7 | `RUN_FALSIFICATION` is canonical and is a verifier dependency. | `test_07_run_falsification_step_is_canonical_and_required_by_verifier_step` |
| 8 | Strategy ID or version substitution is rejected. | `test_08_planner_rejects_strategy_id_or_version_substitution` |
| 9 | Capability fingerprint substitution is rejected. | `test_09_planner_rejects_falsification_capability_fingerprint_substitution` |
| 10 | Planning and execution budgets count falsification work exactly. | `test_10_planning_and_execution_budgets_count_falsification_work_exactly` |
| 11 | Finite Unicode scans distinguish `e` and `ē` under NFC and NFD. | `test_11_finite_scan_distinguishes_e_and_long_e_with_nfc_nfd` |
| 12 | Existential, reversal, and duplicate semantics are explicit. | `test_12_existential_reverse_and_duplicate_semantics_are_explicit` |
| 13 | Independent recomputation uses a separate path and catches the wrong candidate. | `test_13_independent_recompute_uses_separate_path_and_catches_wrong_candidate` |
| 14 | Metamorphic identity and provenance are fully fingerprinted. | `test_14_metamorphic_identity_and_provenance_are_fully_fingerprinted` |
| 15 | The executor runs the exact strategy once after dependencies and scopes its output. | `test_15_executor_runs_exact_strategy_after_dependencies_once_and_scopes_output` |
| 16 | Missing or incomplete required output can never enable `PASS`. | `test_16_missing_or_incomplete_required_output_can_never_be_pass` |
| 17 | A verifier cannot ignore a complete counterexample and return `PASS`. | `test_17_verifier_pass_cannot_ignore_a_complete_counterexample` |
| 18 | Only the verifier decides truth. The executor does not auto-pass or auto-fail. | `test_18_only_verifier_decides_truth_and_executor_does_not_auto_fail_or_pass` |
| 19 | Malformed runtime output fails closed. | `test_19_malformed_runtime_output_fails_closed_and_never_becomes_pass` |
| 20 | Runtime exceptions are deterministic, secret-safe, and not retried. | `test_20_strategy_exception_is_stable_secret_safe_and_not_retried` |
| 21 | Runtime identity and side-effect declarations are rechecked before invocation. | `test_21_runtime_identity_and_side_effect_contract_are_rechecked_before_call` |
| 22 | Strategy version and runtime-registry fingerprint substitution fail. | `test_22_strategy_version_and_runtime_registry_fingerprint_substitution_fail` |
| 23 | Contradictory outcomes and probes fail closed. | `test_23_contradictory_outcome_and_probe_is_rejected_fail_closed` |
| 24 | Contracts contain no confidence, LLM, fallback, retry, or product policy. | `test_24_falsification_contract_contains_no_confidence_llm_fallback_retry_or_product_policy` |
| 25 | Legacy schema-v1 planner, executor, and protocol behavior remains compatible. | `test_25_schema_v1_legacy_planner_executor_and_protocol_remain_backward_compatible` |
| 26 | Schema-v1 protocol round-trips exact falsification planning and execution. | `test_26_schema_v1_protocol_round_trips_exact_planner_and_executor_falsification` |

## Separate post-GREEN adversarial review

Review target: `15d4db39e6199098c6150b43b90d87ae2e08d45a`.

Six additional tests were applied to the exact GREEN archive. All six failed before hardening:

```text
test_27_required_complete_result_without_any_probe_cannot_enable_pass
test_28_representation_check_requires_an_explicit_expected_code_point_sequence
test_29_metamorphic_identity_fields_must_be_stable_identifiers
test_30_verifier_input_rejects_falsification_declared_for_another_verifier
test_31_execution_result_rejects_falsification_under_a_forged_step_id
test_32_execution_result_rejects_a_substituted_falsification_fingerprint
6 failed
```

The review found three concrete false-`PASS` paths:

1. A structurally complete required result could contain no probe and still satisfy the required-output gate.
2. A representation check without an explicit expected code-point sequence was treated as vacuously clean.
3. A metamorphic record could use a malformed identity version while still producing a clean result.

It also found three artifact-integrity gaps: foreign-verifier falsification input, forged result-to-step mapping, and substituted step/result fingerprints were not rejected by the public immutable records.

Hardening commit: `5aefab8486a57c409d1a90deed8e4bc4ea17858c` (`fix: harden falsification fail-closed artifacts`).

The remediation requires nonempty outcome-consistent probes, explicit representation expectations, stable metamorphic identity fields, exact verifier and claim scoping, accepted strategy kinds, unique binding IDs, and exact completed-step/result fingerprint correspondence.

## Final validation

```text
tests/test_falsification.py: 32 passed
full suite: 516 passed
python -m compileall -q src tests: passed
git diff --check: passed
wheel: gvr-0.2.0-py3-none-any.whl
fresh installed API smoke: passed
fresh installed planner smoke: passed
fresh installed executor counterexample gate: passed
fresh installed schema-v1 protocol compile/execute/describe smoke: passed
fresh installed gvr CLI describe smoke: passed
```

The installed executor smoke deliberately used a verifier that returned `PASS` for a wrong exact-membership candidate. The counterexample strategy exposed the mismatch and the executor published root `UNKNOWN` with `VERIFIER_IGNORED_FALSIFICATION_COUNTEREXAMPLE`.

## Architecture and license reference review

Only public Akon Labs and GitNexus material was used as architecture and license reference. The design takeaway was deterministic precomputed relationships and exact graph validation. GitNexus is PolyForm Noncommercial 1.0.0 licensed. No external source code was copied, adapted, or incorporated.

## Scope and known limits

- Built-in Task 20 strategy runtimes currently operate on the strict finite text-sequence input contract.
- Falsification challenges a claim but never decides truth. Only the declared verifier emits `PASS`, `FAIL`, or `UNKNOWN`.
- There is no strategy discovery, ranking, fallback, retry, confidence score, LLM authority, product policy, deployment, external service mutation, push, or Drive report.
