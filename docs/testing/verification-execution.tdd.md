# Verification plan executor TDD evidence

## Source

The user supplied the authorized Task 19 requirements directly. No separate plan file was used.

## User journeys

1. As a caller, I can execute one exact complete `VerificationPlan` against exact verifier and provider runtime registries without hidden selection or fallback.
2. As a verifier author, I receive only evidence and claim dependencies reachable from my exact plan step.
3. As an operator, I receive deterministic lifecycle, issues, counters, termination, bundles, and session state when runtime or prerequisite failures occur.
4. As a protocol or CLI integrator, I can submit schema-v1 `execute_verification_plan` and receive the same canonical execution result, while malformed identities are rejected.
5. As an auditor, I can replay the same semantics and obtain the same fingerprints without clocks, random values, correlation IDs, or raw exception text affecting identity.

## RED evidence

Commit: `e5bcf685b844254d53a07da7dce2e9b2b53a05c4` (`test: specify verification plan executor`)

Command:

```bash
python -m pytest -o addopts='' -q tests/test_verification_execution.py
```

Observed result before production changes:

```text
ImportError: cannot import name 'VerificationExecutionError' from 'gvr'
1 error during collection
```

This was the intended compile-time RED signal because the required public executor API did not exist.

## GREEN evidence

The GREEN checkpoint is the implementation commit containing this evidence file.

Focused command:

```bash
python -m pytest -o addopts='' -q tests/test_verification_execution.py
```

Observed result:

```text
32 passed
```

Focused integration command:

```bash
python -m pytest -o addopts='' -q \
  tests/test_verification_execution.py \
  tests/test_verification_planner.py \
  tests/test_evidence_providers.py \
  tests/test_evidence_provider_hardening.py \
  tests/test_evidence_provider_task_17b.py \
  tests/test_evidence_provider_task_17c.py \
  tests/test_verification_session.py \
  tests/test_verification_bundle.py \
  tests/test_protocol.py
```

Observed result:

```text
333 passed
```

Full command before the post-GREEN review:

```bash
python -m pytest
```

Observed result:

```text
479 passed
```

Additional GREEN validation:

```text
python -m compileall -q src/gvr tests
git diff --check
documentation links: ok
gvr-0.2.0-py3-none-any.whl
SHA-256 925dd57761329f227c2f84dcc9f4003a14f0f97e5e785c00500854b19246499a
```

The wheel was installed without dependencies into a fresh virtual environment outside the repository with `PYTHONPATH` removed. The installed Python API executed one exact provider step and one exact verifier step to `PASS`; the same request executed through injected schema-v1 protocol registries produced the same execution-result fingerprint. The installed `gvr` console script then executed the built-in no-provider data-flow plan and returned a valid `verification_execution_result` with root `UNKNOWN` and execution termination `COMPLETE`.

## Adversarial specification

| # | Guarantee | Test |
| --- | --- | --- |
| 1 | Request/result contracts are immutable, exact, and publicly exported. | `test_01_request_and_result_are_strict_immutable_exact_and_public` |
| 2 | Plan or graph identity substitution fails before execution. | `test_02_plan_and_claim_graph_identity_substitutions_fail_before_execution` |
| 3 | Capability or runtime registry substitution fails before execution. | `test_03_capability_and_runtime_registry_substitutions_fail_before_execution` |
| 4 | Evidence request keys require exact request ID and fingerprint. | `test_04_exact_evidence_request_keys_ids_and_fingerprints_cannot_be_substituted` |
| 5 | Plan step DAG, dependency, ID, and version fields are revalidated. | `test_05_plan_steps_dag_dependencies_and_exact_versions_are_revalidated` |
| 6 | Mutable provider runtime identity is rechecked before invocation. | `test_06_mutated_provider_runtime_identity_is_rechecked_immediately_before_call` |
| 7 | Mutable verifier runtime identity is rechecked before invocation. | `test_07_mutated_verifier_runtime_identity_is_rechecked_immediately_before_call` |
| 8 | A malformed provider result fails closed and never reaches the verifier. | `test_08_malformed_provider_result_fails_closed_and_never_invokes_verifier` |
| 9 | Provider exception text and representation do not enter semantic output. | `test_09_provider_exception_is_stable_secret_safe_and_fail_closed` |
| 10 | Verifier exceptions materialize deterministic `UNKNOWN` bundles. | `test_10_verifier_exception_materializes_unknown_bundle_without_exception_text` |
| 11 | Invalid acquisition prerequisites cannot be upgraded to `PASS`. | `test_11_invalid_acquisition_prerequisite_can_never_be_upgraded_to_pass` |
| 12 | Verifiers receive only directly reachable evidence. | `test_12_verifier_receives_only_directly_reachable_evidence` |
| 13 | Verifiers receive only exact claim dependencies. | `test_13_verifier_receives_only_exact_claim_dependencies` |
| 14 | One exact shared request is acquired once. | `test_14_one_exact_request_shared_across_claims_is_acquired_once` |
| 15 | Identical semantics under two request IDs execute twice. | `test_15_same_semantics_under_two_request_ids_execute_twice` |
| 16 | `AND` uses exact tri-state semantics. | `test_16_and_composition_uses_exact_tri_state` |
| 17 | `OR` uses exact tri-state semantics. | `test_17_or_composition_uses_exact_tri_state` |
| 18 | `NOT` uses exact tri-state semantics. | `test_18_not_composition_uses_exact_tri_state` |
| 19 | Existing reports, bundles, and sessions preserve PASS/FAIL/UNKNOWN. | `test_19_reports_bundles_and_session_preserve_exact_pass_fail_unknown` |
| 20 | Replay is deterministic and correlation is nonsemantic. | `test_20_replay_is_deterministic_and_correlation_is_nonsemantic` |
| 21 | Changed evidence identity changes result, bundle, and session identity. | `test_21_changed_evidence_identity_changes_result_bundle_and_session_identity` |
| 22 | Deterministic limits produce explicit lifecycle, counters, and termination. | `test_22_deterministic_limits_emit_lifecycle_counters_and_termination` |
| 23 | Conflicting reachable evidence IDs block verifier invocation. | `test_23_conflicting_reachable_evidence_ids_fail_closed_before_verifier` |
| 24 | Malformed or unreachable verifier reports fail closed. | `test_24_malformed_or_unreachable_verifier_report_fails_closed` |
| 25 | Execution contracts contain no product policy, ranking, fallback, or LLM fields. | `test_25_execution_contract_has_no_product_policy_fallback_ranking_or_llm_fields` |
| 26 | Schema-v1 API/protocol/CLI works, strict errors are dedicated, and existing operations remain compatible. | `test_26_schema_v1_protocol_cli_strict_errors_and_backward_compatibility` |

Parameterized tri-state tests expand the 26 named guarantees to 32 focused pytest cases.

## Architecture and license reference review

Only material public findings were recorded in [Verification execution](../VERIFICATION_EXECUTION.md): deterministic precomputed structure supports validating the complete DAG before runtime work, and GitNexus's PolyForm Noncommercial license precludes copying code into this MIT project. No external code was copied or adapted.

## Scope and known limits

- The executor runs only caller-supplied exact complete plans. It has no discovery, ranking, fallback, broadening, product policy, or LLM.
- The standalone CLI can bind only runtimes shipped by GVR. Custom executable Python objects are supplied through the Python API or protocol runtime-injection keywords.
- Schema v1 ships a built-in data-flow verifier adapter and no built-in evidence providers.
- Production deployment, external service changes, Drive reporting, and branch push were outside the task and were not performed.
