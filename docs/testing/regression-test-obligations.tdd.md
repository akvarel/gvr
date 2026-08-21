# Regression Test Obligation Engine TDD Evidence

## Source task

Drive Task 18 was implemented on `feature/gvr-regression-test-obligation-engine-v1` from exact base `99dffe8`. The unrelated untracked `probe_false_freshness.py` was preserved and excluded from commits.

## User journeys

- As a verifier consumer, I want behavior evidence limited to a strict vocabulary so arbitrary source data cannot manufacture test duties.
- As a test planner, I want immutable normalized facts and explicit coverage so incomplete analysis does not become a complete plan.
- As a ledger consumer, I want every obligation grounding report bundled with exact evidence so changed evidence makes old grounding stale.
- As an operator, I want finite deterministic budgets and stable gaps so large evidence inventories cannot cause unbounded obligation expansion.
- As a product integrator, I want `READY / BLOCKED / UNKNOWN` planning state without hidden authorization to merge, deploy, generate code, or execute tests.

## RED and GREEN checkpoints

| Stage | Commit | Command | Observed result |
| --- | --- | --- | --- |
| RED | `1d96167` | `python -m pytest -q -p no:cacheprovider tests/test_regression_test_obligations.py` | Collection failed because `gvr.regression_test_obligations` did not exist. The committed file contains exactly 33 adversarial tests. |
| GREEN focused | implementation commit containing this report | `python -m pytest -q -p no:cacheprovider tests/test_regression_test_obligations.py` | All 33 tests passed. |
| Adjacent | implementation commit containing this report | `python -m pytest -q -p no:cacheprovider tests/test_regression_test_obligations.py tests/test_verifier_capabilities.py` | All 66 tests passed. |
| Full | implementation commit containing this report | `python -m pytest -q -p no:cacheprovider` | All 414 collected tests passed. |
| Compile | implementation commit containing this report | `python -m compileall -q src tests` | Passed with no compilation errors. |
| Protocol smoke | implementation commit containing this report | schema-v1 `derive_regression_test_obligations` through `handle_request` | Returned deterministic `regression_obligation_plan` with `READY` and one obligation. |
| Diff | implementation commit containing this report | `git diff --check` | Passed with no whitespace errors. |

## Test specification

The 33 tests cover:

- exact 13-kind behavior evidence vocabulary;
- unsupported and truth-like evidence rejection;
- evidence normalization, semantic duplicate handling, conflict rejection, and deep immutability;
- evidence-backed `COMPLETE / PARTIAL / UNKNOWN` coverage;
- the exact nine obligation rule classes;
- strict immutable `TestObligation` validation and fingerprints;
- anti-laundering checks for evidence kind, fact class, subject, behavior, and coverage;
- exact grounding `VerificationReport` and `VerificationBundle` manifests;
- ClaimLedger stale propagation after evidence mutation;
- deterministic ordering, semantic deduplication, finite budgets, and zero-budget termination;
- stable gap taxonomy and `READY / BLOCKED / UNKNOWN` without authorization;
- plan immutability, alignment, and semantic fingerprint sensitivity;
- an honest built-in verifier capability matching runtime claim, evidence, bounds, and coverage semantics;
- strict schema-v1 derivation, forged fingerprint rejection, and unknown field rejection;
- proof that derivation does not invoke the evidence provider runtime or another external executor.

## Scope and limitations

The engine derives obligations from caller-supplied structured evidence. It does not acquire evidence, inspect source, invoke an LLM, use a browser, generate code, run tests, or authorize product actions. No provider was added. No push, Drive report, production action, or change to `probe_false_freshness.py` was performed.
