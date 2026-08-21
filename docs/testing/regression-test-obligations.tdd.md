# Regression Test Obligation Engine TDD Evidence

## Source and remediation

Task 18 was originally implemented on `feature/gvr-regression-test-obligation-engine-v1` from base `99dffe8`. Commit `d9c2009` was then found materially off-contract. The comprehensive remediation preserves the unrelated untracked `probe_false_freshness.py` and excludes it from commits.

## RED and GREEN checkpoints

| Stage | Commit | Command | Observed result |
| --- | --- | --- | --- |
| Remediation RED | `6354bfd` | `python -m pytest -q -p no:cacheprovider tests/test_regression_test_obligations.py` | 35 adversarial cases failed against the old generic vocabulary and single-fact rules. |
| Remediation GREEN focused | implementation commit containing this report | `python -m pytest -o addopts='' -q -p no:cacheprovider tests/test_regression_test_obligations.py` | 39 passed. |
| Adjacent | implementation commit containing this report | `python -m pytest -o addopts='' -q -p no:cacheprovider tests/test_regression_test_obligations.py tests/test_verifier_capabilities.py` | 72 passed. |
| Full | implementation commit containing this report | `python -m pytest -o addopts='' -q -p no:cacheprovider` | 420 passed. |
| Compile | implementation commit containing this report | `python -m compileall -q src tests` | Passed. |
| Protocol smoke | implementation commit containing this report | schema-v1 `derive_regression_test_obligations` through `safe_handle_request` | Deterministic `READY` plan with all nine obligation kinds. |
| Diff | implementation commit containing this report | `git diff --check` | Passed. |

## Contract covered

The remediated tests cover:

- exactly 13 public evidence kinds from `gvr.test.surface` through `gvr.test.execution_safety`;
- exactly nine obligation kinds: `HAPPY_PATH`, `REQUIRED_FIELD`, `INVALID_FORMAT`, `BOUNDARY_VALUE`, `STATE_TRANSITION`, `ROLE_PERMISSION`, `PERSISTENCE_READ_BACK`, `ERROR_RECOVERY`, and `DEPENDENCY`;
- rejection of old generic and truth-like evidence;
- deterministic normalization, immutability, fingerprints, and conflicting duplicate IDs;
- exact payload `surface_id`, `action_id`, `field_id`, `constraint_id`, `role_id`, and `outcome_id` linkage;
- matching subject/action/surface semantics across every required fact;
- route, button, field, or requirement evidence alone producing no obligation;
- exact linked facts deriving all nine obligations;
- positive local facts with partial coverage deriving a partial, non-ready plan;
- complete empty local coverage proving absence only in the matching scope;
- wrong-scope complete empty coverage remaining unknown rather than proving absence;
- bounded partition records without per-value obligation explosion;
- strict required-field, format, boundary, role/authentication, persistence read-back, recovery, dependency, and state-transition rules;
- execution-safety, contradiction, unsupported-interaction, and required stable gap behavior;
- exact grounding bundles and ClaimLedger stale propagation;
- deterministic finite budgets and `BUDGET_EXHAUSTED` termination;
- honest verifier capability and schema-v1 protocol round trips;
- no evidence-provider or external executor invocation.

## Scope and limitations

The engine derives obligations only from supplied structured evidence. It does not acquire facts, inspect source, invoke an LLM, browse, generate code, execute tests, or authorize product actions. No provider, production action, push, or change to `probe_false_freshness.py` is part of this remediation.
