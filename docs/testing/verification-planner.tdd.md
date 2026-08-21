# Deterministic verification planner TDD evidence

## Source

The user supplied the authorized Task 18 requirements directly. No separate plan file was used.

## User journeys

1. As a caller, I can bind every atomic claim to exact verifier and evidence provider contracts and receive a deterministic immutable plan.
2. As a caller, I receive stable fail-closed issues when an exact capability, class, evidence kind, required request, graph dependency, or budget is invalid.
3. As a protocol client, I can submit the same exact schema-v1 planning request and receive the same canonical plan, while malformed or fingerprint-mismatched input is rejected.
4. As an integrator, I can install the wheel and use the same public planning API and protocol without invoking providers or verifiers.

## RED evidence

Commit: `e5e9e89` (`test: specify deterministic verification planner`)

Command:

```bash
python -m pytest tests/test_verification_planner.py
```

Observed result before production changes:

```text
ImportError: cannot import name 'AtomicClaimBinding' from 'gvr'
1 error during collection
```

This was the intended compile-time RED signal because the required public planner API did not exist.

## GREEN evidence

Commit: `041c469ba6031a001787102e145d56b037c20002` (`feat: implement deterministic verification planner`)

Focused command:

```bash
python -m pytest tests/test_verification_planner.py
```

Observed result:

```text
39 passed
```

Full command:

```bash
python -m pytest
```

Observed final result:

```text
420 passed
```

Additional validation:

```bash
python -m compileall -q src/gvr tests/test_verification_planner.py
git diff --check 99dffe8065cfd7cb1eee5aa40608c224768cc15d..HEAD
python -m pip wheel . --no-deps --no-build-isolation
```

All commands completed successfully. The generated `gvr-0.2.0-py3-none-any.whl` was installed into a fresh isolated virtual environment. An installed-package smoke test imported the public planning API, compiled a plan through that API, compiled the same request through schema-v1 `compile_verification_plan`, and confirmed matching plan fingerprints.

## Test specification

| # | Guarantee | Test target | Type | Result |
| --- | --- | --- | --- | --- |
| 1 | Compatible exact binding produces acquisition then atomic verification steps | `test_01_compatible_atomic_flow_is_strict_immutable_and_canonical` | unit | PASS |
| 2 | Provider request kinds stay distinct from verifier claim kinds | `test_02_provider_request_kind_is_distinct_from_verifier_claim_kind` | unit | PASS |
| 3 | Unknown, mismatched, wrong-version, wrong-fingerprint, unsupported, or non-authoritative verifier contracts fail closed | tests 03–08 | adversarial unit | PASS |
| 4 | Unknown or structurally invalid provider contracts, evidence kinds, and classes fail closed | tests 09–15 | adversarial unit | PASS |
| 5 | Missing required evidence requests or kinds fail closed | tests 16–17 | adversarial unit | PASS |
| 6 | Only identical request fingerprints share acquisition, while conflicting reused request IDs are rejected | tests 18–19 | adversarial unit | PASS |
| 7 | Request, binding, graph, and registry insertion order is non-semantic | tests 20–22 | determinism | PASS |
| 8 | Provider, verifier, claim, request, and dependency identity changes alter plan identity | tests 23–27 | identity | PASS |
| 9 | `AND`, `OR`, and `NOT` preserve deterministic graph order and cycles are rejected | tests 28–29 | graph integration | PASS |
| 10 | Exact budgets pass, every configured overflow fails with stable insertion-invariant termination | tests 30–31 | boundary | PASS |
| 11 | Plan output contains no claim-result, free-text diagnostic, arbitrary metadata, or generic evidence-adequacy fields | test 32 | contract | PASS |
| 12 | Schema-v1 protocol is deterministic, strict, fingerprinted, and the API is publicly exported | test 33 | protocol integration | PASS |

## Coverage and known gaps

The focused file contains 33 named adversarial scenarios and 39 executed pytest cases because budget overflow is parameterized across seven independent limits.

No provider, verifier, Graphify, network, or file-system execution path is part of the planner. Runtime acquisition and verification remain intentionally outside this task.
