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

Three later adversarial review cycles added focused RED coverage for contract gaps found after the initial implementation:

- `4476d8ca726f6559ab207d5889f3ed3b8cca30e0` (`test: expose verification planner contract gaps`) produced `4 failed, 39 passed`. It covered invalid requests hiding missing required evidence, subclass substitution of exact registries, and omitted nested protocol fingerprints. `d58517fb9406d327dcb1b96162bab33d64d81c23` (`fix: harden verification planner contracts`) made those cases GREEN.
- `51e5b00c20d23b98070f3a778a1ebd173f9a4c3d` (`test: harden planner issue metadata contract`) produced `6 failed, 43 passed`. It covered verdict and evidence-adequacy aliases in planner issue details. `fe9cebfd8d26472a2f2d0e16a2be433e086bc143` (`fix: reject planner result metadata aliases`) made those cases GREEN.
- `346bb0f` (`test: expose compound planner metadata aliases`) produced `4 failed, 51 passed`. It covered compound status/sufficiency keys and direct `PASS`/`UNKNOWN` keys. `2433425` (`fix: reject compound planner metadata aliases`) made those cases GREEN through normalized semantic-token rejection.

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

## Final remediation validation

```bash
python -m pytest -q tests/test_verification_planner.py
# 55 passed

python -m pytest
# 436 passed

python -m compileall -q src/gvr tests/test_verification_planner.py
git diff --check f107742575ef86ca9816e79cde0dd5965226b10b..HEAD
```

Additional probes exercised 16 simultaneous graph, binding, request, verifier-registry, and provider-registry reorder combinations; exact-type substitution attempts; protocol fingerprint omissions, mismatches, and unknown fields; and mocked provider, verifier, Graphify, network, and file-system execution entry points. All probes passed, and no execution entry point was called.

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
| 13 | Invalid requests cannot hide missing required evidence, exact registries reject subclass substitution, and nested protocol fingerprints are mandatory | tests 34–36 | adversarial contract | PASS |
| 14 | Planner issues reject verdict and evidence-adequacy metadata aliases | test 37 | adversarial contract | PASS |

## Coverage and known gaps

The focused file contains 37 named adversarial scenarios and 55 executed pytest cases. Budget overflow is parameterized across seven independent limits, nested fingerprint omission across two locations, and metadata aliases across twelve direct, compound, nested, case, and hyphenation forms.

No provider, verifier, Graphify, network, or file-system execution path is part of the planner. Runtime acquisition and verification remain intentionally outside this task.
