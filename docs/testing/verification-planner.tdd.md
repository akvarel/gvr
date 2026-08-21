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

The final HEAD was also built as a wheel, installed without dependencies into a fresh isolated virtual environment, and exercised from outside the repository with `PYTHONPATH` cleared. The installed package passed the complete API/protocol fingerprint equivalence flow, strict immutability, missing-required-evidence reporting, registry-substitution rejection, nested fingerprint omission rejection, normalized metadata-alias rejection, and mocked no-execution checks.

## Authorized remediation 18b: exact acquisition execution identity

Schema v1 now treats one `ACQUIRE_EVIDENCE` step as one executable `(request_id, request_fingerprint)` key. The singular `request_id` is part of step identity. The same exact key reused across claims shares one step, while identical request semantics under different request IDs produce distinct steps, dependency edges, request consumption, and step consumption.

### RED evidence

Commit: `372dce0a2ff6e0135e030c3e9c5ef243a4499a15` (`test: expose acquisition request identity conflation`)

Command:

```bash
python -m pytest -q tests/test_verification_planner.py tests/test_evidence_provider_hardening.py
```

Observed result before production changes: six planner cases failed. The existing step schema had only plural `request_ids`, same-semantics requests with different IDs were merged, `max_requests=1` did not exhaust, and protocol output did not preserve singular executable identities. The mandatory provider-result guard already passed because runtime result validation compares both the exact request ID and request fingerprint.

### GREEN evidence

Commit: `f3e170b0ec04d8b22fc735bea86efe0c5c96afe0` (`fix: preserve exact acquisition request identities`)

Validation:

```bash
python -m pytest -o addopts='' -q tests/test_verification_planner.py
# 60 passed

python -m pytest -o addopts='' -q \
  tests/test_verification_planner.py \
  tests/test_evidence_provider_hardening.py
# 119 passed

python -m pytest
# 442 passed

python -m compileall -q src/gvr tests
git diff --check 89614dec74d63a48426601f2c4bdcbac864d5d7a..HEAD
```

All commands completed successfully. A post-GREEN adversarial probe exercised all four graph/binding ordering combinations for two same-semantics request IDs, exact-key sharing across claims, request and step budget exhaustion, missing or misplaced singular request IDs, and rejection of the removed plural constructor field. No additional concrete semantic-versus-executable identity conflation was found in planner accounting, dependency mapping, protocol output, or provider-result validation.

The package was built as `gvr-0.2.0-py3-none-any.whl` with SHA-256 `f2c9e3619b6d8c0169a718ee2ad86092e5a1cdb0fb5deca1eb9e3a0cae24039a`, installed without dependencies into a fresh virtual environment, and exercised outside the repository with `PYTHONPATH` cleared. The installed package produced two singular acquisition identities for identical semantics under `request-A` and `request-B`, reported `requests=2` and `steps=4`, preserved both identities through schema-v1 protocol output, and exhausted `max_requests=1` with `required=2`.

### Separate post-GREEN adversarial review

Review target: `793964472905fab1adbf13da5ee28e1ae3cf2310`.

The separate review found one remaining semantic-versus-executable conflation. `AtomicClaimBinding` rejected two requests in the same claim whenever their semantic fingerprints matched, even when their request IDs differed. That validation prevented the planner's exact `(request_id, request_fingerprint)` accounting from representing two required executions, two verifier dependencies, same-claim budget consumption, or the equivalent schema-v1 protocol flow.

RED command:

```bash
python -m pytest -o addopts='' -q \
  tests/test_verification_planner.py::test_43_same_claim_preserves_same_semantics_different_request_ids
# 1 failed: duplicate evidence request semantics in claim A
```

The fix removes only the semantic-fingerprint duplicate rejection inside one binding. Duplicate request IDs remain rejected, including conflicting semantics, while different request IDs with the same fingerprint remain distinct exact executions. Regression tests cover same-claim acquisition and verifier dependency IDs, request order determinism, exact `max_requests`, `max_steps`, and `max_requests_per_claim` exhaustion, and schema-v1 protocol preservation.

GREEN validation:

```bash
python -m pytest -o addopts='' -q tests/test_verification_planner.py
# 65 passed

python -m pytest -o addopts='' -q \
  tests/test_verification_planner.py \
  tests/test_evidence_provider_hardening.py
# 124 passed

python -m pytest
# 447 passed

python -m compileall -q src/gvr tests
git diff --check
```

A separate executable probe also passed exact-key sharing, same-claim dependencies, all three affected budget counters, request-ID-only step and plan identity, schema-v1 roundtrip, provider-result request-ID rejection, four independent graph/binding reorder combinations plus request reversal, provider and verifier capability identity, and claim/dependency step identity.

The final code was also built as `gvr-0.2.0-py3-none-any.whl`, installed without dependencies into a fresh virtual environment, and exercised outside the repository with `PYTHONPATH` removed. The installed public API emitted acquisition IDs `request-A` and `request-B`, two exact verifier dependency step IDs, and consumption `requests=2`, `requests_per_claim=2`, `steps=3`. The installed `gvr` console command accepted the serialized request through stdin, returned `kind=verification_plan`, and produced a payload exactly equal to the public API result. Installed provider-result validation rejected replay from `request-A` to same-semantic `request-B` with `result request_id does not match request`.

## Test specification

| # | Guarantee | Test target | Type | Result |
| --- | --- | --- | --- | --- |
| 1 | Compatible exact binding produces acquisition then atomic verification steps | `test_01_compatible_atomic_flow_is_strict_immutable_and_canonical` | unit | PASS |
| 2 | Provider request kinds stay distinct from verifier claim kinds | `test_02_provider_request_kind_is_distinct_from_verifier_claim_kind` | unit | PASS |
| 3 | Unknown, mismatched, wrong-version, wrong-fingerprint, unsupported, or non-authoritative verifier contracts fail closed | tests 03–08 | adversarial unit | PASS |
| 4 | Unknown or structurally invalid provider contracts, evidence kinds, and classes fail closed | tests 09–15 | adversarial unit | PASS |
| 5 | Missing required evidence requests or kinds fail closed | tests 16–17 | adversarial unit | PASS |
| 6 | Only the same exact request ID and fingerprint share acquisition, while conflicting reused request IDs are rejected | tests 18–19 | adversarial unit | PASS |
| 7 | Request, binding, graph, and registry insertion order is non-semantic | tests 20–22 | determinism | PASS |
| 8 | Provider, verifier, claim, request, and dependency identity changes alter plan identity | tests 23–27 | identity | PASS |
| 9 | `AND`, `OR`, and `NOT` preserve deterministic graph order and cycles are rejected | tests 28–29 | graph integration | PASS |
| 10 | Exact budgets pass, every configured overflow fails with stable insertion-invariant termination | tests 30–31 | boundary | PASS |
| 11 | Plan output contains no claim-result, free-text diagnostic, arbitrary metadata, or generic evidence-adequacy fields | test 32 | contract | PASS |
| 12 | Schema-v1 protocol is deterministic, strict, fingerprinted, and the API is publicly exported | test 33 | protocol integration | PASS |
| 13 | Invalid requests cannot hide missing required evidence, exact registries reject subclass substitution, and nested protocol fingerprints are mandatory | tests 34–36 | adversarial contract | PASS |
| 14 | Planner issues reject verdict and evidence-adequacy metadata aliases | test 37 | adversarial contract | PASS |
| 15 | Same semantics under different request IDs produce distinct exact acquisition steps and exact consumption | test 38 | executable identity | PASS |
| 16 | Request budgets count same-semantics request IDs as separate executions | test 39 | boundary | PASS |
| 17 | Request-ID-only changes alter acquisition step ID and full plan identity | test 40 | identity | PASS |
| 18 | Schema-v1 protocol preserves two same-semantics request identities | test 41 | protocol integration | PASS |
| 19 | Reordering the exact request set remains deterministic | test 42 | determinism | PASS |
| 20 | A provider result for request A cannot validate against same-semantics request B | `test_result_for_request_a_cannot_validate_against_same_semantics_request_b` | adversarial integration | PASS |
| 21 | One claim preserves two same-semantics request IDs as two exact acquisition dependencies | test 43 | executable identity | PASS |
| 22 | Same-claim exact executions exhaust request, step, and per-claim request budgets exactly | test 44 | boundary | PASS |
| 23 | Schema-v1 protocol preserves both same-claim exact request identities and dependencies | test 45 | protocol integration | PASS |

## Coverage and known gaps

The planner-focused file contains 45 named adversarial scenarios and 65 executed pytest cases. Together with evidence-provider hardening, the remediation-focused run contains 124 cases. Budget overflow is parameterized across seven independent limits, with three additional same-claim exact-execution boundary cases. Nested fingerprint omission spans two locations, and metadata aliases span twelve direct, compound, nested, case, and hyphenation forms.

No provider, verifier, Graphify, network, or file-system execution path is part of the planner. Runtime acquisition and verification remain intentionally outside this task.
