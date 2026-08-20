# Graphify Data-Flow Claims TDD Evidence

## Source task

Google Drive taskbus documents:

- `09-gvr-graphify-claim-verification`;
- `10-gvr-graphify-claim-supervising-remediation`.

Approved base: `958651411b843f5903ad0eaf6bfdc2220e2240a5`.

## User journeys

1. As a GVR caller, I can verify whether exact Graphify evidence proves that a value can flow from one node to another.
2. As a GVR caller, I can verify absence only when Graphify completed the explicitly supported search.
3. As a ClaimLedger user, I can record exact direct evidence dependencies and receive stale propagation after evidence changes.
4. As a wire-protocol caller, I can invoke the verifier through schema version 1 without losing audit fields.
5. As a reviewer, I can trust malformed, MAY, PARTIAL, truncated, unresolved, ambiguous, or contradictory inputs to fail closed.

## RED and GREEN checkpoints

| Stage | Commit | Command | Observed result |
|---|---|---|---|
| RED | `f81ad93c135d7d4458f07a510fd8cffe0a00a279` | `python -m pytest -q tests/test_data_flow_verifier.py` | Collection failed because the new public verifier API did not exist. |
| GREEN | `0bd2d1028d1c4f0dad0a15c103910bccbcf16786` | `python -m pytest -q tests/test_data_flow_verifier.py` | New verifier tests passed. |
| Regression GREEN | `0bd2d1028d1c4f0dad0a15c103910bccbcf16786` | `python -m pytest -q` | Existing and new tests passed before adversarial hardening. |
| Adversarial RED | working tree after GREEN | `python -m pytest -q tests/test_data_flow_verifier.py` | Four newly added probes reproduced false absence conclusions or insufficient validation. |
| Adversarial GREEN | working tree after fixes | `python -m pytest -q tests/test_data_flow_verifier.py` | All 28 focused tests passed. |
| Remediation RED | `50ccf4ea3a587fc741b3655db3aeea6a97f99552` | `python -m pytest -q tests/test_data_flow_verifier.py` | Collection failed because immutable scope and query-result evidence APIs did not exist. |
| Remediation GREEN | `b79c5360f4e83f27e53157ce92ae3b395fdc4786` | `python -m pytest -q tests/test_data_flow_verifier.py` | Scope binding, query evidence, ledger freshness, and mandatory accounting tests passed. |
| Independent accounting RED | working tree after remediation GREEN | Two focused malformed-result tests | Underreported visits still produced definitive verdicts for a positive expansion and for divergent returned paths. |
| Independent accounting GREEN | working tree after fixes | `python -m pytest -o addopts='' -q tests/test_data_flow_verifier.py` | All 45 focused tests passed. |

## Test specification

| # | Guarantee | Evidence | Type | Result |
|---|---|---|---|---|
| 1 | Exact PROVEN and complete paths prove `CAN_FLOW_TO` with exact `df:...` dependencies. | `test_exact_proven_complete_path_passes_can_flow_to_with_exact_dependencies` | Unit | PASS |
| 2 | MAY or PARTIAL paths never become proven through aggregation. | MAY, PARTIAL, and multiple-path tests in `tests/test_data_flow_verifier.py` | Adversarial unit | PASS |
| 3 | An exact path can prove positive flow despite incomplete overall search, without implying search completeness. | `test_exact_path_can_prove_positive_claim_despite_partial_overall_search` | Unit | PASS |
| 4 | Complete empty search produces `CAN_FLOW_TO FAIL` and `NO_SUPPORTED_PATH PASS`; incomplete absence stays UNKNOWN. | Complete/truncated/missing-input/boundary tests | Unit | PASS |
| 5 | Unsupported, malformed, duplicate-key, contradictory, and confidence/completeness-laundering payloads fail closed. | Fail-closed tests in `tests/test_data_flow_verifier.py` | Adversarial unit | PASS |
| 6 | Reordered paths and boundary events produce identical reports. | `test_output_is_deterministic_under_reordered_paths_and_boundaries` | Determinism | PASS |
| 7 | Direct evidence mutation or removal makes a recorded PASS stale and effectively UNKNOWN. | `test_positive_claim_recorded_in_ledger_becomes_stale_after_evidence_mutation_or_removal` | Integration | PASS |
| 8 | Schema v1 preserves verdict, verifier, dependencies, issue codes, claim endpoints, and Graphify audit metadata. | `test_version_1_wire_operation_preserves_auditable_fields` | Protocol integration | PASS |
| 9 | Real forward and backward Graphify dataclass payloads are accepted without importing Graphify into GVR. | Manual `PYTHONPATH=/sharedssd/git/graphify:$PWD/src` integration snippets | Cross-repository integration | PASS |
| 10 | Definitive verdicts require exact relation, direction, and stop-node scope equality between claim and traversal. | Scope laundering and explicit-scope tests | Adversarial unit | PASS |
| 11 | Empty-search and identity-path verdicts depend on deterministic replaceable `gvrq:...` evidence and become stale after result, context, or evidence changes. | Query evidence and ClaimLedger tests | Integration | PASS |
| 12 | Producer-impossible path depth, path count, expansion count, visited/expanded relationships, and unresolved accounting fail closed. | Accounting remediation tests | Adversarial unit | PASS |

## Final validation

- `python -m pytest -o addopts='' -q tests/test_data_flow_verifier.py`: `45 passed in 0.08s`.
- `python -m pytest -o addopts='' -q`: `108 passed in 0.18s`.
- `python -m compileall -q src`: PASS.
- `git diff --check`: PASS.
- Real Graphify forward payload: `PASS`, two direct evidence IDs.
- Real Graphify backward payload with explicit `BACKWARD` claim scope: `PASS`.
- Independent adversarial review found and drove fixes for invalid relation partitions, impossible completeness/coverage state, impossible zero traversal accounting with returned paths, underreported visits after expansion, and visit counts that do not cover the union of returned path nodes.

## Coverage and known gaps

No coverage, lint, or static type-checking tool is configured in `pyproject.toml`, and `coverage`, `pytest-cov`, `ruff`, and `mypy` are not installed in the environment. The complete repository test suite and focused adversarial suite were run instead. No tests were skipped or disabled.
