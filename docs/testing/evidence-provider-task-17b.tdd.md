# Evidence Provider Task 17b TDD Evidence

## Source task

Drive Task 17b was implemented on `feature/gvr-evidence-provider-protocol-v1`. The reviewed base named by the task was `3847edf`; the working branch also contained the pre-existing follow-up `49cdfa4` before this TDD cycle. The untracked `probe_false_freshness.py` was preserved and excluded from commits.

## User journeys

- As a runtime caller, I want requests and mutable runtime provider identity checked before invocation so that unsupported or substituted providers never execute.
- As a protocol consumer, I want capability discovery separated from runtime execution and source/snapshot classes included in canonical capability identity.
- As a verifier integrator, I want request-kind compatibility kept distinct from claim-kind compatibility and only structural evidence facts exposed.
- As an operator, I want fail-closed acquisition to convert only real execution exceptions and emit deterministic diagnostics without exception text or secrets.
- As a protocol consumer, I want provider issues to be verdict-free and coverage contradictions or truth-like control metadata rejected.

## RED and GREEN checkpoints

| Stage | Commit | Command | Observed result |
| --- | --- | --- | --- |
| RED | `6c92cac` | `python -m pytest -q tests/test_evidence_provider_task_17b.py` | 9 intended failures: split registries, provider issue, source/snapshot metadata, structural verifier facts, and hardened validation were absent. |
| GREEN | implementation commit containing this report | `python -m pytest -q tests/test_evidence_provider_task_17b.py tests/test_evidence_providers.py tests/test_evidence_provider_hardening.py` | Focused provider suite passed. |
| Full | implementation commit containing this report | `python -m pytest -q` | All 340 collected tests passed. |
| Compile | implementation commit containing this report | `python -m compileall -q src tests` | Passed with no compilation errors. |
| Diff | implementation commit containing this report | `git diff --check` | Passed with no whitespace errors. |

## Test specification

| Guarantee | Evidence |
| --- | --- |
| Capability discovery is pure and runtime execution is separate. | `test_capability_and_runtime_registries_are_separate_contracts` |
| Invalid request type, request kind, or requested evidence kind is rejected before provider execution. | `test_runtime_validates_request_contract_before_invoking_provider` |
| Mutable runtime provider ID, version, and capability are rechecked before every call. | `test_runtime_rechecks_mutable_provider_identity_and_capability_before_each_call` |
| `fail_closed` converts only exceptions raised by provider execution. Invalid returned results remain contract errors. | `test_fail_closed_only_converts_provider_execution_exceptions` |
| Execution diagnostics are deterministic and contain neither raw exception messages nor exception class names. | `test_fail_closed_only_converts_provider_execution_exceptions` |
| `EvidenceProviderIssue` has no verdict, and the JSON protocol rejects a provider issue `verdict` field. | `test_provider_issue_has_no_verdict_and_protocol_rejects_verdict` |
| Provider `request_kind` and verifier `claim_kind` are required and evaluated independently. | `test_request_kind_and_verifier_claim_kind_are_distinct_compatibility_inputs` |
| Verifier adaptation exposes emitted, present-required, and missing-required evidence kinds without `sufficient` or truth-upgrade fields. | `test_verifier_input_exposes_structural_compatibility_facts_not_sufficiency` |
| `source_classes` and `snapshot_classes` are explicit capability fields, affect fingerprints, and cross the strict protocol. | `test_capability_source_and_snapshot_classes_are_fingerprinted_and_in_protocol` |
| Emitted evidence must be covered, contradictory partial results are rejected, and truth-like coverage metadata is rejected recursively. | `test_result_validation_hardens_coverage_partial_and_truth_like_metadata` |

## Scope and limitations

No built-in runtime evidence provider was introduced. The built-in capability registry remains honestly empty. No push, Drive update, production action, or change to `probe_false_freshness.py` was performed.
