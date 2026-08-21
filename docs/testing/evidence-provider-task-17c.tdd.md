# Evidence Provider Task 17c TDD Evidence

## Source task

Drive Task 17c final remediation was implemented on `feature/gvr-evidence-provider-protocol-v1` from exact base `072fa8f`. The untracked `probe_false_freshness.py` was preserved and excluded from both commits.

## User journeys

- As a provider caller, I want source and snapshot classes to be explicit request semantics so class-incompatible requests cannot invoke a provider.
- As a registry consumer, I want one public request validator used by runtime dispatch so compatibility rules have a single fail-closed boundary.
- As a protocol consumer, I want provider issues to contain only stable codes, optional safe categories, and evidence IDs so arbitrary diagnostic prose cannot affect identity or leak through exports.
- As an operator, I want execution exceptions mapped to meaningful allowlisted categories without raw exception text or class representations.
- As a verifier boundary maintainer, I want truth-like provider issue codes and categories rejected so acquisition diagnostics cannot smuggle claim verdicts.

## RED and GREEN checkpoints

| Stage | Commit | Command | Observed result |
| --- | --- | --- | --- |
| RED | `6b0ee38` | `python -m pytest -q tests/test_evidence_provider_task_17c.py` | 37 intended failures covering absent request class fields, empty capability class lists, registry validation, categorical issues, obsolete protocol fields, and safe execution categories. |
| GREEN focused | implementation commit containing this report | `python -m pytest -q tests/test_evidence_provider_task_17c.py tests/test_evidence_provider_task_17b.py tests/test_evidence_providers.py tests/test_evidence_provider_hardening.py` | All 147 collected provider tests passed. |
| Full | implementation commit containing this report | `python -m pytest -q` | All 381 collected tests passed. |
| Compile | implementation commit containing this report | `python -m compileall -q src tests` | Passed with no compilation errors. |
| Diff | implementation commit containing this report | `git diff --check` | Passed with no whitespace errors. |

## Test specification

| Guarantee | Evidence |
| --- | --- |
| `source_class` and `snapshot_class` are optional explicit request fields, cross the strict protocol, and affect semantic fingerprints. | `test_request_source_and_snapshot_classes_are_explicit_semantics_and_protocol_fields` |
| Empty capability class lists are valid and accept only missing request classes; non-empty lists require an exact member. | `test_source_class_compatibility_is_exact_and_empty_capability_is_meaningful`, `test_snapshot_class_compatibility_is_exact_and_empty_capability_is_meaningful` |
| Runtime dispatch uses `EvidenceProviderCapabilityRegistry.validate_request` and class incompatibility prevents provider invocation even with `fail_closed=True`. | `test_runtime_uses_public_registry_validation_and_never_calls_class_incompatible_provider` |
| Provider issues export only stable code, optional allowlisted category, and evidence IDs, with no message or verdict. | `test_provider_issue_exports_only_stable_code_optional_category_and_evidence_ids` |
| Direct and tokenized truth-like issue codes/categories are rejected, including `PASS`, `FAIL`, `UNKNOWN`, `VERDICT`, `VERIFIED`, `SUFFICIENT`, and `TRUTH`. | `test_provider_issue_rejects_direct_and_tokenized_truth_like_codes_and_categories` |
| The strict protocol rejects obsolete provider issue `message` and `verdict` fields. | `test_protocol_rejects_obsolete_provider_issue_message_and_verdict` |
| Fail-closed execution maps timeout, access, connection, I/O, cancellation, and generic failures to safe stable categories without raw text or class names. | `test_fail_closed_maps_execution_failures_to_safe_stable_categories` |
| Failure identity depends on the safe category, not raw exception text or generic exception class. | `test_fail_closed_identity_depends_on_category_not_raw_exception_text_or_class` |

## Scope and limitations

No built-in runtime evidence provider was introduced. The built-in capability registry remains honestly empty. No push, Drive update, production action, or change to `probe_false_freshness.py` was performed.
