# Task 23 correlation metadata and multi-acquisition hardening TDD evidence

## Authorized source and boundary

Task 23 starts from exact verified base `f59d54c04f67fb6d11209d503b9df6d217800e63` on `feature/gvr-correlation-metadata-hardening-v1`.

The work is limited to the generic provider, executor, protocol, and SQLite durable boundary. It preserves the untracked `probe_false_freshness.py`, does not deploy, does not push, and does not write a Drive report.

## Required outcomes

1. Correlation, run, request, span, and trace identifiers are audit observations, including nested and aliased forms. They are forbidden recursively in semantic `EvidenceCoverage` maps and the validation error directs providers to the audit channel.
2. A generic immutable audit observation has its own integrity fingerprint. It is excluded from coverage, provider-result, execution-result, evidence-artifact, slot, bundle, falsification, claim, and session truth fingerprints.
3. Audit metadata remains available through protocol round trips and durable session execution observations.
4. Genuine coverage semantics remain fingerprinted.
5. One `VerificationExecutionRequest` may contain two or more independent acquisitions that return the same raw `Evidence.id`. Exact source/request slot identities and all durable dependency sets remain distinct.
6. Multi-acquisition recording is atomic, restart replay is idempotent, changing acquisition B advances only B's slot, and acquisition A's slot remains current.
7. The required dependency-link schema change transactionally preserves authoritative schema-v2 data and the schema-v1 ambiguous-slot fail-closed policy.

## Six-scenario specification

| # | Scenario | Test |
|---:|---|---|
| 1 | Recursive aliases are rejected from every semantic coverage map; audit order is canonical; audit-only changes preserve semantic fingerprints; genuine coverage changes do not. | `test_task23_01_coverage_rejects_recursive_audit_ids_and_fingerprints_semantics` |
| 2 | Real provider, executor, falsification, and SQLite runs prove audit-only changes preserve every truth basis and invalidation count while two retrievable audit observations remain distinct. | `test_task23_02_audit_only_change_is_retrievable_without_truth_churn` |
| 3 | One execution with two same-raw-ID acquisitions records two exact slots/dependencies atomically, survives reopen/replay, advances only B, and transactionally migrates authoritative v2 dependency links. | `test_task23_03_one_execution_keeps_same_raw_id_acquisitions_independent` |
| 4 | Source/request semantics create distinct slots; snapshot/content/provider-version changes advance the documented same slot. | `test_task23_04_semantic_dimension_properties_match_documented_slot_rules` |
| 5 | Protocol round trips audit data without mixing it into semantic fingerprints and rejects forged audit fingerprints, semantic-map aliases, and wrong-channel forms. | `test_task23_05_protocol_preserves_audit_boundary_and_rejects_forgery` |
| 6 | An injected failure after both acquisition writes rolls back artifacts, slots, bundles, falsification, claims, sessions, observations, and invalidation events together. | `test_task23_06_multi_acquisition_injected_failure_rolls_back_atomically` |

## Exact-base Blocker A reproduction

An ephemeral real-path test ran a provider twice through `execute_verification_plan(..., storage=SQLiteStorage(...))`. The only change was a nested audit identifier placed in one currently semantic coverage map. All three cases failed the desired stability assertion on base.

| Channel and nested alias | Coverage fingerprints | Provider-result fingerprints | Durable evidence fingerprints | Observed durable effect |
|---|---|---|---|---|
| `details.transport.trace.id` | `3160efb18c3b7d1b249d62d4a66b597f23e4f86db0afd688fcabab55cce4ab17` -> `829af369a281461287a09aa154a75b5fcd4d5cb81e34b4ef77add52c389f29b6` | `ef9962d674b440971ab7e3b03855c50b25317fe1ab4c59230a3c40441c045cda` -> `48593f4080493af50380c57adaa7d9f5175a2ed5ee567d3b8d1088ba8757301e` | `4f9f58fd947a44a292b813f1551570d809a3859381201c46cd66a8855ff2c6cc` -> `9555ae474732388257277116cf9db1108b37d623ccedd588a883f9bb1aad6882` | slot `[1, 2]`; old bundle/claim/session stale; 2 invalidation events |
| `consumed.runner.run_id` | `1e07445b92806d3855d5ead80dbce54c58bb9612886fc71db2292d3a22f55e03` -> `0b3821b9e493366c8ee03767a4df05d5d284892a7e8c818320b559eb8eba4f6d` | `62c2580a3c78056785fb4c7572400d8268288da893124dd4364ad4c26351eabd` -> `586a9e0abb9ee0fc5d7db2b31d9e6d592dce591b77984e77c993d5249391236e` | `0d7a313778b99a406ef60402d9ff5846c977af5e610561f606d0c2902dfec4a9` -> `0eeebafaccd5389c78d77ce014430b42cb765a34c64c21a9b8d16cb3916d84a9` | slot `[1, 2]`; old bundle/claim/session stale; 2 invalidation events |
| `termination.metadata.correlationId` | `1da59bd5ce6c266fa56fc0f540d128e56f5b17609d0b0406e983a8a35fb612ac` -> `7c94ad1b00fe446752f2ca5896dab09125c94c140f1c5941049ff546d4d173b3` | `671c5f503827850eb6a93944d8ae6e21c097d5733667265ad896901ec19df434` -> `88a2faaa428962cfc26538fe7608faa4cfa41cd60a6823d8b96a7dafa88117d7` | `bc86e099f6904a9dd55c8ba1bac853de79943fdc46681fafd73ec600ca43f6ec` -> `b8aaf372a44eddd07cc8698089b00cf7f0723cd2ec2a7161077736a93df73518` | slot `[1, 2]`; old bundle/claim/session stale; 2 invalidation events |

This proves the leak is not limited to a request field. Nested operational identifiers altered coverage, provider-result, durable artifact, slot, bundle record, claim basis, session basis, currentness, and invalidation history.

## Exact-base Blocker B acceptance outcome

The acceptance test was added and run before any production source changed. It builds one real `VerificationExecutionRequest` with two independent acquisitions. Both return raw `Evidence.id == "task23-shared-raw-id"`, while source and request semantics differ.

Command:

```text
python -m pytest -q -p no:cacheprovider --tb=short \
  tests/test_durable_storage_task_23.py::test_task23_03_one_execution_keeps_same_raw_id_acquisitions_independent
```

Observed base result: **RED**.

```text
StorageIntegrityError: bundle evidence task23-shared-raw-id has ambiguous durable acquisition identities
VerificationExecutionError: durable storage recording failed closed
```

The failure is honest and occurs on the first atomic recording attempt. The executor correctly retains two acquisitions, but schema-v2 bundle, falsification, and claim dependency links assume one dependency per raw evidence ID.

## Complete RED run

Command:

```text
python -m pytest -q -p no:cacheprovider --tb=short \
  tests/test_durable_storage_task_23.py
```

Observed exact-base result:

```text
5 failed, 1 passed
```

The passing scenario is the already-documented source/request/snapshot/content/provider-version dimension behavior. The five failures expose the absent audit channel, absent protocol transport, same-raw-ID dependency ambiguity, and missing multi-acquisition rollback injection point.

## Task 22 mandatory requirements 1-12 compliance map

| Task 22 # | Existing evidence | Task 23 reopening and missing behavioral coverage |
|---:|---|---|
| 1 | `test_task22_01_request_id_only_change_is_same_slot_version_and_current_basis` | Task 23 tests 1, 2, and 5 extend correlation isolation recursively into every coverage map, provider-result transport, durable artifact identity, and audit retrieval. |
| 2 | `test_task22_02_execution_correlation_only_is_audit_not_slot_or_session_basis` | Task 23 test 2 proves two full execution observations can differ only by provider audit metadata while execution/session truth remains one basis. |
| 3 | `test_task22_03_same_raw_id_in_different_sources_never_collides` | Task 23 test 3 adds the behaviorally missing same-execution case and exact dependency-set proof. Test 4 retains the cross-execution property. |
| 4 | `test_task22_04_same_raw_id_in_different_request_parameters_never_collides` | Task 23 tests 3 and 4 cover distinct request semantics in one execution and as an independent dimension. |
| 5 | `test_task22_05_same_request_id_cannot_alias_different_semantic_sources` | Existing guarantee remains authoritative; Task 23 recursive validation prevents hidden request/correlation aliases from bypassing it through coverage metadata. |
| 6 | `test_task22_06_provider_identity_scopes_slots_but_provider_version_advances_same_slot` | Task 23 test 4 reasserts provider-version replacement beside every other dimension. |
| 7 | `test_task22_07_snapshot_change_with_identical_content_versions_bundle_claim_and_session_once` | Task 23 tests 3 and 4 add snapshot replacement in a multi-acquisition request and prove only B advances. |
| 8 | `test_task22_08_content_change_stales_exact_only_and_leaves_unrelated_current` | Task 23 test 4 reasserts content replacement; test 2 proves audit content is not evidence content. |
| 9 | `test_task22_09_falsification_tracks_exact_semantic_slot_version_transitively` | Task 23 test 2 adds the missing audit-only falsification invariance and retrieval chain. |
| 10 | `test_task22_10_undeclared_evidence_remains_immutable_without_fake_slots` | Existing direct immutable dependency guarantee remains complete. Task 23 does not infer a slot from audit metadata or a raw evidence ID. |
| 11 | `test_task22_11_outer_rollback_removes_slot_advance_and_all_transitive_records` | Task 23 test 6 adds the behaviorally missing injected mid-record failure after two acquisition writes. |
| 12 | `test_task22_12_v1_migration_marks_ambiguous_raw_slots_stale_and_restart_replay_is_idempotent` | Task 23 test 3 preserves that v1 policy while adding transactional authoritative-v2 to dependency-schema-v3 migration and replay. |

## GREEN evidence

Implemented behavior:

- `AuditObservation` schema v1 provides a generic immutable audit channel with its own canonical integrity fingerprint. `EvidenceCoverage` semantic transport and fingerprints exclude that channel, while full transport and durable session execution observations retain it.
- Recursive validation now rejects correlation, request, execution, invocation, run, span, trace, `traceparent`, and `tracestate` identifier aliases from all semantic coverage maps, including combined, nested, UUID, token, and scalar forms. Errors direct providers to `EvidenceCoverage.audit`.
- Provider, verifier, execution, protocol, and SQLite projections preserve the semantic/audit boundary. The protocol accepts only the nested coverage audit form, requires its fingerprint, recomputes it, and rejects unknown, forged, ambiguous, and wrong-channel forms.
- Durable database schema v3 keys bundle, falsification, and claim evidence dependency links by canonical ordinal. Exact dependency records therefore preserve multiple independent acquisitions with one raw evidence ID. Record document schema v2 and all existing semantic domain schemas remain unchanged.
- The atomic execution write now passes exact acquisition dependencies through bundle, falsification, claim, session, observation, and invalidation handling. The existing schema-v1 ambiguous-slot fail-closed policy is preserved through schema v2 and the transactional v2 to v3 migration.

Validation performed before the GREEN commit:

```text
Task 23 focused:                 6 passed in 2.99s
Task 22 + Task 23:              18 passed in 6.51s
Full source suite:             572 passed in 12.23s
python -m compileall -q src tests: passed
git diff --check: passed
```

An exact-base-created authoritative schema-v2 database was opened by the implementation and migrated transactionally to schema v3. Its slot, claim, and session remained current, and replay remained idempotent with one slot, claim, and session record.

Wheel validation was performed outside the source tree with `PYTHONPATH` removed. The imported module resolved to the temporary environment's `site-packages`, durable schema v3 and audit schema v1 were asserted, and all six Task 23 scenarios passed:

```text
gvr-0.2.0-py3-none-any.whl
SHA-256 c116ee3407ad767862609aab5d231c9b575ba9313e10e8f5802bda94c602789d
6 passed in 3.14s
```

The wire protocol envelope remains schema v1. Evidence request, slot identity, coverage, provider result, execution request/result, bundle, falsification, claim graph, and session semantic schemas remain v1. Durable bundle, falsification, claim, session, and execution-observation record documents remain schema v2.

## Post-GREEN adversarial review

The adversarial pass exercised nested and combined correlation aliases, scalar context aliases, `traceparent`/`tracestate`, UUID/token suffixes, audit map ordering, same raw evidence IDs, restart replay, and falsification dependency replay. Earlier review findings for abbreviated `corr`, scalar trace values, trace context fields, UUID/token aliases, and the combined duplicate-ID falsification path were incorporated in the GREEN implementation and tests.

The repeated post-GREEN generated matrix rejected all 108 semantic-map alias cases. Six permutations of one audit observation produced one audit fingerprint, while audit-only changes kept the semantic boundary stable. The three real SQLite scenarios covering audit retrieval, duplicate-ID restart/falsification, and protocol forgery rejection also passed:

```text
{'recursive_aliases_rejected': 108, 'audit_order_permutations': 6,
 'audit_order_fingerprints': 1, 'semantic_boundary': 'stable'}
3 passed in 1.91s
```

No residual finding required a production change after the GREEN commit.
