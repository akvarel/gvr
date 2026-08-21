# Regression test obligations

The Regression Test Obligation Engine turns structured behavior facts into a deterministic, bounded plan of tests that should exist.

It does **not** write test code, run a provider, call a model, browse source, execute a browser, or authorize a merge or deployment.

Its public entry point is:

```python
derive_regression_test_obligations(inventory, budget=...)
```

The output is an immutable `RegressionObligationPlan`.

## Why this layer exists

A change can imply several testing duties:

- lock a changed behavior against recurrence;
- exercise a new boundary or branch;
- assert an exception path;
- observe a state transition or side effect;
- verify a collaborator, data-flow, or concurrency interaction.

Those duties must not be invented from prose or from an untrusted `PASS` field. The engine derives them only from normalized `Evidence` records in a closed behavior vocabulary.

## Closed schema-v1 evidence vocabulary

Schema v1 accepts exactly these 13 `Evidence.kind` values:

| Evidence kind | Fact class |
| --- | --- |
| `gvr.test.behavior_contract` | `CONTRACT` |
| `gvr.test.behavior_change` | `CHANGE` |
| `gvr.test.input_partition` | `INPUT` |
| `gvr.test.output_observation` | `OUTPUT` |
| `gvr.test.branch_condition` | `BRANCH` |
| `gvr.test.exception_behavior` | `EXCEPTION` |
| `gvr.test.state_transition` | `STATE` |
| `gvr.test.side_effect` | `SIDE_EFFECT` |
| `gvr.test.collaborator_interaction` | `INTERACTION` |
| `gvr.test.data_flow` | `DATA_FLOW` |
| `gvr.test.concurrency_behavior` | `CONCURRENCY` |
| `gvr.test.existing_test` | `EXISTING_TEST` |
| `gvr.test.coverage_observation` | `COVERAGE` |

Unknown kinds are rejected. The vocabulary is not a wildcard for arbitrary source-analysis output.

Payloads are deeply snapshotted and must be canonical JSON-compatible values. Truth-like control fields such as `verdict`, `status`, `grounded`, `authorized`, `can_merge`, and `can_deploy` are rejected. Evidence describes facts. It cannot decide the result of the grounding verifier.

Derivable fact evidence uses these required payload fields:

```json
{
  "subject": "checkout.total",
  "behavior": "applies the revised discount rule"
}
```

An optional stable `fact_key` can identify multiple records that describe the same source fact. Conflicting behavior for one exact fact key is reported as a stable gap.

## Immutable evidence inventory

`BehaviorEvidenceInventory` normalizes:

- evidence into exact UTF-8 ID order;
- identical repeated records into one record;
- per-fact-class coverage into one record per fact class;
- caller-owned nested mappings and lists into immutable snapshots;
- semantic content into a domain-separated fingerprint.

Different records using the same evidence ID are rejected as ambiguous.

`FactClassCoverage` uses three values:

- `COMPLETE`;
- `PARTIAL`;
- `UNKNOWN`.

`COMPLETE` and `PARTIAL` coverage must cite available evidence of the same fact class. `UNKNOWN` cannot cite positive evidence IDs. If a class has no supplied coverage record, `coverage_for()` returns an explicit `UNKNOWN` value.

## Nine obligation rules

Schema v1 has exactly nine derivation rule classes:

| Obligation kind | Accepted fact class | Default level |
| --- | --- | --- |
| `CHARACTERIZATION` | `CONTRACT` | `UNIT` |
| `REGRESSION` | `CHANGE` | `UNIT` |
| `BOUNDARY` | `INPUT` | `UNIT` |
| `OUTPUT` | `OUTPUT` | `UNIT` |
| `BRANCH` | `BRANCH` | `UNIT` |
| `EXCEPTION` | `EXCEPTION` | `UNIT` |
| `STATE_TRANSITION` | `STATE` | `UNIT` |
| `SIDE_EFFECT` | `SIDE_EFFECT` | `INTEGRATION` |
| `INTERACTION` | `INTERACTION`, `DATA_FLOW`, or `CONCURRENCY` | `INTEGRATION` |

`EXISTING_TEST` and `COVERAGE` are supporting inventory classes. They do not independently manufacture a test obligation.

A `TestObligation` contains:

- a deterministic obligation ID and claim ID;
- one strict obligation kind;
- subject and expected behavior;
- rationale and test level;
- exact fact classes and evidence IDs;
- immutable non-truth metadata;
- a semantic fingerprint.

The constructor rejects empty subjects, empty evidence manifests, rule/fact mismatches, incorrect test levels, unsupported values, and truth-like metadata.

## No obligation laundering

The claim checked by the verifier is:

```text
TEST_OBLIGATION_GROUNDED
```

The exact verifier ID is:

```text
gvr.regression_test_obligation.v1
```

A grounding `PASS` requires all of the following:

1. every cited evidence ID exists in the normalized inventory;
2. every cited evidence kind maps to one of the obligation's declared fact classes;
3. evidence subject equals the obligation subject;
4. evidence behavior equals the obligation expected behavior;
5. every referenced fact class has `COMPLETE` evidence-backed coverage.

Missing, unrelated, subject-mismatched, behavior-mismatched, partial, or unknown grounding returns `UNKNOWN`. It never becomes `PASS` because an evidence producer supplied a favorable field.

`verify_test_obligation_grounding_bundle()` packages each report with exactly its evidence dependency manifest. A bundle can be recorded in `ClaimLedger`. If any dependency changes or is removed, the recorded grounding claim becomes stale and its effective verdict becomes `UNKNOWN` until reverified.

## Deterministic bounded plan

`RegressionObligationPlan` contains ordered:

- obligations;
- one aligned `VerificationBundle` per obligation;
- normalized fact coverage;
- stable gaps;
- budget and consumption;
- termination reason;
- readiness;
- inventory and plan fingerprints.

Semantically identical candidate obligations are deduplicated. Their evidence IDs are merged instead of discarding provenance. Candidate and final ordering do not depend on input order.

The default finite budget is:

```json
{
  "max_obligations": 256,
  "max_bundles": 256,
  "max_evidence_records": 4096,
  "max_steps": 8192
}
```

Every limit can be reduced to zero. Reaching a limit terminates with `BUDGET_EXHAUSTED`, emits a `BUDGET_EXHAUSTED` gap, and returns `BLOCKED`. The engine does not continue unbounded candidate expansion after a cutoff.

## Stable gap taxonomy

Schema v1 exports these gap codes:

- `PARTIAL_FACT_COVERAGE`;
- `UNKNOWN_FACT_COVERAGE`;
- `MISSING_REQUIRED_FIELD`;
- `NO_DERIVATION_RULE`;
- `UNGROUNDED_OBLIGATION`;
- `BUDGET_EXHAUSTED`;
- `CONFLICTING_FACTS`.

Gap order is deterministic. Gap details are immutable and cannot contain authorization or verdict fields.

## Readiness is not authorization

Plan readiness is one of:

- `READY` when derivation completed, at least one obligation exists, all relevant coverage is complete, and every bundle is grounded `PASS`;
- `BLOCKED` for a known blocking gap or budget cutoff;
- `UNKNOWN` when coverage or grounding is not safely decidable.

`READY` means the obligation plan is complete under this verifier's declared evidence and bounds. It does **not** mean:

- merge the change;
- deploy it;
- execute generated code;
- make an external side effect.

Those decisions remain product policy outside GVR.

## Honest capability descriptor

The built-in verifier capability snapshot publishes the runtime contract:

- verifier: `gvr.regression_test_obligation.v1` version `1`;
- claim kind: `TEST_OBLIGATION_GROUNDED`;
- accepted evidence: exactly the 13 schema-v1 behavior kinds;
- required evidence kinds: empty, because the exact kind is conditional on the obligation rule;
- determinism: `D1`;
- cost: `MEDIUM`;
- side-effect-free and authoritative under its exact contract;
- finite bounds equal to the runtime default budget;
- coverage rule: `COMPLETE_REFERENCED_FACT_COVERAGE`.

## Schema-v1 protocol operation

Use `derive_regression_test_obligations` with a serialized inventory and optional budget:

```json
{
  "schema_version": 1,
  "op": "derive_regression_test_obligations",
  "payload": {
    "inventory": {
      "schema_version": 1,
      "kind": "gvr.behavior_evidence_inventory",
      "fingerprint_format": "gvr.behavior_evidence_inventory.ieee754-json.v1",
      "evidence": [
        {
          "id": "ev-change",
          "kind": "gvr.test.behavior_change",
          "payload": {
            "subject": "checkout.total",
            "behavior": "applies the revised discount rule"
          },
          "source": "static-analysis",
          "fingerprint": "producer-fingerprint"
        }
      ],
      "coverage": [
        {
          "fact_class": "CHANGE",
          "completeness": "COMPLETE",
          "evidence_ids": ["ev-change"],
          "scope": {"revision": "candidate-1"}
        }
      ],
      "fingerprint": "the exact inventory fingerprint"
    },
    "budget": {
      "max_obligations": 256,
      "max_bundles": 256,
      "max_evidence_records": 4096,
      "max_steps": 8192
    }
  }
}
```

The response kind is `regression_obligation_plan`. Unknown fields, unsupported vocabulary, invalid coverage, and forged inventory fingerprints return a machine-readable `protocol_error`.

The protocol operation is pure derivation over supplied immutable evidence. It does not invoke `EvidenceProviderRuntimeRegistry` or any external executor.
