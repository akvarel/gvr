# Regression test obligations

The Regression Test Obligation Engine turns caller-supplied structured behavior facts into a deterministic, bounded plan of tests that should exist.

It does **not** inspect source, acquire evidence, call a model, browse, generate test code, run tests, or authorize a merge or deployment.

```python
plan = derive_regression_test_obligations(inventory, budget=...)
```

The result is an immutable, fingerprinted `RegressionObligationPlan`.

## Closed schema-v1 evidence vocabulary

Schema v1 accepts exactly these 13 `Evidence.kind` values:

| Evidence kind | Fact class | Purpose |
| --- | --- | --- |
| `gvr.test.surface` | `SURFACE` | A navigable route, screen, endpoint, or other interaction surface. |
| `gvr.test.actor_role` | `ACTOR_ROLE` | A role that can interact with a surface. |
| `gvr.test.action` | `ACTION` | An action on an exact surface. |
| `gvr.test.field` | `FIELD` | A field used by an exact action. |
| `gvr.test.constraint` | `CONSTRAINT` | A required, format, or boundary constraint on an exact field. |
| `gvr.test.data_partition` | `DATA_PARTITION` | One bounded invalid-format or boundary-value partition. |
| `gvr.test.observable_outcome` | `OBSERVABLE_OUTCOME` | The oracle for an exact action. |
| `gvr.test.state_transition` | `STATE_TRANSITION` | A linked before/after state transition. |
| `gvr.test.persistence_relation` | `PERSISTENCE_RELATION` | A linked persistence read-back relation. |
| `gvr.test.permission_relation` | `PERMISSION_RELATION` | A linked role/action permission relation. |
| `gvr.test.dependency` | `DEPENDENCY` | A supported linked dependency interaction. |
| `gvr.test.error_recovery` | `ERROR_RECOVERY` | A linked error and recovery behavior. |
| `gvr.test.execution_safety` | `EXECUTION_SAFETY` | Bounded local execution-safety evidence. |

Old generic kinds such as `gvr.test.behavior_change` are not aliases and are rejected. Payloads are deeply snapshotted. Truth-like control fields such as `verdict`, `status`, `grounded`, `authorized`, `can_merge`, and `can_deploy` are rejected.

## Exact linking contract

An obligation is never derived from one generic change, route, button, field, or requirement fact. Required records must form one exact chain using both payload IDs and matching semantics.

A minimal happy-path chain is:

```json
[
  {
    "id": "surface-checkout",
    "kind": "gvr.test.surface",
    "payload": {
      "subject": "checkout.order",
      "surface": "/checkout",
      "navigation": "route:/checkout"
    }
  },
  {
    "id": "action-submit",
    "kind": "gvr.test.action",
    "payload": {
      "subject": "checkout.order",
      "surface": "/checkout",
      "action": "submit_order",
      "surface_id": "surface-checkout",
      "precondition": "cart contains an item"
    }
  },
  {
    "id": "outcome-accepted",
    "kind": "gvr.test.observable_outcome",
    "payload": {
      "subject": "checkout.order",
      "surface": "/checkout",
      "action": "submit_order",
      "surface_id": "surface-checkout",
      "action_id": "action-submit",
      "oracle": "order confirmation is shown"
    }
  }
]
```

Every linked record repeats the same `subject`, `surface`, and, where applicable, `action`. Relationship fields such as `surface_id`, `action_id`, `field_id`, `constraint_id`, `role_id`, and `outcome_id` must name the exact cited evidence records. A matching kind with a wrong ID or wrong subject/action/surface does not ground an obligation.

Specialized relation requirements are strict:

- required fields use `constraint: "required"`;
- invalid-format cases use `constraint: "format"` plus `partition: "invalid_format"`;
- boundary cases use `constraint: "boundary"` plus `partition: "boundary_value"`;
- state transitions reference the exact `outcome_id` and supply non-empty `from_state` and `to_state`;
- permission relations reference an exact role and outcome, use `permission: "allow"` or `"deny"`, and require `authenticated: true`;
- persistence obligations require `relation: "read_back"` plus non-empty `read_surface` and `read_action`;
- recovery facts reference the exact outcome and supply non-empty `error` and `recovery`;
- dependency facts reference the exact outcome, supply dependency/interaction names, and require `supported: true`;
- execution-safety evidence links to the exact action, names a non-empty `mode`, and requires `bounded: true`.

`data_partition.values` is data inside one bounded fact. The engine does not expand every member into a separate obligation.

## Scoped coverage and absence

`FactClassCoverage` records `COMPLETE`, `PARTIAL`, or `UNKNOWN` coverage plus a semantic `scope`.

Positive grounding requires `COMPLETE` coverage in the same subject/action/surface scope and that coverage must contain the exact evidence IDs used by the obligation. `PARTIAL` positive evidence can still derive a useful local obligation, but its bundle remains `UNKNOWN` and the plan reports `COVERAGE_PARTIAL`.

`COMPLETE` coverage may have an empty evidence manifest. That is explicit negative evidence for its declared scope. It can prove a fact absent only when the scope matches. A complete empty scan for another route, subject, or action is **not** proof of absence in the requested journey and produces `COVERAGE_UNKNOWN` instead.

Inventories may contain multiple coverage records for one fact class when their scopes differ. Identical class/scope records are merged deterministically; conflicting completeness for the same class and scope is rejected.

## Exact nine obligation rules

Schema v1 exposes exactly these obligation kinds:

| Obligation kind | Exact required fact classes | Level |
| --- | --- | --- |
| `HAPPY_PATH` | `SURFACE`, `ACTION`, `OBSERVABLE_OUTCOME` | `SYSTEM` |
| `REQUIRED_FIELD` | `SURFACE`, `ACTION`, `FIELD`, `CONSTRAINT`, `OBSERVABLE_OUTCOME` | `SYSTEM` |
| `INVALID_FORMAT` | `SURFACE`, `ACTION`, `FIELD`, `CONSTRAINT`, `DATA_PARTITION`, `OBSERVABLE_OUTCOME` | `SYSTEM` |
| `BOUNDARY_VALUE` | `SURFACE`, `ACTION`, `FIELD`, `CONSTRAINT`, `DATA_PARTITION`, `OBSERVABLE_OUTCOME` | `SYSTEM` |
| `STATE_TRANSITION` | `SURFACE`, `ACTION`, `OBSERVABLE_OUTCOME`, `STATE_TRANSITION` | `SYSTEM` |
| `ROLE_PERMISSION` | `SURFACE`, `ACTOR_ROLE`, `ACTION`, `OBSERVABLE_OUTCOME`, `PERMISSION_RELATION` | `SYSTEM` |
| `PERSISTENCE_READ_BACK` | `SURFACE`, `ACTION`, `OBSERVABLE_OUTCOME`, `PERSISTENCE_RELATION` | `INTEGRATION` |
| `ERROR_RECOVERY` | `SURFACE`, `ACTION`, `OBSERVABLE_OUTCOME`, `ERROR_RECOVERY` | `INTEGRATION` |
| `DEPENDENCY` | `SURFACE`, `ACTION`, `OBSERVABLE_OUTCOME`, `DEPENDENCY` | `INTEGRATION` |

A `TestObligation` declares the exact rule fact classes, exact evidence IDs, subject, expected oracle, level, derivation metadata, stable obligation/claim IDs, and semantic fingerprint.

## Grounding verifier, bundles, and ledger

The authoritative claim is:

```text
TEST_OBLIGATION_GROUNDED
```

The verifier is:

```text
gvr.regression_test_obligation.v1
```

A grounding `PASS` requires:

1. every cited evidence ID exists;
2. cited evidence has exactly the fact classes required by the obligation kind;
3. the evidence forms the exact payload-ID and subject/action/surface chain;
4. specialized constraint, role, persistence, recovery, dependency, and transition semantics are valid;
5. every required fact class has complete same-scope coverage containing the exact cited facts.

A mismatch returns `UNKNOWN`, including `OBLIGATION_LINK_MISMATCH` or `OBLIGATION_COVERAGE_INCOMPLETE`. Every report is wrapped in a `VerificationBundle` containing its exact direct and coverage evidence manifest. Recording that bundle in `ClaimLedger` preserves normal stale propagation when a dependency changes.

## Stable gaps

Schema v1 includes at least these stable gap codes:

- `MISSING_NAVIGATION`;
- `MISSING_PRECONDITION`;
- `MISSING_ACTION`;
- `MISSING_ORACLE`;
- `MISSING_CONSTRAINT`;
- `MISSING_TEST_DATA_PARTITION`;
- `MISSING_ROLE_EVIDENCE`;
- `MISSING_PERSISTENCE_READ_BACK`;
- `AUTHENTICATION_UNPROVEN`;
- `EXECUTION_SAFETY_UNKNOWN`;
- `COVERAGE_PARTIAL`;
- `COVERAGE_UNKNOWN`;
- `CONTRADICTORY_EVIDENCE`;
- `UNSUPPORTED_INTERACTION`;
- `BUDGET_EXHAUSTED`.

Missing, contradictory, partial, unsupported, and budget gaps block readiness. Unknown coverage, unproven authentication, and unknown execution safety keep readiness `UNKNOWN`. A fully grounded, safely bounded plan with no gaps is `READY`. Readiness is descriptive and never an authorization signal.

## Bounds and determinism

The default budget is finite:

```text
max_obligations      256
max_bundles          256
max_evidence_records 4096
max_steps            8192
```

Canonical evidence order, exact semantic identities, scoped coverage, obligation ordering, gaps, consumption, termination, bundles, and plan fingerprints make repeated derivation deterministic. Reaching any declared bound produces `BUDGET_EXHAUSTED`, bounded output, `BUDGET_EXHAUSTED` termination, and `BLOCKED` readiness.

## Protocol

The schema-v1 operation is:

```json
{
  "schema_version": 1,
  "op": "derive_regression_test_obligations",
  "payload": {
    "inventory": {
      "schema_version": 1,
      "kind": "gvr.behavior_evidence_inventory",
      "fingerprint_format": "gvr.behavior_evidence_inventory.ieee754-json.v1",
      "evidence": [],
      "coverage": [],
      "fingerprint": "3d6cd78d55eba063f8a01cc6506ca01c72d9397df7e96992677fb1f553833ff1"
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

The protocol strictly reconstructs and fingerprints the inventory. Unknown fields, unsupported evidence kinds, invalid enum values, malformed coverage, and forged fingerprints return a machine-readable `protocol_error`.
