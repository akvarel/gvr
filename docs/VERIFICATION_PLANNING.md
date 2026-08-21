# Verification planning

Verification planning turns an exact `ClaimGraph` plus exact verifier and evidence provider bindings into an immutable sequence of work descriptions.

The planner does not run that work.

It does not call providers, verifiers, Graphify, a network, or the file system. It only validates contracts and compiles deterministic steps.

## Why planning is separate

A caller may know what it wants to verify before it has acquired evidence.

The planner answers a narrower question:

> Which exact acquisitions, atomic checks, and composite operations would be needed under these published contracts?

It does not answer whether a claim is correct. A plan therefore contains no claim result, no free-text diagnostic field, and no generic evidence adequacy field.

## Public objects

### `AtomicClaimBinding`

An `AtomicClaimBinding` connects one exact atomic claim to:

- the same `verifier_id` named by `AtomicClaim.verifier`;
- one exact verifier version;
- the exact verifier capability fingerprint;
- zero or more immutable `EvidenceRequest` objects.

Every atomic claim has exactly one binding. Composite claims do not have bindings.

Evidence request order is not semantic. Duplicate request IDs inside one binding are rejected. Reusing the same exact `(request_id, request_fingerprint)` across claims is allowed so acquisition can be shared. Requests with identical semantic fingerprints but different request IDs remain distinct executable requests, including when they belong to the same claim.

### `VerificationPlanningRequest`

A planning request contains:

- one immutable `ClaimGraph`;
- exactly one `AtomicClaimBinding` per atomic claim;
- an exact `VerifierCapabilityRegistry` and its fingerprint;
- an exact `EvidenceProviderCapabilityRegistry` and its fingerprint;
- deterministic planning budgets.

Binding order is not semantic. Missing, extra, or duplicate bindings are rejected.

The request also rejects one `request_id` reused with different request semantics. The same ID may be reused only when its canonical `EvidenceRequest.fingerprint` is identical.

"Exact" means the concrete public record types are required. Subclasses cannot replace claim graphs, claim nodes, bindings, evidence requests, capability registries, capability descriptors, or budgets and override their contract behavior.

### `VerificationPlan`

A plan contains:

- the planning request fingerprint;
- the claim graph fingerprint;
- both exact capability registry fingerprints;
- budget and consumption values;
- stable termination;
- zero or more canonical steps;
- zero or more stable structured planner issues;
- a canonical plan fingerprint.

The plan and every step are frozen records.

Each `VerificationPlanStep` has a `VerificationPlanStepKind`, a stable step ID, a canonical fingerprint, and deterministic dependency step IDs. `VerificationPlanTermination` represents the final planner state.

## Canonical step kinds

A complete plan uses only three step kinds.

### `ACQUIRE_EVIDENCE`

This step identifies:

- the exact provider ID and version;
- the exact provider capability fingerprint;
- one exact correlation request ID;
- one canonical request fingerprint;
- its request kind and requested evidence kinds.

One acquisition step represents one executable key: `(request_id, request_fingerprint)`. Reusing that same exact key across claims shares the step. Requests with identical canonical semantics but different request IDs remain separate executions and produce separate step IDs.

### `VERIFY_ATOMIC_CLAIM`

This step identifies:

- the atomic claim ID, kind, and canonical claim fingerprint;
- the exact verifier ID and version;
- the exact verifier capability fingerprint;
- acquisition steps required by the binding;
- earlier claim steps named by `AtomicClaim.dependencies`.

The planner never substitutes another verifier or version.

### `COMPOSE_CLAIM`

This step identifies:

- the composite claim ID and canonical claim fingerprint;
- the exact `AND`, `OR`, or `NOT` operator;
- the completed dependency claim steps.

Composition steps follow the same deterministic topological order as the `ClaimGraph`.

## Exact contract validation

For every atomic claim, the planner checks:

1. binding verifier ID equals `AtomicClaim.verifier`;
2. exact verifier ID and version exist in the supplied verifier registry;
3. the binding capability fingerprint matches that descriptor;
4. the verifier supports the exact claim kind and is authoritative;
5. every evidence request names an exact provider ID and version in the supplied provider registry;
6. the provider supports the request kind;
7. the provider produces every requested evidence kind;
8. source and snapshot classes match the provider contract exactly;
9. requested evidence has a structural intersection with evidence accepted by the verifier;
10. the combined valid requests include every required verifier evidence kind.

Provider `request_kind` and verifier `claim_kind` are different contract dimensions. They do not need the same text.

If a verifier requires evidence and the binding contains no request, planning fails closed with a stable issue.

## Stable issues and termination

Each `VerificationPlannerIssue` is a frozen structured record containing only:

- an uppercase stable `code`;
- optional `claim_id`;
- optional `request_id`;
- canonical structured `details`.

They contain no free-text message, claim result, or arbitrary metadata. Verdict and evidence-adequacy aliases such as `status`, `outcome`, `result`, `truth_value`, `is_sufficient`, and `evidence_adequacy` are rejected even when nested or written with different letter case or hyphenation.

Important issue codes include:

- `VERIFIER_ID_MISMATCH`;
- `UNKNOWN_VERIFIER_CAPABILITY`;
- `VERIFIER_CAPABILITY_FINGERPRINT_MISMATCH`;
- `UNSUPPORTED_CLAIM_KIND`;
- `NON_AUTHORITATIVE_VERIFIER`;
- `UNKNOWN_EVIDENCE_PROVIDER_CAPABILITY`;
- `UNSUPPORTED_REQUEST_KIND`;
- `UNSUPPORTED_REQUESTED_EVIDENCE_KIND`;
- `UNSUPPORTED_SOURCE_CLASS`;
- `UNSUPPORTED_SNAPSHOT_CLASS`;
- `STRUCTURAL_EVIDENCE_INCOMPATIBILITY`;
- `MISSING_EVIDENCE_REQUEST`;
- `MISSING_REQUIRED_EVIDENCE_KIND`;
- `BUDGET_EXHAUSTED`.

Termination is one of:

- `COMPLETE` when every contract and budget check passes;
- `UNSUPPORTED_CLAIM` when an exact binding or capability check fails;
- `BUDGET_EXHAUSTED` when required deterministic work exceeds a configured limit.

A non-complete plan contains no executable steps. This prevents callers from accidentally running a partial plan.

## Deterministic budgets

`VerificationPlanningBudget` is the immutable input limit record. It supports:

- `max_atomic_claims`;
- `max_composite_claims`;
- `max_steps`;
- `max_requests`;
- `max_dependency_edges`;
- `max_requests_per_claim`;
- `max_depth`.

`max_requests` counts unique executable `(request_id, request_fingerprint)` keys after exact sharing. Reusing the same exact request across claims consumes one request, while identical semantics under different request IDs consume separate requests. `max_steps` counts those acquisition executions plus all atomic and composite claim steps. `max_depth` counts claim nodes on the longest dependency path, so an independent claim has depth 1.

`VerificationPlanningConsumption` is the immutable output record for the corresponding measured counts.

A value equal to consumption is accepted. A lower value produces stable `BUDGET_EXHAUSTED` termination and no steps. Input insertion order does not change consumption, issues, termination, or plan identity.

## Deterministic identity

Planner artifacts use the canonical cross-language implementation in `canonical.py` with separate fingerprint domains:

```text
gvr.atomic_claim_binding.ieee754-json.v1
gvr.verification_planning_request.ieee754-json.v1
gvr.verification_plan_step.ieee754-json.v1
gvr.verification_plan.ieee754-json.v1
```

Reordering bindings, requests, claim graph nodes, registry entries, or mapping keys does not change identity when semantics are unchanged.

Changing provider identity, verifier identity or version, claim content, request identity or semantics, dependencies, operators, capability fingerprints, registry fingerprints, or budgets changes the applicable artifact identity.

Fingerprints are content identities. They are not signatures.

## Python example

```python
from gvr import (
    AtomicClaimBinding,
    VerificationPlanningBudget,
    VerificationPlanningRequest,
    compile_verification_plan,
)

request = VerificationPlanningRequest(
    claim_graph=claim_graph,
    bindings=(
        AtomicClaimBinding(
            claim_id="A",
            verifier_id="example.verifier",
            verifier_version="1",
            verifier_capability_fingerprint=verifier_capability.fingerprint,
            evidence_requests=(evidence_request,),
        ),
    ),
    verifier_capability_registry=verifier_registry,
    verifier_capability_registry_fingerprint=verifier_registry.fingerprint,
    evidence_provider_capability_registry=provider_registry,
    evidence_provider_capability_registry_fingerprint=provider_registry.fingerprint,
    budget=VerificationPlanningBudget(max_steps=20),
)

plan = compile_verification_plan(request)
```

`compile_verification_plan` performs no acquisition and no verification.

## JSON protocol

Schema v1 exposes:

```text
compile_verification_plan
```

The payload is the exact serialized `VerificationPlanningRequest`, including the claim graph, bindings, evidence requests, capability registries, registry fingerprints, budget, fingerprint formats, and fingerprints.

The parser rejects unknown fields, malformed arrays or mappings, unsupported schema or kind values, duplicate bindings, conflicting request IDs, omitted required nested fingerprints, and every claimed fingerprint mismatch. A successful response has kind `verification_plan`.

See [CLI and JSON protocol](CLI_AND_PROTOCOL.md) for the wire shape.

## Execution boundary

A complete plan can be passed to `execute_verification_plan` only through an exact `VerificationExecutionRequest`. The executor revalidates and deterministically recompiles the plan from the exact graph, request keys, capability registries, and plan budget before invoking any runtime.

Planning still has no runtime behavior. Execution adds no discovery or repair policy: it runs the exact `ACQUIRE_EVIDENCE`, `VERIFY_ATOMIC_CLAIM`, and `COMPOSE_CLAIM` steps or fails closed. See [Verification execution](VERIFICATION_EXECUTION.md).
