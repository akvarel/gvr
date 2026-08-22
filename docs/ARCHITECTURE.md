# GVR architecture

This page shows how the current GVR pieces fit together.

## The big picture

```text
                 caller
          AI / agent / human / app
                   |
                   v
          structured claim/request
                   |
                   v
        +-----------------------+
        |   GVR API / protocol  |
        +-----------------------+
                   |
                   v
        +-----------------------+
        | verification planner  |
        | exact bindings, DAG,  |
        | capability snapshots  |
        +-----------------------+
                   |
                   v
            VerificationPlan
                   |
                   v
        +-----------------------+
        | verification executor |
        | exact runtimes,       |
        | requests, and limits  |
        +-----------------------+
             |             |
             v             v
    exact provider     exact verifier
       runtime            runtime
             |             ^
             v             |
 EvidenceProviderResult ---+
                           |
                 VerificationReport
                           |
                           v
                 VerificationBundle
                           |
                           v
                    ClaimLedger
                           |
                           v
                    ClaimGraph
                           |
                           v
                VerificationSession
                           |
                           v
               optional durable stores
             SQLite evidence / bundles /
              claims / sessions / index
```

The important idea is separation.

Each part has one job.

## Caller

The caller asks GVR to check something.

The caller may be:

- a Python program;
- a command-line script;
- an AI agent;
- another service.

The caller is allowed to propose a claim.

The caller is not allowed to make that claim true just by saying it is true.

## API and protocol layer

GVR can be called directly as a Python library.

It also has a schema-v1 JSON protocol.

The protocol layer:

- checks request shape;
- converts JSON into GVR data models;
- calls the correct planner, executor, verifier, or session composer;
- returns a machine-readable response;
- returns a protocol error for malformed input.

It should not invent evidence or change truth rules.

## Verification planner layer

The planner accepts a `ClaimGraph`, exact `AtomicClaimBinding` records, exact verifier and provider capability registry fingerprints, and deterministic budgets.

It validates exact IDs, versions, claim and request kinds, evidence-kind structure, source/snapshot classes, required evidence kinds, graph dependencies, and work limits. It then emits only `ACQUIRE_EVIDENCE`, `VERIFY_ATOMIC_CLAIM`, and `COMPOSE_CLAIM` steps in deterministic order.

The planner invokes nothing. It has no runtime provider bindings and does not call verifiers, Graphify, a network, or the file system. Non-complete planning returns stable structured issues and no executable steps.

## Verification executor layer

The executor accepts one exact complete `VerificationPlan`, the exact `ClaimGraph`, exact request identities, selected session roots, exact verifier and provider runtime registries, and deterministic execution limits.

Before invocation it reconstructs every nested fingerprinted contract, recompiles the expected plan, and checks exact DAG dependencies, step IDs, claim identities, capability identities, runtime keys, and request keys. A mismatch fails before any runtime call.

`ACQUIRE_EVIDENCE` dispatches once through the exact `EvidenceProviderRuntimeRegistry`. Operational provider metadata is carried in an integrity-protected `AuditObservation`. Semantic coverage is determined by explicit placement, not lexical field names, so domain fields such as `run_id`, `trace_id`, `execution_id`, or `request_count` remain valid fingerprinted semantics when placed in coverage maps. `VERIFY_ATOMIC_CLAIM` receives only directly reachable evidence, audit-free semantic acquisition projections, and exact claim dependencies. `COMPOSE_CLAIM` uses the existing session tri-state logic. Runtime exceptions, malformed artifacts, invalid prerequisites, and limit exhaustion materialize explicit lifecycle issues and preserve affected claims as `UNKNOWN`; no fallback, ranking, scope broadening, product policy, or LLM is present.

See [Verification execution](VERIFICATION_EXECUTION.md) for the full contract.

When the caller explicitly supplies storage or a unit of work, the executor records completed provider evidence metadata, explicit semantic slot versions or direct immutable evidence, every exact acquisition dependency, falsification and bundle records, claim bases, graph and plan references, execution audit observations, and the sealed session in one logical transaction before returning. The exact records returned by each write are revalidated against the current execution and threaded into downstream claim and session records. Same-domain records from another still-current basis are never reselected by domain fingerprint. Persistence failure raises rather than returning an unstored `PASS`.

## Durable storage layer

The durable layer is optional and has no effect on execution fingerprints when omitted. Five generic protocols separate evidence, bundles, claims, sessions, and reverse dependencies. `SQLiteStorage` is the standard-library reference adapter.

Evidence artifacts are immutable and content-addressed. Replacement is opt-in: an `EvidenceProviderResult` may carry canonical `EvidenceSlotIdentity` records built from stable provider/source/request semantics. The identity excludes request correlation, provider version, snapshot, and evidence content. Raw `Evidence.id` is never a global mutable slot. Evidence without a declaration remains a direct immutable dependency.

Replaceable slots append versions and atomically move one authoritative current pointer. Domain bundles, falsification results, and sessions use separate durable record fingerprints for exact historical dependency bases. Dependency records are keyed independently of raw evidence ID, so two source/request acquisitions that emit one identical ID remain distinct. Executor recording threads the exact bundle and falsification records produced for that execution through claim and session records, including A to B to reopen to replay A histories. Session plan/execution documents, correlation IDs, and nested provider audit observations are audit data, not truth-currentness inputs. Reverse edges are indexed, so a slot change invalidates only reachable exact records:

```text
slot version -> bundle or falsification record -> claim versions -> session records
```

Current and stale state is structural. No TTL, cache entry, file timestamp, or session scan decides truth. Historical artifacts remain immutable and readable. See [Durable storage](DURABLE_STORAGE.md).

## Verifier layer

A verifier knows how to check one kind of claim.

Examples in the current codebase include:

- goal and action checks;
- exact text search;
- functional regression checks;
- data-flow claims.

A verifier should be narrow enough that its behavior can be tested clearly.

## Evidence layer

Evidence is the structured data a verifier uses.

Some evidence comes directly from the caller.

Other evidence comes from an external producer.

### Graphify example

For source-code data flow:

```text
source code
    |
    v
Graphify
    |
    v
bounded traversal result
    |
    v
GVR Graphify adapter
    |
    v
GVR data-flow verifier
```

Graphify answers source-analysis questions and produces graph evidence.

GVR checks verification claims against that evidence.

GVR does not secretly build another source graph in the verifier.

## Evidence provider layer

An evidence provider is an acquisition contract, not a truth-producing verifier.

`EvidenceRequest` names one exact provider ID and version, a request kind, requested evidence kinds, optional explicit source/snapshot classes, subject/spec, semantic scope, source/snapshot context, and bounds. Its semantic fingerprint excludes only the correlation request ID. Its separate slot-request identity also excludes provider version and snapshot context. `EvidenceProviderCapability` publishes exact request kinds, produced evidence kinds, source classes, and snapshot classes; empty class lists explicitly accept only unclassified requests. `EvidenceProviderResult` references the exact request fingerprint and carries exact provider identity, acquisition status, explicit fingerprinted semantic coverage, an optional separately fingerprinted `AuditObservation`, deeply snapshotted evidence, stable code/category `EvidenceProviderIssue` diagnostics with no free text or verdict, the capability fingerprint used for validation, and optional exact `EvidenceSlotIdentity` declarations for explicitly replaceable evidence.

The built-in schema-v1 `EvidenceProviderCapabilityRegistry` is honestly empty and purely descriptive. Its public request validator enforces exact source/snapshot class compatibility. `EvidenceProviderRuntimeRegistry` separately owns detached immutable runtime bindings, fingerprints the exact capability snapshot and registered runtime keys, and uses the validator before every invocation. It rechecks provider identity, converts only real execution exceptions to deterministic allowlisted secret-safe categories, and leaves malformed returned results as contract errors. Provider-to-verifier adapters expose structural evidence-kind facts without a generic sufficiency or truth field and strip audit metadata from the verifier/falsification semantic input.

The schema-v1 protocol exposes `describe_evidence_provider_capabilities` with optional `request_kind` and `evidence_kind` filters, and `validate_evidence_provider_result`, which parses serialized request, capability, and result payloads and returns either a normalized `evidence_provider_result` or a machine-readable protocol error.

The schema-v1 `compile_verification_plan` operation separately parses exact claim, binding, request, registry, budget, and fingerprint artifacts and returns an immutable `verification_plan`. It does not dispatch through the runtime provider registry. The schema-v1 `execute_verification_plan` operation accepts the resulting exact plan plus runtime registry descriptors, exact request identities, roots, and deterministic limits, then returns a `verification_execution_result`.

## VerificationReport

The report is the immediate result of a verifier.

It contains the verdict and supporting information such as issues and evidence IDs.

A report is useful inside one process, but evidence IDs alone are not enough for trusted remote transport.

## VerificationBundle

A bundle makes the verification self-contained.

```text
bundle
├── report
├── exact evidence records
├── optional claim dependencies
├── fingerprint format
└── fingerprint
```

The bundle validates that the evidence set exactly matches the report dependencies.

This makes it possible for another program to receive both the result and its proof basis.

## Canonical fingerprint layer

A bundle fingerprint must mean the same thing in different programming languages.

GVR therefore uses a defined canonical transport format instead of relying on whatever JSON string a language happens to produce.

The canonical layer handles details such as:

- number representation;
- deterministic map ordering;
- Unicode-safe ordering;
- unsupported values.

This matters when a Python producer sends a bundle to a TypeScript, Java, Go, or other consumer that wants to independently verify the fingerprint.

## ClaimLedger

The ledger tracks what a claim depends on.

Example:

```text
Claim C
├── Evidence E1 version 10
└── Evidence E2 version 12
```

If E1 changes, C becomes stale.

If another claim depends on C, that dependent claim also becomes stale.

This is how GVR prevents old results from silently surviving source changes.

## ClaimGraph

`ClaimGraph` describes how several claims depend on each other.

It supports:

- atomic claims checked by verifiers;
- composite claims using exact `AND`, `OR`, and `NOT` logic.

Example:

```text
A -----+
       |
B -----+--> ROOT = AND(A, B)
```

The graph rejects cycles, unknown dependencies, malformed operators, and conflicting duplicate claim IDs.

## VerificationSession

`VerificationSession` combines current bundle-backed claim states into one deterministic multi-claim state.

A session contains things such as:

- the claim graph;
- selected root claims;
- bundle fingerprints for atomic claims;
- stored and effective verdicts;
- freshness;
- deterministic budgets and consumption;
- termination reason;
- session fingerprint.

If a needed claim is stale or missing, a dependent root stays `UNKNOWN`.

A budget cutoff also leaves affected roots `UNKNOWN` instead of creating a false final PASS or FAIL.

Independent bundle arrival order does not change semantic session identity when the final semantic state is the same.

The raw ClaimLedger mutation clock is audit data and is not used as session semantic identity.

See [Verification sessions](VERIFICATION_SESSIONS.md) for a simpler walkthrough.

## Historical verdict vs current verdict

GVR separates stored history from current effective truth.

Example:

```text
yesterday:
C = PASS using Evidence E version 1

now:
Evidence E is version 2
```

GVR can remember that yesterday's verification was PASS.

But current effective C is:

```text
UNKNOWN
```

until C is verified again.

The same rule continues through a ClaimGraph: a dependent composite claim becomes effectively UNKNOWN when its support is stale.

## Verifier capability registry

`VerifierCapabilityRegistry` is a descriptive layer beside the executable verifier layer.

It contains immutable `VerifierCapability` records keyed by exact verifier ID and version. A record declares:

- published claim and evidence kinds;
- input and output schemas when those schemas are actually defined;
- D0, D1, O1, or M1 determinism semantics;
- side-effect, cost, bounds, coverage, and authority properties.

The capability registry is intentionally not `VerifierRegistry`. It does not execute verifier objects, rank candidates, acquire evidence, or select a substitute for an `AtomicClaim`.

Descriptor and registry fingerprints use the strict language-neutral canonical layer with their own domain formats. Contract list order and mapping key order are normalized. Human descriptions do not affect semantic identity.

The built-in snapshot uses exact IDs emitted by current runtime reports. Where GVR does not yet publish a stable `AtomicClaim.claim_kind`, `Evidence.kind`, or formal schema, the descriptor stays empty instead of inventing one.

The schema-v1 `describe_verifier_capabilities` operation exposes this snapshot and supports deterministic claim-kind and authoritative-only filters.

See [Verifier capabilities](VERIFIER_CAPABILITIES.md) for the full contract.

## Falsification layer

`FalsificationStrategyCapabilityRegistry` is a descriptive registry of exact immutable strategy contracts. `FalsificationStrategyRuntimeRegistry` separately binds exact side-effect-free runtimes. Neither registry ranks or selects a strategy.

The caller explicitly attaches `FalsificationStrategyBinding` records to an `AtomicClaimBinding`. The planner validates the exact strategy ID, version, capability fingerprint, claim-kind support, verifier acceptance, and budget before emitting `RUN_FALSIFICATION` steps.

The executor runs each exact strategy only after its evidence and claim prerequisites. It validates result identity, probes, coverage, provenance, and fingerprint, then exposes the result only to the declared verifier. A strategy result never becomes truth directly. A verifier remains responsible for `PASS`, `FAIL`, or `UNKNOWN`.

Two executor gates prevent unsafe `PASS`:

- a declared counterexample cannot be ignored;
- `REQUIRED_BEFORE_PASS` cannot be satisfied by missing or incomplete output.

See [Falsification](FALSIFICATION.md) for the exact built-in IDs, finite Unicode contract, independent recomputation, and metamorphic semantics.

## What is outside the GVR core

The generic GVR core should not contain private product decisions such as:

- tenant billing;
- customer permissions;
- production deployment authorization;
- commercial risk policy;
- private incident-routing logic.

A product can use GVR truth, but product policy is a separate layer.

## What is being built next

GVR is under active development.

Potential later layers include:

- separately governed plugin loading and attestation;
- additional built-in verifier and provider runtimes once their public contracts are stable.

Automatic ranking, fallback, scope broadening, product policy, and LLM authority are not hidden future behavior of the executor. New capabilities should be treated as available only after they are merged and documented as current behavior.
