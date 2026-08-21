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
        |       verifier        |
        | clear rules for one   |
        | kind of claim         |
        +-----------------------+
                   ^
                   |
                evidence
                   |
       +-----------+-----------+
       |                       |
       v                       v
 direct structured data   evidence provider
                           or adapter such as Graphify
       |                       |
       +-----------+-----------+
                   |
                   v
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
- calls the correct verifier or session composer;
- returns a machine-readable response;
- returns a protocol error for malformed input.

It should not invent evidence or change truth rules.

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

`EvidenceRequest` names one exact provider ID and version, the request kind, required and accepted evidence kinds, input, and bounds. `EvidenceProviderCapability` publishes the exact request kinds and produced evidence kinds a provider can support. `EvidenceProviderResult` carries acquisition status, coverage, evidence records, issues, and the capability fingerprint used for validation.

The built-in schema-v1 evidence provider registry is honestly empty. It still defines deterministic lookup, exact runtime provider dispatch, fail-closed unavailable results, canonical fingerprints, and compatibility checks against verifier capabilities.

The schema-v1 protocol exposes `describe_evidence_provider_capabilities` with optional `request_kind` and `evidence_kind` filters, and `validate_evidence_provider_result`, which parses serialized request, capability, and result payloads and returns either a normalized `evidence_provider_result` or a machine-readable protocol error.

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

Planned runtime layers include ideas such as:

- evidence provider protocol;
- deterministic verification planning;
- automatic evidence acquisition;
- counterexample and falsification support.

These should be treated as available only after they are merged into the integration branch and documented as current behavior.
