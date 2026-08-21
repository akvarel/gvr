# GVR Documentation

This documentation is written for people who are new to GVR.

You do not need to know AI research terms to read it. You do not need to know graph theory. You only need basic programming knowledge.

## Start here

1. [What is GVR?](WHAT_IS_GVR.md) — the main idea in plain English.
2. [Core concepts](CORE_CONCEPTS.md) — claim, evidence, verifier, verdict, bundle, ledger, and freshness.
3. [How GVR works](HOW_GVR_WORKS.md) — what happens from a claim to a final result.
4. [Examples](EXAMPLES.md) — small examples with text, program behavior, and data flow.
5. [Verification sessions](VERIFICATION_SESSIONS.md) — how several claims are combined safely.
6. [Verifier capabilities](VERIFIER_CAPABILITIES.md) — how exact verifier and evidence provider contracts are described and discovered.
7. [Architecture](ARCHITECTURE.md) — how the current GVR pieces fit together.
8. [CLI and JSON protocol](CLI_AND_PROTOCOL.md) — how another program can call GVR.
9. [Code map](CODE_MAP.md) — where the main pieces live in the repository.
10. [Design rules](DESIGN_RULES.md) — the safety rules GVR follows and why they exist.

## The shortest explanation

GVR checks claims using evidence.

A claim is something we want to check, for example:

> "The value can flow from A to B."

GVR does not answer this because an AI model sounds confident. It asks a verifier to check evidence.

The verifier returns one of three results:

- `PASS` — the claim was proven by the evidence that the verifier accepts.
- `FAIL` — the claim was disproven by the evidence that the verifier accepts.
- `UNKNOWN` — GVR does not have enough safe evidence to say PASS or FAIL.

`UNKNOWN` is an important result. It means "do not pretend we know."

## One picture

```text
claim
  |
  v
evidence
  |
  v
verifier
  |
  v
PASS / FAIL / UNKNOWN
  |
  v
VerificationBundle
  |
  v
ClaimLedger
  |
  v
ClaimGraph / VerificationSession
```

The bundle keeps the result together with the evidence used for that result.

The ledger remembers which result depends on which evidence. If the evidence changes, the old result becomes stale and must not be treated as current truth.

A verification session can combine several current claims with exact `AND`, `OR`, and `NOT` rules. Missing or stale required claims stay `UNKNOWN`.

A verifier capability registry describes the exact verifier IDs and contracts GVR currently publishes. A pure evidence provider capability registry separately describes exact `(provider_id, version)` acquisition contracts, including source and snapshot classes, and can be queried by deterministic `request_kind` and `evidence_kind` filters. Runtime provider bindings live in another exact registry. None of these registries silently ranks or substitutes entries, and only the runtime provider registry executes acquisition.

## If you want to contribute

Read [the code map](CODE_MAP.md) first.

Then read the tests next to the area you want to change. In GVR, adversarial tests are part of the design: they try to make the runtime produce a false definitive PASS or FAIL.

When adding or changing a verifier, keep the main rule:

> If the verifier cannot safely prove PASS or FAIL under its contract, return UNKNOWN.
