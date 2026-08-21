# GVR Documentation

This documentation is written for people who are new to GVR.

You do not need to know AI research terms to read it. You do not need to know graph theory. You only need basic programming knowledge.

## Start here

1. [What is GVR?](WHAT_IS_GVR.md) — the main idea in plain English.
2. [Core concepts](CORE_CONCEPTS.md) — claim, evidence, verifier, verdict, bundle, ledger, and freshness.
3. [How GVR works](HOW_GVR_WORKS.md) — what happens from a claim to a final result.
4. [Examples](EXAMPLES.md) — small examples with text, program behavior, and data flow.
5. [CLI and JSON protocol](CLI_AND_PROTOCOL.md) — how another program can call GVR.
6. [Design rules](DESIGN_RULES.md) — the safety rules GVR follows and why they exist.

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
```

The bundle keeps the result together with the evidence used for that result.

The ledger remembers which result depends on which evidence. If the evidence changes, the old result becomes stale and must not be treated as current truth.
