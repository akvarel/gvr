# Verification sessions

A verification session lets GVR work with more than one claim at a time.

You can think of it as a small proof graph.

## Why sessions exist

One real decision often depends on several smaller claims.

For example:

```text
A: the deployed revision is the expected revision
B: data can flow from input X to output Y
C: the important behavior did not regress

ROOT = A AND B AND C
```

Checking only ROOT as one large sentence would be hard to audit.

GVR keeps the smaller claims separate and combines their current results.

## Atomic claims

An atomic claim is checked by one verifier.

Example:

```text
A = "Data can flow from X to Y"
```

An atomic claim has:

- a stable ID;
- a claim kind;
- a structured specification;
- a required verifier;
- an optional scope;
- explicit dependencies when needed.

Trusted atomic results enter a session as `VerificationBundle` objects.

A naked remote `PASS` is not enough.

## Composite claims

A composite claim combines other claims.

GVR currently supports three operators.

### AND

```text
PASS    AND PASS    = PASS
PASS    AND UNKNOWN = UNKNOWN
PASS    AND FAIL    = FAIL
```

### OR

```text
FAIL    OR FAIL    = FAIL
FAIL    OR UNKNOWN = UNKNOWN
FAIL    OR PASS    = PASS
```

### NOT

```text
NOT PASS    = FAIL
NOT FAIL    = PASS
NOT UNKNOWN = UNKNOWN
```

There are no confidence scores and no voting.

## ClaimGraph

`ClaimGraph` stores the claims and their dependencies.

Example:

```text
A -----+
       |
B -----+--> ROOT = AND(A, B)
```

The graph rejects bad structures such as:

- unknown dependency IDs;
- a claim depending on itself;
- dependency cycles;
- duplicate claim IDs with different meanings;
- `NOT` with more than one dependency.

## Freshness still matters

Suppose:

```text
A = PASS
B = PASS
ROOT = PASS
```

Then the evidence for A changes.

A's old stored result may still exist in history, but A becomes stale.

Current truth becomes:

```text
A    = UNKNOWN
ROOT = UNKNOWN
```

After A is verified again, composite claims must be recomputed before their new result is current.

## Missing claims stay UNKNOWN

Suppose ROOT needs A and B, but only A has a bundle.

GVR does not guess B.

It does not turn missing B into FAIL either.

It keeps B as:

```text
UNKNOWN
```

and ROOT is also UNKNOWN when ROOT needs B.

## Budgets

A session can have deterministic work limits.

Current limits can cover:

- number of claims;
- number of bundles;
- number of evidence records;
- evidence bytes;
- generic processing steps.

If a budget stops work before a required claim is ready, GVR does not return a false final PASS or FAIL for that root.

The affected root stays UNKNOWN.

The session records:

```text
BUDGET_EXHAUSTED
```

## Termination reasons

A session currently uses these main termination states:

- `COMPLETE` — the session finished its deterministic composition work;
- `BUDGET_EXHAUSTED` — a declared limit stopped processing;
- `UNSUPPORTED_CLAIM` — some needed current claim state is not available.

`COMPLETE` does not mean every root must be PASS.

A complete session may contain a valid FAIL or UNKNOWN result.

It means the requested composition work itself finished without a cutoff or stale/missing required state.

## Session fingerprint

A session has a deterministic fingerprint.

It covers semantic state such as:

- the claim graph;
- selected roots;
- bundle fingerprints;
- current claim verdicts and freshness;
- claim-local semantic revisions;
- budget declaration and deterministic consumption;
- termination reason.

Independent bundles can arrive in a different order without changing the final session fingerprint when the final semantic state is the same.

Internal ClaimLedger mutation clocks are audit data. They are not used as semantic session identity.

## JSON protocol

Schema version 1 exposes:

```text
compose_verification_session
```

The request contains:

- a claim graph;
- root claim IDs;
- materialized verification bundles for atomic claims;
- a budget.

The response contains:

- canonical claim graph;
- claim states;
- root verdicts;
- bundle/evidence references;
- budget accounting;
- termination reason;
- session fingerprint.

Malformed graphs or bundles fail closed as protocol errors.

## One important boundary

A `VerificationSession` composes verification state.

It does not decide product permissions.

For example, this is still outside GVR:

```text
ROOT = PASS
therefore deploy to production
```

A product policy layer must decide whether a verified PASS is enough for a real-world action.
