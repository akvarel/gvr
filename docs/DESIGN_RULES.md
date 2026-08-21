# GVR design rules

GVR is conservative on purpose.

These rules explain why.

## Rule 1: do not turn uncertainty into success

If a verifier does not have enough safe evidence, the result is `UNKNOWN`.

Do not change this into PASS because:

- the answer looks reasonable;
- an AI is confident;
- most evidence points in one direction;
- no counterexample was found in a partial search.

This is called **fail closed** behavior.

## Rule 2: evidence and verdict are different things

Evidence is observed data.

A verdict is the result of applying verifier rules to that data.

GVR should not let an evidence producer declare its own final truth just by putting `PASS` inside a payload.

## Rule 3: scope is part of meaning

A claim can change meaning when its scope changes.

For example:

```text
"No path exists using relation X"
```

is not the same claim as:

```text
"No path exists using any supported relation"
```

Direction, allowed relations, stop nodes, source revision, and other important bounds must stay attached to the claim when they affect truth.

## Rule 4: negative claims need complete search rules

A witness can often prove that something exists.

Absence is harder.

For example:

```text
one valid path       -> enough to prove "a path exists"
no path found so far -> not enough to prove "no path exists"
```

A negative result needs an explicit completeness contract.

## Rule 5: a trusted result travels with its proof basis

For remote or stored verification, GVR uses `VerificationBundle`.

A bundle keeps together:

- report;
- exact evidence records used by the report;
- dependencies;
- deterministic fingerprint.

The consumer should not have to guess which evidence was used.

## Rule 6: evidence changes make old results stale

A correct answer can become outdated.

If evidence changes, dependent claims become stale.

A stale historical PASS must not be treated as a current PASS.

Its effective result becomes `UNKNOWN` until reverification.

## Rule 7: source matters

Two pieces of evidence can have the same payload but come from different sources.

Example:

```text
payload = {"value": 42}
source = revision-A
```

and later:

```text
payload = {"value": 42}
source = revision-B
```

These are not automatically the same evidence state.

Typed evidence versioning includes the evidence kind, payload, source, and producer fingerprint.

## Rule 8: do not hide ambiguity

If two different evidence records claim the same stable ID, GVR rejects the ambiguity.

It should not silently keep the first one or choose the one that makes the claim pass.

## Rule 9: deterministic means the same meaning gives the same identity

Ordering that has no semantic meaning should not change a fingerprint.

Examples:

- dictionary key order;
- evidence input order;
- normalized dependency order where dependency order is not meaningful.

Semantic changes should change identity.

Examples:

- different verdict;
- different evidence payload;
- different source;
- different claim scope;
- different dependency set.

## Rule 10: fingerprints are not signatures

A content fingerprint tells us whether content is the same.

It does not prove who created the content.

Remote authentication, signatures, PKI, and attestation are separate trust problems.

## Rule 11: do not create a second hidden source of truth

The Graphify adapter consumes Graphify traversal evidence.

GVR should not secretly parse source code again and build another graph just to get a nicer result.

That would create two different source-analysis systems with possible disagreement.

The intended split is:

```text
Graphify -> source-derived graph evidence
GVR      -> verification rules over evidence
```

## Rule 12: product policy is not verification truth

GVR decides verification truth under verifier rules.

A product may later decide what a PASS allows a user or agent to do.

Those are different questions.

Example:

```text
GVR: "the claim passed"
```

does not automatically mean:

```text
"deploy to production"
"delete data"
"spend money"
```

Authorization belongs outside the generic GVR truth layer.

## Rule 13: prefer small verifiers

A verifier should do one clear job well.

Small deterministic checks are easier to:

- test;
- audit;
- replay;
- compare;
- combine later.

The goal is not to create one giant verifier that tries to understand everything.

## Rule 14: UNKNOWN is useful information

A high UNKNOWN rate can reveal that the system needs:

- better evidence;
- better source coverage;
- another verifier;
- clearer scope;
- a larger but still bounded search.

Do not hide this information by converting UNKNOWN into a confidence percentage.

## Rule 15: do not launder a test obligation

A proposed test duty is not grounded merely because it cites some evidence ID.

The evidence kind, exact payload relationship IDs, subject, action, surface, rule-specific relation semantics, and local coverage must all match the obligation rule. A route, button, field, requirement, or generic change fact alone is never enough. Partial or wrong-scope coverage stays non-passing, and complete empty coverage proves absence only inside its declared scope.

An obligation plan's `READY` state describes completeness under the declared evidence and finite derivation bounds. It never authorizes merge, deployment, code generation, test execution, or another external side effect.
