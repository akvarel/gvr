# Core concepts

This page explains the main GVR words.

You can think of GVR as a careful fact-checking system.

## Claim

A **claim** is something we want to check.

Examples:

- "This file contains the word `hello`."
- "The value can flow from function A to function B."
- "This action keeps the required postcondition true."
- "There is no supported path from A to B."

A good claim is specific. The verifier should know exactly what is being asked.

## Evidence

**Evidence** is the data used to check a claim.

Examples:

- a string or list of strings;
- a JSON document;
- a test result;
- a code-analysis result;
- a graph edge;
- a graph traversal result;
- a known program state.

Evidence is not the same as a verdict.

Evidence says:

> "Here is what we observed."

A verifier says:

> "Given that evidence, here is the result of the claim."

## Verifier

A **verifier** is code that knows how to check one kind of claim.

A verifier should have clear rules.

For example, a text verifier may know how to check whether an exact character appears in every item in a list.

A data-flow verifier may know which graph relations count as value flow and which relations do not.

A verifier should not silently guess missing information.

## Falsification strategy

A **falsification strategy** is deterministic code that tries to challenge an atomic claim before its verifier publishes a verdict.

It may search for a witness or counterexample, check an invariant or representation, apply a named metamorphic transformation, or recompute through an independent path.

A strategy returns probes, coverage, and provenance. It does not return verification truth. The declared verifier still decides `PASS`, `FAIL`, or `UNKNOWN`.

If a declared counterexample exists, a verifier cannot ignore it and return `PASS`. If the verifier requires complete falsification before `PASS`, missing or partial output keeps the claim `UNKNOWN`.

## Verdict

A **verdict** is the result from a verifier.

GVR uses:

- `PASS`
- `FAIL`
- `UNKNOWN`

These are not confidence scores.

GVR does not say:

```text
83% PASS
```

A claim is either proven by the verifier rules, disproven by the verifier rules, or not safely decided.

## VerificationReport

A **VerificationReport** is the verifier result plus useful details.

It can contain:

- the verdict;
- the verifier name;
- issues found during verification;
- evidence IDs used by the result;
- metadata that explains the check.

The report tells us what happened, but a remote program should not need to fetch all evidence again just to understand the proof basis.

That is why GVR also has bundles.

## VerificationBundle

A **VerificationBundle** is a self-contained verification package.

It contains:

```text
VerificationReport
+ exact Evidence records used by the report
+ claim dependency IDs, when needed
+ deterministic fingerprint
```

A simple analogy is a school answer with the working shown.

A verdict alone is:

> "Answer: 42."

A bundle is:

> "Answer: 42, and here is the exact work and source data used to get it."

The bundle rejects missing evidence and unrelated extra evidence. This makes it harder to accidentally send a result without the proof basis that produced it.

## Fingerprint

A **fingerprint** is a SHA-256 hash of the important semantic content.

It helps answer this question:

> "Is this exactly the same verification content as before?"

If important content changes, the fingerprint changes.

For transport between programming languages, GVR uses a defined canonical format so Python and another language can calculate the same bundle fingerprint from the same JSON meaning.

A fingerprint is not a digital signature.

It proves content identity, not who created the content.

## ClaimLedger

The **ClaimLedger** keeps verified claims and their dependencies.

Think of it like this:

```text
Claim C depends on Evidence E
```

When C is verified, the ledger remembers which version of E was used.

Later, if E changes, C must not stay trusted as if nothing happened.

The ledger marks C as stale.

## Fresh and stale

A verified result can be:

- **FRESH** — its dependencies are still the same versions used during verification;
- **STALE** — at least one dependency changed or disappeared.

A stale old `PASS` is not a current PASS.

Its effective result becomes `UNKNOWN` until the claim is verified again.

This rule prevents an old correct answer from becoming a new wrong answer after the world changes.

## Source and producer fingerprint

An Evidence record can also carry information such as:

- `kind` — what type of evidence this is;
- `source` — where it came from;
- `fingerprint` — a fingerprint supplied by the evidence producer.

GVR treats these fields as part of the meaning of typed evidence.

If the same evidence ID now points to another source or another producer fingerprint, that is a real evidence change and dependent claims become stale.

## Scope

Some claims are only meaningful inside a specific **scope**.

For example, a graph question may depend on:

- search direction;
- allowed relation types;
- stop nodes;
- search bounds;
- source revision.

A result for one scope must not be reused as if it proved a larger scope.

Example:

> "No path was found while checking only relation X"

must not become:

> "No path exists using any relation."

GVR binds scope to the claim when scope changes the meaning of the claim.

## Dependency

A claim can depend on evidence. A claim can also depend on another claim.

For example:

```text
Claim A: the input is valid
Claim B: the transformation is correct
Claim C: the final result is safe

C depends on A and B
```

If A or B becomes stale, C must not remain trusted.

This is called **transitive stale propagation**.

## Verification execution

A `VerificationPlan` is only a deterministic work description. A `VerificationExecutionRequest` binds that exact complete plan to:

- the exact `ClaimGraph` and roots;
- exact provider, optional falsification, and verifier runtime registries;
- exact evidence requests keyed by `(request_id, request_fingerprint)`;
- deterministic execution limits.

The executor revalidates and recompiles the plan before invocation. It then records provider results, validated falsification results, verifier reports, bundles, step lifecycle, issues, counters, termination, and a final `VerificationSession` in one `VerificationExecutionResult`.

Execution identity is semantic. It includes exact artifact fingerprints and excludes correlation IDs, clocks, random values, runtime object addresses, and raw exception text.

Execution state is not product policy. `COMPLETE`, `FAILED_CLOSED`, and `LIMIT_EXHAUSTED` describe how the plan ran; they do not authorize a deployment, deletion, payment, or another side effect.
