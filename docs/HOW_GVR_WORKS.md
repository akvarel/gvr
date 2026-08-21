# How GVR works

This page shows the normal life of a verification result.

## Step 1: someone proposes a claim

The claim can come from:

- an AI model;
- an agent;
- a human;
- another program.

Example:

> "Data can flow from `userInput` to `saveToDatabase`."

At this point the claim is only a proposal. GVR does not trust it yet.

## Optional planning step: compile exact work descriptions

Before evidence exists, a caller may submit a `ClaimGraph`, exact atomic bindings, exact capability registries, and deterministic budgets to the verification planner.

The planner can describe acquisition, atomic verification, and composition steps. It does not run any of them and does not decide a claim result.

If an exact capability is missing, evidence structure does not match, required evidence is not requested, the graph is cyclic, or a budget is exceeded, planning fails closed before execution.

## Step 2: GVR receives evidence

A verifier needs evidence that matches the kind of claim.

For a text claim, the evidence may be the exact text.

For a data-flow claim, the evidence may be a Graphify traversal result.

For a goal or action claim, the evidence may be the initial state, action preconditions, effects, and the required goal state.

GVR does not want a sentence like:

> "I checked it and it seems correct."

It wants structured data that code can inspect.

## Step 3: the verifier checks rules

Each verifier has a narrow job.

It checks only the rules it understands.

If everything required by those rules is proven, it can return `PASS`.

If the rules prove the claim is false, it can return `FAIL`.

If something important is missing, incomplete, stale, ambiguous, or outside the verifier's supported area, it returns `UNKNOWN`.

## Step 4: GVR creates a report

A `VerificationReport` records the result.

A report normally tells you:

```text
verdict
verifier
issues
evidence IDs
metadata
```

This is useful for debugging because `UNKNOWN` should have a reason.

For example:

```text
UNKNOWN
reason: search was truncated
```

is much more useful than:

```text
not sure
```

## Step 5: GVR can create a VerificationBundle

For trusted transport, a result should travel with its evidence.

The bundle contains the report and the exact evidence records that the report depends on.

```text
VerificationBundle
├── report
├── evidence record A
├── evidence record B
├── optional claim dependencies
└── fingerprint
```

If the report says it depends on evidence `E1`, but `E1` is missing from the bundle, GVR rejects the bundle.

If the bundle contains unrelated evidence that the report does not use, GVR rejects that too.

The goal is simple: the package should show the exact basis of the result.

## Step 6: the ClaimLedger records dependencies

The ledger remembers the relationship between claims and evidence.

Example:

```text
Claim: FLOW_A_TO_B
    depends on
Evidence: df:123
Evidence: df:456
```

The ledger also remembers the versions of those dependencies.

## Step 7: evidence changes

Later, the source code may change.

Or a query-result evidence slot may get a new result.

Or the same evidence ID may now come from another source revision.

GVR treats a real semantic evidence change as a new evidence version.

The old dependent claim becomes `STALE`.

## Step 8: stale truth stops propagating

Suppose the old stored verdict was:

```text
PASS
```

After its evidence changes, the stored historical verdict can still be remembered as PASS, but its **effective** verdict becomes:

```text
UNKNOWN
```

until verification runs again.

This is important.

GVR does not rewrite history. It says:

> "This used to pass with the old evidence, but that result is no longer current."

## Why negative claims need more care

Positive and negative claims are often different.

To prove:

> "A path exists from A to B"

one valid path can be enough.

To prove:

> "No path exists from A to B"

you normally need to know that the supported search was complete.

If the search stopped early, GVR returns `UNKNOWN`.

This rule appears in many areas, not only graphs:

```text
finding one example can prove existence
not finding an example does not prove absence unless the search was complete
```

## What happens when evidence is ambiguous

GVR prefers `UNKNOWN` over inventing a cleaner story.

Examples:

- two different evidence records use the same ID;
- a graph boundary cannot be resolved;
- a source symbol is ambiguous;
- a query says it was complete but its accounting is contradictory;
- a report references evidence that is missing.

These are not situations where GVR should "pick the most likely answer."

It fails closed.

## What "fail closed" means

Fail closed means:

> When GVR cannot prove that a definitive result is safe, it does not turn the uncertainty into success.

In practice this usually means returning `UNKNOWN` or rejecting malformed input.
