# Examples

The examples on this page are small on purpose.

The point is to show how GVR thinks: exact claim, exact evidence, clear rules.

## Example 1: exact text search

Suppose we have this list:

```text
apple
pear
melon
```

And someone claims:

> "Every word contains the letter `e`."

A deterministic verifier can check each word.

```text
apple  -> yes
pear   -> yes
melon  -> yes
```

Result:

```text
PASS
```

Now change the list:

```text
apple
pear
plum
```

The verifier finds:

```text
plum -> no `e`
```

Result:

```text
FAIL
```

The important point is that the verifier checks the exact character. It does not use a language model to guess what the user probably meant.

### Transformations must be explicit

Suppose the user asks to reverse every word before searching.

Then:

```text
pear -> raep
```

The transformation is part of the check.

GVR should not silently reverse text, normalize it differently, or change the requested character unless the verification request says to do that.

## Example 2: action and goal

Imagine a state:

```json
{
  "door": "closed",
  "key": "available"
}
```

Goal:

```text
door = open
```

Proposed action:

```text
Action: unlock_and_open
Precondition: key = available
Effect: door = open
```

A goal verifier can check:

1. Is the precondition true in the initial state?
2. Does the action have a supported effect?
3. Does the resulting state satisfy the goal?

If all required checks pass, the goal verification can return `PASS`.

If the key is missing, GVR should not assume the door can still be opened. The result becomes `FAIL` or `UNKNOWN` depending on the exact verifier contract and whether the missing state is known to disprove the precondition or is itself indeterminate.

## Example 3: data-flow presence

Claim:

> "A value can flow from A to C."

Graph evidence:

```text
A --FLOWS_TO--> B --PASSED_AS_ARGUMENT--> C
```

If both edges are exact, supported value-flow relations and the path is proven, the data-flow verifier can return:

```text
PASS
```

The bundle should contain the exact direct evidence records for the selected proving path.

It should not add unrelated edges just because they were found during the same traversal.

## Example 4: data-flow absence

Claim:

> "There is no supported path from A to C."

Suppose the search finds no path, but stops because the maximum depth was reached.

Result:

```text
UNKNOWN
```

Why not `PASS`?

Because this only proves:

> "No path was found before the search stopped."

It does not prove:

> "No path exists in the supported search space."

For a definitive no-path result, GVR needs a complete supported search.

## Example 5: scope matters

Suppose a search is allowed to use only this relation:

```text
FLOWS_TO
```

It finds no path.

That does not prove there is no path using:

```text
PASSED_AS_ARGUMENT
RETURNED_AS
READ_FROM
WRITTEN_TO
TRANSFORMED_BY
```

So the claim scope is part of the meaning of the result.

GVR checks that the claim scope matches the traversal scope.

This prevents a narrow search from being presented as a broad proof.

## Example 6: evidence changes after PASS

At time 1:

```text
Evidence E1 version 1
Claim C depends on E1
C = PASS
```

Later E1 changes:

```text
Evidence E1 version 2
```

The old PASS is now stale.

GVR keeps the old result in history, but the current effective result becomes:

```text
UNKNOWN
```

After C is verified again using E1 version 2, C can become fresh again.

## Example 7: same payload, different source

Suppose evidence has this payload:

```json
{"value": 42}
```

At first it comes from:

```text
source = revision-A
```

Later the same evidence ID and same payload come from:

```text
source = revision-B
```

GVR treats this as a semantic evidence change.

Why?

Because evidence is not only its payload. Where the evidence came from can matter to the truth of a claim.

Dependent claims become stale.

## Example 8: bundle tampering

A report says it depends on:

```text
E1
E2
```

But the received bundle contains only:

```text
E1
```

GVR rejects the bundle.

It does not say:

> "E1 is probably enough."

A trusted verification package must contain the exact declared evidence basis.

## Example 9: an answer GVR cannot safely verify

Claim:

> "This logo is beautiful."

There is no deterministic GVR rule for beauty.

A model can give an opinion, but that opinion should not be turned into an authoritative GVR `PASS`.

For unsupported claims, GVR should stay explicit about the limit instead of pretending everything is mechanically decidable.

## Example 10: exact plan execution does not merge request IDs

Two atomic claims depend on the same exact evidence request key:

```text
(request-A, fingerprint-X)
```

The planner emits one `ACQUIRE_EVIDENCE` step. The executor calls the exact provider once and gives the validated result only to verifier steps that depend on that acquisition step.

Now consider two requests with identical semantic content but different IDs:

```text
(request-A, fingerprint-X)
(request-B, fingerprint-X)
```

These are two executable identities. The planner emits two acquisition steps and the executor calls the provider twice. It does not merge them because doing so would erase caller-visible execution identity.

If either provider returns a malformed result, or a required result is unavailable, the dependent verifier is not allowed to manufacture `PASS`. The executor records an explicit `UNKNOWN` bundle and a failed or blocked lifecycle issue instead.
