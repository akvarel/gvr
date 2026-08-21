# What is GVR?

GVR means **General Verification Runtime**.

It is a small system for checking whether a claim is supported by evidence.

The main idea is simple:

> An AI may suggest an answer. GVR should check the parts that can be checked.

## Why this is useful

AI models can make very small mistakes.

For example, an AI can:

- count letters incorrectly;
- confuse one character with another;
- use the wrong file or code revision;
- say that a path does not exist after checking only part of the graph;
- keep using an old result after the source data changed.

These mistakes can look small. But many small mistakes can build a wrong final answer.

GVR tries to catch this kind of problem early.

## GVR is not another AI judge

A common way to check an AI answer is to ask another AI:

> "Is this answer correct?"

That can help, but the second AI can make the same kind of mistake.

GVR takes a different approach when possible.

It uses code with clear rules.

For example:

- exact string search;
- exact arithmetic;
- explicit state checks;
- code-flow evidence;
- known preconditions and postconditions;
- deterministic graph traversal results.

This does not mean GVR can check every sentence in the world.

If GVR cannot safely check something, the correct answer is `UNKNOWN`.

## The three results

GVR uses only three main truth results.

### PASS

`PASS` means the verifier found enough valid evidence to prove the claim under its rules.

Example:

> Claim: "The list contains the exact string `apple`."

If the verifier reads the complete list and finds `apple`, it can return `PASS`.

### FAIL

`FAIL` means the verifier found enough valid evidence to disprove the claim.

Example:

> Claim: "2 + 2 = 5."

A deterministic arithmetic verifier can return `FAIL`.

### UNKNOWN

`UNKNOWN` means GVR cannot safely say PASS or FAIL.

Example:

> Claim: "There is no path from A to B."

If the graph search stopped early, GVR must not say the path does not exist. It returns `UNKNOWN`.

This is one of the most important GVR rules:

> Missing proof is not proof of failure.

## GVR separates two jobs

There are two different jobs in an AI system.

### Job 1: propose

An AI, agent, or human can suggest:

- an answer;
- a plan;
- a code change;
- a possible cause of an incident;
- a claim that should be true.

### Job 2: verify

GVR checks the parts that have a clear verification method.

This separation matters because a system should not be allowed to prove its own guess just by sounding confident.

## A simple example

Suppose an AI says:

> "The letter `e` appears in every word in this list."

A GVR-style verifier does not reason about how likely that sounds.

It can do this:

```text
1. Get the exact list.
2. Keep the exact character being searched for.
3. Check each word character by character.
4. Record which words match and which do not.
5. Return PASS, FAIL, or UNKNOWN.
```

If one word does not contain `e`, the claim is false.

The important part is that the final result comes from an explicit check, not from language-model confidence.

## What GVR is trying to become

GVR now includes deterministic planning and exact plan execution for combining many small verifiers.

A complex answer can be split into smaller claims. Different exact runtime verifiers can check different claims. The executor runs only the caller-supplied complete plan, gives each verifier reachable evidence and dependencies only, and builds reports, bundles, lifecycle records, and a final session without fallback or product policy. GVR can then keep track of what is proven, what is false, what is unknown, and what became stale because evidence changed.

GVR is designed so this core can stay open source while products can build their own private policy on top of it.
