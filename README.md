# GVR — General Verification Runtime

GVR is an open-source runtime for checking claims with evidence.

It is built around one simple rule:

> **An AI can propose. Evidence and verifier rules decide what is proven.**

GVR is not another AI judge. When a check can be done with clear deterministic rules, GVR uses those rules instead of model confidence.

## Why GVR exists

AI systems can make small mistakes that later become big mistakes.

Examples:

- counting a character incorrectly;
- checking the wrong code revision;
- saying "no path exists" after only a partial search;
- using an old PASS after its evidence changed;
- treating missing information as if it proved something.

GVR tries to catch these problems early.

## The three verdicts

Every GVR verifier uses the same basic truth model:

- `PASS` — the claim is proven by the evidence accepted by that verifier.
- `FAIL` — the claim is disproven by the evidence accepted by that verifier.
- `UNKNOWN` — GVR cannot safely prove or disprove the claim.

`UNKNOWN` is a normal and useful result.

It means:

> **Do not pretend we know.**

## The basic flow

```text
claim
  |
  v
VerificationPlan (optional, executes nothing)
  |
  v
VerificationExecutionRequest / exact plan executor
  |
  +--> exact EvidenceProviderRuntimeRegistry
  |
  +--> exact VerifierRuntimeRegistry
  |
  v
evidence + verifier reports
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

A `VerificationBundle` keeps a report together with the exact evidence used by that report.

The `ClaimLedger` remembers dependencies. If evidence changes, old dependent results become stale and must not be treated as current truth.

A `VerificationSession` can combine several current claims with exact `AND`, `OR`, and `NOT` rules.

## A tiny example

Suppose someone claims:

> "Every word in this list contains the letter `e`."

Given:

```text
apple
pear
plum
```

A deterministic text verifier can check every word exactly.

`plum` does not contain `e`, so the claim is:

```text
FAIL
```

No confidence score is needed.

## Current GVR building blocks

GVR currently includes:

- deterministic goal, precondition, effect, and postcondition checks;
- explicit `MISSING`, `NULL`, and `INDETERMINATE` state handling;
- exact text-search verification with explicit Unicode normalization and reverse mode;
- functional snapshot comparison and conservative functional-regression verification;
- evidence records and deterministic evidence versioning;
- `ClaimLedger` with transitive stale propagation;
- Graphify traversal evidence adapter;
- deterministic `CAN_FLOW_TO` and `NO_SUPPORTED_PATH` data-flow claim verification;
- `VerificationBundle` transport with exact evidence manifests;
- language-neutral bundle fingerprint format for trusted cross-language transport;
- `ClaimGraph` with atomic and composite claims;
- `VerificationSession` with exact tri-state composition, freshness, budgets, termination state, and deterministic session identity;
- immutable `VerifierCapability` descriptors and a distinct deterministic `VerifierCapabilityRegistry`;
- strict evidence provider request with explicit source/snapshot classes, coverage, stable categorical issue, result, capability, fail-closed class compatibility, public capability-registry validation, and exact runtime registry contracts;
- deterministic verification planning with exact atomic bindings, capability snapshots, bounded canonical acquisition/check/composition steps, and no execution;
- deterministic verification execution with exact runtime registries, exact request identities, reachable-only verifier inputs, explicit step lifecycle, fail-closed `UNKNOWN` artifacts, deterministic limits, and replay-stable result identity;
- an honest built-in verifier capability snapshot with exact verifier IDs, bounds, coverage, cost, and D0/D1/O1/M1 semantics;
- an honest empty built-in evidence provider capability snapshot;
- schema-v1 JSON protocol and CLI, including `compile_verification_plan`, `execute_verification_plan`, `compose_verification_session`, `describe_verifier_capabilities`, `describe_evidence_provider_capabilities`, and `validate_evidence_provider_result`.

GVR is under active development. The executor runs only an exact caller-supplied complete plan against exact runtime bindings. Automatic discovery, ranking, substitution, scope broadening, product policy, and LLM-based execution are not part of the core. The built-in evidence provider registry remains empty, while Python callers can supply exact custom provider and verifier runtime registries. Provider and verifier capability registries remain descriptive and never select alternatives.

## Five-minute start

Clone the repository and install the development package:

```bash
python -m pip install -e '.[dev]'
```

Run tests:

```bash
python -m pytest
```

Run a JSON request through the CLI:

```bash
python -m gvr --pretty --request '{
  "schema_version": 1,
  "op": "verify_text_search",
  "payload": {
    "corpus": ["apple", "pear", "plum"],
    "needle": "e",
    "claimed_matches": ["apple", "pear"]
  }
}'
```

The CLI also accepts JSON from standard input:

```bash
python -m gvr < request.json
```

## Documentation

Start with [the documentation index](docs/README.md).

Recommended reading order:

1. [What is GVR?](docs/WHAT_IS_GVR.md)
2. [Core concepts](docs/CORE_CONCEPTS.md)
3. [How GVR works](docs/HOW_GVR_WORKS.md)
4. [Examples](docs/EXAMPLES.md)
5. [Verification sessions](docs/VERIFICATION_SESSIONS.md)
6. [Verifier capabilities](docs/VERIFIER_CAPABILITIES.md)
7. [Verification planning](docs/VERIFICATION_PLANNING.md)
8. [Verification execution](docs/VERIFICATION_EXECUTION.md)
9. [CLI and JSON protocol](docs/CLI_AND_PROTOCOL.md)
10. [Design rules](docs/DESIGN_RULES.md)

The docs intentionally use plain English and short examples.

## One important rule about negative claims

Finding one valid example can prove that something exists.

Not finding an example does **not** prove absence unless the search was complete.

For example:

```text
one valid A -> B path
```

can prove:

```text
CAN_FLOW_TO = PASS
```

But:

```text
no path found before the search stopped
```

must not prove:

```text
NO_SUPPORTED_PATH = PASS
```

unless the supported search was complete.

When search completeness is not proven, GVR returns `UNKNOWN`.

## GVR and Graphify

GVR does not parse source code to build its own second code graph.

For data-flow verification, Graphify produces source-derived traversal evidence and GVR checks claims against that evidence.

```text
source code
    |
    v
Graphify
    |
    v
structured graph evidence
    |
    v
GVR verifier
```

This keeps source analysis and verification as separate jobs.

## GVR and product policy

GVR answers questions like:

> "Is this claim proven by the current evidence?"

It does **not** decide product authorization such as:

- deploy to production;
- delete data;
- make a purchase;
- allow an external side effect.

A product can use GVR results, but product policy belongs outside the generic GVR truth layer.

## Safety model in one sentence

> **If GVR cannot prove that a definitive result is safe, it stays UNKNOWN or rejects malformed input.**

## License

GVR is released under the MIT License.
