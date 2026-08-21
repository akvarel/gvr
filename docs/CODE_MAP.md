# Code map

This page helps a new contributor find the main pieces of GVR.

You do not need to read every file to understand the project.

## `src/gvr/model.py`

This file contains the basic shared data types.

Important ideas live here, including:

- `PASS / FAIL / UNKNOWN`;
- evidence state;
- freshness;
- verification reports and issues.

Start here if you want to understand the common language used by all verifiers.

## `src/gvr/core.py`

This is the original deterministic goal/action verification core.

It contains concepts such as:

- predicates;
- goals;
- actions;
- preconditions;
- effects;
- proposal verification.

Use this area for structured state-transition checks.

## `src/gvr/text_search.py`

This contains the exact text-search verifier.

It handles things such as:

- exact needle search;
- Unicode normalization;
- reverse mode;
- grounding the requested needle.

This is a good small example of the GVR idea: a narrow verifier with explicit rules.

## `src/gvr/dependencies.py`

This file tracks dependency versions.

It knows that:

```text
claim -> evidence
claim -> another claim
```

and it marks dependent claims stale when evidence or upstream claim state changes.

This is where the low-level dependency graph lives.

## `src/gvr/ledger.py`

The `ClaimLedger` is built on top of the dependency graph.

It records:

- claim definitions;
- verification history;
- evidence dependencies;
- claim dependencies;
- fresh/stale state.

If you are debugging why an old PASS became UNKNOWN, this is one of the main files to inspect.

## `src/gvr/bundle.py`

This implements `VerificationBundle`.

A bundle packages:

- one `VerificationReport`;
- exactly the evidence used by the report;
- optional claim dependencies;
- deterministic fingerprint.

This is the main trusted transport object for a verification result.

## `src/gvr/canonical.py`

This contains canonical transport fingerprint logic.

Its job is to make the same semantic bundle produce the same fingerprint across programming languages.

It deals with details such as:

- number representation;
- map ordering;
- Unicode-safe canonical ordering.

Most users do not need this file. It matters when implementing another language client or checking fingerprint compatibility.

## `src/gvr/session.py`

This contains the multi-claim composition layer.

Important public types include:

- `AtomicClaim`;
- `CompositeClaim`;
- `ClaimGraph`;
- `VerificationSession`;
- `SessionBudget`;
- session termination states.

This file implements exact `AND`, `OR`, and `NOT` composition, root selection, stale handling, deterministic session accounting, and session semantic identity.

It uses `ClaimLedger`; it does not replace the ledger's evidence-version logic.

Read [Verification sessions](VERIFICATION_SESSIONS.md) before changing this file.

## `src/gvr/adapters/graphify.py`

This converts Graphify traversal output into evidence structures GVR can check.

The adapter does not build a second source-code graph.

Its job is translation and validation of the Graphify evidence contract.

## `src/gvr/verifiers/data_flow.py`

This contains the data-flow claim verifier.

Important claim types include:

```text
CAN_FLOW_TO
NO_SUPPORTED_PATH
```

This verifier checks:

- exact proving paths;
- allowed value-flow relations;
- query scope;
- search completeness;
- truncation;
- boundary problems;
- contradictory traversal accounting.

This is one of the best places to see GVR's fail-closed behavior in a larger verifier.

## `src/gvr/software/`

This area contains functional snapshot and regression verification.

It compares baseline and candidate behavior and keeps incomplete analysis from becoming a false clean regression result.

## `src/gvr/capabilities.py`

This contains the immutable verifier-description layer:

- `VerifierCapability`;
- `VerifierCapabilityRegistry`;
- D0, D1, O1, and M1 determinism classes;
- stable qualitative cost classes;
- exact lookup and deterministic claim-kind queries;
- exact `AtomicClaim` validation;
- the honest built-in capability snapshot.

This registry is separate from the executable `VerifierRegistry` in `core.py`. It describes contracts but does not run or rank verifiers.

Read [Verifier capabilities](VERIFIER_CAPABILITIES.md) before adding or changing a descriptor.

## `src/gvr/protocol.py`

This is the schema-v1 request dispatcher.

It turns JSON operations into GVR library calls.

Current operations include:

- `verify_goal`;
- `compare_functionality`;
- `verify_functional_regression`;
- `verify_text_search`;
- `verify_data_flow_claim`;
- `verify_data_flow_claim_bundle`;
- `compose_verification_session`;
- `describe_verifier_capabilities`.

The session wire path also validates the explicit bundle fingerprint format before accepting a materialized bundle.

## `src/gvr/wire.py`

This file handles the common JSON envelope and special GVR wire markers.

## `src/gvr/cli.py` and `src/gvr/__main__.py`

These files provide:

```bash
python -m gvr
```

They are intentionally small. The CLI sends work into the same protocol layer used by other callers.

## `tests/`

The tests are part of the specification.

GVR uses many adversarial tests because the most dangerous bugs are often not normal crashes. They are false definitive answers such as a wrong PASS or a wrong absence result.

When changing verifier semantics, add tests that try to make GVR produce a false definitive verdict.

Session tests also check that different operation histories cannot change semantic identity when the final semantic state is the same.

## Where should a new verifier go?

A generic verifier belongs in GVR if it:

- checks a clear claim type;
- has explicit evidence requirements;
- has deterministic or clearly bounded observational semantics;
- can return `UNKNOWN` when its contract is not satisfied;
- does not contain private product policy.

A new verifier should not hide product authorization rules inside truth verification.
