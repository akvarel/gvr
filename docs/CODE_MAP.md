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

## `src/gvr/storage.py`

This defines the generic durable storage boundary:

- `EvidenceStore`, `BundleStore`, `ClaimStore`, `SessionStore`, and `DependencyIndex`;
- `StorageUnitOfWork` and `UnitOfWorkFactory`;
- `EvidenceDependency`, `EvidenceSlotVersion`, versioned stored-record views, and nonsemantic `SessionExecutionObservation` audit records;
- immutable stored-record views and durable storage errors;
- the explicit completed-execution persistence hook.

The interfaces contain no product-specific fields and do not require SQL.

## `src/gvr/sqlite_storage.py`

This is the standard-library SQLite reference adapter. It implements schema-v3 transactional migration, fail-closed legacy slot authority, immutable evidence plus canonical semantic slot identities, versioned bundle/falsification/session dependency records, duplicate-raw-ID-safe exact dependency tuples, direct immutable evidence links, exact claim bases, exact returned-record validation and threading through claims and sessions, separate audit-bearing execution observations, indexed reverse dependencies, idempotent invalidation events, corruption checks, rollback, and completed-execution recording without raw-ID slot inference.

Read [Durable storage](DURABLE_STORAGE.md) before changing schema or current/stale semantics.

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

This file implements exact `AND`, `OR`, and `NOT` composition, root selection, stale handling, deterministic session accounting, session semantic identity, exact one-claim composition, and optional sealing for published execution-result sessions.

It uses `ClaimLedger`; it does not replace the ledger's evidence-version logic.

Read [Verification sessions](VERIFICATION_SESSIONS.md) before changing this file.

## `src/gvr/planning.py`

This contains deterministic verification planning:

- `AtomicClaimBinding` and explicit `FalsificationStrategyBinding` records;
- `VerificationPlanningRequest` and `VerificationPlanningBudget`;
- stable planner issues and termination;
- immutable `VerificationPlan` and `VerificationPlanStep`;
- canonical `ACQUIRE_EVIDENCE`, `RUN_FALSIFICATION`, `VERIFY_ATOMIC_CLAIM`, and `COMPOSE_CLAIM` steps;
- exact capability, evidence-kind, class, graph, sharing, and budget validation.

The planner compiles descriptions only. It does not call runtime providers, verifiers, Graphify, a network, or the file system. Read [Verification planning](VERIFICATION_PLANNING.md) before changing this file.

## `src/gvr/falsification.py`

This contains the deterministic falsification layer:

- immutable strategy descriptors and exact capability/runtime registries;
- six generic strategy kinds and exact built-in IDs;
- finite Unicode code-point text/sequence parameter validation;
- witness, counterexample, exact count/membership, universal, and existential probes;
- separate primary and independent recomputation paths;
- explicit reverse-both metamorphic transformation checks;
- deterministic result, coverage, and provenance records.

Strategies do not publish verification truth. Their validated output is scoped to the declared verifier. Read [Falsification](FALSIFICATION.md) before changing this file.

## `src/gvr/execution.py`

This contains the exact plan execution layer:

- frozen `VerificationExecutionRequest`, limits, lifecycle, issues, counters, termination, and result contracts;
- `VerifierRuntimeRegistry` with exact `(verifier_id, version)` bindings;
- full pre-execution plan, graph, capability, runtime, request, step, and DAG revalidation;
- one-call-per-step provider acquisition through `EvidenceProviderRuntimeRegistry.acquire`;
- reachable-only verifier inputs, exact dependency records, and directly declared falsification results;
- exact `RUN_FALSIFICATION` execution with prerequisite, runtime, result, provenance, and counterexample gates;
- deterministic fail-closed `UNKNOWN` reports and bundles;
- exact session composition and replay-stable execution identity;
- semantic provider-result projection that excludes audit observations while retaining them in transport;
- the schema-v1 built-in data-flow verifier runtime adapter.

It contains no fallback, retry, ranking, scope broadening, product authorization, or LLM. Read [Verification execution](VERIFICATION_EXECUTION.md) before changing this file.

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

## `src/gvr/evidence_providers.py`

This contains the evidence acquisition contract layer:

- `EvidenceRequest` and its stable slot-request identity;
- canonical `EvidenceSlotIdentity` for explicit replaceable acquisition semantics;
- generic integrity-protected `AuditObservation` metadata;
- `EvidenceCoverage` with explicit semantic maps and a separate nonsemantic audit channel;
- `EvidenceProviderResult`, optional exact slot declarations, and stable code/category `EvidenceProviderIssue` without free text or verdicts;
- `EvidenceProviderCapability` with possibly empty source/snapshot class metadata;
- pure `EvidenceProviderCapabilityRegistry` with public exact request validation;
- executable `EvidenceProviderRuntimeRegistry`;
- provider-to-verifier structural compatibility checks and audit-free semantic projection;
- pre-invocation request validation and post-result validation against the exact request and capability.

The capability registry is deterministic, fingerprinted, and has no runtime objects. Its request validator requires exact source/snapshot class compatibility and treats empty capability class lists as accepting only missing request classes. The runtime registry fingerprints its capability snapshot and exact runtime keys, dispatches only an exact `(provider_id, version)` binding, calls that validator before invocation, and rechecks mutable provider identity immediately before invocation. Fail-closed conversion applies only to an exception from provider execution and emits deterministic allowlisted categories with no raw exception text or class representation. The built-in schema-v1 capability registry is intentionally empty until GVR ships stable acquisition providers.

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
- `describe_verifier_capabilities`;
- `describe_evidence_provider_capabilities`;
- `validate_evidence_provider_result`;
- `compile_verification_plan`;
- `execute_verification_plan`.

The session wire path also validates the explicit bundle fingerprint format before accepting a materialized bundle. The provider-result path separately parses and authenticates `AuditObservation`, preserves identifier-like semantic fields by explicit coverage placement, and rejects wrong-channel or forged audit forms. The planning wire path strictly validates every nested schema, kind, unknown field, and claimed fingerprint before compilation. The execution wire path additionally validates exact plan steps, runtime registry descriptors, exact request keys, deterministic limits, and the outer execution fingerprint before dispatch.

## `src/gvr/wire.py`

This file handles the common JSON envelope and special GVR wire markers.

## `src/gvr/cli.py` and `src/gvr/__main__.py`

These files provide:

```bash
python -m gvr
```

They are intentionally small. The CLI sends work into the same protocol layer used by other callers.

## `tests/`

The tests are part of the specification. `tests/test_verification_execution.py` contains the Task 19 adversarial matrix for identity substitution, malformed or exceptional runtimes, prerequisite fail-closed behavior, reachable-only inputs, exact request execution counts, tri-state composition, deterministic replay, changed evidence identity, execution limits, product-policy absence, and installed CLI/protocol behavior.

GVR uses many adversarial tests because the most dangerous bugs are often not normal crashes. They are false definitive answers such as a wrong PASS or a wrong absence result.

When changing verifier semantics, add tests that try to make GVR produce a false definitive verdict.

Session tests also check that different operation histories cannot change semantic identity when the final semantic state is the same.

`tests/test_verification_planner.py` specifies the deterministic planner contract, including exact capability bindings, request sharing and conflicts, graph ordering, budget boundaries, protocol parsing, and installed public exports.

## Where should a new verifier go?

A generic verifier belongs in GVR if it:

- checks a clear claim type;
- has explicit evidence requirements;
- has deterministic or clearly bounded observational semantics;
- can return `UNKNOWN` when its contract is not satisfied;
- does not contain private product policy.

A new verifier should not hide product authorization rules inside truth verification.
