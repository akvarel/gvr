# Verification execution

Verification execution runs one exact, already-compiled `VerificationPlan` against exact runtime bindings.

It does not discover, rank, broaden, repair, or replace any plan step. It does not make product decisions. It does not call an LLM.

## Public API

The main entry point is:

```python
result = execute_verification_plan(request)
```

The execution layer exposes these public contracts:

- `VerificationExecutionRequest`;
- `VerificationExecutionLimits`;
- `VerificationExecutionResult`;
- `VerificationExecutionStep` and `VerificationExecutionStepStatus`;
- `VerificationExecutionIssue`;
- `VerificationExecutionConsumption`;
- `VerificationExecutionTermination`;
- `VerifierExecutionInput` and `VerifierDependency`;
- `VerifierRuntimeRegistry`;
- `FalsificationStrategyRuntimeRegistry` and `FalsificationExecutionInput`;
- `execute_verification_plan`.

The existing `EvidenceProviderRuntimeRegistry` remains the only provider-dispatch mechanism. Its runtime identity is now fingerprinted from the exact capability-registry fingerprint and exact registered `(provider_id, version)` keys.

## Exact execution request

`VerificationExecutionRequest` is a frozen semantic contract. Fingerprinted data artifacts and request mappings are detached and immutable. Executable runtime objects remain behind immutable registry mappings because they must be invoked; their declared ID, version, capability, and callable are rechecked before execution and immediately before each invocation. The request covers:

- one exact `VerificationPlan` plus its claimed fingerprint;
- one exact `ClaimGraph` plus its claimed fingerprint;
- selected session root claim IDs;
- one exact `VerifierRuntimeRegistry` and verifier capability-registry fingerprint;
- one exact `EvidenceProviderRuntimeRegistry` and provider capability-registry fingerprint;
- an optional exact `FalsificationStrategyRuntimeRegistry` and falsification capability-registry fingerprint for plans with `RUN_FALSIFICATION` steps;
- every exact `EvidenceRequest`, keyed by `(request_id, request_fingerprint)`;
- deterministic execution limits;
- an optional `correlation_id`.

`correlation_id` is transport correlation only. It is included in `to_dict()` but excluded from request and result semantic fingerprints.

Before any runtime is invoked, construction and execution revalidate:

1. plan, graph, request, capability, and registry fingerprints;
2. concrete public record types rather than substituting subclasses;
3. graph nodes, DAG order, plan step IDs, step fingerprints, and dependency step IDs;
4. exact claim IDs, claim kinds, claim fingerprints, operators, verifier IDs and versions;
5. exact request IDs, request fingerprints, request kinds, evidence kinds, provider IDs and versions;
6. exact provider, strategy, and verifier runtime keys and capability identities;
7. exact falsification binding, parameter, and dependency identity;
8. exact recompilation of the supplied plan from the graph, requests, capability registries, and plan budget.

A mismatch raises `VerificationExecutionError` before provider or verifier invocation.

## Verifier runtime contract

`VerifierRuntimeRegistry` binds an exact `(verifier_id, version)` key to a runtime object with:

```text
verifier_id
version
capability
verify(VerifierExecutionInput) -> VerificationReport
```

Registration and every invocation recheck the runtime ID, version, exact capability fingerprint, and callable method. There is no fallback to another verifier or version.

A `VerifierExecutionInput` contains only:

- the exact atomic claim;
- the exact verifier capability;
- structurally validated acquisition inputs reachable from that verifier step;
- reachable evidence records only;
- exact claim dependencies only;
- validated falsification results from directly declared `RUN_FALSIFICATION` dependencies only.

Unrelated evidence and unrelated claims are not passed to the verifier.

## Step execution

A complete plan contains four executable step kinds.

### `ACQUIRE_EVIDENCE`

The executor resolves the exact request key and calls:

```python
provider_runtime_registry.acquire(request, fail_closed=True)
```

One exact acquisition step runs once. The same `(request_id, request_fingerprint)` shared by several claims is acquired once. Two different request IDs with identical semantic request fingerprints remain two executions.

Returned results are reconstructed and validated again against the exact request and capability, including request identity, provider identity, capability fingerprint, evidence kinds, coverage, scope, bounds, source identity, and snapshot identity.

A provider execution exception becomes the existing deterministic `UNAVAILABLE` provider result. A provider that returns a malformed result causes the acquisition step to fail closed. Raw exception text and exception class representation are never included in semantic output.

### `RUN_FALSIFICATION`

The executor calls one exact side-effect-free strategy runtime after all declared acquisition and claim prerequisites complete. The runtime receives exact claim, verifier, descriptor, parameter, evidence, acquisition, and dependency identity.

The returned `FalsificationResult` is reconstructed and validated against the exact input and descriptor. Identity, probes, coverage, provenance, input fingerprint, parameter fingerprint, and result fingerprint must all agree.

Malformed output produces `FALSIFICATION_RESULT_INVALID`. Runtime exceptions produce `FALSIFICATION_EXECUTION_ERROR`. A blocked or failed strategy result is never substituted, retried, or replaced.

Validated output is stored by exact plan step ID and exposed only to the directly dependent declared verifier.

### `VERIFY_ATOMIC_CLAIM`

The executor gathers only directly reachable acquisition results and exact claim dependencies.

It also gathers only directly declared falsification results. A verifier cannot see results declared for another verifier or claim.

The verifier is not called when a required acquisition prerequisite is missing, malformed, unavailable, unsupported, missing required evidence kinds, or blocked by an earlier lifecycle failure. Instead, the executor materializes an explicit `UNKNOWN` `VerificationReport` and `VerificationBundle` for the atomic claim.

Conflicting reachable evidence records that share one evidence ID also block verifier invocation and produce `UNKNOWN`.

A valid verifier report must:

- be an exact `VerificationReport`;
- preserve `PASS`, `FAIL`, or `UNKNOWN` exactly;
- name the exact verifier ID;
- reference only evidence reachable from the step;
- form a valid `VerificationBundle` with the exact claim dependencies.

Verifier exceptions and malformed reports produce deterministic `UNKNOWN` bundles with stable issue codes. Exception text, stack data, object addresses, and class names are excluded.

If a verifier returns `PASS` while a reachable result contains a counterexample, the executor publishes `UNKNOWN` with `VERIFIER_IGNORED_FALSIFICATION_COUNTEREXAMPLE`. If the verifier declares `REQUIRED_BEFORE_PASS` and output is absent or incomplete, `PASS` becomes `UNKNOWN` with `REQUIRED_FALSIFICATION_INCOMPLETE`.

The executor never turns a clean strategy result into `PASS` and never turns a counterexample directly into `FAIL`. The verifier still decides truth.

### `COMPOSE_CLAIM`

The executor composes one exact composite claim through `VerificationSession.compose_claim()`.

Composition uses the existing tri-state rules:

| Operator | Result |
| --- | --- |
| `AND` | `FAIL` if any child fails, otherwise `UNKNOWN` if any child is unknown, otherwise `PASS`. |
| `OR` | `PASS` if any child passes, otherwise `UNKNOWN` if any child is unknown, otherwise `FAIL`. |
| `NOT` | swaps `PASS` and `FAIL`; preserves `UNKNOWN`. |

No confidence arithmetic is used.

## Lifecycle, issues, counters, and termination

Every plan step receives one final lifecycle status:

- `COMPLETED`;
- `FAILED`;
- `BLOCKED`.

Execution issues contain stable codes and exact step, claim, or request IDs. They do not contain free exception text, a product authorization, a ranking, a recommendation, or an LLM decision.

`VerificationExecutionConsumption` records deterministic counters for:

- started steps;
- completed, failed, and blocked steps;
- provider acquisitions;
- falsification invocations;
- verifier invocations;
- compositions;
- evidence records and canonical evidence bytes.

`VerificationExecutionLimits` can bound those deterministic dimensions. It never uses wall-clock time, random sampling, or nondeterministic scheduling.

When a limit blocks a step, the provider, verifier, or composite operation is not invoked. A blocked atomic step receives an explicit `UNKNOWN` bundle; a blocked composite remains `UNKNOWN` rather than being composed to a definitive verdict.

When a falsification limit blocks a strategy step, the runtime is not invoked and no falsification invocation is consumed. Its dependent verifier cannot produce a definitive result through that blocked dependency.

Final execution termination is:

- `COMPLETE` when every step completes, including legitimate verifier `UNKNOWN` results;
- `FAILED_CLOSED` when a runtime, result, identity, or prerequisite failure blocks a definitive execution path;
- `LIMIT_EXHAUSTED` when a deterministic execution limit prevents further work.

These are execution states, not product decisions.

## Result identity and replay

`VerificationExecutionResult` contains:

- exact request, plan, graph, and capability-registry fingerprints;
- validated provider results keyed by exact request identity;
- validated falsification results keyed by exact plan step identity;
- atomic verification bundles keyed by claim ID;
- the final `VerificationSession`;
- step lifecycle records;
- stable execution issues;
- deterministic consumption and termination;
- a canonical result fingerprint.

Before publication, the executor seals the final `VerificationSession`. Public session mutation methods then raise `VerificationSessionError`, so a caller cannot change root verdicts or session content while leaving the already-issued execution-result fingerprint behind.

The result fingerprint includes evidence and bundle identities through the provider results and session. Changing an evidence ID, payload, source, or producer fingerprint changes the applicable artifact and execution identity.

The fingerprint excludes:

- correlation IDs;
- human capability descriptions;
- clocks and timestamps;
- random values;
- runtime object identity;
- raw exception text and representation.

Replaying the same exact semantic inputs and runtime outputs therefore produces the same request, bundle, session, and execution-result fingerprints.

## Schema-v1 protocol and CLI

The JSON operation is:

```text
execute_verification_plan
```

Its payload is the exact `VerificationExecutionRequest.to_dict()` shape. The response kind is:

```text
verification_execution_result
```

Malformed fields, missing nested fingerprints, runtime descriptor mismatches, and any exact identity mismatch return:

```text
INVALID_VERIFICATION_EXECUTION_REQUEST
```

Python callers may inject exact runtime registries through the keyword arguments on `handle_request()` or `safe_handle_request()`. The standalone CLI has no way to serialize executable Python objects, so it binds only runtime keys shipped by GVR. Schema v1 ships the generic falsification runtimes, a built-in data-flow verifier adapter, and no built-in evidence providers. Custom provider, strategy, and verifier runtimes are supplied through the Python API.

## Boundaries

The executor deliberately does not:

- discover capabilities or runtime plugins;
- rank or select alternatives;
- broaden claim scope, evidence scope, or search bounds;
- retry with a substitute provider, strategy, or verifier;
- infer missing request fields;
- authorize deployment, deletion, payment, access, or another product action;
- use model-generated output as authoritative truth.

A product may consume the final GVR verdicts, but product policy remains outside this layer.

## External architecture and license references

Two public reference sets were reviewed without copying code:

- [Akon Labs / GitNexus](https://www.akonlabs.com/) emphasizes precomputed, deterministic structural relationships rather than runtime guesswork. The material architectural takeaway for GVR is to validate the complete execution DAG and exact identities before invocation, then expose compact deterministic artifacts.
- GitNexus is licensed under [PolyForm Noncommercial 1.0.0](https://github.com/abhigyanpatwari/GitNexus/blob/main/LICENSE), with commercial use requiring a separate license according to [Akon Labs terms](https://www.akonlabs.com/terms). No GitNexus code was copied or adapted. GVR remains an original MIT-licensed implementation.
