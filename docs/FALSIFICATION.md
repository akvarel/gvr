# Falsification and counterexample strategies

GVR falsification is a deterministic layer that tries to challenge an atomic claim before its declared verifier publishes a result.

It does not decide truth by itself.

A strategy can produce a witness, a counterexample, a completed negative search, or an explicitly incomplete result. The declared verifier receives that result and remains responsible for `PASS`, `FAIL`, or `UNKNOWN`. The executor enforces two safety boundaries:

- a verifier cannot return `PASS` while ignoring a declared counterexample;
- a verifier that declares `REQUIRED_BEFORE_PASS` cannot return `PASS` when its required falsification output is missing or incomplete.

The executor converts either unsafe `PASS` into deterministic `UNKNOWN`. It never converts a strategy result directly into `PASS` or `FAIL`.

## Exact generic strategy kinds

Task 20 publishes six generic strategy kinds:

| Kind | Exact built-in strategy ID | Version | Purpose |
| --- | --- | --- | --- |
| `WITNESS_SEARCH` | `gvr.falsification.witness_search.v1` | `1` | Search a finite domain for a concrete witness. |
| `COUNTEREXAMPLE_SEARCH` | `gvr.falsification.counterexample_search.v1` | `1` | Search a finite domain for an observation that contradicts a candidate result. |
| `INVARIANT_CHECK` | `gvr.falsification.invariant_check.v1` | `1` | Check a finite universal or exact invariant. |
| `METAMORPHIC_TRANSFORM` | `gvr.falsification.metamorphic_transform.v1` | `1` | Apply a named transformation and check an explicit invariant between the original and transformed computations. |
| `INDEPENDENT_RECOMPUTE` | `gvr.falsification.independent_recompute.v1` | `1` | Recompute through a deliberately separate implementation path. |
| `REPRESENTATION_CHECK` | `gvr.falsification.representation_check.v1` | `1` | Check the explicit Unicode code-point representation used by a candidate operation. |

IDs and versions are exact. Registries do not select a newer, cheaper, similar, or otherwise preferred strategy.

## Descriptors and registries

### `FalsificationStrategyDescriptor`

A descriptor is a frozen, deeply detached capability record for one exact `(strategy_id, version)` pair. Its semantic identity includes:

- strategy kind;
- supported claim kinds;
- canonical input and output schemas;
- deterministic execution class;
- the side-effect-free requirement;
- cost, bounds, and coverage contracts.

Human descriptions are exported but excluded from the semantic fingerprint.

Built-in strategy descriptors are `D0`, side-effect free, finite-input strategies. Their capability registry is available through:

```python
registry = builtin_falsification_strategy_capability_registry()
```

### `FalsificationStrategyCapabilityRegistry`

The capability registry contains descriptors only. It supports exact lookup and unranked filtering by strategy kind or claim kind. Registry order and fingerprint are canonical.

```python
descriptor = registry.lookup(
    "gvr.falsification.counterexample_search.v1",
    "1",
)
```

### `FalsificationStrategyRuntimeRegistry`

The runtime registry separately binds exact runtime objects to one exact capability registry. A runtime must expose:

```text
strategy_id
version
descriptor
side_effect_free = True
run(FalsificationExecutionInput) -> FalsificationResult
```

Registration and invocation recheck:

- exact strategy ID and version;
- exact descriptor fingerprint;
- callable `run` method;
- `side_effect_free is True` before and after execution.

There is no fallback and no retry.

## Verifier capability contract

`VerifierCapability` has two optional falsification fields:

- `accepted_falsification_strategy_kinds` lists the kinds that the verifier knows how to consume;
- `falsification_requirement` is `NONE`, `OPTIONAL`, or `REQUIRED_BEFORE_PASS`.

A non-`NONE` requirement needs at least one accepted strategy kind. Legacy schema-v1 verifier descriptors that omit both fields preserve their previous serialized shape and fingerprint.

`REQUIRED_BEFORE_PASS` means only that complete declared output is a prerequisite for `PASS`. It does not mean that a clean falsification result proves the claim.

## Explicit planning bindings

Falsification is never selected automatically.

A caller adds one or more `FalsificationStrategyBinding` records to an `AtomicClaimBinding`. Each binding fixes:

- a unique `binding_id` inside the atomic claim;
- the same declared verifier ID as the atomic binding;
- exact strategy ID and version;
- exact strategy capability fingerprint;
- canonical immutable parameters.

If a verifier requires falsification and the caller supplies no binding, planning terminates fail closed with `MISSING_REQUIRED_FALSIFICATION_BINDING`.

The planning request carries the exact falsification capability registry and its fingerprint only when falsification bindings are present. Planning validates exact identity, claim-kind support, verifier acceptance, and budget limits.

## `RUN_FALSIFICATION` plan steps

A complete plan may contain the canonical `RUN_FALSIFICATION` step.

For one atomic claim, execution order is:

```text
acquisition steps
claim dependency final steps
        |
        v
RUN_FALSIFICATION step or steps
        |
        v
VERIFY_ATOMIC_CLAIM
```

Every falsification step depends on the same evidence acquisitions and earlier claim dependencies that are prerequisites for the verifier. The verifier step then depends on every declared falsification step.

The plan fingerprints:

- binding ID;
- claim and verifier identity;
- strategy ID, version, kind, and capability fingerprint;
- canonical strategy parameters and their fingerprint;
- exact dependency step IDs.

Planning budgets include `max_falsification_steps` and `max_falsifications_per_claim`.

## Exact executor behavior

The executor reconstructs the exact planning request from the serialized plan, graph, evidence requests, and all capability registries. It recompiles the plan and requires byte-for-byte equivalent exported content before invoking a runtime.

For a `RUN_FALSIFICATION` step, the executor:

1. waits for all declared acquisition and claim prerequisites;
2. rejects blocked, failed, unavailable, unsupported, or structurally invalid prerequisites;
3. builds one immutable `FalsificationExecutionInput`;
4. invokes the exact runtime once;
5. validates result type, identity, fingerprint, probes, coverage, and provenance;
6. exposes the validated result only to the directly dependent declared verifier.

Malformed output produces `FALSIFICATION_RESULT_INVALID`. Runtime exceptions produce `FALSIFICATION_EXECUTION_ERROR`. Raw exception text and exception class representations do not enter semantic output.

Execution limits include `max_falsification_invocations`. A blocked invocation consumes no falsification invocation count and cannot lead to `PASS` through a dependent verifier.

## Deterministic result contract

A `FalsificationResult` contains:

- exact binding, verifier, strategy, and claim identity;
- `FalsificationOutcome`;
- one or more deterministic `FalsificationProbe` records;
- `FalsificationCoverage`;
- `FalsificationProvenance`;
- a canonical fingerprint.

Outcomes are:

- `WITNESS_FOUND`;
- `COUNTEREXAMPLE_FOUND`;
- `NO_COUNTEREXAMPLE_FOUND`;
- `INCOMPLETE`.

Probe outcomes are:

- `WITNESS`;
- `COUNTEREXAMPLE`;
- `SATISFIED`;
- `INCONCLUSIVE`.

The result validator rejects contradictions such as:

- `COUNTEREXAMPLE_FOUND` without a counterexample probe;
- a counterexample probe under another declared outcome;
- `NO_COUNTEREXAMPLE_FOUND` with partial coverage;
- `INCOMPLETE` with complete coverage;
- provenance that does not match the exact input or descriptor.

Coverage states exactly how many finite items were examined and whether the finite domain was complete. Absence under partial coverage remains `INCOMPLETE`.

Provenance fingerprints:

- exact input and parameter fingerprints;
- exact strategy and claim identity;
- declared verifier and binding identity;
- implementation path;
- normalization, casefold, reversal, duplicate semantics, and metamorphic transformation identity.

## Generic finite text and sequence contract

The built-in generic runtimes currently accept:

```text
input_kind = gvr.falsification.finite_text_sequence.v1
```

Parameters are strict. Unknown fields are rejected.

### Required text semantics

- `corpus` is a finite array of strings;
- `needle` is a string;
- `unicode_unit` must explicitly be `CODE_POINT`;
- `normalization` is `NONE`, `NFC`, or `NFD`;
- `casefold` is an explicit boolean;
- `reverse` is an explicit boolean;
- `duplicate_semantics` is `PRESERVE` or `DISTINCT`;
- optional `max_items` bounds the inspected prefix.

The transform order is fixed and fingerprinted:

```text
NORMALIZE -> CASEFOLD -> REVERSE
```

Reversal operates on Python Unicode scalar-value strings by explicit code-point sequence reversal. It is not byte reversal.

### Predicates

The exact predicates are:

- `EXACT_MEMBERSHIP` with `expected_members`;
- `EXACT_COUNT` with `expected_count`;
- `UNIVERSAL` for every item containing the transformed needle;
- `EXISTENTIAL` for at least one item containing the transformed needle.

`PRESERVE` counts duplicate corpus entries separately. `DISTINCT` keeps the first entry for each transformed identity.

A finite scan can report a counterexample as soon as one is observed. It can report `NO_COUNTEREXAMPLE_FOUND` only after examining the entire effective finite domain.

## Independent recomputation

`INDEPENDENT_RECOMPUTE` does not call the primary scan or its text-transform helper. It has a separate loop, duplicate handling, transform implementation, and count/membership accumulation path.

It still uses the shared immutable parameter and result contracts so the recomputation can be compared and transported canonically.

This separation is intentional. It catches errors where the candidate and a supposed checker would otherwise share the same faulty computation path.

## Metamorphic reversal

The built-in metamorphic strategy supports one explicit operation:

```text
REVERSE_BOTH over Unicode code points
```

The transformation record must carry exact identity fields:

- `transformation_id`;
- `version`;
- `operation = REVERSE_BOTH`;
- `unicode_unit = CODE_POINT`.

The runtime computes baseline membership and membership after reversing both the needle and each corpus item. Membership indexes must remain identical. The transformation record and fingerprint are included in result provenance.

A clean metamorphic check means that this transformation found no inconsistency. It does not prove the original claim.

## Latvian weekday regression corpus

`tests/fixtures/latvian_weekdays_falsification.json` provides a finite regression corpus for:

- plain `e` versus Latvian long `ē`;
- NFC and NFD representations of `ē`;
- universal and existential predicates;
- explicit reversal;
- duplicate-preserving and distinct counts;
- a historically wrong candidate membership list.

The independent recomputation strategy detects the wrong candidate. If a verifier still returns `PASS`, the executor publishes deterministic `UNKNOWN` with `VERIFIER_IGNORED_FALSIFICATION_COUNTEREXAMPLE`.

## Schema-v1 protocol

Task 20 extends schema version 1 without changing legacy payloads.

- `compile_verification_plan` accepts optional falsification registry and binding fields.
- `execute_verification_plan` accepts an optional exact falsification runtime registry.
- `describe_falsification_strategy_capabilities` returns the immutable built-in descriptor snapshot and supports exact `strategy_kind` and `claim_kind` filters.

A direct protocol operation for running an isolated strategy is not required for orchestration. Normal orchestration must pass through `VerificationPlanningRequest`, `VerificationPlan`, `VerificationExecutionRequest`, and `execute_verification_plan` so prerequisites, budgets, identity, output scope, and verifier gates remain enforced.

## Non-goals and safety boundaries

The falsification layer contains no:

- confidence score;
- model or LLM authority;
- ranking or automatic selection;
- fallback or retry policy;
- product authorization;
- tenant or billing policy;
- direct truth verdict.

Those omissions are deliberate. Falsification challenges a claim under an exact finite contract. The declared verifier remains the only component that returns verification truth.
