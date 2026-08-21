# Verifier capabilities

A verifier capability says what one exact verifier implementation can honestly check.

It is metadata about a verifier contract. It does not run the verifier, acquire evidence, choose a preferred verifier, or authorize product actions.

## Two different registries

GVR has four intentionally separate registry types:

- `VerifierRegistry` in `core.py` contains executable goal/action verifier objects and combines their reports.
- `VerifierCapabilityRegistry` in `capabilities.py` contains immutable descriptions of verifier contracts.
- `EvidenceProviderCapabilityRegistry` in `evidence_providers.py` contains immutable, fingerprinted evidence acquisition descriptors only.
- `EvidenceProviderRuntimeRegistry` in `evidence_providers.py` separately binds exact runtime providers to one capability registry and performs validated acquisition.

Keeping these separate prevents descriptive metadata from becoming a hidden execution, acquisition, or selection mechanism.

## `VerifierCapability`

A descriptor is bound to one exact `(verifier_id, version)` pair.

Its semantic fields are:

| Field | Meaning |
| --- | --- |
| `verifier_id` | Exact value emitted in `VerificationReport.verifier`. |
| `version` | Exact capability contract version used for lookup. |
| `claim_kinds` | Published `AtomicClaim.claim_kind` values this verifier supports. |
| `accepted_evidence_kinds` | Published `Evidence.kind` values that may appear in a verifier result. |
| `required_evidence_kinds` | Evidence kinds that must appear every time. This must be a subset of accepted kinds. |
| `input_schema` | Canonical structured input contract, when GVR has published one. |
| `output_schema` | Canonical structured output contract, when GVR has published one. |
| `determinism` | `D0`, `D1`, `O1`, or `M1`. |
| `side_effect_free` | Whether running the verifier itself has no external side effects. |
| `cost` | Stable qualitative class: `LOW`, `MEDIUM`, `HIGH`, or `EXTERNAL`. |
| `bounds` | Canonical mapping describing the domain and work bounds. |
| `coverage` | Canonical mapping describing what the result covers and any completeness rule. |
| `authoritative` | Whether the result can be verification truth under its declared contract. |
| `description` | Human explanation. It is exported but intentionally non-semantic. |

Descriptors are frozen and deeply detached from caller-owned mappings and lists. Unsupported values, non-string mapping keys, invalid Unicode, non-finite numbers, duplicate contract values, and inconsistent required evidence are rejected.

An empty schema, claim-kind list, or evidence-kind list means no stable machine-readable contract is currently published for that surface. It is not a wildcard.

## Determinism classes

### `D0`: pure deterministic computation

The verifier computes directly from the supplied structured input. Repeating the same semantic input gives the same result without relying on separately captured evidence.

Examples include the current exact text-search and goal/action checks.

### `D1`: deterministic evaluation of immutable evidence

The verifier or composer evaluates immutable snapshots, bundles, or other fixed evidence artifacts deterministically.

Examples include functional regression, composite claim sessions, and regression test obligation grounding.

### `O1`: deterministic evaluation of a captured observation

The verifier evaluates an observation captured by an external source or tool. The observation and its bounds must travel with the result.

The current data-flow verifier is `O1`: Graphify captures traversal evidence, then GVR checks that observation deterministically. GVR does not reparse source code.

### `M1`: proposal-only model output

`M1` can describe model-generated proposal material. It cannot be authoritative, and `authoritative_only=True` queries always exclude it.

This registry does not turn model output into verification truth.

## Canonical identity

Capability and registry fingerprints use the strict cross-language canonical rules in `canonical.py` with separate domain formats:

```text
gvr.verifier_capability.ieee754-json.v1
gvr.verifier_capability_registry.ieee754-json.v1
```

The following do not change capability identity:

- input order of `claim_kinds`;
- input order of accepted or required evidence kinds;
- mapping key order, including nested `bounds`, `coverage`, and schemas;
- the human `description`.

Semantic changes do change identity, including:

- verifier ID or version;
- determinism class;
- side-effect or authoritative status;
- cost;
- claim or evidence contract;
- input/output schema;
- bounds or coverage semantics.

Registry input order does not affect listing order, export order, or fingerprint. Listings use exact UTF-8 byte order by verifier ID and then version.

Fingerprints are content identities, not signatures or attestations.

## Lookup, queries, and claim validation

Exact lookup requires both ID and version:

```python
registry.lookup("gvr.graphify.data_flow.v1", "1")
```

Claim-kind queries return every matching descriptor in deterministic ID/version order:

```python
registry.query(claim_kind="CAN_FLOW_TO", authoritative_only=True)
```

The result is deliberately unranked. The registry does not silently choose a cheaper, newer, or otherwise "best" verifier.

`AtomicClaim` validation preserves its exact verifier binding:

```python
claim.validate_capability(registry, version="1")
```

Unknown verifier IDs, unknown versions, unsupported claim kinds, and ambiguous omitted versions are rejected. No substitution is attempted.

## Built-in snapshot

`builtin_verifier_capability_registry()` returns the immutable schema-v1 snapshot shipped with GVR.

| Runtime verifier ID | Version | Class | Cost | Published claim/evidence contract |
| --- | --- | --- | --- | --- |
| `preconditions` | `1` | `D0` | `LOW` | No stable `AtomicClaim` or `Evidence.kind` contract yet. |
| `effect_support` | `1` | `D0` | `LOW` | No stable `AtomicClaim` or `Evidence.kind` contract yet. |
| `goal_satisfaction` | `1` | `D0` | `LOW` | No stable `AtomicClaim` or `Evidence.kind` contract yet. |
| `text_search` | `1` | `D0` | `LOW` | No stable `AtomicClaim` or `Evidence.kind` contract yet. |
| `functional_regression` | `1` | `D1` | `MEDIUM` | Uses functional snapshots, but no stable `Evidence.kind` contract is emitted. |
| `gvr.graphify.data_flow.v1` | `1` | `O1` | `EXTERNAL` | Claims: `CAN_FLOW_TO`, `NO_SUPPORTED_PATH`. Evidence may be an edge, a query result, or a blocking boundary. |
| `gvr.claim_graph.composite.v1` | `1` | `D1` | `MEDIUM` | Operates on composite nodes and bundles, not `AtomicClaim.claim_kind`. |
| `gvr.regression_test_obligation.v1` | `1` | `D1` | `MEDIUM` | Claim: `TEST_OBLIGATION_GROUNDED`. Accepts exactly the 13 schema-v1 `gvr.test.*` behavior evidence kinds and requires complete coverage for referenced fact classes. |

The snapshot uses the verifier IDs the runtime actually emits. It does not invent claim kinds, evidence kinds, or formal schemas for APIs that do not yet publish them.

The runtime `VerifierRegistry` report ID is intentionally absent from this snapshot. A `VerifierRegistry` may contain any number of caller-supplied verifiers, including none, and those verifiers may have different determinism, cost, side-effect, bounds, and coverage properties. The stable report ID `registry` therefore does not identify one stable verifier capability contract. Individual executable verifiers must publish their own descriptors before a composed registry can be described honestly.

The data-flow verifier publishes these evidence kinds:

- `graphify.data_flow_edge` for a direct step in a proven path;
- `graphify.data_flow_query_result` for a complete no-path result or a zero-step identity path;
- `graphify.data_flow_boundary` when a blocking boundary keeps the answer unknown.

Its `required_evidence_kinds` list is empty because these proof paths are conditional. No single evidence kind appears in every result.

The regression test obligation descriptor also has an empty `required_evidence_kinds` list because the exact required kind depends on the obligation rule. Its accepted union exactly matches the runtime's closed behavior vocabulary. Its finite bounds match `DEFAULT_REGRESSION_OBLIGATION_BUDGET`, and its coverage contract publishes `COMPLETE_REFERENCED_FACT_COVERAGE` as the requirement for grounding PASS.

## Schema-v1 discovery operation

List the built-in snapshot:

```json
{
  "schema_version": 1,
  "op": "describe_verifier_capabilities",
  "payload": {}
}
```

Filter by one exact claim kind and exclude proposal/advisory entries:

```json
{
  "schema_version": 1,
  "op": "describe_verifier_capabilities",
  "payload": {
    "claim_kind": "CAN_FLOW_TO",
    "authoritative_only": true
  }
}
```

The response kind is `verifier_capability_registry`. Its payload contains the registry schema version, kind, fingerprint format, fingerprint, and deterministically ordered capability descriptors.

## Evidence provider discovery and result validation

Evidence provider capabilities describe acquisition contracts. They are separate from verifier capabilities because providers gather evidence but do not decide verification truth.

The schema-v1 provider discovery operation accepts deterministic optional filters:

```json
{
  "schema_version": 1,
  "op": "describe_evidence_provider_capabilities",
  "payload": {
    "request_kind": "CAN_FLOW_TO",
    "evidence_kind": "graphify.data_flow_query_result"
  }
}
```

`claim_kind` is intentionally not accepted for provider discovery. Use `request_kind` for the provider request contract and `evidence_kind` for produced evidence.

Provider results can be validated over the schema-v1 protocol:

```json
{
  "schema_version": 1,
  "op": "validate_evidence_provider_result",
  "payload": {
    "request": {},
    "capability": {},
    "result": {}
  }
}
```

The operation parses serialized request, capability, and result objects, checks exact provider identity, version, capability fingerprint, produced and accepted evidence kinds, required coverage, and fail-closed source/snapshot class compatibility, then returns a canonical `evidence_provider_result`. Provider issues carry only stable codes, optional allowlisted categories, and evidence IDs; obsolete free-text `message` and `verdict` fields are rejected. Invalid inputs return a `protocol_error` with codes such as `INVALID_EVIDENCE_PROVIDER_REQUEST`, `INVALID_EVIDENCE_PROVIDER_CAPABILITY`, or `INVALID_EVIDENCE_PROVIDER_RESULT`.

## Current limits

The registry is descriptive and static in schema v1.

It does not yet:

- load plugins dynamically;
- negotiate provider availability;
- rank or select verifiers;
- acquire evidence;
- estimate numeric runtime cost;
- authorize product side effects;
- attest who produced a descriptor.

Those concerns belong to later planning, provider, policy, and trust layers.
