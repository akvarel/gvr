# Evidence providers

Evidence providers are acquisition contracts. They collect immutable `Evidence` records for later verifier use, but they do not produce `PASS`, `FAIL`, or `UNKNOWN` verdicts for claims.

## Core API

### `EvidenceRequest`

`EvidenceRequest` is a strict frozen request for one exact `(provider_id, provider_version)` pair. It carries:

- `schema_version`, stable `kind`, `fingerprint_format`, and deterministic `fingerprint`;
- non-semantic correlation `request_id`;
- `request_kind` and `requested_evidence_kinds`;
- optional explicit `source_class` and `snapshot_class` selectors;
- structured `subject` and `spec`;
- `semantic_scope`;
- `source_context` and `snapshot_context`;
- explicit `bounds`.

The request fingerprint excludes `request_id`, so retry or transport correlation can change without changing request semantics. It includes every other request field, including `source_class` and `snapshot_class` even when either value is null. A provider result must reference the exact request fingerprint, which prevents replay against a semantically different request that happens to reuse the same `request_id`.

`EvidenceRequest.slot_request_identity()` exposes the stable subset used only for durable replaceable-slot namespacing. It excludes `request_id`, `provider_version`, and `snapshot_context`: those identify correlation or one acquisition version, not the logical source/request slot.

### `EvidenceSlotIdentity`

`EvidenceSlotIdentity` is the smallest public acquisition-to-storage contract for explicit replacement semantics. A provider opts one emitted record into a replaceable slot with:

```python
slot_identity = request.evidence_slot_identity(
    evidence.id,
    source_identity=coverage.source_identity,
)
```

The identity is frozen, versioned, canonically fingerprinted, and exports its derived `slot_id`. Its fingerprint contains provider ID, evidence ID, canonical source identity, and the stable slot request identity. It excludes correlation request ID, provider version, source snapshot, evidence content, execution/result/session fingerprints, and all wall-clock data.

The raw evidence ID is therefore never a global durable slot. It is only one discriminator inside the canonical provider/source/request namespace. Same raw IDs from different providers, sources, subjects, specs, scopes, bounds, or request kinds produce different slots. A provider-version, snapshot, or content change advances the same slot.

Including an identity in `EvidenceProviderResult.evidence_slot_identities` is the explicit declaration that the corresponding evidence is replaceable. Omission means the evidence remains immutable and must be linked directly by durable storage.

### `EvidenceCoverage`

`EvidenceCoverage` reports `COMPLETE`, `PARTIAL`, or `UNKNOWN` completeness and carries explicit:

- covered evidence kinds;
- declared and observed scope;
- declared bounds;
- consumed resources;
- termination data and termination reason;
- truncation state;
- source and snapshot identities;
- optional structured details.

Coverage is deeply snapshotted, immutable, versioned, and independently fingerprinted. Complete coverage cannot be truncated. Partial coverage and truncation are separate facts. Unknown coverage cannot claim covered evidence kinds.

### `EvidenceProviderResult`

`EvidenceProviderResult` carries:

- `schema_version`, stable `kind`, `fingerprint_format`, and deterministic `fingerprint`;
- correlation `request_id` and semantic `request_fingerprint`;
- exact provider ID and version;
- acquisition status and full coverage;
- deeply snapshotted immutable `Evidence` records;
- provider-specific `EvidenceProviderIssue` diagnostics with no verdict field;
- the exact provider capability fingerprint;
- optional exact `evidence_slot_identities` for emitted evidence that is explicitly replaceable.

`EvidenceProviderIssue` is a separate acquisition diagnostic contract with only a stable uppercase `code`, an optional allowlisted `category`, and `evidence_ids`. It has no free-text message and cannot carry a verifier verdict. Codes and categories reject direct or tokenized truth-like terms such as `PASS`, `FAIL`, `UNKNOWN`, `VERDICT`, `VERIFIED`, `SUFFICIENT`, and `TRUTH`. The exported failure categories are `TIMEOUT`, `ACCESS_DENIED`, `CONNECTION`, `IO`, `CANCELLED`, and `PROVIDER_EXCEPTION`. Evidence payloads are recursively detached and frozen. `Evidence.source` and the producer-supplied `Evidence.fingerprint` remain part of the result semantics. Evidence order does not affect the result fingerprint. Identical duplicate evidence IDs are deterministically deduplicated. Duplicate IDs with conflicting kind, payload, source, or producer fingerprint are rejected.

`EvidenceAcquisitionStatus` is `COMPLETE`, `PARTIAL`, `UNAVAILABLE`, or `UNSUPPORTED`. Unavailable and unsupported results contain no evidence and use unknown coverage. Provider results never contain a claim verdict.

Slot identity declarations are part of the provider result fingerprint. `request_id` remains outside that fingerprint. This makes correlation-only results semantically idempotent while ensuring that changing immutable versus replaceable acquisition semantics changes the result identity.

### Provider capability and runtime protocol

`EvidenceProviderCapability` describes one exact provider implementation. Its fingerprint includes `request_kinds`, `produced_evidence_kinds`, and explicit `source_classes` and `snapshot_classes`, as well as schemas, bounds, coverage, determinism, side-effect, and cost metadata. Either class list may be empty, which explicitly means that the capability accepts no asserted class in that dimension.

The runtime `EvidenceProvider` protocol declares:

- `provider_id`;
- `version`;
- exact `capability`;
- `acquire(request)`.

`EvidenceProviderCapabilityRegistry` is a pure, immutable, fingerprinted descriptor registry. It never stores or executes runtime provider objects. Its public `validate_request(request)` method resolves the exact capability and applies the complete request compatibility contract. `EvidenceProviderRuntimeRegistry` separately binds exact `(provider_id, version)` keys to runtime providers, references one capability registry, and fingerprints that capability-registry identity plus its exact runtime keys. Registration and every dispatch recheck the runtime provider ID, version, exact capability identity, and callable protocol. Runtime dispatch calls the public registry validator before invocation. There is no fallback to another provider or version.

## Validation

`validate_evidence_provider_request(request, capability)` runs before invocation and checks exact request type, provider identity and version, supported `request_kind`, requested evidence kinds, and source/snapshot class compatibility. Class compatibility is exact and fail-closed in each dimension: a non-empty capability list requires a request class from that list; missing or wrong classes fail; an empty capability list accepts only a missing request class. `validate_evidence_provider_result(result, request, capability)` then checks:

- exact request ID and request fingerprint;
- exact provider identity and version across request, result, and capability;
- request-kind support;
- requested, produced, emitted, and covered evidence-kind compatibility;
- exact capability fingerprint;
- emitted evidence kinds are included in the provider's reported coverage;
- exact declared scope, bounds, source identity, and snapshot identity;
- every slot declaration references emitted evidence, uses the exact provider ID, and equals the canonical identity reconstructed from the request's stable slot semantics plus reported source identity;
- complete coverage of every requested evidence kind for `COMPLETE` results;
- equality of declared and observed scope for `COMPLETE` results;
- rejection of contradictory `PARTIAL` results that claim every requested kind, the full declared scope, and no truncation.

These checks prevent cross-request replay, including replay where the attacker preserves the same correlation ID.

## Fail-closed behavior

`EvidenceProviderRuntimeRegistry.acquire(request, fail_closed=True)` converts only exceptions raised by `provider.acquire(request)` into an `UNAVAILABLE` result. Pre-invocation validation failures and post-result contract violations still raise. The unavailable result contains no evidence, uses unknown coverage, and emits the stable code `PROVIDER_EXECUTION_ERROR` plus one safe category: `TIMEOUT`, `ACCESS_DENIED`, `CONNECTION`, `IO`, `CANCELLED`, or `PROVIDER_EXCEPTION`. Raw exception text, exception class names, stack data, and arbitrary representations are excluded. Failures in the same category therefore have the same semantic identity regardless of raw message, while meaningfully different categories have different identities.

## Compatibility with verifiers

`provider_capability_is_compatible_with_verifier(provider, verifier, request_kind=..., claim_kind=...)` takes both dimensions explicitly. Provider request support and verifier claim support are reported separately, alongside accepted evidence intersections and missing required evidence kinds.

`provider_result_for_verifier(result, verifier)` validates every emitted evidence kind against the exact verifier capability and preserves the provider result's status, coverage, evidence, issues, and fingerprint. Its canonical `to_dict()` representation can be included in falsification provenance. It exposes only structural compatibility facts: emitted evidence kinds, present required evidence kinds, and missing required evidence kinds. It has no generic `sufficient` or truth-upgrade field. Acquisition status and coverage never become verification truth.

## Use by the verification planner

`AtomicClaimBinding` contains full immutable `EvidenceRequest` records. The planning request supplies one exact `EvidenceProviderCapabilityRegistry` plus the exact registry fingerprint expected by the caller.

Before emitting an `ACQUIRE_EVIDENCE` step, the planner validates exact provider ID and version, request-kind support, every requested evidence kind, source class, snapshot class, structural evidence intersection with the exact verifier, and the verifier's combined required evidence kinds.

The provider request kind remains distinct from the verifier claim kind. The planner does not infer one from the other.

Acquisition sharing uses the exact executable key `(request_id, request_fingerprint)`. Reusing that exact key across claims shares one plan step and one execution. Identical semantic request fingerprints under different request IDs remain separate steps and executions. Reusing one request ID with different semantics is rejected.

The planner never calls `EvidenceProviderRuntimeRegistry.acquire`. It only describes possible acquisition work.

## Use by the verification executor

`VerificationExecutionRequest` carries every exact request in a mapping keyed by `(request_id, request_fingerprint)` and carries the exact provider runtime registry plus its capability-registry fingerprint.

For each `ACQUIRE_EVIDENCE` step, the executor calls `EvidenceProviderRuntimeRegistry.acquire(request, fail_closed=True)` exactly once, then reconstructs and validates the result again. A malformed returned result fails the acquisition step; an actual provider execution exception remains the existing deterministic `UNAVAILABLE` result. Downstream verifiers receive only results and evidence reachable from their exact dependency step IDs.

Unavailable, unsupported, missing-required-kind, malformed, or blocked acquisitions cannot be upgraded to `PASS`. The verifier is not called for that invalid prerequisite, and the executor records an explicit `UNKNOWN` bundle. See [Verification execution](VERIFICATION_EXECUTION.md).

When durable storage is explicitly supplied, each provider evidence artifact also preserves canonical provenance, `snapshot_identity`, declared bounds, and the complete `EvidenceCoverage` document. The evidence ID is the default replaceable slot for executor recording, while the immutable artifact retains the exact request and provider-result fingerprints. See [Durable storage](DURABLE_STORAGE.md).

Graphify materialized evidence kinds remain the stable data-flow evidence surface:

- `graphify.data_flow_edge`
- `graphify.data_flow_query_result`
- `graphify.data_flow_boundary`

## Canonical identity

Every provider contract uses a distinct canonical fingerprint domain:

```text
gvr.evidence_request.ieee754-json.v1
gvr.evidence_coverage.ieee754-json.v1
gvr.evidence_provider_result.ieee754-json.v1
gvr.evidence_provider_capability.ieee754-json.v1
gvr.evidence_provider_capability_registry.ieee754-json.v1
gvr.evidence_provider_runtime_registry.ieee754-json.v1
```

These are intentionally distinct from verifier capability and verification bundle domains. Mapping key order, request/evidence kind order, evidence record order, issue order, and capability registry input order do not affect semantic identity where those collections are sets by contract.

## JSON protocol

`validate_evidence_provider_result` parses full request, capability, coverage, evidence, provider issue, and result fields. Nested objects are strict. Provider issues reject `verdict`, including `UNKNOWN`. Capability payloads require explicit `source_classes` and `snapshot_classes`. Obsolete, unknown, or truth-like control fields are rejected. Claimed request, capability, coverage, and result fingerprints are recomputed and rejected when they do not match canonical content. Successful output is normalized and includes every schema, kind, format, and fingerprint field.

## Built-in registry

The schema-v1 built-in evidence provider capability registry is honestly empty. GVR currently ships verifier contracts and Graphify evidence adapters, but no built-in runtime evidence acquisition provider is registered.

Discovery uses the JSON protocol operation:

```json
{
  "schema_version": 1,
  "op": "describe_evidence_provider_capabilities",
  "payload": {}
}
```

The response kind is `evidence_provider_capability_registry` and currently contains an empty `capabilities` list.
