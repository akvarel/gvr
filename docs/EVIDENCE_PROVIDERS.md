# Evidence providers

Evidence providers are acquisition contracts. They collect immutable `Evidence` records for later verifier use, but they do not produce `PASS`, `FAIL`, or `UNKNOWN` verdicts for claims.

## Core API

### `EvidenceRequest`

`EvidenceRequest` is a strict frozen request for one exact `(provider_id, provider_version)` pair. It carries:

- `schema_version`, stable `kind`, `fingerprint_format`, and deterministic `fingerprint`;
- non-semantic correlation `request_id`;
- `request_kind` and `requested_evidence_kinds`;
- structured `subject` and `spec`;
- `semantic_scope`;
- `source_context` and `snapshot_context`;
- explicit `bounds`.

The request fingerprint excludes `request_id`, so retry or transport correlation can change without changing request semantics. It includes every other request field. A provider result must reference the exact request fingerprint, which prevents replay against a semantically different request that happens to reuse the same `request_id`.

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
- provider issues, all with `UNKNOWN` verdict;
- the exact provider capability fingerprint.

Evidence payloads are recursively detached and frozen. `Evidence.source` and the producer-supplied `Evidence.fingerprint` remain part of the result semantics. Evidence order does not affect the result fingerprint. Identical duplicate evidence IDs are deterministically deduplicated. Duplicate IDs with conflicting kind, payload, source, or producer fingerprint are rejected.

`EvidenceAcquisitionStatus` is `COMPLETE`, `PARTIAL`, `UNAVAILABLE`, or `UNSUPPORTED`. Unavailable and unsupported results contain no evidence and use unknown coverage. Provider results never contain a claim verdict.

### Provider capability and runtime protocol

`EvidenceProviderCapability` describes one exact provider implementation, including `request_kinds` and `produced_evidence_kinds`, with deterministic canonical identity.

The runtime `EvidenceProvider` protocol declares:

- `provider_id`;
- `version`;
- exact `capability`;
- `acquire(request)`.

`EvidenceProviderRegistry` snapshots capability and runtime mappings into detached immutable mappings. Runtime registration and dispatch require exact key, provider identity, version, and capability fingerprint matches. There is no fallback to another provider or version.

## Validation

`validate_evidence_provider_result(result, request, capability)` checks:

- exact request ID and request fingerprint;
- exact provider identity and version across request, result, and capability;
- request-kind support;
- requested, produced, emitted, and covered evidence-kind compatibility;
- exact capability fingerprint;
- exact declared scope, bounds, source identity, and snapshot identity;
- complete coverage of every requested evidence kind for `COMPLETE` results;
- equality of declared and observed scope for `COMPLETE` results.

These checks prevent cross-request replay, including replay where the attacker preserves the same correlation ID.

## Fail-closed behavior

`EvidenceProviderRegistry.acquire(request, fail_closed=True)` converts provider exceptions into an `UNAVAILABLE` result with no evidence, explicit unknown coverage, the original request fingerprint, and an `UNKNOWN` issue. This preserves safety at acquisition boundaries. It is not a verifier result and does not prove or disprove a claim.

## Compatibility with verifiers

`provider_capability_is_compatible_with_verifier(provider, verifier, request_kind=...)` checks exact request-kind support, verifier required evidence kinds, and the intersection between produced and accepted evidence kinds.

`provider_result_for_verifier(result, verifier)` validates every emitted evidence kind against the exact verifier capability and preserves the provider result's status, coverage, evidence, issues, and fingerprint. Empty evidence is permitted as a compatible transport state, but is always `sufficient=False`. The helper reports `truth_upgraded=False` by construction. Provider metadata and acquisition completeness never become verification truth.

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
```

These are intentionally distinct from verifier capability and verification bundle domains. Mapping key order, request/evidence kind order, evidence record order, issue order, and capability registry input order do not affect semantic identity where those collections are sets by contract.

## JSON protocol

`validate_evidence_provider_result` parses full request, capability, coverage, evidence, issue, and result fields. Nested objects are strict. Obsolete or unknown fields are rejected. Claimed request, capability, coverage, and result fingerprints are recomputed and rejected when they do not match canonical content. Successful output is normalized and includes every schema, kind, format, and fingerprint field.

## Built-in registry

The schema-v1 built-in evidence provider registry is honestly empty. GVR currently ships verifier contracts and Graphify evidence adapters, but no built-in runtime evidence acquisition provider is registered.

Discovery uses the JSON protocol operation:

```json
{
  "schema_version": 1,
  "op": "describe_evidence_provider_capabilities",
  "payload": {}
}
```

The response kind is `evidence_provider_capability_registry` and currently contains an empty `capabilities` list.
