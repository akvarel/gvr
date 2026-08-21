# Evidence providers

Evidence providers are acquisition contracts. They collect immutable `Evidence` records for later verifier use, but they do not produce `PASS`, `FAIL`, or `UNKNOWN` verdicts for claims.

## Core API

- `EvidenceRequest` is a strict frozen request for one exact `(provider_id, provider_version)` pair. Required evidence kinds must be a subset of accepted evidence kinds.
- `EvidenceAcquisitionStatus` is `COMPLETE`, `PARTIAL`, `UNAVAILABLE`, or `UNSUPPORTED`.
- `EvidenceCoverage` reports `COMPLETE`, `PARTIAL`, or `UNKNOWN` completeness. Complete coverage cannot be truncated. Partial coverage must declare truncation. Unknown coverage cannot claim covered kinds.
- `EvidenceProviderResult` contains typed `Evidence`, provider issues, a capability fingerprint, and no verdict field.
- `EvidenceProviderCapability` describes one exact provider implementation with deterministic canonical identity.
- `EvidenceProviderRegistry` is a deterministic capability registry and optional exact runtime provider registry. Runtime acquisition invokes only the exact requested provider and version. It does not fallback to another provider.

## Fail closed behavior

`EvidenceProviderRegistry.acquire(request, fail_closed=True)` converts provider exceptions into an `UNAVAILABLE` result with no evidence and an `UNKNOWN` issue. This is for preserving safety at acquisition boundaries. It is not a verifier result and does not prove or disprove a claim.

## Compatibility with verifiers

`provider_capability_is_compatible_with_verifier(provider, verifier, claim_kind=...)` checks exact claim-kind support, verifier required evidence kinds, and the intersection between produced and accepted evidence kinds. The helper reports `truth_upgraded=False` by construction. Provider evidence can satisfy verifier input contracts, but provider metadata never turns into verification truth.

Graphify materialized evidence kinds remain the stable data-flow evidence surface:

- `graphify.data_flow_edge`
- `graphify.data_flow_query_result`
- `graphify.data_flow_boundary`

## Canonical identity

Provider capability and registry fingerprints use distinct domains:

```text
gvr.evidence_provider_capability.ieee754-json.v1
gvr.evidence_provider_capability_registry.ieee754-json.v1
```

These are intentionally distinct from verifier capability fingerprint domains. Input order of claim kinds, evidence kinds, mapping keys, and descriptions does not affect semantic identity.

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
