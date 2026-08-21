# GVR — General Verification Runtime

GVR is a deterministic verification core for evidence-backed agent decisions.

Core rule:

> Propose freely. Propagate only verified state.

The runtime separates proposal generation from verification. It models goals,
actions, state transitions, evidence, claims, dependencies, and conservative
`PASS / FAIL / UNKNOWN` outcomes.

Current modules:

- deterministic goal/postcondition verification;
- explicit MISSING vs NULL vs INDETERMINATE state;
- independently grounded literal text-search verifier;
- Claim Dependency Graph with evidence invalidation and transitive STALE propagation;
- Graphify traversal evidence adapter and deterministic `CAN_FLOW_TO` /
  `NO_SUPPORTED_PATH` claim verifier;
- deterministic `VerificationBundle` transport packages with exact evidence manifests;
- versioned wire envelope for future CLI / hooks / MCP / standalone runtime.

The repository intentionally does not contain BugZero product policy. Product
policy belongs in the private BugZero Verify service.

## Graphify data-flow claims

`verify_data_flow_claim()` consumes the public Graphify bounded traversal-result
mapping. It does not parse source code or build a second graph. A positive flow
claim passes only for an individually exact `PROVEN` path with complete coverage
and valid deterministic `df:...` dependencies. Absence is accepted only when
Graphify reports a complete supported search with no path and no MAY evidence,
and the traversal relation/direction/stop-node scope exactly matches the
immutable `DataFlowQueryScope` carried by the claim. Malformed, contradictory,
truncated, unresolved, partial, ambiguous, scope-mismatched, or unsupported
evidence fails closed to `UNKNOWN`.

Empty-search and zero-step identity verdicts depend on deterministic `gvrq:...`
query-result evidence rather than fabricated direct edges. The evidence ID names
the semantic query slot; its normalized payload carries the current result and
optional `source_context`, so replacing or removing it makes recorded
`ClaimLedger` verdicts stale. Callers can use `evidence_namespace` to isolate
query slots and `build_query_result_evidence()` to construct the record.

Schema version 1 also exposes the `verify_data_flow_claim` wire operation. Its
report preserves the claim kind and endpoints, exact evidence IDs, issue codes,
and Graphify termination, bounds, boundary, and search-coverage metadata.

## Verification bundles

`build_verification_bundle()` packages a `VerificationReport` with exactly the
`Evidence` records named by `report.evidence_ids`, optional claim dependencies,
and a deterministic SHA-256 fingerprint of canonical semantic content. Bundle
construction rejects missing dependencies, conflicting duplicate IDs, unrelated
extra evidence, unsupported semantic values, and issue evidence outside the
report dependency set. Evidence order and mapping key order do not affect the
fingerprint. Report metadata and evidence payloads are snapshotted into immutable
canonical structures so later caller mutation cannot invalidate bundle identity.

`verify_data_flow_claim_bundle()` is the first producer integration. It includes
only the selected direct `df:...` records for a proven path, the stable `gvrq:...`
record for complete absence or zero-step identity, and exact `bnd:...` records for
blocking boundaries. Conflicting Graphify records sharing one ID are rejected.

`ClaimLedger.record_bundle()` validates and records the complete package on a
transactional copy before publishing any evidence or verdict state. Failed
validation, verifier mismatch, missing claim dependencies, or dependency-cycle
errors therefore cannot partially mutate the ledger. Bundle recording uses the
typed `put_evidence_record()` path, which retains and versions the exact evidence
ID, kind, payload, source, and producer fingerprint. A change to any of those
fields updates the evidence version, reverification updates the upstream claim
version, and downstream claim dependencies become stale. Semantically identical
records, including reordered mapping keys, remain no-ops.

The legacy `put_evidence(id, payload)` API remains payload-only and stores
explicit `None` defaults for kind, source, and producer fingerprint. Moving an ID
between typed and legacy evidence is therefore an explicit semantic change rather
than a silent equivalence. Stored payloads and evidence views are deep snapshots,
so caller mutation cannot bypass evidence versioning. Returned claim records,
verification snapshots, and history views are defensive copies and cannot rewrite
internal freshness or audit history.

Schema version 1 additionally exposes `verify_data_flow_claim_bundle`. Its
`verification_bundle` envelope preserves the bundle version, kind, verifier,
fingerprint, report, claim dependencies, and deterministically ordered evidence
records with IDs, kinds, payloads, sources, and producer fingerprints.
