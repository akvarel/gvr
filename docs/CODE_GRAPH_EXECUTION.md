# Canonical code graph execution observations

GVR's code graph execution layer verifies code graph claims from external, precomputed provider snapshots. The runtime does not run Graphify, run CodeFlow, parse source files, infer IDs from slots, or substitute missing records. It consumes only canonical `gvr.code_graph.provider_observation` evidence that a provider adapter has already encoded.

## Model

A provider adapter converts a provider-specific snapshot into a provider-independent `GraphEvidenceModel`:

- nodes and edges carry both semantic identity and exact identity;
- `EvidenceConfidence.EXACT` is decisive for positive claims;
- `HEURISTIC` and `INFERRED_HINT` can explain support but cannot upgrade truth;
- `absence_subjects` are explicit complete absence observations, not silence;
- `source_snapshot` is part of the observation identity and must match the claim scope for direct verification.

The adapter then wraps that model with exact observation metadata:

- provider family and implementation identity;
- atomic claim fingerprint;
- graph model fingerprint;
- source snapshot;
- the full canonical graph model payload.

Graphify and CodeFlow parsing remains in `gvr.adapters.graphify` and `gvr.adapters.codeflow`. The generic verifier runtime decodes only canonical observation evidence.

## Supported claims

The built-in verifier `gvr.code_graph.v1` supports the canonical `CodeGraphClaimKind` values:

- `NODE_EXISTS`
- `EDGE_EXISTS`
- `PATH_EXISTS`
- `NO_PATH`
- `ALL_PATHS_PASS_THROUGH`
- `BLAST_RADIUS_CONTAINS`

Claims are encoded as normal `AtomicClaim` records. The claim fingerprint in every provider observation must match the atomic claim being verified. A mismatch fails closed to `UNKNOWN` and is reported as provider claim contamination.

## No voting and corroborated meaning

Provider reconciliation is deterministic corroboration, not voting. Repetition from one provider family does not create independence. Heuristic-only observations remain `UNKNOWN` even if repeated. Two independent decisive providers can mark a verdict as corroborated, but a single decisive exact provider can still produce a normal PASS or FAIL when there is no conflict.

Conflicts fail closed. Independent decisive PASS and FAIL observations for the same claim and snapshot return `UNKNOWN` with preserved evidence IDs. Snapshot mismatches also fail closed. A Graphify complete `NO_PATH` observation can PASS by itself because it is an explicit complete absence proof. CodeFlow silence is not used as absence proof.

## External precomputed snapshots

External providers are responsible for acquiring immutable snapshots and encoding them with stable evidence IDs. Execution persists the exact provider result through `execute_verification_plan(..., storage=SQLiteStorage(...))`. Semantic evidence slot identities come from the exact `EvidenceRequest`, provider/source identity, and evidence ID. Advancing one provider's semantic snapshot advances only that provider's slot and invalidates downstream stored bundles, claims, and sessions that depended on the old slot version.

Because evidence IDs are exact, there is no raw-ID slot inference or substitution. If two acquisitions use the same evidence ID with different content in one reachable claim basis, execution fails closed before verification. If one provider advances and another remains unchanged, storage keeps the unchanged provider slot current while invalidating stale dependents of the advanced slot.
