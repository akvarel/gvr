# Task 34 provider independence registry TDD evidence

## Authorized boundary

- Exact accepted Task 33e base: `48fba3ba73e63049314a9279f7a572dcbadc1152`.
- Source branch verified remotely before creating `feature/gvr-provider-independence-registry-v1`.
- Graphify, CodeFlow, protected branches, production, and `probe_false_freshness.py` were not modified.

## Trust model

`ProviderImplementationRegistry` deterministically resolves a `ProviderImplementationIdentity` to a `VerifiedIndependenceFamily` with an explicit `VERIFIED` or `UNVERIFIED` trust state.

- Graphify adapter identities carry sealed `provider_kind="graphify"` and resolve to the single built-in `graphify` family.
- CodeFlow adapter identities carry sealed `provider_kind="codeflow"` and resolve to the single built-in `codeflow` family.
- Low-level identities default to `provider_kind="low-level"`. Their caller-provided `provider_id` and `family_id` remain descriptive labels and resolve as `UNVERIFIED`.
- Provider display names, transport IDs, run IDs, and caller family labels do not create verified independence.
- Implementation revisions and wrapper versions remain orthogonal to categorical family identity.
- A narrowly scoped `task34-test` deterministic provider registration exists only inside Task 34 tests to prove genuine independent-family behavior.

## RED and GREEN

The tests-only RED commit imports the required registry API before implementation and fails during collection. The GREEN implementation adds registry resolution, adapter sealing, deterministic observation transport, replay validation, and reconciliation.

## Reconciliation

- Decisive truth remains independent from independence metadata.
- Only `VERIFIED` families contribute corroborating family votes.
- One decisive observation remains decisive but is marked single-family, not corroborated.
- Same verified-family PASS/FAIL yields `PROVIDER_FAMILY_CONTRADICTION`.
- Distinct verified-family PASS/FAIL yields `PROVIDER_CONFLICT` only when claim and exact snapshot/scope match.
- Snapshot or scope mismatch fails closed before conflict classification.
- Heuristic evidence remains non-decisive regardless of provider independence.

## Persistence and determinism

Registry resolution is serialized in each canonical provider observation and checked again during decode. The registry-derived family and trust state survive canonical serialization, SQLite close/reopen, replay, observation reordering, and duplicate insertion. Reconciliation fingerprints use semantic implementation/family resolution rather than verified-provider display labels.

## Structural audit

| Value source | Path | Trust |
|---|---|---|
| Graphify adapter | `adapters/graphify.py -> ProviderImplementationIdentity(provider_kind="graphify")` | VERIFIED, sealed built-in family |
| CodeFlow adapter | `adapters/codeflow.py -> ProviderImplementationIdentity(provider_kind="codeflow")` | VERIFIED, sealed built-in family |
| Generic graph model | `GraphEvidenceModel(provider=...)` | UNVERIFIED low-level label |
| Typed low-level identity | public `ProviderImplementationIdentity(...)` default kind | UNVERIFIED unless explicitly resolved by a supplied registry |
| Canonical encoder | `encode_code_graph_observation_evidence` | serializes registry resolution |
| Canonical decoder | `decode_code_graph_observation_evidence` | recomputes and verifies registry resolution |
| Integrated runtime | `_CodeGraphVerifierRuntime.verify` | threads decoded resolution into reconciliation |
| Direct reconciliation fixture | `ProviderVerificationObservation` | defaults to UNVERIFIED unless supplied a machine-checkable resolution |
| Corroboration count | `_decisive_families` | VERIFIED families only |
| Truth decisiveness | `_has_decisive` | orthogonal to independence and still excludes hints/heuristics |

Search terms audited after GREEN: `family_id`, `provider`, `provider_id`, `implementation_id`, `independence`, and corroboration family counting across `src/gvr` and Task 27-34 tests.
