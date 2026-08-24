# Task 32 typed graph authority TDD evidence

## Authorized boundary

- Exact base: `4cce148d96c7a783ee60a9cfaac84d123a64b2fb`.
- Branch: `feature/gvr-typed-graph-authority-v1`.
- `probe_false_freshness.py` remains untracked and untouched.
- Task 33 was not started.

## RED-first checkpoint

The first Task 32 commit adds `tests/test_task32_typed_graph_authority.py` before production changes. The focused RED run failed during collection because `CoverageCertificate` and the other typed authority contracts did not exist.

## Canonical authority model

`GraphEvidenceModel` now separates five immutable authorities:

1. `SourceRevisionIdentity` identifies the repository and exact revision.
2. `GraphQueryScope` identifies start/target, direction, distinct requested/effective/rejected relations, max depth/path/expansion bounds, stop nodes, and evidence namespace.
3. `CoverageCertificate` states whether the bounded search is complete and why it terminated.
4. `ProviderImplementationIdentity` identifies the provider, exact implementation, and adapter-sealed family.
5. `GraphFacts` contains only nodes, edges, blockers, and complete absence subjects.

The canonical graph fingerprint includes every authority independently. Reordering facts is invariant, while changing any revision, scope, coverage, provider implementation, or fact changes the fingerprint. Transport replay reconstructs the typed model and verifies its model fingerprint.

## Authority-safe encoding and verification

- The low-level encoder rejects caller overrides of typed provider implementation, provider family, and source snapshot authorities.
- Provider adapters seal family identity and construct provider implementation identity inside the adapter boundary.
- The observation payload repeats typed revision, query scope, and coverage fields and the decoder checks each against the fingerprinted graph model.
- `verify_code_graph_observation` requires exact typed revision and query-scope equality before graph facts are considered.
- Negative and all-paths conclusions additionally require a complete `CoverageCertificate`.
- Legacy graph inputs remain behaviorally compatible but are explicitly marked as legacy authority mode. They do not silently become typed authority. Flat legacy documents presented to typed replay fail closed.

## Structural audit

The executable structural audit is covered by `test_task32_typed_authorities_are_frozen_canonical_and_distinct` and `test_task32_legacy_flat_graph_documents_fail_closed_instead_of_guessing_authority`. Canonical output has only `provider_identity`, `source_revision`, `query_scope`, `coverage`, and `facts` at the graph-model authority boundary. Revision data is absent from query scope, and coverage data is absent from graph facts.

## Validation

Final commands and observed results are recorded in the supervising Drive report after focused, full-suite, compile, package, wheel, installed-wheel, diff-hygiene, and exact CI validation complete.
