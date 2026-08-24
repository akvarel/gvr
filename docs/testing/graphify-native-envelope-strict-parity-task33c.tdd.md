# Task 33c Graphify native envelope strict parity remediation

## Authorized boundary

- Exact base: `f95e17fe8c7f97d003270daf1ceae76c028a9596` from `origin/feature/gvr-graphify-query-authority-parity-remediation-v1`.
- Implementation branch: `feature/gvr-graphify-native-envelope-strict-parity-v1`.
- Producer reference was read only at Graphify commit `529ade498158a86e6607138b1c3e717874553294`, file `graphify/data_flow_query.py`.
- Graphify, CodeFlow, protected branches, and Task 34 are outside scope.
- The unrelated untracked `probe_false_freshness.py` is preserved outside all commits.

## RED-first evidence

The mandatory tests-only commit is `40e7b8e`. Its first focused run produced
`18 failed, 33 passed`, proving gaps for required native fields and bounds,
expansion accounting, target terminal stop semantics, legacy aliases, and
adapter/data-flow authority parity.

## Shared native authority

`gvr.graphify_contract.validate_graphify_envelope_authority` is the shared
current-native envelope parser and authority validator used by the Graphify
adapter, typed observation encoder, positive traversal contract, and data-flow
verifier. It now requires every producer-emitted top-level field, canonical
query-bound field, and path authority field before exact positive or complete
negative authority is possible.

Canonical relation collections are sorted and unique. Bounds are finite real
integers. Native booleans and strings are not coerced. Legacy or incomplete
shapes may still be ingested fail-closed, but cannot authorize exact edges or
absence conclusions.

Boundary events require the complete native event shape, blocking resolution
vocabulary, consistent diagnostic identity, real integer counts, and the exact
content-addressed `bnd:<sha256>` identity used by Graphify.

## Semantics preserved

- `expanded_count` counts accepted edge expansions and may exceed the number of
  unique visited nodes, while remaining within `max_expansions` and covering
  returned paths.
- The query target is terminal before `stop_nodes` is consulted, so including the
  target is a semantic no-op. A returned path crossing another stop node remains
  non-authoritative.
- A structurally exact returned path can remain authoritative in a consistently
  truncated envelope.
- Empty-path authority still requires a complete, resolved, untruncated,
  unblocked current-native envelope.
- CodeFlow evidence is not upgraded by Graphify parsing.
- SQLite close/reopen replay remains covered by the integrated execution suite.

## Validation

Focused parity, full regression, compilation, diff hygiene, source and wheel
builds, installed-wheel smoke, SQLite replay, and CI status are recorded in the
Drive agent report.
