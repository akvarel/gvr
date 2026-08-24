# Task 33d Graphify accounting/path-set/termination parity remediation

## Authorized boundary

- Exact base: `d40aae6f08c5f9c17aca8b3983a41453c44791d1` from remote `feature/gvr-graphify-native-envelope-strict-parity-v1`.
- Read-only producer reference: Graphify `529ade498158a86e6607138b1c3e717874553294`.
- Target branch: `feature/gvr-graphify-envelope-accounting-parity-v1`.
- Task 34 was not started.

## RED-first evidence

The tests-only commit `8e0b36d` added the Task 33d accounting, duplicate path-set, resolution/termination, path-coverage, zero-step identity, CodeFlow no-upgrade, SQLite replay, and table-driven parity cases.

Before production changes, the focused suite produced `10 failed, 7 passed`. Failures demonstrated generic EXACT authority for impossible visited/expanded accounting, excess returned paths, duplicate path identities, and resolved/failure termination combinations. It also demonstrated rejection of the producer-valid zero-step identity path and CodeFlow/SQLite exposure of an invalid Graphify EXACT edge.

## Shared current-native parser

`gvr.graphify_contract.validate_graphify_envelope_authority` is the single authority-critical current-native parser. It owns:

- mandatory schema, types, vocabularies, query relation partition, and bounds;
- content-addressed boundary validation;
- returned path-set identity and duplicate rejection;
- `visited_count <= expanded_count + 1` for resolved traversals;
- non-identity returned paths not exceeding accepted expansions;
- producer-valid `expanded_count > visited_count` cases;
- exact resolution/termination/truncation/count state transitions;
- current-native path coverage vocabulary;
- positive and complete-negative authority;
- normalized query/accounting facts consumed by the data-flow verifier.

`verifiers.data_flow._global_issues` now reuses that parse and retains only claim/query/scope/revision binding plus user-facing diagnostic categories. Its duplicate producer accounting, bounds, coverage, and termination state machine was removed.

The positive path validator accepts the Graphify zero-step `start == target` identity path. The code-graph adapter emits no fabricated self-edge or absence fact for that identity result.

## Acceptance coverage

The Task 33d suite covers impossible upper accounting, path-count accounting, duplicate identities, complete resolution/termination transitions, strict path coverage, parallel edges, branching/reconvergence, target terminality, interior stop rejection, truncated positive witnesses, complete-only negative authority, zero-step identity, CodeFlow no-upgrade, SQLite close/reopen replay, and a table-driven shared-authority parity matrix.

## Validation

Final validation results, package hashes, installed-wheel acceptance, and exact GitHub Actions matrix status are recorded in the Drive agent report.
