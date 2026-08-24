# Task 33 Graphify positive query authority TDD evidence

## Authorized boundary

- Approved remote base: `feature/gvr-provider-adapter-typed-authority-remediation-v1` at `7959cf43c3cdd015b5408d704f2b300c78c48363`.
- Implementation branch: `feature/gvr-graphify-positive-query-authority-v1`.
- Work is confined to GVR. No Graphify, CodeFlow, protected branch, production, or external repository was modified.
- The untracked `probe_false_freshness.py` remains outside the change set.

## RED-first evidence

`tests/test_task33_graphify_positive_query_authority.py` failed before implementation because the Graphify graph adapter and typed observation encoder accepted disconnected, endpoint-rebound, step-rebound, identity-rebound, out-of-scope, and over-bound positive paths as exact graph authority.

## Shared authority contract

`gvr.graphify_contract.validate_graphify_positive_traversal` is the single strict public traversal validator used by:

1. the Graphify graph adapter;
2. the data-flow verifier;
3. the generic typed code-graph observation path through the Graphify encoder.

It validates ordered step/evidence/path identity equality, content-addressed `df:` keys, connectivity, bounds, and query endpoint/scope authority. Structurally malformed positive paths fail closed. Valid evidence that is not authoritative for the exact query remains available only as `HEURISTIC`, never `EXACT`.

## Preservation and integration coverage

- Complete empty traversal retains negative absence authority.
- Incomplete or truncated empty traversal remains `UNKNOWN`.
- MAY/PARTIAL/unsupported evidence remains heuristic and cannot be upgraded.
- Source revision advancement and query-scope changes remain distinct typed authorities.
- A downgraded Graphify observation executes through the real plan executor and SQLite storage, remains `UNKNOWN`, and replays idempotently after reopen.
- The real CodeFlow typed path remains heuristic and cannot upgrade a claim.

## Validation

- Task 27-33 focused suite: PASS.
- Full test suite: PASS.
- Python compileall: PASS.
- Isolated sdist and wheel build: PASS.
- Installed-wheel positive-authority smoke: PASS.
- Final diff and preserved-file checks: recorded in the agent report.
