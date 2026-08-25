# Task 33e Graphify identity/bound-termination native parity remediation

## Authorized boundary

- Exact base: `110608c0b24abd9dcbe0fd49aae50e08ec9d1284` from remote `feature/gvr-graphify-envelope-accounting-parity-v1`.
- Read-only producer reference: Graphify `529ade498158a86e6607138b1c3e717874553294`.
- Target branch: `feature/gvr-graphify-identity-bound-termination-parity-v1`.
- Task 34 was not started.

## RED-first evidence

The tests-only commit `31d9b22` added identity-absence, real zero-step identity, bound-specific termination, COMPLETE-at-bound, stop-node, missing-node precedence, table-mutation, CodeFlow no-rescue, and SQLite replay coverage.

Before production changes, the focused Task 33e suite produced `9 failed, 5 passed`. The failures exposed false definitive identity absence, producer-impossible MAX_EXPANSIONS/MAX_PATHS envelopes retaining EXACT authority, start-as-stop rejection, invalid missing-target identity remaining current-native, and CodeFlow/typed exposure of malformed Graphify evidence.

## Shared parser semantics

`gvr.graphify_contract.validate_graphify_envelope_authority` remains the single producer-envelope parser. It now additionally enforces:

- a resolved `start == target` query has exactly one zero-step identity path and can never authorize absence;
- `MAX_EXPANSIONS` requires `expanded_count == max_expansions`;
- `MAX_PATHS` requires the returned path count to equal `max_paths`;
- `COMPLETE` remains valid exactly at a configured bound;
- start and target stop-node membership are no-ops, while an interior stop-node crossing is invalid;
- `TARGET_NODE_NOT_FOUND` requires a found start and missing target;
- `START_NODE_NOT_FOUND` retains producer precedence when both endpoints are absent.

The zero-step identity continues to prove the point-to-point data-flow claim without fabricating a code-graph self-edge.

## Validation

Focused, full, packaging, installed-wheel, and CI results are recorded in the Drive agent report.
