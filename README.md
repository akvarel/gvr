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
- versioned wire envelope for future CLI / hooks / MCP / standalone runtime.

The repository intentionally does not contain BugZero product policy. Product
policy belongs in the private BugZero Verify service.

## Graphify data-flow claims

`verify_data_flow_claim()` consumes the public Graphify bounded traversal-result
mapping. It does not parse source code or build a second graph. A positive flow
claim passes only for an individually exact `PROVEN` path with complete coverage
and valid deterministic `df:...` dependencies. Absence is accepted only when
Graphify reports a complete supported search with no path and no MAY evidence.
Malformed, contradictory, truncated, unresolved, partial, ambiguous, or
unsupported evidence fails closed to `UNKNOWN`.

Schema version 1 also exposes the `verify_data_flow_claim` wire operation. Its
report preserves the claim kind and endpoints, exact evidence IDs, issue codes,
and Graphify termination, bounds, boundary, and search-coverage metadata.
