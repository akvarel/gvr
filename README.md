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
- Graphify traversal evidence adapter;
- versioned wire envelope for future CLI / hooks / MCP / standalone runtime.

The repository intentionally does not contain BugZero product policy. Product
policy belongs in the private BugZero Verify service.
