# Task 33b Graphify envelope authority parity remediation TDD evidence

## Authorized boundary

- Exact remote base: `fae42f747ee2ba6a3d007eced957c6bbc42ced14` on `origin/feature/gvr-graphify-positive-query-authority-v1`.
- Implementation branch: `feature/gvr-graphify-query-authority-parity-remediation-v1`.
- Work is confined to GVR. Task 34, protected branches, Graphify, CodeFlow, and external repositories were not modified.
- The untracked `probe_false_freshness.py` remains outside the change set at SHA-256 `3473d65d38558ff6ab484268f0dd455d3842198542f364ecf2aa882cb0266f89`.

## RED-first evidence

The tests-only RED commit is `2ebacc7`. The first focused execution of
`tests/test_task33b_graphify_envelope_authority_parity.py` produced `17 failed, 11 passed`.
The failures demonstrated authority divergence for vocabulary, strict booleans,
counts, finite bounds, relation partitions, completeness certificates,
coverage/termination state, and negative completeness.

## Shared envelope authority

`gvr.graphify_contract.validate_graphify_envelope_authority` is the single
Graphify envelope authority validator used by:

1. the public contract and positive path validator;
2. the Graphify graph adapter and generic typed observation path;
3. the data-flow verifier's structural authority checks.

It validates the public direction and resolution vocabularies, relation
partition, finite bounds, visit/expansion/path accounting, boolean epistemic
flags, completeness certificate parity, coverage state, truncation/termination
state, and blocking boundaries. Canonical current fields are strict while
established public aliases remain compatible and fail closed for authority.

## Semantics preserved

- A structurally exact positive witness remains existentially authoritative when
  a valid finite bound truncates the wider search.
- MAY, PARTIAL, UNKNOWN, blocked, unresolved, malformed, over-bound, or
  contradictory envelopes cannot authorize exact positive edges.
- Negative authority remains universal and requires a complete, resolved,
  untruncated, unblocked envelope with exact coverage and consistent accounting.
- Adapter, typed Graphify observation, and data-flow decisions are exercised by
  one parity helper across all adversarial cases.

## Validation

Exact focused, full-suite, compilation, build, wheel, installed-wheel, SQLite,
structural audit, Git, CI, and report-delivery outcomes are recorded in the
supervising Drive agent report.
