# ClaimGraph and VerificationSession TDD Evidence

## Source task

Google Drive taskbus document `13-gvr-verification-session-claim-graph`.

Approved base: `9d5b24eaf958b65e8582a94353a5c5cc6e67b8a6` on
`feature/gvr-verification-bundle-v1`.

Target branch: `feature/gvr-verification-session-v1`.

## User journeys

1. As a GVR consumer, I can define strict atomic and composite claims in an
   order-independent graph, so graph identity and validation are reproducible.
2. As a verification runtime, I can compose only materialized bundle and ledger
   state with exact `PASS / FAIL / UNKNOWN` logic, so stale or missing support
   never becomes current truth.
3. As an operator, I can bound deterministic work and observe consumption and
   termination, so a cutoff remains explicit and affected roots stay `UNKNOWN`.
4. As a remote caller, I can use schema-v1 `compose_verification_session` and
   receive canonical auditable state or a fail-closed protocol error.

## RED and GREEN checkpoints

- Baseline adjacent regression command:
  `python -m pytest -o addopts='' -q tests/test_dependencies.py tests/test_ledger.py tests/test_verification_bundle.py tests/test_protocol.py`
  produced `69 passed in 0.16s`.
- RED commit: `ffac6d1` (`test: specify verification session composition`).
  `python -m pytest -o addopts='' -q tests/test_verification_session.py` failed
  during collection because the public `AtomicClaim` and session APIs did not
  exist.
- Initial GREEN: the same focused command produced `28 passed in 0.09s`.
- Separate adversarial RED attempted to obtain trusted truth through a mutable
  exposed ledger, replace the graph after construction, and label a stale root
  session complete. The focused selection produced `3 failed, 4 passed` and
  reproduced all three defects.
- Adversarial remediation made the ledger view defensive, graph/roots/budget
  read-only, and stale composition terminate as `UNSUPPORTED_CLAIM` until
  recomputation. The focused session suite then produced `35 passed in 0.10s`.

## Test specification

| # | Guarantee | Test target | Type | Result |
|---|---|---|---|---|
| 1 | Exact AND/OR/NOT truth tables preserve GVR tri-state semantics | `test_*_uses_exact_tri_state_logic` | unit | PASS |
| 2 | Nested composites evaluate in deterministic dependency order | `test_nested_composite_graph_is_deterministic` | unit | PASS |
| 3 | Node, dependency, root, and bundle input order cannot perturb semantic identity | fingerprint and wire determinism tests | unit/integration | PASS |
| 4 | Duplicate ambiguity, unknown/self dependencies, cycles, and invalid arity are rejected | graph validation tests | unit | PASS |
| 5 | Unsupported runtime values are rejected instead of `repr()`-hashed | strict semantic value test | unit | PASS |
| 6 | Missing and explicit UNKNOWN atomic results remain UNKNOWN through roots | missing/UNKNOWN bundle tests | integration | PASS |
| 7 | Verifier or claim-dependency mismatch fails before session mutation | bundle mismatch test | integration | PASS |
| 8 | Changed typed Evidence semantics re-version atomics and stale dependent composites | changed evidence test | integration | PASS |
| 9 | Identical bundle rerecording leaves atomic and downstream versions/freshness unchanged | semantic no-op test | integration | PASS |
| 10 | Removed evidence and stale stored PASS cannot produce a root PASS | stale evidence test | integration | PASS |
| 11 | Trusted atomic recording cannot be bypassed through the exposed ledger view | defensive ledger test | adversarial | PASS |
| 12 | Claim graph state cannot be replaced after session construction | read-only graph test | adversarial | PASS |
| 13 | Claim, bundle, evidence-record, evidence-byte, and step limits fail closed | budget tests | unit/integration | PASS |
| 14 | Budget cutoff marks `BUDGET_EXHAUSTED` and leaves affected roots UNKNOWN | cutoff test | integration | PASS |
| 15 | Irrelevant unconnected claims do not alter selected root truth but remain session semantics | irrelevant claim test | unit | PASS |
| 16 | Root selection and budget declaration change the session fingerprint | session identity tests | unit | PASS |
| 17 | Malformed bundles cannot partially mutate session-owned ledger state | atomicity test | adversarial | PASS |
| 18 | Schema-v1 composition is deterministic and exposes graph, claims, roots, bundle refs, budgets, termination, and fingerprint | protocol composition test | integration | PASS |
| 19 | Cyclic graphs and inconsistent fingerprints fail closed as protocol errors | protocol error tests | integration | PASS |
| 20 | Existing dependency, ledger, bundle, protocol, goal, text, functional, and data-flow behavior remains clean | adjacent/full pytest commands | regression | PASS |

## Fingerprint and accounting contract

- ClaimGraph fingerprints cover schema/kind and canonical semantic node records.
  Human descriptions are not truth-bearing identity.
- Session fingerprints cover schema/kind, canonical graph and roots, atomic
  bundle fingerprints or unverified markers, stored/effective verdicts,
  freshness and versions, evidence and claim dependency references, budget
  declaration and deterministic consumption, and termination.
- Canonical Evidence byte consumption is UTF-8 length of strict canonical
  evidence-record JSON. Wall-clock time is excluded.
- Rejected malformed inputs do not consume budget or mutate ledger state.

## Validation and known limits

Final validation from the completed working tree:

- `python -m pytest -o addopts='' -q tests/test_verification_session.py`:
  `35 passed in 0.09s`.
- `python -m pytest -o addopts='' -q tests/test_dependencies.py tests/test_ledger.py tests/test_verification_bundle.py tests/test_protocol.py tests/test_verification_session.py`:
  `104 passed in 0.24s`.
- `python -m pytest -o addopts='' -q`: `186 passed in 0.29s`.
- `python -m compileall -q src`: PASS.
- `git diff --check`: PASS.

This layer intentionally does not schedule verifiers, acquire evidence, persist
state, decompose claims with an LLM, add policy, or change Graphify or BugZero.
It consumes only already-materialized `VerificationBundle` inputs.
