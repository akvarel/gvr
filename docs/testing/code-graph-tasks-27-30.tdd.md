# Tasks 27-30 code evidence and graph verification TDD evidence

## Authorized boundary

- Exact GVR base: `45f9f804c795a0b7faae58a8f12eee7371225c8f`
- Branch: `feature/gvr-code-evidence-verification-v1`
- CodeFlow behavioral pin inspected read-only: `262206cb468e91566d417e21b4182eea1c4cab9d`
- Graphify inspected read-only: branch `feature/java-persistence-boundary-completion-v8`, SHA `7e35c05714be27ea9b25b0ae5d8928a589d57904`
- Graphify reference files: `graphify/data_flow_query.py` and `docs/data-flow/GVR-DERIVED-EVIDENCE-CONTRACT.md`
- No CodeFlow, Graphify, protected branch, production, or other repository was modified.

## Phase checkpoints

| Phase | RED | GREEN/checkpoint | Evidence |
| --- | --- | --- | --- |
| Task 27 | `362f0de1531133edc4318232fec6c8cfc2ce6dc1` | `36367a707edc6b16ffa77f10406a6f80143fef76` | Canonical provider-independent graph model and offline CodeFlow adapter. |
| Task 28 | `4690f8a49715fdf515c0bd01e9b0a35eb341be18` | `4f42ed10c82e9a2ee7bcc10ba2c92c5e91901935` | Strict Graphify public traversal mapping and complete negative-search evidence. |
| Task 29 | `0a3272af8fb5eaacdbe33581bdec8d4b7bf89cd3` | `0770f7f2d78b1530bf47a1047ec43760b7a26533` | Deterministic provider-independent graph claims and algorithms. |
| Task 30 | `a60a21816d1aa07a8ed1b9e3d192b4b88658c1c5` | `ffb8adc8a6bd9a84fe2c6190d3f69610d76a59bf` | Deterministic no-voting provider reconciliation. |
| Integrated executor | `60ce8a58f719910a19bddeb651d12bf5d1aed342` | `1924d8aba1f2b2de75d50ae772d8b48d224fcbff` | Built-in canonical observation verifier runtime and exact SQLite replay/currentness. |
| Adversarial review | `a986a25637a97e39a5af1c07e3ff25d6593ebf1e` | `f2735e45319a8971572a3bca7464ed9e6a12a763` | Order-independent fingerprints, canonical Graphify absence IDs, no FAIL from silence, exact counterexamples only, explicit bypass completeness. |
| Public contract closure | `7abf4c8c3eae83ad588e2a5f5a5a49673d70df23` | `ef7ae01f14cc780c6879521ac329b7473f25cb07` | Scope direction/namespace/depth/stop nodes and required stable issue codes. |

## Canonical identity and epistemic boundary

Canonical graph observations separate a provider-independent semantic fingerprint from a provider-specific exact fingerprint. Exact identity binds provider implementation/native identity, analyzer provenance, source snapshot, and exact normalized content. Request IDs, run IDs, timestamps, UI order, and correlation metadata do not enter semantic identity.

CodeFlow file/function/call observations are offline precomputed evidence. Call/reference observations are heuristic and cannot independently produce `PASS` or negative proof. Skipped, oversized, fetch-failed, and unsupported parsing become blockers. Architecture Diagram dependencies are synthetic `INFERRED_HINT` observations and never truth evidence.

Graphify observations become exact/proven only after strict public-contract checks for `df:<sha256>` keys, step/support consistency, supported relations, receiver confidence, exact path coverage, query validity, endpoint resolution, traversal scope, boundaries, truncation, termination, and complete supported search. Provider claims of truth are not trusted directly.

## Graph verifier truth table

- Positive node/edge/path/blast claims pass only on exact admissible evidence. Missing evidence fails only when exact scoped complete absence exists; otherwise it is `UNKNOWN`.
- `NO_PATH` fails only on an exact counterexample and passes only on exact complete supported absence.
- `ALL_PATHS_PASS_THROUGH` is nonvacuous. Exact bypass produces `FAIL`; `PASS` requires proven reachability and explicit complete absence of bypass paths.
- Heuristic, observed, inferred, blocked, stale, unsupported, mixed-snapshot, or malformed evidence cannot independently produce truth.
- Direction, relation set, evidence namespace, depth, and stop nodes are explicit immutable scope fields. Traversal ordering and returned paths are canonical.

## Provider reconciliation truth table

- Repetition and same-family wrappers never create independent votes.
- Heuristic agreement remains `UNKNOWN`.
- One decisive proven result retains its verdict when other observations are heuristic, silent, or unknown.
- Independent decisive disagreement for one exact claim/snapshot returns `UNKNOWN` with conflict evidence from both providers.
- Independent decisive agreement retains the verdict and adds `CORROBORATED` metadata; corroboration is not a new truth source.
- Different source snapshots do not corroborate each other.

## Integrated durable coverage

The real executor suite covers Graphify-proven plus CodeFlow-heuristic `PASS`, CodeFlow-only `UNKNOWN`, Graphify complete `NO_PATH` proof without CodeFlow silence, decisive cross-provider conflict, close/reopen/replay exact idempotency, isolated one-provider snapshot advancement, and adversarial contamination. Canonical provider observations flow through normal evidence acquisition, verifier capability/runtime binding, bundles, claims, sessions, and SQLite exact records.

## Final local validation

```text
Task 27 focused: 5 passed
Task 28 focused: 5 passed
Task 29 focused: 14 passed
Task 30 focused: 10 passed
Integrated focused: 7 passed
Full suite: 641 passed in 30.60s
python -m compileall -q src tests: PASS
git diff --check: PASS
```

The system Python lacked an executable `python -m build` frontend. An isolated scratch virtual environment installed the standard `build` package, after which `python -m build` succeeded and produced both sdist and wheel. `python -m pip wheel . --no-deps` also succeeded.

```text
gvr-0.2.0-py3-none-any.whl sha256 3e726882b68fc84ada6b77426534e21a718241f3dfd4de55cee8f8e7583fd8f2
gvr-0.2.0.tar.gz sha256 b6f0c16101489cca7d23ba8153f1fef18e2f0ebbc0cd330734a750bc019e0ee7
```

Installed-wheel testing ran outside the repository with `PYTHONPATH` removed and `gvr` loaded from the temporary environment's `site-packages`. The Task 27, 28, 29, 30, and integrated suites passed: `41 passed in 3.23s`.

Remote CI evidence is recorded in the final taskbus report after the feature branch push.
