# Task37b Graphify v2 identity / immutability / replay remediation TDD evidence

## Authorized boundary

- Exact approved GVR base: `a3f040c30794f218ee143b7a927cf4e02f765361` (Task37 final HEAD, remote-verified before branching).
- Base branch: `feature/gvr-graphify-v2-bound-snapshot-authority-v1`.
- Target branch: `feature/gvr-graphify-v2-identity-immutability-remediation-v1`.
- Graphify was inspected read-only at exact contract HEAD `529ade498158a86e6607138b1c3e717874553294`.
- `probe_false_freshness.py` remains preserved and untracked. It is not an authority source for Task37b.

## TDD checkpoints

| Phase | Commit | Evidence |
| --- | --- | --- |
| RED | `bc4cc9a` | Tests-only commit with genuine RED on exact base: focused suite 9 failed / 37 passed. Failures covered zero-step identity rejection, missing bound minima parity, shallow-freeze mutation bypass, unsealed direct construction, adapter typed-object trust, and the installed-wheel matrix (six attacks then succeeded). All Task37 placeholders were replaced with real tests in this commit. |
| Initial GREEN | `11855cb` | Deep-frozen canonical v2 state, ingestion seal, mandatory adapter revalidation, producer query-bound parity (`max_paths >= 1`, `max_expansions >= 1` in `query` and `coverage.query_bounds`), and producer-valid zero-step identity acceptance. Focused 46 passed; full 913 passed. |
| Stealth review remediation | `7d3f601` | Addressed independent review blockers: removed `_FrozenList` list subclass (tuple freezing, fully thawed detached projections), removed the importable `_INGESTION_SEAL` token so directly built typed views are inert and gain authority only through boundary revalidation, and moved zero-step identity strictness into the parser (duplicate empty identities, label exactness, resolved/complete/unblocked identity state, visited/expanded accounting). Focused 61 passed; full 928 passed. |
| Matrix hardening | `f357859` | Installed-wheel matrix builds robustly even when executed from a minimal fresh-venv wheel install (isolated-build fallback), and was extended to the full section 6 acceptance surface: producer-valid identity, positive witness, complete negative, cross-snapshot substitution, binding/fingerprint mutation, post-parse mutation protection, projection-only rejection, public UNVERIFIED, trusted VERIFIED under `ProviderTrustContext`, SQLite close/reopen replay, and mismatch precedence. |

## Independent review record

1. First stealth reviewer (openrouter `stealth/ox-alpha`) failed with a provider error mid-review; the coordinator ran a fallback review (openai `gpt-5.6-luna`, session "dolphin") which reported BLOCKED on `11855cb` with three findings: list-subclass escape hatches over sealed state, importable seal token permitting construction shortcuts, and identity-path strictness deferred to envelope validation.
2. All findings were fixed in `7d3f601` with adversarial regressions for each.
3. Independent stealth re-review of exact HEAD `f357859` returned PASS/CLEAN (all blockers closed; one non-blocking mixed identity-path observation recorded by the reviewer).

## Design summary

- Canonical v2 state is sealed at ingest via recursive `MappingProxyType`/tuple freezing; no reachable mutation path exists (including `list.__setitem__`-style escapes).
- `to_dict()`, `to_gvr_traversal_dict()` and persisted authority metadata all thaw from the same canonical state; projections are detached mutable JSON and lists stay JSON lists after round-trip.
- `GraphifyStructuralEvidenceV2` is an inert deeply immutable typed view. The single typed-object boundary (trusted adapter encoding) mandatorily re-ingests `snapshot.to_dict()` and re-checks every binding, content address, duplicate rule, path reference, and the outer snapshot fingerprint. Authority flows only from content that revalidates.
- Zero-step identity: exactly one empty `path_identity` is accepted only for a bound `start == target` query in the producer's resolved, complete, unblocked, untruncated state with exact identity labels and `visited_count == 1`, `expanded_count == 0`; every other empty identity fails closed at parse time.
- Producer minima parity: `max_depth >= 0`, `max_paths >= 1`, `max_expansions >= 1` enforced on both `query` and `coverage.query_bounds`.

## Validation record

```text
python -m pytest -o addopts='' -q tests/test_task37_graphify_v2_bound_snapshot_authority.py
61 passed

python -m pytest -o addopts='' -q tests/
928 passed

python -m compileall -q src tests
PASS

git diff --check
PASS

clean sdist + wheel build: gvr-0.2.0.tar.gz, gvr-0.2.0-py3-none-any.whl
PASS

installed-wheel replay (fresh venv, PYTHONPATH removed, gvr from site-packages):
focused task37b suite 61 passed; extended attack/replay matrix MATRIX OK
```

Exact final SHA, CI run link, and Drive report reference are recorded in the agent report.
