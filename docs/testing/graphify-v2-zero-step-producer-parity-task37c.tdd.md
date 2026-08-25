# Task37c TDD: Graphify v2 zero-step producer parity

## Objective

Separate Graphify v2 zero-step identity **document validity** (parser) from
**decisive truth** (Task33e envelope authority). The exact read-only Graphify
producer HEAD `529ade498158a86e6607138b1c3e717874553294` emits two genuine
zero-step `start == target` results:

- clean identity: one zero-step path, no blockers, COMPLETE coverage;
- identity with a real blocking boundary in the reached start file: one
  zero-step path, PARTIAL coverage, `complete_supported_search=false`,
  `termination_reason=COMPLETE`.

Both are producer-valid documents. Task37b's parser wrongly failed closed on
the second; authority, not the parser, must degrade it to non-decisive.

## Branch and commit discipline

- Base branch: `feature/gvr-graphify-v2-identity-immutability-remediation-v1`
  at exact remote HEAD `b64f95ae9b114b57417a9297a388b54921248d17` (verified).
- Target branch: `feature/gvr-graphify-v2-zero-step-producer-parity-v1`.
- Read-only Graphify producer reference: exact accepted
  `529ade498158a86e6607138b1c3e717874553294`, never modified.
- `probe_false_freshness.py` remains preserved and untracked; not an authority
  source for this task.

## TDD checkpoints

| Phase | Commit | Evidence |
| --- | --- | --- |
| RED + provenance | `f93687688043bc95da776665475b144a04d3f7d2` | Tests, fixtures, generator, and provenance only. Both zero-step vectors are direct producer output of the exact bound pipeline (`gen_vectors.py` recipe committed); no field mutated or resealed. Independent re-run of the focused suite at this SHA: 6 failed / 12 passed — `test_task37c_07..10` (boundary identity rejected as malformed), `test_task37c_11` (mixed-path rule absent), `test_task37c_16`. |
| GREEN | `0e806d57c1f2b33ee209ee0e4134a500bad78c81` | Both producer-valid zero-step identity states parse. Decisiveness moved fully to the envelope authority surface: clean identity may be decisive positive; boundary identity is non-decisive UNKNOWN, never malformed. Explicit parser rules: mixed zero+nonzero paths, duplicate zero identities, and non-identity empty paths fail closed. The derived traversal projection restores the producer-native boundary event shape so `bnd:` keys reach envelope authority and the data-flow verifier. |

## Parser-vs-authority separation after this task

```text
Graphify v2 parser      -> could the exact producer have serialized this?
Task33e envelope authority -> may this valid traversal decide positive/negative truth?
ProviderTrustContext    -> does this observation come from a trusted provider origin?
```

Outcomes enforced by tests and the installed-wheel matrix:

- valid clean identity -> parse PASS, positive authorized, negative false;
- valid identity with blocking boundary -> parse PASS, positive false,
  negative false, verdict UNKNOWN with `BLOCKING_BOUNDARY` and no
  `MALFORMED_TRAVERSAL`/`MALFORMED_PATH`;
- mixed zero-step + non-zero paths, duplicate zero identities, and non-identity
  empty paths -> parser fail closed;
- tamper with stale seal -> parser fail closed;
- wrong source revision context -> UNKNOWN via `SOURCE_REVISION_MISMATCH`.

## Provenance of both genuine vectors

Committed record:
`tests/fixtures/structural_evidence/provenance/task37c_zero_step_identity_provenance.json`.

- Producer: `git@github.com:akvarel/graphify.git`, exact HEAD
  `529ade498158a86e6607138b1c3e717874553294`, clean worktree.
- Pipeline: `derive_git_source_authority` -> `build_bound_structural_index`
  (rglob `*.java`) -> `run_bound_data_flow_query(start=s, target=s, max_depth=6)`
  -> `build_structural_evidence_snapshot` -> `StructuralEvidenceSnapshot.to_dict()`.
- Clean vector fingerprint `ef744d8641573288fcb188523662128518568a1ca44f31b660669253d82d44fe`,
  source revision `35cf74e79d671f982988988922f3a1659ed6ee60`.
- Boundary vector fingerprint `0623ecc71e2771550b8af3cabd11340797c0f02595222488bef72ab91f73948b`,
  source revision `474dc8a20d5deb93fab6030eee487bf894bb5491`, boundary keys
  `bnd:43c8a416…98ae`, `bnd:9bd20a8c…3197`.
- Generator recipe: `tests/fixtures/structural_evidence/provenance/gen_vectors.py`.

## Validation record

```text
python -m pytest -o addopts='' -q tests/test_task37c_zero_step_producer_parity.py
18 passed

python -m pytest -o addopts='' -q tests/test_task37_graphify_v2_bound_snapshot_authority.py tests/test_task37c_zero_step_producer_parity.py tests/test_task32*.py tests/test_task33*.py tests/test_provider_independence_task_34.py tests/test_provider_origin_attestation_task_34b.py tests/test_provider_trust_context_task_34c.py tests/test_provider_trust_context_task_34d.py
298 passed

python -m pytest -o addopts='' -q
946 passed

python -m compileall -q src tests
PASS

git diff --check
PASS

uv build (clean sdist + wheel): gvr-0.2.0.tar.gz, gvr-0.2.0-py3-none-any.whl
PASS

installed-wheel attack/replay matrix (fresh venv, gvr from site-packages):
MATRIX OK — 32 checks PASS including all task37c sections
```

Exact final SHA, CI run link, and Drive report reference are recorded in the
final agent report.
