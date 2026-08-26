# Task38 TDD: Provider-origin observation content binding / replay forgery remediation

## Objective

Close the P0 where a legitimate VERIFIED provider-origin assertion behaved as a
transferable bearer token: at base `609750e496510480d2d6b4ce693ac71c0e2ef1ae`
the v2 seal (`gvr.provider_origin_assertion.v2`) covered only provider identity
(`provider_kind`, `implementation_id`, `family`, `configuration_identity`,
`registry_fingerprint`, `context_key_id`). A captured assertion could be copied
onto any other observation with all public fingerprints recomputed, and the
decode path still accepted it as `VERIFIED graphify`.

## Core invariant

```
VERIFIED provider origin
    means
this authorized provider implementation, under this active trust context,
issued THIS EXACT observation subject
```

## Design

- New explicit version `gvr.provider_origin_assertion.v3`. The seal covers one
  added field, `observation_subject_fingerprint`.
- The subject fingerprint is `canonical_fingerprint` over
  `gvr.provider_observation_subject.v1` of:
  - `provider_kind`, `provider_id`, `implementation_id`, `family_id`;
  - canonical `graph_model_fingerprint` (transitively commits typed source
    revision, query scope, coverage certificate, nodes/edges/blockers/absence,
    and Graphify-v2 `authority_metadata`);
  - exact `claim_fingerprint`.
- No circular dependency: the subject excludes origin/independence/seal fields.
  No hard-coded signing secret; the HMAC key stays process-private.
- Issuance order is mandatory: adapters finalize the claim fingerprint first,
  compute the subject from the finalized graph model + claim, then the active
  `ProviderTrustContext` issues an origin bound to that subject. Issuing from
  implementation identity alone before the observation exists is removed.
- Decode reconstructs and revalidates the graph model, recomputes the exact
  subject fingerprint, and validates the recorded origin against identity,
  active trust context/key/config/registry AND the recomputed subject before
  yielding `ValidatedProviderOrigin` / VERIFIED family.

## Compatibility

- Legacy v2 VERIFIED assertions (no observation-subject binding) fail closed;
  they can never be upgraded to VERIFIED by the new runtime.
- Public UNVERIFIED observations remain readable across v2/v3 shapes
  (unverified assertions carry an empty subject binding).
- Identical replay under the same still-valid context/key stays VERIFIED;
  restart/new ephemeral context does not retain trust; Graphify-v2 content
  binding remains deterministic provenance; Gate19 remains out of scope.

## RED evidence (exact base `609750e...`, commit `41c185d`)

Tests-only suite `tests/test_provider_origin_content_binding_task_38.py`
covers all 18 Drive cases. Genuine RED baseline: **12 failed / 8 passed** —
every failure was an actual transplant exploit reaching VERIFIED:

| Case | Attack | Base behavior |
|------|--------|---------------|
| 01 | claim_fingerprint transplant | reached VERIFIED |
| 02 | graph-model node mutation | reached VERIFIED |
| 03 | source revision transplant | reached VERIFIED |
| 04 | query scope / coverage transplant | reached VERIFIED |
| 05 | v2 snapshot_fingerprint swap | reached VERIFIED |
| 06 | origin moved to another genuine v2 observation | reached VERIFIED |
| 11 | SQLite persisted tamper | reached VERIFIED |
| 12 | CodeFlow content transplant | reached VERIFIED |
| 13 | host-registered custom provider transplant | reached VERIFIED |
| 14 | two forged observations manufacturing verdicts | participated as trusted |
| 15 | integrated executor accepted transplanted observation | participated in reconciliation |

Cases 07–10, 16–18 (identical replay, no-context, new-context, SQLite benign
replay, mismatch precedence, Task37c clean/boundary producer vectors) passed on
base and must keep passing.

## GREEN results (commit `52c13bb`)

- Task38 exploit suite: 20/20 PASS locally.
- Installed-wheel Task38 content-transplant matrix: 17/17 PASS outside the
  source tree with `PYTHONPATH` removed.
- Installed-wheel Task37b/37c replay and producer-vector matrix: 32/32 PASS
  outside the source tree with `PYTHONPATH` removed.
- Full pytest: 966 passed, 0 failed. Tasks27–38 focused suites pass.
- `python -m compileall -q src tests` clean, `git diff --check` clean.
- Repeated installed-wheel attacks: every content transplant fails closed under
  the same context; identical SQLite replay stays VERIFIED with a stable origin
  document.

## Installed-wheel matrix

`tests/task38_installed_wheel_transplant_matrix.py` re-runs the attack surface
against site-packages only (no repo source on `sys.path`). Exit code 0 requires
every check to pass.

## Final delivery validation

The final delivery rerun also recorded:

- Tasks27–38 focused acceptance suites: 366 passed.
- Exact Task37 and Task37c producer-vector suites: 79 passed.
- Provider independence/origin/trust, corroboration, integrated executor,
  Graphify/CodeFlow adapters and SQLite suites: 131 passed.
- Clean isolated package build produced `gvr-0.2.0.tar.gz` and
  `gvr-0.2.0-py3-none-any.whl`; both were built from an archived clean HEAD.
- The installed-wheel matrices imported `gvr` from site-packages and ran with
  `PYTHONPATH` removed. Temporary virtual environments and package artifacts
  were removed after the run.
- `probe_false_freshness.py` remains preserved and untracked; no reviewer
  scratch file was present.
