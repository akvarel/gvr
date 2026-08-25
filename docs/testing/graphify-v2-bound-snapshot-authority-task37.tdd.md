# Task37 Graphify v2 bound-snapshot consumption authority TDD evidence

## Authorized boundary

- Exact approved GVR base: `47df5ae06b1f4c323737c58a0b840e810e8b2f5b`.
- Base branch: `feature/gvr-provider-trust-context-adversarial-closure-v1`.
- Target branch: `feature/gvr-graphify-v2-bound-snapshot-authority-v1`.
- Graphify was inspected read-only at exact contract HEAD `529ade498158a86e6607138b1c3e717874553294`.
- The committed fixture is the preserved `graphify.structural_evidence.v2` snapshot captured from that Graphify contract and independently checked against producer canonicalization, source-scope binding, analysis binding, content fingerprints, `df:` keys, `bnd:` keys, path identity, and coverage accounting.
- `probe_false_freshness.py` remains preserved and untracked. It is not an authority source for Task37.

## TDD checkpoints

| Phase | Commit | Evidence |
| --- | --- | --- |
| RED | `f85c45bdf7faa01efc08a41436bbbe7de057f092` | Fixture and 30 acceptance tests were committed before implementation. The focused command failed during collection because the v2 ingestion API did not exist. |
| Initial GREEN | `63ac70f21d831f4237f21378b38d1f659cc3f5c2` | Added strict typed full-snapshot ingestion, producer-compatible fingerprints, snapshot-derived traversal projection, authority metadata persistence, and provider-trust separation. |
| Review remediation | `7393124` | Addressed independent openrouter `stealth/ox-alpha` review: producer blocker metadata fallback, traversal accounting preservation, empty-path fail-closed behavior, and explicit JSON transport validation. |

## Authority and security boundary

`ingest_graphify_structural_evidence_v2` accepts only the complete v2 document. It rejects missing or extra top-level fields, caller-provided source/query/traversal overrides, malformed scope or binding fingerprints, mutated outer fingerprints, invalid or duplicate `df:`/`bnd:` records, unknown path references, empty paths, and non-JSON transport values. The document's source revision scope, analysis binding, query, coverage, facts, paths, blockers, and carried fingerprint remain together as one bound snapshot.

Fingerprint helpers mirror the read-only Graphify producer contract:

- JSON canonical values use UTF-8 key ordering, deterministic compact JSON, `ensure_ascii=False`, and `allow_nan=False`.
- The outer snapshot fingerprint excludes only the carried `fingerprint` and normalizes identity-bearing fact, path, and blocker ordering exactly as the producer does.
- Source scope uses `graphify.structural_evidence.fingerprint.v2`.
- Analysis binding uses `graphify.structural_analysis.binding.v1` and binds source scope, index fingerprint, and traversal fingerprint.
- Direct facts are revalidated with GVR's shared `df:<sha256>` contract.
- Boundary keys use the producer's public fields, including `repositoryFqn` and `entityFqn` from authentic nested blocker details when top-level compatibility fields are absent.

The GVR traversal view is a derived projection only. It is generated from the validated snapshot's facts, paths, blockers, query, and coverage. It preserves producer `visited_count` and `expanded_count`; it never accepts an independently supplied traversal result, source revision, query scope, or verdict. Partial, MAY, UNKNOWN, blocked, truncated, unresolved, or malformed evidence remains non-decisive under the existing Graphify envelope and verifier rules.

Provider origin is separate from content validity. Public serialized use is `UNVERIFIED`. Only the existing trusted built-in adapter execution under an active `ProviderTrustContext` can produce `VERIFIED` provider-origin metadata. Snapshot fingerprints and Graphify provider labels cannot self-authorize trust or create independent provider votes.

## Review findings and remediation

Independent `openrouter` `stealth/ox-alpha` review found one HIGH issue and three lower-severity issues:

1. HIGH: boundary-key validation ignored `repositoryFqn` and `entityFqn` carried in producer blocker details. Fixed by canonical fallback across top-level snake-case, producer camel-case, and nested details fields, with a hard-coded producer-derived regression vector.
2. MEDIUM: the derived traversal omitted producer accounting fields. Fixed by carrying `visited_count` and `expanded_count` into the native projection so positive authority validation sees the real bounded traversal accounting.
3. LOW: empty schema-valid paths could fail later with an indexing error. Fixed by rejecting empty path identities during typed ingestion.
4. LOW: JSON-only transport semantics were implicit. Fixed with an explicit recursive transport check and a regression test for Python-only tuple input.

## Validation record

Focused remediation validation:

```text
python -m pytest -o addopts='' -q tests/test_task37_graphify_v2_bound_snapshot_authority.py
34 passed

python -m pytest -o addopts='' -q tests/test_task32*.py tests/test_task33*.py tests/test_provider_independence_task_34.py tests/test_provider_origin_attestation_task_34b.py tests/test_provider_trust_context_task_34c.py tests/test_provider_trust_context_task_34d.py
219 passed

python -m compileall -q src tests
PASS

git diff --check
PASS
```

The preserved `probe_false_freshness.py` was executed. Its earlier adversarial checks passed, then its stale construction path raised the expected `BundleValidationError` before the script's later exception handler. The probe remains unmodified and untracked; this is recorded as a harness limitation, not used as Task37 authority evidence.

Broader full-suite, package/wheel, installed-wheel replay, audit, exact Python 3.10-3.13 CI, and Drive report verification are recorded after completion in the final report.
