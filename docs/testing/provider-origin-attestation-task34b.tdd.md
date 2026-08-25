# Task 34b provider-origin attestation and registry sealing TDD evidence

## Authorized boundary

- Exact accepted Task 34 base: `133799474b022a53d373b1a6bc626f8ce3c87a93`.
- The remote source branch was fetched and verified before creating `feature/gvr-provider-origin-attestation-v1`.
- `probe_false_freshness.py` remains untracked and unchanged.

## Trust-transition invariant

A provider observation can reach `VERIFIED` independence only through a sealed origin attestation:

1. The Graphify or CodeFlow adapter invokes the internal adapter-only encoder with an attestation issued by the built-in adapter authority.
2. A custom provider is registered by a host/runtime authority bound to one explicit configuration identity and one deterministic registry fingerprint.
3. Canonical decode verifies the attestation seal, implementation/kind binding, configuration identity, registry fingerprint, and recorded family before reconciliation.
4. Direct reconciliation accepts verified independence only when a sealed `ProviderOriginAttestation` is present. A caller-built `VerifiedIndependenceFamily` is rejected.

Public `provider_id`, `provider_kind`, `family_id`, implementation labels, wrapper labels, and public low-level identities remain descriptive and resolve as `UNVERIFIED`.

## Structural trust-transition audit

| Trust transition | Issuer | Validation | Public string upgrade possible |
|---|---|---|---|
| Graphify adapter to `VERIFIED` | `adapters/graphify.py` through internal `_attest_builtin_provider_origin` | Canonical decode validates built-in seal and exact identity | No |
| CodeFlow adapter to `VERIFIED` | `adapters/codeflow.py` through internal `_attest_builtin_provider_origin` | Canonical decode validates built-in seal and exact identity | No |
| Custom provider to `VERIFIED` | `ProviderOriginAuthority.host_runtime` plus authority-bound registry | Configuration identity, registry fingerprint, identity, family, and seal | No |
| Public low-level encode | No trusted issuer | Recomputed as untrusted during decode | No |
| Direct reconciliation | Existing sealed attestation only | `ProviderVerificationObservation.__post_init__` rejects unattested verified family | No |

## Orthogonality

Truth authority remains independent of provider-origin trust. A decisive observation remains decisive even when its provider origin is unverified, while verified origin never converts heuristic or unknown evidence into decisive truth. Existing claim, snapshot, scope, contradiction, conflict, duplication, ordering, persistence, and replay semantics from Tasks 27 through 34 remain intact.

## Adversarial coverage

The Task 34b suite contains 20 tests covering public Graphify/CodeFlow kind forgery, provider/family labels, caller-built verified families, custom per-observation registries, sealed built-in adapters, low-level built-in impersonation, host-authorized custom providers, wrong authority use, configuration and registry replay mismatch, exact replay, origin tampering, fail-closed direct reconciliation, genuine cross-family corroboration, truth orthogonality, and heuristic non-upgrade.
