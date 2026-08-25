# Task 34c provider trust context and external-forgery remediation

## Authorized base and RED evidence

- Remote `feature/gvr-provider-origin-attestation-v1` was verified at exact SHA `54fcbb772b5811ff491c7cf696cee8c2a11ffb1e` before branching.
- `feature/gvr-provider-trust-context-v1` was created from that exact base.
- The mandatory tests-only RED commit is `cdd4321`. Its 24-test module failed during collection because `ProviderTrustContext` did not exist.
- `probe_false_freshness.py` remained untracked and its SHA-256 remained `3473d65d38558ff6ab484268f0dd455d3842198542f364ecf2aa882cb0266f89`.

## Trust invariant

`VERIFIED` provider independence exists only after a serialized `ProviderOriginAssertion` has been authenticated by the currently active, host/runtime-owned `ProviderTrustContext`. The context owns a cryptographically random process-lifetime key, configuration identity, and exact registry fingerprint. None is accepted as a generic encoder argument.

The generic `encode_code_graph_observation_evidence()` path always emits `UNVERIFIED`, including while a trust context is active. Graphify and CodeFlow can emit a sealed assertion only through their private active-context capability. A custom registered provider is encoded through the active context's method. Decode recomputes and verifies configuration identity, registry fingerprint, random-key identity, exact implementation/kind/family binding, and HMAC before creating the non-serializable `ValidatedProviderOrigin` consumed by reconciliation.

## Same-process threat model

This remediation prevents offline forgery by evidence producers that know package source code, public constants, serialized evidence, configuration labels, and old deterministic keys. It also prevents replay under a rotated key, wrong context, wrong configuration, or changed registry.

It is not a Python sandbox against malicious code already executing inside the trusted host process. Same-process hostile code can use introspection or invoke private implementation details. Hosts must isolate untrusted plugins and evidence producers outside the process that owns `ProviderTrustContext`. Context activation has an explicit context-manager lifetime and is restored correctly across nesting.

## Structural trust audit

| Transition | Required issuer | Required validation | Public generic upgrade |
|---|---|---|---|
| Generic graph encoding | None | Canonical unverified assertion equality | Impossible |
| Graphify built-in | Active context plus private Graphify capability | Active context, config, registry, key identity, seal, exact identity | Impossible |
| CodeFlow built-in | Active context plus private CodeFlow capability | Active context, config, registry, key identity, seal, exact identity | Impossible |
| Registered custom provider | Active context method and exact registration | Same validation as built-ins | Impossible |
| Serialized replay | Existing assertion | Same active context only | Impossible under wrong/rotated context |
| Direct reconciliation | `ValidatedProviderOrigin` only | Already validated by active context | Caller-built family/assertion rejected |

The public package no longer exports `ProviderOriginAuthority`. Source contains no deterministic built-in signing secret and the generic encoder has no `provider_registry`, `provider_authority`, `_adapter_origin`, or key argument.

## Test coverage

The Task 34c suite contains exactly 24 adversarial and integrated tests covering old-public-key offline forgery, independent runtime keys, structural API removal, generic safe-unverified behavior, real Graphify and CodeFlow adapters, required active-context replay, context rotation, configuration mismatch, registry mismatch, key mismatch, assertion tampering, context lifetime, nested restoration, registered and unregistered custom providers, direct-reconciliation validation, cross-family reconciliation, SQLite same/wrong-context replay, and public-surface secret/authority removal.

Prior Task 34 and 34b tests were migrated to the new context without weakening provider-independence, truth-orthogonality, conflict, persistence, or replay semantics.

## Validation evidence

- Focused Task 34/34b/34c provider trust suites: `54 passed`.
- Full source-tree suite: `843 passed`.
- `python -m compileall -q src tests`: passed.
- `git diff --check`: passed.
- Clean PEP 517 sdist and wheel build: passed, producing `gvr-0.2.0.tar.gz` and `gvr-0.2.0-py3-none-any.whl`.
- Full suite against the isolated installed wheel: `843 passed`; import path was verified under the virtual environment's `site-packages`.
- CI-equivalent CLI smoke: passed.
- Structural audit found no `ProviderOriginAuthority`, deterministic built-in secret, `provider_authority`, or `_adapter_origin` symbol in `src`.
