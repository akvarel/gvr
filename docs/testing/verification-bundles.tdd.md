# Verification Bundle and Evidence Manifest TDD Evidence

## Source task

Google Drive taskbus document `11-gvr-verification-bundle-evidence-manifest`.

Approved base: `d578e8f4c4f1820a1630bf4819dd4176d0480daf`.

## User journeys

1. As a remote GVR consumer, I can transport a report together with exactly the evidence records that form its dependency basis.
2. As a verifier author, I can build a deterministic package whose identity changes for verification-semantic changes but not for input ordering.
3. As a Graphify data-flow caller, I receive only the selected `df:...`, required `gvrq:...`, or blocking `bnd:...` records referenced by the report.
4. As a ClaimLedger caller, I can record a complete bundle atomically without repeating evidence plumbing or risking partial mutation.
5. As a schema-v1 wire consumer, I can request a versioned bundle while the existing report operation remains compatible.
6. As a reviewer, I can rely on missing, extra, conflicting, mutable, or otherwise malformed bundle content to fail closed.

## RED and GREEN checkpoints

| Stage | Commit or state | Command | Observed result |
|---|---|---|---|
| Bundle RED | `d51232492f20865bd258ca7337f1a68ac660e2e2` | `python -m pytest -o addopts='' -q tests/test_verification_bundle.py` | Collection failed because the required public bundle APIs did not exist. |
| Bundle GREEN | `b571cbcb33d3b23a80b239914f923aa345b89d9b` | focused bundle suite, then full suite | `22 passed`; full repository suite `130 passed`. |
| Immutability adversarial RED | working tree after GREEN | `test_bundle_snapshots_and_freezes_report_and_evidence_semantic_content` | Mutating caller-owned nested mappings changed the already-fingerprinted bundle content. |
| Graphify conflict adversarial RED | working tree after GREEN | `test_data_flow_bundle_rejects_conflicting_boundary_records_with_one_id` | Adapter deduplication hid two different boundary records sharing one ID. |
| Wire fail-closed adversarial RED | working tree after GREEN | `test_safe_bundle_wire_operation_fails_closed_on_ambiguous_evidence` | `BundleValidationError` escaped the safe schema-v1 protocol boundary. |
| Hardened GREEN | working tree after fixes | `python -m pytest -o addopts='' -q tests/test_verification_bundle.py` | All 29 focused bundle tests passed. |

## Test specification

| # | Guarantee | Evidence | Type | Result |
|---|---|---|---|---|
| 1 | A positive path bundle contains only the canonical selected path's exact direct `df:...` records. | Positive and two-qualifying-path tests | Integration | PASS |
| 2 | Complete absence and zero-step identity bundles contain exactly one stable `gvrq:...` record and no fabricated edge. | Empty-search and identity tests | Integration | PASS |
| 3 | Boundary-driven UNKNOWN contains the exact reported `bnd:...` record; UNKNOWN without dependencies has an explicit empty manifest. | Boundary and empty-manifest tests | Integration | PASS |
| 4 | Missing dependencies, conflicting duplicates, unrelated extras, and issue evidence outside report dependencies are rejected. | Generic malformed bundle tests | Adversarial unit | PASS |
| 5 | Semantically identical duplicate evidence is deterministically deduplicated. | Identical duplicate test | Unit | PASS |
| 6 | Evidence input order and mapping key order do not affect equality or fingerprint. | Reordering tests | Determinism | PASS |
| 7 | Verdict, verifier, issue, evidence payload, and claim-dependency changes alter the bundle fingerprint. | Semantic fingerprint tests | Unit | PASS |
| 8 | Report metadata and evidence payloads are canonical snapshots and recursively immutable after construction. | Immutability adversarial test | Adversarial unit | PASS |
| 9 | Conflicting Graphify records sharing one ID are exposed by the adapter and rejected before bundle construction. | Graphify conflict test | Adversarial integration | PASS |
| 10 | `ClaimLedger.record_bundle()` records evidence and report atomically and leaves a fresh expected verdict. | Valid bundle recording test | Ledger integration | PASS |
| 11 | `gvrq:` replacement, direct payload replacement, and evidence removal preserve stale propagation. | Query/direct/removal stale tests | Ledger integration | PASS |
| 12 | Replacement bundle reverification restores freshness and history; claim dependencies preserve transitive staleness. | Reverification and claim-dependency tests | Ledger integration | PASS |
| 13 | Verifier mismatch or undefined claim dependency cannot partially register bundle evidence or history. | Atomic failure tests | Adversarial integration | PASS |
| 14 | Existing `verify_data_flow_claim` remains unchanged while `verify_data_flow_claim_bundle` returns a complete deterministic bundle envelope. | Wire compatibility and deterministic output tests | Protocol integration | PASS |
| 15 | Ambiguous bundle evidence becomes `INVALID_VERIFICATION_BUNDLE` at the safe wire boundary rather than escaping as an exception. | Safe wire failure test | Adversarial protocol | PASS |
| 16 | A real Graphify `dataclasses.asdict(...)` traversal produces a PASS bundle with exactly two direct evidence records. | Manual cross-repository probe | Cross-repository integration | PASS |

## Canonical fingerprint contract

The bundle SHA-256 fingerprint covers:

- bundle schema version and kind;
- verifier identity;
- report verdict, verifier, normalized issues, dependency IDs, and metadata;
- exact evidence ID, kind, canonical payload, source, and producer fingerprint;
- optional claim-dependency IDs.

Mapping keys are sorted recursively. Evidence, issue, report dependency, and claim-dependency sets are normalized into deterministic order. Lists and tuples inside semantic payloads preserve their sequence. Unsupported object types and non-finite floats are rejected rather than converted through unstable runtime representations. The bundle adds no timestamps, UUIDs, object IDs, or checkout-root values.

## Final validation

- `python -m pytest -o addopts='' -q tests/test_verification_bundle.py`: `29 passed in 0.07s`.
- `python -m pytest -o addopts='' -q tests/test_verification_bundle.py tests/test_graphify_adapter.py tests/test_data_flow_verifier.py tests/test_ledger.py tests/test_protocol.py tests/test_wire.py`: `97 passed in 0.20s`.
- `python -m pytest -o addopts='' -q`: `137 passed in 0.22s`.
- `python -m compileall -q src`: PASS.
- `git diff --check`: PASS.
- Real Graphify bundle probe: `PASS`, two selected direct evidence records, deterministic fingerprint `24abb0649b1a3a43f8fdaf6b38c52c552d97a66881c86b47a2ba16d98e1e00b7`.

## Coverage and known gaps

No coverage, lint, or static type-check tool is configured in `pyproject.toml`; `coverage`, `pytest-cov`, `ruff`, and `mypy` are not installed in the environment. The focused adversarial suite, adjacent integration suite, complete repository suite, compilation, diff validation, and real Graphify contract probe were run instead. No tests were skipped or disabled.

Evidence producer fingerprints remain producer-defined. GVR includes them in canonical bundle identity and rejects conflicts for one ID, but it does not reinterpret `df:`, `bnd:`, or other producer-specific fingerprint algorithms generically. Cryptographic signatures and remote attestation remain later-gate non-goals.
