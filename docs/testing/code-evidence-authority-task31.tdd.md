# Task31 code evidence authority remediation TDD evidence

## Authorized boundary

- Exact GVR base requested: `72e14cd8cff0`.
- Branch: `feature/gvr-code-evidence-authority-remediation-v1`.
- CodeFlow was read-only. The exact public fixture was captured from `262206cb` in scratch by extracting `git archive 262206cb` and running `node card/analyze.js --path tests/fixtures/golden-world`.
- Captured fixture committed unchanged: `tests/fixtures/codeflow_262206cb_golden_world.json`.
- Scratch capture observed sha256 at capture time: `27950ff31a30556d847372cb6bfa7a8a7be5ec8c0d8f1d3dccfd3f41a2c83b56`. The public CodeFlow envelope includes an `snapshot.at` timestamp, so regeneration is behaviorally reproducible but byte hashes vary by capture time.
- Graphify was not modified. GVR consumes only its public traversal result contract.
- `probe_false_freshness.py` was preserved and not committed.

## TDD checkpoints

| Phase | Commit | Evidence |
| --- | --- | --- |
| RED | `7fefb32a9088` | Added failing Task31 tests and the actual CodeFlow `{schemaVersion,data,snapshot}` fixture before production changes. Focused RED command: `python -m pytest tests/test_task31_authority_remediation.py -q`, failed with missing `gvr.graphify_contract` before implementation. |
| GREEN | this commit | Implements real CodeFlow envelope ingestion, shared Graphify `df:<sha256>` validator, query/path authority evidence, typed source revision/scope/completeness separation, adapter-sealed provider families, and same-family contradiction semantics. |

## Remediation coverage

- **A. Real pinned CodeFlow ingestion.** `ingest_codeflow_graph` now accepts the real CodeFlow `schemaVersion/data/snapshot` envelope, maps files/functions/connections into canonical graph evidence, and retains CodeFlow snapshot/stats as source snapshot authority.
- **B. Shared Graphify validator.** `gvr.graphify_contract` defines the single content-addressed `df:<sha256>` validator reused by the Graphify adapter and data-flow verifier. Tampered public content fails closed.
- **C. Query/path authority.** Data-flow reports and bundles now include the query-result evidence id alongside selected path or boundary evidence so ledger dependencies bind both the returned path and the exact query execution basis.
- **D. Typed separation.** `SourceRevision`, `DataFlowQueryScope`, and `CompletenessCertificate` are separate authorities. Source revision is not folded into query semantic scope, and typed source revision mismatches fail closed.
- **E. Provider independence.** CodeFlow and Graphify adapter family ids are sealed by the adapters. Reconciliation treats same-family decisive PASS/FAIL as `PROVIDER_FAMILY_CONTRADICTION`, not an independent provider conflict.

## Final validation

```text
python -m pytest tests/test_task31_authority_remediation.py -q
5 passed

python -m pytest tests/test_code_graph_execution_tasks_27_30_integrated.py tests/test_task31_authority_remediation.py -q
14 passed

python -m pytest tests/test_graphify_task28_adapter.py tests/test_data_flow_verifier.py tests/test_verification_bundle.py tests/test_provider_corroboration_task_30.py tests/test_codeflow_adapter_task_27.py tests/test_code_graph_execution_tasks_27_30_integrated.py tests/test_task31_authority_remediation.py -q
115 passed

python -m pytest -q
648 collected, passed (dots-only quiet output)

python -m compileall -q src tests
PASS

git diff --check
PASS

python -m pip wheel . --no-deps -w "$JCODE_SCRATCH_DIR/gvr-task31-wheel"
PASS, gvr-0.2.0-py3-none-any.whl sha256 fb575a5c4243533293b52c0cdbaf086d9b702fdd65aa818f4559e3b7c822a646

python -m build --sdist --wheel --outdir "$JCODE_SCRATCH_DIR/gvr-task31-build"
System package was not executable: /usr/bin/python: No module named build.__main__

$JCODE_SCRATCH_DIR/gvr-task31-build-venv/bin/python -m build --sdist --wheel --outdir "$JCODE_SCRATCH_DIR/gvr-task31-build"
PASS in isolated scratch venv; emitted setuptools license-table deprecation warnings only.
```
