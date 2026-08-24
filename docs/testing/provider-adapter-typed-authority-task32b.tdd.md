# Task 32b provider adapter typed-authority remediation TDD evidence

## Authorized boundary

- Exact remote base: `cc9b6d74099f3bd89db0258dc00a1666176fef14` on `origin/feature/gvr-typed-graph-authority-v1`.
- Branch: `feature/gvr-provider-adapter-typed-authority-remediation-v1`.
- RED commit: `45dd2ba0eaa95e6c4655ff57bc1503982b075d92`.
- `probe_false_freshness.py` remained untracked and unchanged at SHA-256 `3473d65d38558ff6ab484268f0dd455d3842198542f364ecf2aa882cb0266f89`.
- Task 33 and external provider repositories were not modified.

## RED-first evidence

`tests/test_task32b_provider_adapter_typed_authority.py` was committed before production changes. Its first focused execution produced seven failures. The failures demonstrated that the wrappers did not accept typed source revision/query scope, `GraphQueryScope` lacked requested/effective/rejected relations and finite path/expansion bounds, and both authoritative wrappers still contained `_typed_authority=False`.

## Remediated authority flow

The authoritative built-in flow is now:

```text
validated provider result
-> SourceRevisionIdentity
-> GraphQueryScope
-> CoverageCertificate
-> ProviderImplementationIdentity
-> GraphFacts
-> GraphEvidenceModel(_typed_authority=True)
-> canonical provider observation
-> exact revision and query-scope verification
```

Graphify derives query authority only from its native traversal result. A compatibility `source_snapshot` is accepted only when it contains revision identity fields. Scope-bearing legacy snapshots fail closed. CodeFlow requires typed source revision and query scope when the native envelope does not carry them, rejects conflicts with native typed fields, keeps all facts heuristic or inferred, and never receives negative authority.

## Canonical query-scope schema

`GraphQueryScope` preserves these independent semantic fields:

- start and target;
- direction;
- requested relations;
- effective relations;
- rejected relations;
- stop nodes;
- max depth;
- max paths;
- max expansions;
- evidence namespace.

Set-like fields canonicalize as sorted immutable sets. Reordering is fingerprint-invariant. Changing any relation set, finite bound, source revision, or query scope changes the graph semantic fingerprint independently.

## Coverage mapping

Graphify coverage retains complete supported search, search coverage, termination reason, truncation, query validity, input resolution, start/target resolution, encountered PARTIAL/MAY/UNKNOWN flags, and blocking boundary keys. CodeFlow coverage is explicitly `HEURISTIC_INDEX`, incomplete for negative authority, and records `negative_authority: false`.

## Structural audit

- `_typed_authority=False`: no production matches.
- Built-in authoritative Graphify and CodeFlow wrappers construct all five typed authority objects and do not call legacy authority conversion helpers.
- `_source_revision_from_legacy`, `_query_scope_from_legacy`, and `_coverage_from_legacy` remain only inside the generic `GraphEvidenceModel` compatibility constructor for explicitly legacy callers.
- Adapter `source_snapshot=` construction remains in the non-authoritative public ingestion helpers. Authoritative encode wrappers reject scope-bearing compatibility snapshots.
- Execution/storage `source_snapshot` fields remain provider reconciliation and persistence transport metadata. They do not reinterpret provider JSON or replace typed revision/query/coverage authority.
- Provider-specific JSON interpretation remains confined to `gvr.adapters.graphify` and `gvr.adapters.codeflow`. The generic verifier compares canonical typed objects only.

## Validation

Final validation commands and exact outcomes are recorded in the supervising Drive report. The focused Task 32b suite, Task 27-32 suites, Graphify/data-flow tests, full pytest, compilation, build, wheel, installed-wheel scenarios, diff hygiene, and exact GitHub Actions checks are required before completion.
