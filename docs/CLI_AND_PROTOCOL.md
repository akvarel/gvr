# CLI and JSON protocol

GVR can be used as a Python library, but another program can also call it through a small JSON protocol.

The current protocol version is:

```text
schema_version = 1
```

## Install for development

From the repository root:

```bash
python -m pip install -e '.[dev]'
```

Run the test suite:

```bash
python -m pytest
```

## Run the CLI

You can run GVR with:

```bash
python -m gvr
```

The CLI reads one JSON request from standard input.

A request always has this basic shape:

```json
{
  "schema_version": 1,
  "op": "operation_name",
  "payload": {}
}
```

The response is also JSON.

## Example: text search

Save this as `request.json`:

```json
{
  "schema_version": 1,
  "op": "verify_text_search",
  "payload": {
    "corpus": ["apple", "pear", "plum"],
    "needle": "e",
    "claimed_matches": ["apple", "pear"],
    "normalization": "NFC"
  }
}
```

Run:

```bash
python -m gvr < request.json
```

For pretty JSON output:

```bash
python -m gvr --pretty < request.json
```

You can also pass the JSON directly:

```bash
python -m gvr --request '{"schema_version":1,"op":"verify_text_search","payload":{"corpus":["apple"],"needle":"e","claimed_matches":["apple"]}}'
```

## Supported schema-v1 operations

### `describe_verifier_capabilities`

Returns the immutable built-in verifier capability snapshot.

An empty payload lists every published capability:

```json
{
  "schema_version": 1,
  "op": "describe_verifier_capabilities",
  "payload": {}
}
```

The optional filters are:

- `claim_kind` — one exact published claim kind;
- `authoritative_only` — when `true`, omit advisory and M1 proposal-only entries.

Example:

```json
{
  "schema_version": 1,
  "op": "describe_verifier_capabilities",
  "payload": {
    "claim_kind": "CAN_FLOW_TO",
    "authoritative_only": true
  }
}
```

The response kind is `verifier_capability_registry`. Capabilities are ordered by exact UTF-8 verifier ID and version. The result is not ranked and does not select a preferred verifier.

See [Verifier capabilities](VERIFIER_CAPABILITIES.md) for field and fingerprint semantics.

### `describe_evidence_provider_capabilities`

Returns the immutable built-in `EvidenceProviderCapabilityRegistry` snapshot. It is a pure descriptor registry with no runtime bindings. The schema-v1 built-in snapshot is honestly empty because no runtime acquisition providers ship with GVR yet.

```json
{
  "schema_version": 1,
  "op": "describe_evidence_provider_capabilities",
  "payload": {}
}
```

Optional filters are `request_kind` and `evidence_kind`. Both match exact published provider contract values and may be combined. `claim_kind` is not accepted for provider discovery. The response kind is `evidence_provider_capability_registry`. See [Evidence providers](EVIDENCE_PROVIDERS.md) for request, coverage, result, exact registry, compatibility, and fingerprint semantics.

### `validate_evidence_provider_result`

Parses strict serialized `request`, `capability`, and `result` objects, including request `source_class` and `snapshot_class`, capability `source_classes` and `snapshot_classes`, complete coverage, source/snapshot identities, stable provider issue codes and optional allowlisted categories, schema/kind fields, fingerprint formats, and fingerprints. It validates the result against the exact request fingerprint and provider capability, enforces fail-closed class compatibility, and rejects cross-request replay, uncovered emitted evidence, contradictory partial coverage, truth-like control metadata, obsolete issue `message` or `verdict` fields, and claimed fingerprint mismatches before returning a normalized `evidence_provider_result`.

Unknown or obsolete nested fields and invalid values return machine-readable `protocol_error` responses through the safe handler, including `INVALID_EVIDENCE_PROVIDER_REQUEST`, `INVALID_EVIDENCE_PROVIDER_CAPABILITY`, and `INVALID_EVIDENCE_PROVIDER_RESULT`.

### `derive_regression_test_obligations`

Parses one strict serialized `BehaviorEvidenceInventory` and an optional finite `RegressionObligationBudget`, then returns a deterministic `regression_obligation_plan`.

The inventory contains the exact 13-kind behavior vocabulary plus scoped `COMPLETE`, `PARTIAL`, or `UNKNOWN` coverage. It supports complete empty manifests as scope-bound negative evidence, but never treats a complete scan of another subject, action, or surface as proof of absence. The operation rejects unknown fields, old generic evidence kinds, truth-like controls, ambiguous duplicate IDs, invalid coverage references, conflicting class/scope coverage, and forged inventory fingerprints.

The result contains ordered obligations, one exact grounding bundle per obligation, normalized scoped coverage, stable gaps, budget/consumption, termination, `READY / BLOCKED / UNKNOWN` readiness, and a plan fingerprint. Obligations are derived only from exact payload-ID and subject/action/surface-linked facts under the nine public rules. The operation does not call providers, models, browsers, code generators, or test executors, and readiness does not authorize a merge or deployment.

See [Regression test obligations](REGRESSION_TEST_OBLIGATIONS.md) for the 13 evidence kinds, nine rules, gap taxonomy, default budget, and a complete request example.

### `verify_goal`

Checks a proposed action sequence against an initial state and goal predicates.

Use this when you have structured:

- initial state;
- action preconditions;
- action effects;
- required goal state.

### `compare_functionality`

Compares two structured functional snapshots.

This is useful for describing what was added, removed, changed, preserved, or left unknown between two revisions.

### `verify_functional_regression`

Checks a functional-delta result using conservative regression rules.

Incomplete coverage does not become a clean PASS just because no known regression was found.

### `verify_text_search`

Checks an exact text-search assertion.

The request can make text transformations explicit, including:

- Unicode normalization;
- reverse mode;
- exact requested needle grounding.

### `verify_data_flow_claim`

Checks a Graphify traversal result against a data-flow claim.

The main claim kinds are:

```text
CAN_FLOW_TO
NO_SUPPORTED_PATH
```

This operation returns a verification report.

### `verify_data_flow_claim_bundle`

Runs the same data-flow verification and returns a `VerificationBundle`.

Use this form when the result must travel with its exact evidence records.

For trusted remote use, this is safer than sending only a verdict and evidence IDs.

### `compose_verification_session`

Combines several already-materialized verification bundles through a `ClaimGraph`.

Use this when one root claim depends on several smaller claims.

The request contains:

- `claim_graph` — atomic and composite claim definitions;
- `roots` — which claim IDs are the requested outputs;
- `bundles` — materialized `VerificationBundle` objects for atomic claims;
- `budget` — deterministic work limits.

A simple shape looks like this:

```json
{
  "schema_version": 1,
  "op": "compose_verification_session",
  "payload": {
    "claim_graph": {
      "nodes": [
        {
          "node_type": "ATOMIC",
          "claim_id": "A",
          "claim_kind": "EXAMPLE",
          "spec": {"subject": "A"},
          "verifier": "example.verifier.v1",
          "scope": {},
          "dependencies": []
        },
        {
          "node_type": "ATOMIC",
          "claim_id": "B",
          "claim_kind": "EXAMPLE",
          "spec": {"subject": "B"},
          "verifier": "example.verifier.v1",
          "scope": {},
          "dependencies": []
        },
        {
          "node_type": "COMPOSITE",
          "claim_id": "ROOT",
          "operator": "AND",
          "dependencies": ["A", "B"]
        }
      ]
    },
    "roots": ["ROOT"],
    "bundles": [
      {"claim_id": "A", "bundle": {"...": "VerificationBundle for A"}},
      {"claim_id": "B", "bundle": {"...": "VerificationBundle for B"}}
    ],
    "budget": {
      "max_claims": 10,
      "max_bundles": 10,
      "max_evidence_records": 100,
      "max_evidence_bytes": 100000,
      "max_steps": 100
    }
  }
}
```

The response includes current claim states, root verdicts, bundle references, budget accounting, termination reason, and the deterministic session fingerprint.

A stale or missing required claim does not become a guessed PASS or FAIL. It remains `UNKNOWN`.

## VerificationBundle transport rule

A current bundle carries an explicit fingerprint format:

```text
gvr.bundle_fingerprint.ieee754-json.v1
```

The format is part of the bundle's semantic content.

`compose_verification_session` rejects a bundle if the format marker is missing or unsupported. It does not silently ignore the field and guess a format.

This is important when bundles move between Python and other languages.

## Example data-flow request shape

A data-flow request looks like this:

```json
{
  "schema_version": 1,
  "op": "verify_data_flow_claim_bundle",
  "payload": {
    "claim_kind": "CAN_FLOW_TO",
    "start": "A",
    "target": "C",
    "scope": {
      "direction": "FORWARD",
      "effective_allowed_relations": [
        "FLOWS_TO",
        "PASSED_AS_ARGUMENT",
        "RETURNED_AS",
        "READ_FROM",
        "WRITTEN_TO",
        "TRANSFORMED_BY"
      ],
      "stop_nodes": []
    },
    "evidence_namespace": "example",
    "source_context": "git-revision-or-snapshot-id",
    "traversal_result": {
      "...": "Graphify bounded traversal result"
    }
  }
}
```

The `traversal_result` must follow the Graphify result contract. GVR does not rebuild the graph from source code.

## Protocol errors

Malformed requests are returned as machine-readable protocol errors.

Example shape:

```json
{
  "schema_version": 1,
  "kind": "protocol_error",
  "payload": {
    "code": "INVALID_PAYLOAD",
    "message": "..."
  }
}
```

GVR does not try to repair an ambiguous request by guessing what the caller meant.

## Exit codes

The CLI returns a non-zero exit code for invalid JSON or a protocol error.

A valid GVR response may still contain verdict `UNKNOWN`. That is not a process failure. It is a normal verification result.

This distinction is useful in automation:

```text
protocol/process error -> the request could not be handled correctly
UNKNOWN                -> the request was handled, but the claim could not be safely decided
```
