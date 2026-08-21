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

### `compile_verification_plan`

Compiles an immutable deterministic work description from exact claims, bindings, capability snapshots, and budgets. It does not acquire evidence, invoke a verifier, call Graphify, or access a network or file system.

The payload is the exact `VerificationPlanningRequest.to_dict()` shape:

```json
{
  "schema_version": 1,
  "op": "compile_verification_plan",
  "payload": {
    "schema_version": 1,
    "kind": "gvr.verification_planning_request",
    "fingerprint_format": "gvr.verification_planning_request.ieee754-json.v1",
    "fingerprint": "...",
    "claim_graph": {
      "schema_version": 1,
      "kind": "gvr.claim_graph",
      "nodes": [],
      "fingerprint": "..."
    },
    "bindings": [],
    "verifier_capability_registry": {
      "schema_version": 1,
      "kind": "gvr.verifier_capability_registry",
      "fingerprint_format": "gvr.verifier_capability_registry.ieee754-json.v1",
      "fingerprint": "...",
      "capabilities": []
    },
    "verifier_capability_registry_fingerprint": "...",
    "evidence_provider_capability_registry": {
      "schema_version": 1,
      "kind": "gvr.evidence_provider_capability_registry",
      "fingerprint_format": "gvr.evidence_provider_capability_registry.ieee754-json.v1",
      "fingerprint": "...",
      "capabilities": []
    },
    "evidence_provider_capability_registry_fingerprint": "...",
    "budget": {
      "max_atomic_claims": null,
      "max_composite_claims": null,
      "max_steps": null,
      "max_requests": null,
      "max_dependency_edges": null,
      "max_requests_per_claim": null,
      "max_depth": null
    }
  }
}
```

Each atomic binding includes its own schema, kind, fingerprint format, fingerprint, exact claim ID, verifier ID/version/capability fingerprint, and full serialized evidence requests. Each nested request and capability also carries its existing exact schema, kind, format, and fingerprint fields. Omitting a required nested fingerprint is a malformed planning request, not permission for the protocol to recompute and accept it.

The response kind is `verification_plan`. A complete plan contains deterministic `ACQUIRE_EVIDENCE`, `VERIFY_ATOMIC_CLAIM`, and `COMPOSE_CLAIM` steps. Unsupported contracts or exhausted budgets return stable termination and structured planner issues with no executable steps.

The wire parser is strict. It rejects unknown fields at every new planning layer, malformed arrays and objects, unsupported schema/kind/format values, duplicate bindings, request ID conflicts, and mismatched claim graph, evidence request, binding, capability, registry, or planning request fingerprints. These failures return `INVALID_VERIFICATION_PLANNING_REQUEST` through `safe_handle_request`.

See [Verification planning](VERIFICATION_PLANNING.md) for sharing, ordering, compatibility, budget, issue, and identity rules.

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
