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
