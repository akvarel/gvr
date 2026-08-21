from __future__ import annotations

from copy import deepcopy

from gvr import (
    Evidence,
    VERIFICATION_BUNDLE_FINGERPRINT_FORMAT,
    VerificationReport,
    VerificationVerdict,
    build_verification_bundle,
    envelope,
    handle_request,
    safe_handle_request,
)


def _bundle_payload() -> dict[str, object]:
    bundle = build_verification_bundle(
        VerificationReport(
            verdict=VerificationVerdict.PASS,
            verifier="test.verifier.v1",
            evidence_ids=("E:A",),
            metadata={"claim_id": "A", "score": 1.0},
        ),
        (
            Evidence(
                id="E:A",
                kind="test.evidence.v1",
                payload={"value": 1.0},
                source="revision-A",
                fingerprint="producer-A",
            ),
        ),
    )
    return envelope("fixture", bundle)["payload"]


def _request(bundle_payload: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "op": "compose_verification_session",
        "payload": {
            "claim_graph": {
                "nodes": [
                    {
                        "node_type": "ATOMIC",
                        "claim_id": "A",
                        "claim_kind": "TEST_ASSERTION",
                        "spec": {"subject": "A"},
                        "verifier": "test.verifier.v1",
                        "scope": {},
                        "dependencies": [],
                    }
                ]
            },
            "roots": ["A"],
            "bundles": [{"claim_id": "A", "bundle": bundle_payload}],
            "budget": {},
        },
    }


def test_session_wire_accepts_current_language_neutral_bundle_format():
    payload = _bundle_payload()
    assert payload["fingerprint_format"] == VERIFICATION_BUNDLE_FINGERPRINT_FORMAT

    result = handle_request(_request(payload))

    assert result["kind"] == "verification_session"
    assert result["payload"]["root_verdicts"] == {"A": "PASS"}
    assert result["payload"]["termination_reason"] == "COMPLETE"


def test_session_wire_rejects_wrong_bundle_fingerprint_format():
    payload = deepcopy(_bundle_payload())
    payload["fingerprint_format"] = "gvr.bundle_fingerprint.unknown.v999"

    result = safe_handle_request(_request(payload))

    assert result["kind"] == "protocol_error"
    assert result["payload"]["code"] == "INVALID_VERIFICATION_BUNDLE"


def test_session_wire_rejects_missing_bundle_fingerprint_format():
    payload = deepcopy(_bundle_payload())
    del payload["fingerprint_format"]

    result = safe_handle_request(_request(payload))

    assert result["kind"] == "protocol_error"
    assert result["payload"]["code"] == "INVALID_VERIFICATION_BUNDLE"
