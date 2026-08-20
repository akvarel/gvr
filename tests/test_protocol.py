import json
import subprocess
import sys

from gvr import VerificationVerdict, handle_request, safe_handle_request


def _goal_request(car_effect):
    return {
        "schema_version": 1,
        "op": "verify_goal",
        "payload": {
            "initial_state": {"person": "home", "car": "home"},
            "goal": [{"slot": "car", "op": "eq", "expected": "wash"}],
            "actions": [{
                "id": "act",
                "effects": car_effect,
            }],
        },
    }


def test_goal_protocol_drive_passes():
    out = handle_request(_goal_request([
        {"slot": "person", "value": "wash"},
        {"slot": "car", "value": "wash"},
    ]))
    assert out["kind"] == "verification_report"
    assert out["payload"]["verdict"] == "PASS"


def test_goal_protocol_walk_fails():
    out = handle_request(_goal_request([{"slot": "person", "value": "wash"}]))
    assert out["payload"]["verdict"] == "FAIL"


def test_text_protocol_spec_mismatch_fails():
    days = ["pirmdiena", "otrdiena", "trešdiena", "ceturtdiena", "piektdiena", "sestdiena", "svētdiena"]
    out = handle_request({
        "schema_version": 1,
        "op": "verify_text_search",
        "payload": {
            "corpus": days,
            "needle": "e",
            "requested_needle": "ē",
            "claimed_matches": days,
        },
    })
    assert out["payload"]["report"]["verdict"] == "FAIL"


def test_unknown_operation_is_machine_readable_error():
    out = safe_handle_request({"schema_version": 1, "op": "nope", "payload": {}})
    assert out["kind"] == "protocol_error"
    assert out["payload"]["code"] == "UNKNOWN_OPERATION"


def test_wrong_schema_is_machine_readable_error():
    out = safe_handle_request({"schema_version": 99, "op": "verify_goal", "payload": {}})
    assert out["payload"]["code"] == "UNSUPPORTED_SCHEMA_VERSION"


def test_module_cli_reads_stdin_and_emits_json():
    request = _goal_request([{"slot": "car", "value": "wash"}])
    proc = subprocess.run(
        [sys.executable, "-m", "gvr"],
        input=json.dumps(request), text=True, capture_output=True,
        env={**__import__("os").environ, "PYTHONPATH": "src"},
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["kind"] == "verification_report"
    assert out["payload"]["verdict"] == "PASS"


def test_functional_delta_protocol_proves_removed_only_with_complete_candidate():
    request = {
        "schema_version": 1,
        "op": "compare_functionality",
        "payload": {
            "baseline": {
                "revision": {"repository": "repo", "revision": "main"},
                "coverage_by_kind": {"DATA_FLOW": "COMPLETE"},
                "observables": [{"kind": "DATA_FLOW", "key": "discount->pricing", "value": True, "evidence_ids": ["e1"]}],
            },
            "candidate": {
                "revision": {"repository": "repo", "revision": "feature"},
                "coverage_by_kind": {"DATA_FLOW": "COMPLETE"},
                "observables": [],
            },
        },
    }
    out = handle_request(request)
    assert out["kind"] == "functional_delta"
    assert out["payload"]["items"][0]["delta"] == "REMOVED"
    assert out["payload"]["items"][0]["verdict"] == "PASS"


def test_functional_delta_protocol_partial_candidate_returns_unknown():
    request = {
        "schema_version": 1,
        "op": "compare_functionality",
        "payload": {
            "baseline": {
                "revision": {"repository": "repo", "revision": "main"},
                "coverage_by_kind": {"DATA_FLOW": "COMPLETE"},
                "observables": [{"kind": "DATA_FLOW", "key": "x", "value": 1}],
            },
            "candidate": {
                "revision": {"repository": "repo", "revision": "feature"},
                "coverage_by_kind": {"DATA_FLOW": "PARTIAL"},
                "observables": [],
            },
        },
    }
    out = handle_request(request)
    assert out["payload"]["items"][0]["delta"] == "UNKNOWN"
    assert out["payload"]["items"][0]["verdict"] == "UNKNOWN"
