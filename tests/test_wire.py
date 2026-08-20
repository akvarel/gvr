from gvr import INDETERMINATE, MISSING, VerificationVerdict, decode_markers, envelope


def test_wire_version_and_enum():
    out = envelope("test", {"verdict": VerificationVerdict.PASS})
    assert out == {"schema_version": 1, "kind": "test", "payload": {"verdict": "PASS"}}


def test_missing_and_indeterminate_are_not_null():
    out = envelope("state", {"missing": MISSING, "unknown": INDETERMINATE, "null": None})
    assert out["payload"]["missing"] == {"$gvr": "MISSING"}
    assert out["payload"]["unknown"] == {"$gvr": "INDETERMINATE"}
    assert out["payload"]["null"] is None
    decoded = decode_markers(out["payload"])
    assert decoded["missing"] is MISSING
    assert decoded["unknown"] is INDETERMINATE


def test_dataclass_encoding_preserves_missing_marker_identity():
    from dataclasses import dataclass
    @dataclass
    class Holder:
        value: object
    out = envelope("holder", Holder(MISSING))
    assert out["payload"]["value"] == {"$gvr": "MISSING"}
