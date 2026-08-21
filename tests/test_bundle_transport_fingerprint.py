from __future__ import annotations

import pytest

from gvr import (
    VERIFICATION_BUNDLE_FINGERPRINT_FORMAT,
    BundleValidationError,
    Evidence,
    VerificationReport,
    VerificationVerdict,
    build_verification_bundle,
)


def _bundle(*, numeric: int | float = 1):
    return build_verification_bundle(
        VerificationReport(
            verdict=VerificationVerdict.PASS,
            verifier="v",
            issues=(),
            evidence_ids=("E",),
            metadata={"confidence": numeric, "unicode": "ē"},
        ),
        (
            Evidence(
                id="E",
                kind="kind",
                payload={"confidence": numeric, "count": 1},
                source="rev",
                fingerprint="producer",
            ),
        ),
    )


def test_bundle_declares_language_neutral_fingerprint_format():
    bundle = _bundle()
    assert (
        bundle.fingerprint_format
        == VERIFICATION_BUNDLE_FINGERPRINT_FORMAT
        == "gvr.bundle_fingerprint.ieee754-json.v1"
    )


def test_json_equivalent_integer_and_float_numbers_share_bundle_fingerprint():
    assert _bundle(numeric=1).fingerprint == _bundle(numeric=1.0).fingerprint


def test_negative_zero_and_positive_zero_share_transport_fingerprint():
    assert _bundle(numeric=-0.0).fingerprint == _bundle(numeric=0.0).fingerprint


def test_unsafe_integer_is_rejected_for_cross_language_bundle_fingerprint():
    with pytest.raises(BundleValidationError, match="safe range"):
        _bundle(numeric=(1 << 53))


def test_shared_python_typescript_fixture_fingerprint():
    assert _bundle(numeric=1.0).fingerprint == (
        "e2a8b664cf80302660950a22e83b8e248f61d1c7c76730f38bd3a2809e697324"
    )
