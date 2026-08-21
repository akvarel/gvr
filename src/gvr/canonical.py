from __future__ import annotations

import hashlib
import json
import math
import struct
from typing import Any, Mapping


BUNDLE_FINGERPRINT_FORMAT = "gvr.bundle_fingerprint.ieee754-json.v1"
_JS_SAFE_INTEGER_MAX = (1 << 53) - 1


class CanonicalizationError(ValueError):
    """Raised when semantic content cannot be canonically transported."""


def canonical_utf8_key(value: str, *, path: str = "string") -> bytes:
    try:
        return value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError(
            f"{path} contains an invalid Unicode surrogate"
        ) from exc


def _number_token(value: int | float, *, path: str) -> dict[str, str]:
    if isinstance(value, int):
        if abs(value) > _JS_SAFE_INTEGER_MAX:
            raise CanonicalizationError(
                f"{path} integer is outside the cross-language safe range"
            )
        number = float(value)
    else:
        if not math.isfinite(value):
            raise CanonicalizationError(f"{path} contains a non-finite number")
        number = float(value)

    if number == 0.0:
        number = 0.0
    bits = struct.pack(">d", number).hex()
    return {"$gvr_num64": bits}


def canonical_transport_value(value: Any, *, path: str = "value") -> Any:
    """Build a language-neutral canonical tree for bundle fingerprinting.

    Numbers use normalized IEEE-754 binary64 tokens. Mapping keys are ordered by
    their exact UTF-8 byte sequences rather than host-language string ordering.
    Strings must be valid Unicode scalar sequences encodable as strict UTF-8.
    """

    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        canonical_utf8_key(value, path=path)
        return value
    if isinstance(value, int):
        return _number_token(value, path=path)
    if isinstance(value, float):
        return _number_token(value, path=path)
    if isinstance(value, Mapping):
        items: list[list[Any]] = []
        for key in value:
            if not isinstance(key, str):
                raise CanonicalizationError(f"{path} contains a non-string mapping key")
            canonical_utf8_key(key, path=f"{path} key")
            items.append([
                key,
                canonical_transport_value(value[key], path=f"{path}.{key}"),
            ])
        items.sort(key=lambda item: canonical_utf8_key(item[0], path=f"{path} key"))
        return {"$gvr_map": items}
    if isinstance(value, (list, tuple)):
        return {
            "$gvr_list": [
                canonical_transport_value(item, path=f"{path}[{index}]")
                for index, item in enumerate(value)
            ]
        }
    raise CanonicalizationError(
        f"{path} contains unsupported semantic value {type(value).__name__}"
    )


def canonical_transport_json(value: Any) -> str:
    envelope = {
        "content": canonical_transport_value(value),
        "format": BUNDLE_FINGERPRINT_FORMAT,
    }
    return json.dumps(
        envelope,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_transport_fingerprint(value: Any) -> str:
    try:
        encoded = canonical_transport_json(value).encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError(
            "canonical content contains an invalid Unicode surrogate"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()
