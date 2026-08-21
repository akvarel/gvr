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

    # JSON consumers preserve the sign bit of -0 inconsistently during
    # stringify/canonicalization. Treat both zero spellings as one semantic value.
    if number == 0.0:
        number = 0.0
    bits = struct.pack(">d", number).hex()
    return {"$gvr_num64": bits}


def canonical_transport_value(value: Any, *, path: str = "value") -> Any:
    """Build a language-neutral canonical tree for bundle fingerprinting.

    JSON itself does not preserve lexical number distinctions such as ``1`` vs
    ``1.0`` and different runtimes stringify exponent forms differently. The
    fingerprint tree therefore tags maps/lists and encodes every finite numeric
    value by its normalized IEEE-754 binary64 bits. Safe integers and equivalent
    floats intentionally share one semantic numeric representation.
    """

    if value is None or isinstance(value, (str, bool)):
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
            items.append([
                key,
                canonical_transport_value(value[key], path=f"{path}.{key}"),
            ])
        items.sort(key=lambda item: item[0])
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
        "format": BUNDLE_FINGERPRINT_FORMAT,
        "content": canonical_transport_value(value),
    }
    return json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_transport_fingerprint(value: Any) -> str:
    return hashlib.sha256(canonical_transport_json(value).encode("utf-8")).hexdigest()
