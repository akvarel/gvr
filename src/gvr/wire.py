from __future__ import annotations

from dataclasses import fields, is_dataclass
from enum import Enum
from typing import Any

from .model import INDETERMINATE, MISSING

SCHEMA_VERSION = 1


def _encode(value: Any) -> Any:
    if value is MISSING:
        return {"$gvr": "MISSING"}
    if value is INDETERMINATE:
        return {"$gvr": "INDETERMINATE"}
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {f.name: _encode(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, dict):
        return {str(k): _encode(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_encode(v) for v in value]
    return value


def envelope(kind: str, value: Any) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "payload": _encode(value),
    }


def decode_markers(value: Any) -> Any:
    if isinstance(value, dict):
        if value == {"$gvr": "MISSING"}:
            return MISSING
        if value == {"$gvr": "INDETERMINATE"}:
            return INDETERMINATE
        return {k: decode_markers(v) for k, v in value.items()}
    if isinstance(value, list):
        return [decode_markers(v) for v in value]
    return value
