from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

from .code_graph import GraphEvidenceModelError

GRAPHIFY_DF_KEY_RE = re.compile(r"^df:[0-9a-f]{64}$")
_GRAPHIFY_DF_KEY_FORMAT = "graphify.data_flow.evidence_key.v1"
_GRAPHIFY_DF_KEY_FIELDS = (
    "relation",
    "source",
    "target",
    "source_file",
    "source_location",
    "provenance",
)


def _field_pairs(item: Mapping[str, Any]) -> list[tuple[str, str]]:
    fields: list[tuple[str, str]] = [
        ("r", str(item.get("relation") or "")),
        ("s", str(item.get("source") or "")),
        ("t", str(item.get("target") or "")),
        ("f", str(item.get("source_file") or "")),
        ("l", str(item.get("source_location") or "")),
        ("p", str(item.get("provenance") or "")),
    ]
    argument_index = item.get("argument_index")
    if argument_index is not None:
        fields.append(("ai", str(argument_index)))
    return fields


def expected_graphify_df_key(item: Mapping[str, Any]) -> str:
    """Return the public content-addressed Graphify df evidence key."""

    canonical = json.dumps(sorted(_field_pairs(item)), sort_keys=True, separators=(",", ":"))
    return "df:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_graphify_df_evidence(item: Mapping[str, Any]) -> str:
    """Validate Graphify's public df key against the evidence content.

    Both the Graphify adapter and data-flow verifier use this one validator so
    path evidence cannot be re-keyed, rebound to different content, or accepted
    with a syntactically plausible but non-content-addressed id.
    """

    if not isinstance(item, Mapping):
        raise GraphEvidenceModelError("Graphify df evidence must be a mapping")
    key = str(item.get("key") or "")
    if not GRAPHIFY_DF_KEY_RE.fullmatch(key):
        raise GraphEvidenceModelError("Graphify df evidence key must be df:<64 lowercase sha256 hex>")
    missing = [field for field in _GRAPHIFY_DF_KEY_FIELDS if not str(item.get(field) or "")]
    if missing:
        raise GraphEvidenceModelError("Graphify df evidence is missing content-addressed fields: " + ", ".join(missing))
    expected = expected_graphify_df_key(item)
    if key != expected:
        raise GraphEvidenceModelError("Graphify df evidence key is not content-addressed to its public content")
    return key


def graphify_df_key_is_valid(item: Mapping[str, Any]) -> bool:
    try:
        validate_graphify_df_evidence(item)
        return True
    except GraphEvidenceModelError:
        return False
