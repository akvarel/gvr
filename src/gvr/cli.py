from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from .protocol import safe_handle_request


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gvr", description="General Verification Runtime")
    p.add_argument("--request", help="JSON request. If omitted, read one JSON object from stdin.")
    p.add_argument("--pretty", action="store_true", help="Pretty-print JSON response.")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        raw = args.request if args.request is not None else sys.stdin.read()
        request = json.loads(raw)
        if not isinstance(request, dict):
            raise ValueError("top-level request must be an object")
    except Exception as exc:
        response = {
            "schema_version": 1,
            "kind": "protocol_error",
            "payload": {"code": "INVALID_JSON", "message": str(exc)},
        }
        print(json.dumps(response, ensure_ascii=False, sort_keys=True, indent=2 if args.pretty else None))
        return 2

    response = safe_handle_request(request)
    print(json.dumps(response, ensure_ascii=False, sort_keys=True, indent=2 if args.pretty else None))
    return 0 if response.get("kind") != "protocol_error" else 2


if __name__ == "__main__":
    raise SystemExit(main())
