#!/usr/bin/env python3
"""Classify gateway-attributed provider failures without excusing router failures."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from pathlib import Path

PROVIDER_FAILURE_EXIT = 3
INFERENCE_PROBES = frozenset({"openai_sdk_pong", "responses_pong"})


def is_provider_http_error(status: object, payload: object) -> bool:
    if isinstance(status, bool) or not isinstance(status, int) or not 400 <= status <= 599:
        return False
    error = payload.get("error") if isinstance(payload, Mapping) else None
    return isinstance(error, Mapping) and error.get("source") == "provider"


def is_provider_probe_failure(check: Mapping[str, object]) -> bool:
    probe_type = check.get("probe_type")
    return (
        isinstance(probe_type, str)
        and probe_type in INFERENCE_PROBES
        and (check.get("effective_status") or check.get("status")) == "down"
        and check.get("error_type") == "provider_error"
        and is_provider_http_error(check.get("http_status"), {"error": {"source": "provider"}})
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("status", type=int)
    parser.add_argument("body", type=Path)
    args = parser.parse_args()
    try:
        payload = json.loads(args.body.read_bytes())
    except (OSError, ValueError):
        return 1
    if is_provider_http_error(args.status, payload):
        return PROVIDER_FAILURE_EXIT
    if args.status != 200 or not isinstance(payload, dict):
        return 1
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return 1
    message = choices[0].get("message")
    content = message.get("content") if isinstance(message, dict) else None
    return 0 if isinstance(content, str) and content.strip() == "PONG" else 1


if __name__ == "__main__":
    raise SystemExit(main())
