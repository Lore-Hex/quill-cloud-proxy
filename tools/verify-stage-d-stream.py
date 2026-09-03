#!/usr/bin/env python3
"""Offline parser for the per-instance streaming and Stage D evidence gate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any


EVIDENCE_KEYS = {
    "authorization_id",
    "gateway_request_id",
    "workspace_id",
    "authorization_kind",
    "settled",
    "disposition",
    "stage_d_boot_kid",
    "heartbeat_seq",
}
AUTHORIZATION_ID_RE = re.compile(r"^[0-9a-f]{32}$")
GATEWAY_REQUEST_ID_RE = re.compile(r"^rlog_[0-9a-f]{32}$")


def validate_stream(raw: bytes) -> None:
    if not raw.startswith(b"data:"):
        raise ValueError("stream did not begin with an SSE data field")
    saw_data = False
    saw_terminal = False
    for raw_line in raw.splitlines():
        if not raw_line:
            continue
        if not raw_line.startswith(b"data:"):
            if raw_line.startswith((b"event:", b"id:", b"retry:", b":")):
                continue
            raise ValueError("stream contains a non-SSE line")
        saw_data = True
        value = raw_line[len(b"data:") :].strip()
        if value == b"[DONE]":
            saw_terminal = True
            continue
        try:
            chunk = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("stream contains an invalid JSON data field") from exc
        if not isinstance(chunk, dict):
            raise ValueError("stream JSON chunk must be an object")
        choices = chunk.get("choices")
        if isinstance(choices, list):
            for choice in choices:
                if isinstance(choice, dict) and choice.get("finish_reason") is not None:
                    saw_terminal = True
    if not saw_data:
        raise ValueError("stream contains no SSE data fields")
    if not saw_terminal:
        raise ValueError("stream has no [DONE] or finish_reason terminal")


def _authorization(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("authorization lookup response must be an object")
    if set(payload) != {"data"}:
        raise ValueError("authorization lookup response must contain exactly data")
    data = payload["data"]
    if not isinstance(data, dict):
        raise ValueError("authorization lookup data must be an object")
    if set(data) != EVIDENCE_KEYS:
        raise ValueError("authorization lookup data has keys outside the literal contract")
    if not isinstance(data["authorization_id"], str) or not AUTHORIZATION_ID_RE.fullmatch(
        data["authorization_id"]
    ):
        raise ValueError("authorization lookup has an invalid authorization_id")
    if not isinstance(data["gateway_request_id"], str) or not GATEWAY_REQUEST_ID_RE.fullmatch(
        data["gateway_request_id"]
    ):
        raise ValueError("authorization lookup has an invalid gateway_request_id")
    if not isinstance(data["workspace_id"], str) or not data["workspace_id"]:
        raise ValueError("authorization lookup has an invalid workspace_id")
    if not isinstance(data["settled"], bool):
        raise ValueError("authorization lookup settled must be boolean")
    if data["disposition"] is not None and not isinstance(data["disposition"], str):
        raise ValueError("authorization lookup disposition must be a string or null")
    if data["stage_d_boot_kid"] is not None and not isinstance(
        data["stage_d_boot_kid"], str
    ):
        raise ValueError("authorization lookup stage_d_boot_kid must be a string or null")
    heartbeat_seq = data["heartbeat_seq"]
    if heartbeat_seq is not None and (
        isinstance(heartbeat_seq, bool) or not isinstance(heartbeat_seq, int)
    ):
        raise ValueError("authorization lookup heartbeat_seq must be an integer or null")
    return data


def validate_evidence(
    payload: object,
    *,
    expected_gateway_request_id: str,
    expected_boot_kid: str,
    require_stage_d: bool,
) -> None:
    authorization = _authorization(payload)
    if authorization["gateway_request_id"] != expected_gateway_request_id:
        raise ValueError("authorization lookup returned a different gateway_request_id")
    if not authorization["settled"]:
        raise ValueError("authorization is not settled")
    kind = authorization["authorization_kind"]
    if kind != "local_typed":
        raise ValueError(
            "Stage D probe key must resolve to a local-typed authorization, "
            f"not {kind!r}"
        )
    if not require_stage_d:
        return
    boot_kid = authorization["stage_d_boot_kid"]
    if boot_kid != expected_boot_kid or not expected_boot_kid:
        raise ValueError("authorization Stage D boot kid does not match this instance")
    heartbeat_seq = authorization["heartbeat_seq"]
    if (
        isinstance(heartbeat_seq, bool)
        or not isinstance(heartbeat_seq, int)
        or heartbeat_seq <= 0
    ):
        raise ValueError("authorization has no positive Stage D heartbeat sequence")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    stream = subparsers.add_parser("stream")
    stream.add_argument("response", type=Path)
    evidence = subparsers.add_parser("evidence")
    evidence.add_argument("response", type=Path)
    evidence.add_argument("--expected-gateway-request-id", required=True)
    evidence.add_argument("--expected-boot-kid", required=True)
    evidence.add_argument("--require-stage-d", choices=("on", "off"), required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "stream":
        validate_stream(args.response.read_bytes())
        return
    payload = json.loads(args.response.read_text(encoding="utf-8"))
    validate_evidence(
        payload,
        expected_gateway_request_id=args.expected_gateway_request_id,
        expected_boot_kid=args.expected_boot_kid,
        require_stage_d=args.require_stage_d == "on",
    )


if __name__ == "__main__":
    main()
