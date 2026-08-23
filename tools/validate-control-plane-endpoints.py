#!/usr/bin/env python3
"""Require the canonical billing authority before rendering a gateway deploy."""

from __future__ import annotations

import sys
from urllib.parse import urlsplit


OBSERVER_HOSTS = {
    "aws.trustedrouter.com",
    "azure.trustedrouter.com",
    "status.trustedrouter.com",
}


def is_observer_host(host: str) -> bool:
    normalized = host.lower().rstrip(".")
    if normalized in OBSERVER_HOSTS:
        return True
    return normalized.endswith(".trustedrouter.com") and normalized.startswith(
        ("aws-", "azure-", "status-")
    )


def validate(value: str) -> None:
    endpoints = [part.strip().rstrip("/") for part in value.split(",") if part.strip()]
    if not endpoints:
        raise ValueError("at least one billing authority is required")
    for endpoint in endpoints:
        parsed = urlsplit(endpoint)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError(f"invalid billing authority URL: {endpoint!r}") from exc
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError(f"invalid billing authority URL: {endpoint!r}")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("billing authority URL must not contain userinfo")
        if parsed.query or parsed.fragment or parsed.path not in ("", "/"):
            raise ValueError(
                "billing authority URL must be a root origin without /v1, query, or fragment"
            )
        host = parsed.hostname.lower().rstrip(".")
        if is_observer_host(host):
            raise ValueError(
                f"control-plane endpoint {host!r} is an observer-only service"
            )
        if host != "trustedrouter.com" or port not in (None, 443):
            raise ValueError(
                f"control-plane endpoint {host!r} is not a reviewed billing authority"
            )


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <control-plane-endpoints>", file=sys.stderr)
        return 2
    try:
        validate(argv[1])
    except ValueError as exc:
        print(f"[FAIL] TR_CONTROL_PLANE_BASE_URL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
