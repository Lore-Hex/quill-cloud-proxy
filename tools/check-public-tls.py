#!/usr/bin/env python3
"""Fail before a public TrustedRouter TLS certificate approaches expiry."""

from __future__ import annotations

import argparse
import socket
import ssl
from datetime import UTC, datetime, timedelta
from typing import Mapping


DEFAULT_HOSTS = (
    "trustedrouter.com",
    "www.trustedrouter.com",
    "status.trustedrouter.com",
    "eu.trustedrouter.com",
    "trust.trustedrouter.com",
    "api.trustedrouter.com",
    "allyrouter.com",
    "www.allyrouter.com",
    "status.allyrouter.com",
    "trust.allyrouter.com",
    "api.allyrouter.com",
)


def certificate_expiry(cert: Mapping[str, object]) -> datetime:
    not_after = cert.get("notAfter")
    if not isinstance(not_after, str) or not not_after:
        raise ValueError("peer certificate did not include notAfter")
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=UTC)


def probe_expiry(host: str, *, timeout_seconds: float = 10.0) -> datetime:
    context = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=timeout_seconds) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            return certificate_expiry(tls.getpeercert())


def expiry_is_safe(
    expires_at: datetime,
    *,
    now: datetime,
    minimum_remaining: timedelta,
) -> bool:
    return expires_at - now >= minimum_remaining


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("hosts", nargs="*", default=DEFAULT_HOSTS)
    parser.add_argument("--minimum-days", type=int, default=14)
    parser.add_argument("--timeout-seconds", type=float, default=10.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    now = datetime.now(UTC)
    minimum_remaining = timedelta(days=args.minimum_days)
    failed = False
    for host in args.hosts:
        try:
            expires_at = probe_expiry(host, timeout_seconds=args.timeout_seconds)
            remaining = expires_at - now
            if not expiry_is_safe(
                expires_at,
                now=now,
                minimum_remaining=minimum_remaining,
            ):
                print(
                    f"::error::{host} TLS certificate expires at "
                    f"{expires_at.isoformat()} ({remaining} remaining)"
                )
                failed = True
                continue
            print(
                f"{host}: TLS valid until {expires_at.isoformat()} "
                f"({remaining.days} days remaining)"
            )
        except (OSError, ssl.SSLError, ValueError) as exc:
            print(f"::error::{host} TLS check failed: {exc}")
            failed = True
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
