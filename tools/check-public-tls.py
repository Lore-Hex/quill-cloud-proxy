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
    "uptimerouter.com",
    "www.uptimerouter.com",
    "status.uptimerouter.com",
    "trust.uptimerouter.com",
    "api.uptimerouter.com",
    # Per-region gateway hostnames. The canonical names above rotate to
    # whichever region is healthy, so a SINGLE region whose renewal stalled
    # could run its cert to zero unalerted while every canonical probe
    # stayed green — the region goes dark only when DNS finally sends
    # someone there. Probe the regions directly (GCP regions publish
    # api-<region>.quillrouter.com via the DNS reconciler; AWS/Azure use
    # their cloud-scoped trustedrouter.com names).
    "api-us-central1.quillrouter.com",
    "api-us-east4.quillrouter.com",
    "api-europe-west4.quillrouter.com",
    "api-southamerica-east1.quillrouter.com",
    "api-azure.trustedrouter.com",
)


# Hosts that MUST NOT be probed here, with the reason, so nobody adds them back.
#
# This check validates against the public CA trust store. That is the right test
# for every name above, and the wrong test for a host whose certificate is
# deliberately self-signed inside an enclave and bound to its attestation
# document: `ssl.create_default_context()` rejects it by design, on every run,
# forever.
#
# api-aws.trustedrouter.com was added to DEFAULT_HOSTS on 2026-08-10 (PR #143)
# together with the per-region names. The PR verified the new names "all
# resolving", which is a different property from "serves a publicly-issued
# certificate" — only the first was checked. Every scheduled run from
# 2026-08-11 onward failed on it, 40 consecutive red runs, which is what a
# permanently-failing assertion looks like from the outside: the workflow's
# red/green signal stopped carrying information, and a genuine NS drift or
# expiry warning in the same run would not have changed what it reported.
#
# The AWS plane's TLS is not unchecked. Its declared mode is published at
# trust/aws-release.json as "attested-self-signed-inside-enclave", and
# verify-trust-freshness.yml compares the live attestation against the
# published measurement twice daily — which is a stronger check than chain
# validation, not a weaker one.
#
# Re-adding a host here is correct only once its trust record stops declaring
# an attested self-signed mode.
ATTESTED_SELF_SIGNED_HOSTS = frozenset(
    {
        "api-aws.trustedrouter.com",
    }
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
        if host in ATTESTED_SELF_SIGNED_HOSTS:
            print(
                f"::error::{host} serves an attested self-signed certificate and "
                f"cannot pass public-CA validation; it is covered by "
                f"verify-trust-freshness.yml instead"
            )
            failed = True
            continue
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
