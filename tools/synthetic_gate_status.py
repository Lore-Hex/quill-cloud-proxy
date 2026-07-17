#!/usr/bin/env python3
"""Evaluate whether a region has a complete fresh synthetic probe set."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections.abc import Iterable, Mapping
from typing import Any


REQUIRED_PROBES = frozenset(
    {
        "attestation_nonce",
        "control_plane_health",
        "openai_sdk_pong",
        "responses_pong",
        "tls_health",
    }
)


def _timestamp(value: object) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def evaluate_region(
    payload: Mapping[str, Any],
    *,
    region: str,
    started_at: float,
    monitor_regions: Iterable[str],
) -> str:
    """Return ``up``, ``down``, or ``waiting`` for a post-roll probe set.

    Every required probe must have a sample created after ``started_at`` from
    every expected monitor region. Old failures cannot poison a new rollout,
    and a single fast health sample cannot release the gate before inference
    and attestation have also succeeded.
    """

    expected_monitors = {item.strip() for item in monitor_regions if item.strip()}
    expected = {
        (monitor_region, probe_type)
        for monitor_region in expected_monitors
        for probe_type in REQUIRED_PROBES
    }
    if not expected:
        return "waiting"

    data = payload.get("data", {})
    if not isinstance(data, Mapping):
        return "waiting"
    current = data.get("current", {})
    checks = current.get("checks", []) if isinstance(current, Mapping) else []
    latest: dict[tuple[str, str], tuple[float, str]] = {}
    if not isinstance(checks, list):
        return "waiting"

    for raw_check in checks:
        if not isinstance(raw_check, Mapping):
            continue
        if raw_check.get("target_region") != region:
            continue
        key = (
            str(raw_check.get("monitor_region") or ""),
            str(raw_check.get("probe_type") or ""),
        )
        if key not in expected:
            continue
        created_at = _timestamp(raw_check.get("created_at"))
        if created_at is None or created_at < started_at:
            continue
        status = str(
            raw_check.get("effective_status") or raw_check.get("status") or ""
        ).lower()
        prior = latest.get(key)
        if prior is None or created_at > prior[0]:
            latest[key] = (created_at, status)

    if expected - latest.keys():
        return "waiting"
    if any(latest[key][1] != "up" for key in expected):
        return "down"
    return "up"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("region")
    parser.add_argument("started_at", type=float)
    parser.add_argument("monitor_regions")
    args = parser.parse_args()
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError):
        print("waiting")
        return 0
    print(
        evaluate_region(
            payload,
            region=args.region,
            started_at=args.started_at,
            monitor_regions=args.monitor_regions.split(","),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
