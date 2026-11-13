#!/usr/bin/env python3
"""Keep the gateway's gates attributable while the control plane may move.

Several gateway gates send requests through the control plane: the PONG gate
(tools/wait-region-synthetic-up.sh), the per-instance gate before DNS
(tools/verify-region-before-dns.sh: inference, streaming, settled evidence)
and the image-discovery check. The control plane authorizes and settles every
PONG, and it serves the status.json the synthetic gates read. Once the
control plane and the gateway can hold leases at once (quill-router
docs/design/component-leases-v3.md), a control-plane deploy or outage during
one of those gates must not read as a gateway failure.

Each gate runs unchanged. The rules for its verdict:

  * A pass is a pass, as before, with one addition. A canary that passed
    while the control plane moved (or while its lanes were unreadable) also
    needs the latest fresh `tls_health` and `attestation_nonce` row for the
    region from every monitor to be up. The canary reads an unreachable
    status page as `unknown` and passes; a failing latest row then makes it
    the gateway's failure, and a missing or not-up row makes it inconclusive.
  * A failure counts against the gateway, at once and as before, when the gate
    failed on something the control plane does not touch, or when the control
    plane was provably still and healthy over the gate's window: no
    control-plane or public-surface lease at either end of the window, no
    lease granted during it (lane epochs and the journal id unchanged),
    status.json readable, no fresh control-plane probe down, and every
    monitor ingesting.
  * Otherwise the result is inconclusive. The region stays as the gate left
    it (out of canonical DNS), nothing is promoted, and the whole gate runs
    again with a fresh window, until a hard deadline: the gate's own hold
    bound (TR_CP_HOLD_MAX_SECONDS, a clock per gate) or the job's budget for
    all holds (TR_CP_HOLD_BUDGET_SECONDS), whichever comes first. An attempt
    in flight at the deadline is stopped, and the gate fails closed.

So a gate passes only when the underlying gate passes; a control-plane
failure can delay the gateway's verdict by a bounded time, never turn it into
a pass.

The loop, the hold clock and the status.json fetch live in
tools/gate-hold-lib.sh, which runs each gate command exactly as before. This
file only decides, from files the library captured:

  gate_hold.py decide --kind pong|pre-dns|canary|discovery --region R \
      --status N --since EPOCH --before LANES.json --after LANES.json \
      --status-json STATUS.json

It prints `pass`, `gateway:<why>` or `inconclusive:<why>`.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

MONITOR_REGIONS = "us-central1,europe-west4"
# tools/verify-region-before-dns.sh exits with this when a request-path check
# failed (inference, streaming or settled evidence): checks that traverse the
# control plane. Its other failures (attestation, image, instance count, DNS)
# are the gateway's alone.
CP_DEPENDENT_STATUS = 65
# tools/gate-hold-lib.sh reports an attempt it stopped at its time cap with
# this status. A pre-DNS attempt that ran out of time may have been waiting on
# the control plane (the settled-evidence lookup), so it counts as a
# request-path failure.
TIMEOUT_STATUS = 124
# The monitor's own probes of the control plane, sent straight to
# trustedrouter.com without any enclave (quill-router synthetic/probes.py).
CONTROL_PLANE_PROBES = frozenset(
    {"gateway_authorize", "gateway_settle", "gateway_authorize_settle", "control_plane_health"}
)
# Answered by the enclave itself; the control plane cannot fail them.
GATEWAY_ONLY_PROBES = frozenset({"tls_health", "attestation_nonce"})
FAILING = frozenset({"down", "trust_degraded"})
# Lanes whose leases change what a gateway gate's requests go through.
MOVING_LANES = ("control-plane", "public-surface")
KINDS = ("pong", "pre-dns", "canary", "discovery")


def _timestamp(value: object) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _rows(payload: object) -> list[Mapping[str, Any]] | None:
    """Every probe row in status.json, or None when it is not a status page."""
    if not isinstance(payload, Mapping):
        return None
    data = payload.get("data")
    if not isinstance(data, Mapping):
        return None
    current = data.get("current", {})
    checks = current.get("checks", []) if isinstance(current, Mapping) else []
    samples = data.get("samples", [])
    rows = [*(checks if isinstance(checks, list) else []), *(samples if isinstance(samples, list) else [])]
    return [row for row in rows if isinstance(row, Mapping)]


def _status(row: Mapping[str, Any]) -> str:
    return str(row.get("effective_status") or row.get("status") or "").lower()


def _fresh(row: Mapping[str, Any], since: float) -> bool:
    created = _timestamp(row.get("created_at"))
    return created is not None and created >= since


def valid_lanes(snapshot: object) -> bool:
    if not isinstance(snapshot, Mapping) or snapshot.get("schema_version") not in (2, 3):
        return False
    if snapshot["schema_version"] == 3 and not (
            isinstance(snapshot.get("journal_id"), str) and len(snapshot["journal_id"]) == 32):
        return False
    lanes = snapshot.get("lanes")
    if not isinstance(lanes, Mapping):
        return False
    for lane in MOVING_LANES:
        entry = lanes.get(lane)
        if not isinstance(entry, Mapping) or type(entry.get("held")) is not bool:
            return False
        epoch = entry.get("epoch")
        if snapshot["schema_version"] == 3 and (type(epoch) is not int or epoch < 0):
            return False
    return True


def control_plane_moved(before: object, after: object) -> str | None:
    """Why the control plane may have changed during the window, or None.

    A lane epoch moves on every grant, so equal epochs and no lease at both
    ends mean no lease existed in between. A v2 journal has one lease per
    cloud; while the gateway holds gcp, no other component can.
    """
    if not valid_lanes(before) or not valid_lanes(after):
        return "the control-plane lane state is unreadable"
    assert isinstance(before, Mapping) and isinstance(after, Mapping)
    if before["schema_version"] != after["schema_version"]:
        return "the journal format changed during the window"
    if before.get("journal_id") != after.get("journal_id"):
        # A downgrade and upgrade in between: the epochs are not comparable.
        return "the journal was re-created during the window"
    for lane in MOVING_LANES:
        for snapshot in (before, after):
            entry = snapshot["lanes"][lane]
            if entry["held"]:
                return f"a {lane} lease is held ({entry.get('state') or 'unknown'})"
        if before["lanes"][lane].get("epoch") != after["lanes"][lane].get("epoch"):
            return f"a {lane} lease was granted during the window"
    return None


def control_plane_unhealthy(payload: object, since: float, monitors: Iterable[str]) -> str | None:
    """Why status.json does not show a healthy control plane since `since`, or None."""
    rows = _rows(payload)
    if rows is None:
        return "status.json is unreadable (the control plane serves it)"
    expected = {m.strip() for m in monitors if m.strip()}
    if not expected:
        return "no monitor regions are configured"
    ingesting: set[str] = set()
    for row in rows:
        if not _fresh(row, since):
            continue
        monitor = str(row.get("monitor_region") or "")
        ingesting.add(monitor)
        probe = str(row.get("probe_type") or "")
        if monitor in expected and probe in CONTROL_PLANE_PROBES and _status(row) in FAILING:
            return f"{probe} from {monitor} read {_status(row)}"
    for monitor in sorted(expected - ingesting):
        # Each monitor ingests through the control plane; silence is its signal.
        return f"monitor {monitor} ingested nothing since the window began"
    return None


def gateway_only_failure(payload: object, region: str, since: float,
                         monitors: Iterable[str]) -> str | None:
    """The latest fresh enclave-only probe for `region` failing: the gateway's alone.

    Only the latest row per monitor and probe counts, so a blip early in the
    window (DNS still propagating) does not outweigh later recovery.
    """
    expected = {m.strip() for m in monitors if m.strip()}
    latest: dict[tuple[str, str], tuple[float, str]] = {}
    for row in _rows(payload) or []:
        key = (str(row.get("monitor_region") or ""), str(row.get("probe_type") or ""))
        created = _timestamp(row.get("created_at"))
        if (row.get("target_region") != region or created is None or created < since
                or key[0] not in expected or key[1] not in GATEWAY_ONLY_PROBES):
            continue
        if key not in latest or created > latest[key][0]:
            latest[key] = (created, _status(row))
    for (monitor, probe), (_, status) in sorted(latest.items()):
        if status in FAILING:
            return f"{probe} from {monitor} read {status}"
    return None


def canary_evidence(payload: object, region: str, since: float,
                    monitors: Iterable[str]) -> tuple[str, str] | None:
    """Whether fresh enclave-only rows confirm a canary that passed blind.

    The canary (tools/watchdog.py) reads status.json, and reads an unreachable
    page as `unknown`, never `down`. So while the control plane moves, its
    pass stands only if the latest fresh `tls_health` and `attestation_nonce`
    row for this region from every monitor is up. Returns None when they are,
    ('gateway', why) when one is failing, and ('inconclusive', why) otherwise.
    """
    rows = _rows(payload)
    if rows is None:
        return "inconclusive", "status.json is unreadable"
    expected = {(m.strip(), p) for m in monitors if m.strip() for p in GATEWAY_ONLY_PROBES}
    if not expected:
        return "inconclusive", "no monitor regions are configured"
    latest: dict[tuple[str, str], tuple[float, str]] = {}
    for row in rows:
        key = (str(row.get("monitor_region") or ""), str(row.get("probe_type") or ""))
        created = _timestamp(row.get("created_at"))
        if row.get("target_region") != region or key not in expected or created is None or created < since:
            continue
        if key not in latest or created > latest[key][0]:
            latest[key] = (created, _status(row))
    for (monitor, probe), (_, status) in sorted(latest.items()):
        if status in FAILING:
            return "gateway", f"the latest {probe} from {monitor} read {status}"
    missing = sorted(expected - latest.keys())
    if missing:
        return "inconclusive", "no fresh " + ", ".join(f"{p} from {m}" for m, p in missing)
    not_up = sorted(f"{p} from {m} read {s or 'nothing'}" for (m, p), (_, s) in latest.items() if s != "up")
    if not_up:
        return "inconclusive", ", ".join(not_up)
    return None


def classify(kind: str, status: int, region: str, since: float, before: object, after: object,
             payload: object, monitors: Iterable[str]) -> tuple[str, str]:
    """('gateway', why) when a failed gate is the gateway's, else ('inconclusive', why)."""
    monitors = list(monitors)
    if kind == "canary":
        return "gateway", "the canary reads only enclave-answered probes"
    if kind == "pre-dns" and status not in (CP_DEPENDENT_STATUS, TIMEOUT_STATUS):
        return "gateway", f"a check the control plane does not touch failed (exit {status})"
    if kind == "pong":
        own = gateway_only_failure(payload, region, since, monitors)
        if own:
            return "gateway", own
    moved = control_plane_moved(before, after)
    if moved:
        return "inconclusive", moved
    unhealthy = control_plane_unhealthy(payload, since, monitors)
    if unhealthy:
        return "inconclusive", unhealthy
    return "gateway", "the control plane was still and healthy for the whole window"


def _load(path: str) -> object:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def decide(kind: str, region: str, status: int, since: float, before: object, after: object,
           payload: object, monitors: Iterable[str]) -> str:
    """One gate attempt's verdict: `pass`, `gateway:<why>` or `inconclusive:<why>`."""
    monitors = list(monitors)
    if status == 0:
        if kind != "canary":
            return "pass"
        moved = control_plane_moved(before, after)
        if moved is None:
            return "pass"
        evidence = canary_evidence(payload, region, since, monitors)
        if evidence is None:
            return "pass"
        verdict, reason = evidence
        return f"{verdict}:the canary passed while {moved}, but {reason}"
    verdict, reason = classify(kind, status, region, since, before, after, payload, monitors)
    return f"{verdict}:{reason}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=("decide",))
    parser.add_argument("--kind", choices=KINDS, required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--status", type=int, required=True)
    parser.add_argument("--since", type=int, required=True)
    parser.add_argument("--before", required=True)
    parser.add_argument("--after", required=True)
    parser.add_argument("--status-json", required=True)
    parser.add_argument("--monitors", default=os.environ.get("WAIT_UP_MONITOR_REGIONS", MONITOR_REGIONS))
    args = parser.parse_args(argv)
    monitors = [m.strip() for m in args.monitors.split(",") if m.strip()]
    if not monitors:
        # Every rule would pass vacuously over an empty monitor set.
        parser.error("WAIT_UP_MONITOR_REGIONS names no monitor region")
    print(decide(args.kind, args.region, args.status, args.since, _load(args.before), _load(args.after),
                 _load(args.status_json), monitors))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
