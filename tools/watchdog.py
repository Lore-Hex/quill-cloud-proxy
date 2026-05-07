#!/usr/bin/env python3
"""Post-rollout watchdog for the GCP enclave deploy. Polls
https://trustedrouter.com/status.json every minute and decides whether
to roll the MIGs back to the previous instance template.

Logic mirrors quill-router/scripts/deploy/watchdog.py — only "down"
counts toward rollback (degraded alone is normal during a rolling
update). Three consecutive "down" reads triggers rollback.

Usage:
  python3 tools/watchdog.py [--duration-min 10] [--rollback-after 3]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request


def fetch_status(url: str, timeout: int = 10) -> str:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            payload = json.load(response)
        status = payload.get("data", {}).get("overall_status")
        if isinstance(status, str):
            return status.lower()
    except Exception as exc:
        print(f"  watchdog: status fetch error: {exc}", flush=True)
        return "unknown"
    return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration-min", type=int, default=10)
    parser.add_argument("--rollback-after", type=int, default=3)
    parser.add_argument(
        "--status-url",
        default="https://trustedrouter.com/status.json",
    )
    args = parser.parse_args()

    consecutive_down = 0
    print(
        f"watchdog: polling {args.status_url} every 60s for {args.duration_min} min; "
        f"rollback if 'down' for {args.rollback_after} consecutive minutes",
        flush=True,
    )
    for minute in range(1, args.duration_min + 1):
        time.sleep(60)
        status = fetch_status(args.status_url)
        if status == "down":
            consecutive_down += 1
        else:
            consecutive_down = 0
        print(
            f"  minute {minute}: status={status}  consecutive_down={consecutive_down}",
            flush=True,
        )
        if consecutive_down >= args.rollback_after:
            print(
                f"watchdog: ROLLBACK — 'down' for {consecutive_down} consecutive minutes",
                flush=True,
            )
            return 1
    print("watchdog: deploy healthy", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
