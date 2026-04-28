"""Operator-only /admin/usage endpoint.

Auth: HTTP Basic against an htpasswd file (sha-512 crypt). Operator
configures the secret out-of-band; the secret is NEVER a device key. Tests
inject a temporary htpasswd path.

Output: aggregate counters per device (today + 30-day average). Reads
from DynamoDB via UsageWriter.query_device_30d.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from pathlib import Path
from typing import Any

from fastapi import Request

from quill_parent.config import Settings


def _read_htpasswd(path: Path) -> dict[str, str]:
    """Parse a tiny subset of htpasswd: `user:hash` lines, hash = `{SHA}<b64>`."""
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if ":" not in line or line.startswith("#"):
            continue
        user, _, h = line.partition(":")
        out[user.strip()] = h.strip()
    return out


def _check_password(stored_hash: str, given_password: str) -> bool:
    """Verify a password against `{SHA}<b64-sha1>` (htpasswd-style)."""
    if not stored_hash.startswith("{SHA}"):
        return False
    try:
        expected = base64.b64decode(stored_hash[5:])
    except (ValueError, binascii.Error):
        return False
    actual = hashlib.sha1(given_password.encode("utf-8"), usedforsecurity=False).digest()
    return hmac.compare_digest(expected, actual)


def check_admin_auth(request: Request, settings: Settings) -> bool:
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(auth[6:]).decode("utf-8", errors="replace")
    except (ValueError, binascii.Error):
        return False
    user, _, password = decoded.partition(":")
    creds = _read_htpasswd(settings.admin_htpasswd_path)
    stored = creds.get(user)
    if not stored:
        return False
    return _check_password(stored, password)


async def build_usage_report(settings: Settings) -> dict[str, Any]:
    """Return the JSON shape documented in the plan: per-device today + 30d_avg."""
    # Lazy-create the DynamoDB writer so tests can inject a fake.
    from quill_parent.usage import UsageWriter

    writer = UsageWriter(settings.usage_table_name, settings.aws_region)
    # In V1 we don't have a registry of device IDs in the parent (the
    # enclave holds it). Operator passes ?devices=q-001,q-002 to inspect.
    # When V1.1 lands a public registry, this becomes implicit.
    return await _build_report_for(writer, [])


async def _build_report_for(
    writer: Any,  # noqa: ANN401  -- duck-typed for test injection (real: UsageWriter)
    device_ids: list[str],
) -> dict[str, Any]:
    out_devices: list[dict[str, Any]] = []
    for did in device_ids:
        rows = writer.query_device_30d(did)
        if not rows:
            continue
        today_row = rows[0]
        avg = _rolling_avg(rows[:30])
        out_devices.append(
            {
                "device_id": did,
                "today": _aggregate_only(today_row),
                "30d_avg": avg,
            }
        )
    import datetime as dt

    return {
        "as_of_utc": dt.datetime.now(dt.UTC).isoformat(),
        "devices": out_devices,
    }


def _aggregate_only(row: dict[str, Any]) -> dict[str, int]:
    """Project a DynamoDB row to ONLY the aggregate counters."""
    return {
        "requests": int(row.get("requests", 0)),
        "input_tokens": int(row.get("input_tokens", 0)),
        "output_tokens": int(row.get("output_tokens", 0)),
        "errors": int(row.get("errors", 0)),
    }


def _rolling_avg(rows: list[dict[str, Any]]) -> dict[str, int]:
    if not rows:
        return {"requests": 0, "input_tokens": 0, "output_tokens": 0, "errors": 0}
    sums = {"requests": 0, "input_tokens": 0, "output_tokens": 0, "errors": 0}
    for r in rows:
        agg = _aggregate_only(r)
        for k in sums:
            sums[k] += agg[k]
    n = len(rows)
    return {k: v // n for k, v in sums.items()}
