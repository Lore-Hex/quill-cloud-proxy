"""DynamoDB UpdateItem on `quill_usage` table.

Schema (matches the Terraform module):
  PK device_id (S), SK day (S, "YYYY-MM-DD"),
  attrs requests (N), input_tokens (N), output_tokens (N), errors (N), ttl (N)

Atomic ADD per delta. TTL is set on first insert per (device, day), 90 days
out from the day key. After 90 days DynamoDB removes the row automatically.

This module is the parent's ONE write path that touches device-identifying
metadata. The values are aggregate counts, never content.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, cast

from typing_extensions import TypedDict


class CounterDelta(TypedDict):
    device_id: str
    d_requests: int
    d_input_tokens: int
    d_output_tokens: int
    d_errors: int


def _today_utc() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%d")


def _ttl_for_day(day: str) -> int:
    """Return epoch seconds 90 days after `day` for DynamoDB TTL auto-cleanup."""
    parsed = dt.datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=dt.UTC)
    return int((parsed + dt.timedelta(days=90)).timestamp())


class UsageWriter:
    """Wraps boto3 DynamoDB Table for the parent's usage flush."""

    def __init__(self, table_name: str, region_name: str) -> None:
        # Lazy import boto3 so tests that mock the writer don't pay the cost.
        import boto3

        self._table = boto3.resource("dynamodb", region_name=region_name).Table(table_name)

    def add(self, delta: CounterDelta) -> None:
        day = _today_utc()
        ttl = _ttl_for_day(day)
        self._table.update_item(
            Key={"device_id": delta["device_id"], "day": day},
            UpdateExpression=(
                "ADD requests :r, input_tokens :i, output_tokens :o, errors :e "
                "SET ttl_epoch = if_not_exists(ttl_epoch, :ttl)"
            ),
            ExpressionAttributeValues={
                ":r": delta["d_requests"],
                ":i": delta["d_input_tokens"],
                ":o": delta["d_output_tokens"],
                ":e": delta["d_errors"],
                ":ttl": ttl,
            },
        )

    def query_device_30d(self, device_id: str) -> list[dict[str, Any]]:
        """Return up to 30 most recent day rows for a device (admin /usage)."""
        from boto3.dynamodb.conditions import Key

        resp = self._table.query(
            KeyConditionExpression=Key("device_id").eq(device_id),
            ScanIndexForward=False,  # most recent first
            Limit=30,
        )
        # boto3's Table.query returns Any-shaped dicts. We trust the schema.
        return cast("list[dict[str, Any]]", resp.get("Items", []))
