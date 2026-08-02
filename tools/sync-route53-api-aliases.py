#!/usr/bin/env python3
"""Mirror attested canonical API membership into independent Route53 zones.

Backup domains intentionally use direct A records rather than CNAMEs to a
TrustedRouter or QuillRouter hostname. If either canonical domain is unavailable,
existing clients can still resolve and connect to the attested enclave fleet.

The GCP reconciler remains the health authority: it publishes only instances
that pass live attestation. This script copies that already-gated IP set into
Route53 and freezes the last-good records if the source is missing or too small.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import subprocess
from typing import Any, NamedTuple

PROJECT = "quill-cloud-proxy"
SOURCE_ZONE = "trustedrouter-com"
SOURCE_RECORD = "api.trustedrouter.com."
TTL = 60
MIN_HEALTHY = 2


class AliasRecord(NamedTuple):
    zone_id: str
    name: str


ALIASES = (
    AliasRecord("Z09662142UE0IQL51B13V", "api.allyrouter.com."),
    AliasRecord("Z00893363GIOMU7Z8647K", "api.uptimerouter.com."),
)


def run_json(command: list[str]) -> Any:
    result = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout or "{}")


def normalized_ipv4(
    values: list[object],
    *,
    minimum: int = MIN_HEALTHY,
) -> list[str]:
    addresses: set[str] = set()
    for value in values:
        try:
            address = ipaddress.ip_address(str(value).strip())
        except ValueError as exc:
            raise ValueError(f"invalid API address: {value!r}") from exc
        if address.version != 4 or address.is_private or address.is_loopback:
            raise ValueError(f"API address must be public IPv4: {address}")
        addresses.add(str(address))
    result = sorted(addresses, key=lambda value: int(ipaddress.ip_address(value)))
    if len(result) < minimum:
        raise ValueError(
            f"only {len(result)} healthy API addresses; refusing to replace last-good DNS"
        )
    return result


def source_ips() -> list[str]:
    rows = run_json(
        [
            "gcloud",
            "dns",
            "record-sets",
            "list",
            "--project",
            PROJECT,
            "--zone",
            SOURCE_ZONE,
            "--name",
            SOURCE_RECORD,
            "--type",
            "A",
            "--format=json",
        ]
    )
    if not isinstance(rows, list):
        raise ValueError("canonical DNS query returned a non-list response")
    for row in rows:
        if (
            isinstance(row, dict)
            and row.get("name") == SOURCE_RECORD
            and row.get("type") == "A"
        ):
            values = row.get("rrdatas")
            if not isinstance(values, list):
                raise ValueError("canonical A record has invalid rrdatas")
            return normalized_ipv4(values)
    raise ValueError(f"canonical A record {SOURCE_RECORD} was not found")


def current_alias_ips(alias: AliasRecord) -> list[str]:
    payload = run_json(
        [
            "aws",
            "route53",
            "list-resource-record-sets",
            "--hosted-zone-id",
            alias.zone_id,
            "--start-record-name",
            alias.name,
            "--start-record-type",
            "A",
            "--max-items",
            "1",
            "--output",
            "json",
        ]
    )
    rows = payload.get("ResourceRecordSets", []) if isinstance(payload, dict) else []
    if not rows or not isinstance(rows[0], dict):
        return []
    row = rows[0]
    if row.get("Name") != alias.name or row.get("Type") != "A":
        return []
    resources = row.get("ResourceRecords", [])
    if not isinstance(resources, list):
        return []
    values = [item.get("Value") for item in resources if isinstance(item, dict)]
    return normalized_ipv4(values, minimum=0) if values else []


def change_batch(alias: AliasRecord, ips: list[str]) -> dict[str, object]:
    return {
        "Comment": "Mirror attested TrustedRouter gateway membership",
        "Changes": [
            {
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": alias.name,
                    "Type": "A",
                    "TTL": TTL,
                    "ResourceRecords": [{"Value": ip} for ip in ips],
                },
            }
        ],
    }


def apply_alias(alias: AliasRecord, ips: list[str]) -> str:
    payload = run_json(
        [
            "aws",
            "route53",
            "change-resource-record-sets",
            "--hosted-zone-id",
            alias.zone_id,
            "--change-batch",
            json.dumps(change_batch(alias, ips), separators=(",", ":")),
            "--output",
            "json",
        ]
    )
    change = payload.get("ChangeInfo", {}) if isinstance(payload, dict) else {}
    change_id = change.get("Id") if isinstance(change, dict) else None
    if not isinstance(change_id, str) or not change_id:
        raise RuntimeError(f"Route53 did not return a change ID for {alias.name}")
    return change_id


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="apply Route53 updates; otherwise report drift only",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ips = source_ips()
    changed = False
    for alias in ALIASES:
        current = current_alias_ips(alias)
        if current == ips:
            print(f"{alias.name} already matches attested canonical set ({len(ips)} A)")
            continue
        changed = True
        print(f"{alias.name} {current} -> {ips}")
        if args.apply:
            change_id = apply_alias(alias, ips)
            print(f"{alias.name} update submitted: {change_id}")
    if changed and not args.apply:
        print("dry run only; pass --apply to update Route53")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
