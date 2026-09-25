"""Read complete Cloud DNS A membership, not a resolver's selected GEO answer.

The CLI consumes `gcloud dns record-sets list --format=json` on stdin. Missing,
empty or unsupported records fail closed so a rollout cannot mistake them for
a completed drain. No cloud calls are made here.
"""
from __future__ import annotations

import argparse
import json
import sys


def record_ips(record: dict) -> list[str]:
    """Flatten static or GEO rrdatas; reject shapes we cannot safely interpret."""
    if "routingPolicy" not in record:
        values = record.get("rrdatas")
    else:
        policy = record["routingPolicy"]
        if not isinstance(policy, dict) or set(policy) - {"geo", "kind"}:
            raise ValueError("unsupported DNS routing policy")
        geo = policy.get("geo")
        if not isinstance(geo, dict) or not isinstance(geo.get("items"), list):
            raise ValueError("invalid GEO items")
        values = []
        for item in geo["items"]:
            if (not isinstance(item, dict) or not item.get("location")
                    or "healthCheckedTargets" in item
                    or not isinstance(item.get("rrdatas"), list)):
                raise ValueError("invalid GEO item rrdatas")
            values.extend(item["rrdatas"])
    if not isinstance(values, list) or any(not isinstance(ip, str) or not ip for ip in values):
        raise ValueError("invalid A record rrdatas")
    return list(values)


def listed_record_ips(rows: object, name: str) -> list[str]:
    if not isinstance(rows, list):
        raise ValueError("DNS query returned a non-list response")
    records = [row for row in rows if isinstance(row, dict)
               and row.get("name") == name and row.get("type") == "A"]
    if len(records) != 1:
        raise ValueError(f"expected exactly one A record for {name}")
    ips = sorted(set(record_ips(records[0])))
    if not ips:
        raise ValueError(f"empty A record for {name}; refusing to infer a drain")
    return ips


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", help="absolute record name, including trailing dot")
    args = parser.parse_args()
    print("\n".join(listed_record_ips(json.load(sys.stdin), args.name)))


if __name__ == "__main__":
    main()
