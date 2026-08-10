"""Reconcile SES DKIM and custom MAIL FROM records in Google Cloud DNS."""

from __future__ import annotations

import argparse
import json
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Record:
    name: str
    record_type: str
    ttl: int
    rrdatas: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> Record:
        return cls(
            name=str(value["name"]),
            record_type=str(value["type"]),
            ttl=int(value["ttl"]),
            rrdatas=tuple(str(item) for item in value["rrdatas"]),
        )


def load_config(path: Path) -> tuple[str, str, tuple[Record, ...]]:
    config = json.loads(path.read_text(encoding="utf-8"))
    return (
        str(config["project"]),
        str(config["zone"]),
        tuple(Record.from_mapping(item) for item in config["records"]),
    )


def current_records(payload: Sequence[dict[str, Any]]) -> dict[tuple[str, str], Record]:
    records: dict[tuple[str, str], Record] = {}
    for item in payload:
        record = Record.from_mapping(item)
        records[(record.name, record.record_type)] = record
    return records


def plan_changes(
    current: dict[tuple[str, str], Record], desired: Sequence[Record]
) -> list[tuple[str, Record]]:
    changes: list[tuple[str, Record]] = []
    for record in desired:
        existing = current.get((record.name, record.record_type))
        if existing is None:
            changes.append(("create", record))
        elif existing.ttl != record.ttl or existing.rrdatas != record.rrdatas:
            changes.append(("update", record))
    return changes


def run(command: Sequence[str]) -> str:
    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def record_command(
    action: str, record: Record, *, project: str, zone: str
) -> list[str]:
    return [
        "gcloud",
        "dns",
        "record-sets",
        action,
        record.name,
        f"--project={project}",
        f"--zone={zone}",
        f"--type={record.record_type}",
        f"--ttl={record.ttl}",
        f"--rrdatas={','.join(record.rrdatas)}",
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(__file__).with_name("dns") / "ses-records.json",
    )
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    project, zone, desired = load_config(args.config)
    raw = run(
        [
            "gcloud",
            "dns",
            "record-sets",
            "list",
            f"--project={project}",
            f"--zone={zone}",
            "--format=json",
        ]
    )
    changes = plan_changes(current_records(json.loads(raw)), desired)

    if not changes:
        print("SES DNS records already match the declared configuration.")
        return 0

    for action, record in changes:
        print(f"{action}: {record.name} {record.record_type}")
        if args.apply:
            run(record_command(action, record, project=project, zone=zone))

    if not args.apply:
        print("Dry run only; pass --apply to reconcile these records.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
