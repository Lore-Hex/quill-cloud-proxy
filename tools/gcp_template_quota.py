#!/usr/bin/env python3
"""Refuse a GCP release without capacity for one template per gateway region."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import subprocess
import sys

from gcp_enclave_inventory import (
    MAIN_INVENTORY, PENDING_INVENTORY, InventoryError, parse_migs, validate_inventories,
)


class QuotaError(ValueError):
    """Template capacity is insufficient or cannot be verified."""


def available_templates(project: object, required: int) -> int:
    if type(required) is not int or required < 1:
        raise QuotaError("required template count must be a positive integer")
    quotas = project.get("quotas") if isinstance(project, dict) else None
    if not isinstance(quotas, list) or any(not isinstance(row, dict) for row in quotas):
        raise QuotaError("project quota response is missing or malformed")
    rows = [row for row in quotas if row.get("metric") == "INSTANCE_TEMPLATES"]
    if len(rows) != 1:
        raise QuotaError("expected exactly one INSTANCE_TEMPLATES quota")
    counts = []
    for field in ("limit", "usage"):
        value = rows[0].get(field)
        if (type(value) not in (int, float) or not math.isfinite(value)
                or value < 0 or int(value) != value):
            raise QuotaError(f"invalid INSTANCE_TEMPLATES {field}")
        counts.append(int(value))
    limit, usage = counts
    remaining = limit - usage
    if remaining < required:
        raise QuotaError(
            f"INSTANCE_TEMPLATES usage={usage} limit={limit}: need {required} free "
            f"slots, have {remaining}. Stop before building or draining. Review "
            "unused templates and obtain approval for cleanup or a quota increase."
        )
    return remaining


def read_project(project_id: str) -> object:
    try:
        result = subprocess.run(
            ["gcloud", "compute", "project-info", "describe",
             f"--project={project_id}", "--format=json"],
            check=True, capture_output=True, text=True, timeout=60,
        )
        return json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise QuotaError("could not read the GCP template quota; no changes made") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--inventory", type=Path, default=MAIN_INVENTORY)
    parser.add_argument("--pending-inventory", type=Path, default=PENDING_INVENTORY)
    args = parser.parse_args()
    try:
        active = parse_migs(args.inventory.read_text(), str(args.inventory))
        pending = parse_migs(args.pending_inventory.read_text(), str(args.pending_inventory))
        validate_inventories(active, pending)
        required = len(active) + len(pending)
        remaining = available_templates(read_project(args.project), required)
    except (OSError, InventoryError, QuotaError) as exc:
        print(f"GCP template quota preflight: {exc}", file=sys.stderr)
        return 1
    print(f"GCP template quota: {remaining} free slots; release requires {required}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
