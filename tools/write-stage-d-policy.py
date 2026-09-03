#!/usr/bin/env python3
"""Build and validate the signed GCP Stage D accepted-digest policy."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any, Iterable


SCHEMA = "tr.stage-d-accepted/1"
PLANE = "gcp"
KINDS = ("transitional", "final")
POLICY_KEYS = {
    "schema",
    "plane",
    "sequence",
    "kind",
    "issued_at",
    "image_digests",
}
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
RFC3339_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def release_sequence(github_run_number: int, kind: str) -> int:
    if isinstance(github_run_number, bool) or github_run_number <= 0:
        raise ValueError("GITHUB_RUN_NUMBER must be a positive integer")
    if kind not in KINDS:
        raise ValueError(f"invalid policy kind: {kind!r}")
    return 2 * github_run_number + (1 if kind == "final" else 0)


def validate_digest(value: object) -> str:
    if not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None:
        raise ValueError(f"invalid OCI image digest: {value!r}")
    return value


def validate_policy(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Stage D policy must be a JSON object")
    unknown = set(payload) - POLICY_KEYS
    missing = POLICY_KEYS - set(payload)
    if unknown:
        raise ValueError(f"unknown Stage D policy keys: {sorted(unknown)!r}")
    if missing:
        raise ValueError(f"missing Stage D policy keys: {sorted(missing)!r}")
    if payload["schema"] != SCHEMA or payload["plane"] != PLANE:
        raise ValueError("Stage D policy schema or plane is invalid")
    sequence = payload["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
        raise ValueError("Stage D policy sequence must be a positive integer")
    if payload["kind"] not in KINDS:
        raise ValueError("Stage D policy kind is invalid")
    issued_at = payload["issued_at"]
    if not isinstance(issued_at, str) or RFC3339_UTC_RE.fullmatch(issued_at) is None:
        raise ValueError("Stage D policy issued_at must be RFC3339 UTC")
    try:
        datetime.strptime(issued_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError("Stage D policy issued_at is not a real UTC timestamp") from exc
    digests = payload["image_digests"]
    if not isinstance(digests, list) or not digests:
        raise ValueError("Stage D policy image_digests must be a non-empty array")
    normalized = [validate_digest(value) for value in digests]
    if normalized != sorted(set(normalized)):
        raise ValueError("Stage D policy image_digests must be sorted and unique")
    return payload


def read_policy(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read Stage D policy {path}: {exc}") from exc
    return validate_policy(payload)


def _flatten_digests(values: Iterable[str]) -> set[str]:
    result: set[str] = set()
    for candidate in values:
        for raw in candidate.replace(",", "\n").splitlines():
            value = raw.strip()
            if value:
                result.add(validate_digest(value))
    return result


def build_policy(
    *,
    github_run_number: int,
    kind: str,
    issued_at: str,
    incoming_digest: str,
    accepted_policies: Iterable[dict[str, Any]] = (),
    running_digests: Iterable[str] = (),
) -> dict[str, Any]:
    sequence = release_sequence(github_run_number, kind)
    incoming = validate_digest(incoming_digest)
    prior = [validate_policy(policy) for policy in accepted_policies]
    for policy in prior:
        if policy["sequence"] >= sequence:
            raise ValueError(
                "published Stage D policy sequence is not below this publication"
            )
    if kind == "transitional":
        accepted = {incoming}
        for policy in prior:
            accepted.update(policy["image_digests"])
        accepted.update(_flatten_digests(running_digests))
    else:
        if prior and any(
            policy["kind"] != "transitional"
            or policy["sequence"] != sequence - 1
            for policy in prior
        ):
            raise ValueError(
                "final Stage D policy must immediately follow this run's transition"
            )
        accepted = {incoming}
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "plane": PLANE,
        "sequence": sequence,
        "kind": kind,
        "issued_at": issued_at,
        "image_digests": sorted(accepted),
    }
    return validate_policy(payload)


def encoded_policy(payload: dict[str, Any]) -> bytes:
    validate_policy(payload)
    return (json.dumps(payload, indent=2) + "\n").encode("utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--github-run-number", type=int)
    parser.add_argument("--kind", choices=KINDS)
    parser.add_argument("--issued-at")
    parser.add_argument("--incoming-digest")
    parser.add_argument("--accepted-policy", action="append", type=Path, default=[])
    parser.add_argument("--running-digest", action="append", default=[])
    parser.add_argument("--running-digest-file", action="append", type=Path, default=[])
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.validate is not None:
        read_policy(args.validate)
        return
    required = {
        "--output": args.output,
        "--github-run-number": args.github_run_number,
        "--kind": args.kind,
        "--issued-at": args.issued_at,
        "--incoming-digest": args.incoming_digest,
    }
    missing = [name for name, value in required.items() if value is None]
    if missing:
        raise SystemExit(f"missing required arguments: {', '.join(missing)}")
    running = list(args.running_digest)
    for path in args.running_digest_file:
        running.append(path.read_text(encoding="utf-8"))
    payload = build_policy(
        github_run_number=args.github_run_number,
        kind=args.kind,
        issued_at=args.issued_at,
        incoming_digest=args.incoming_digest,
        accepted_policies=(read_policy(path) for path in args.accepted_policy),
        running_digests=running,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encoded_policy(payload))


if __name__ == "__main__":
    main()
