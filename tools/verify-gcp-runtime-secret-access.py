#!/usr/bin/env python3
"""Fail before a GCP rollout if the enclave cannot read a referenced secret."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import subprocess
import sys
from collections.abc import Callable, Iterable
from typing import Any

SECRET_ACCESSOR_ROLE = "roles/secretmanager.secretAccessor"


def policy_grants_access(policy: dict[str, Any], member: str) -> bool:
    return any(
        binding.get("role") == SECRET_ACCESSOR_ROLE
        and not binding.get("condition")
        and member in binding.get("members", [])
        for binding in policy.get("bindings", [])
    )


def missing_secret_access(
    secrets: Iterable[str],
    member: str,
    fetch_policy: Callable[[str], dict[str, Any]],
) -> tuple[list[str], dict[str, str]]:
    missing: list[str] = []
    errors: dict[str, str] = {}
    for secret in sorted(set(secrets)):
        try:
            policy = fetch_policy(secret)
        except (RuntimeError, TypeError) as exc:
            errors[secret] = str(exc)
            continue
        if not policy_grants_access(policy, member):
            missing.append(secret)
    return missing, errors


def gcloud_json(args: list[str]) -> dict[str, Any]:
    completed = subprocess.run(
        ["gcloud", *args, "--format=json"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(detail or f"gcloud exited {completed.returncode}")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("gcloud returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise TypeError("gcloud returned a non-object IAM policy")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True)
    parser.add_argument("--service-account", required=True)
    parser.add_argument("--secret", action="append", default=[])
    parser.add_argument("--workers", type=int, default=12)
    args = parser.parse_args()

    secrets = sorted(set(filter(None, args.secret)))
    if not secrets:
        print("runtime secret IAM preflight: no secrets referenced")
        return 0

    member = f"serviceAccount:{args.service_account}"
    try:
        project_policy = gcloud_json(["projects", "get-iam-policy", args.project])
    except (RuntimeError, TypeError) as exc:
        print(
            f"runtime secret IAM preflight: project policy read failed: {exc}",
            file=sys.stderr,
        )
        return 1
    if policy_grants_access(project_policy, member):
        print(
            f"runtime secret IAM preflight: {len(secrets)} secrets covered by project policy"
        )
        return 0

    def fetch(secret: str) -> dict[str, Any]:
        return gcloud_json(
            [
                "secrets",
                "get-iam-policy",
                secret,
                f"--project={args.project}",
            ]
        )

    policies: dict[str, dict[str, Any]] = {}
    errors: dict[str, str] = {}
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, min(args.workers, len(secrets)))
    ) as executor:
        futures = {executor.submit(fetch, secret): secret for secret in secrets}
        for future in concurrent.futures.as_completed(futures):
            secret = futures[future]
            try:
                policies[secret] = future.result()
            except (RuntimeError, TypeError) as exc:
                errors[secret] = str(exc)

    def cached_fetch(secret: str) -> dict[str, Any]:
        if secret in errors:
            raise RuntimeError(errors[secret])
        return policies[secret]

    missing, errors = missing_secret_access(secrets, member, cached_fetch)
    if errors or missing:
        for secret in missing:
            print(
                f"runtime secret IAM preflight: {secret} does not grant {member} {SECRET_ACCESSOR_ROLE}",
                file=sys.stderr,
            )
        for secret, detail in sorted(errors.items()):
            print(
                f"runtime secret IAM preflight: could not verify {secret}: {detail}",
                file=sys.stderr,
            )
        return 1

    print(f"runtime secret IAM preflight: {len(secrets)} referenced secrets verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
