"""Plan or apply the exact NYTE certificate TXT grant, preserving zone IAM."""

from __future__ import annotations

import argparse
import copy
import json
import subprocess
import tempfile
from pathlib import Path

PROJECT = "quill-cloud-proxy"
ZONE = "trustedrouter-com"
ROLE = f"projects/{PROJECT}/roles/confidentialAcmeTxtWriter"
MEMBER = f"serviceAccount:quill-workload@{PROJECT}.iam.gserviceaccount.com"
RECORDS = (
    "_acme-challenge.api-nytokenexchange.trustedrouter.com.",
    "_acme-challenge.api-confidential-nytokenexchange.trustedrouter.com.",
)
TRUSTED_RECORDS = (
    "_acme-challenge.api.trusted.trustedrouter.com.",
    *(f"_acme-challenge.api-trusted-{brand}.trustedrouter.com."
      for brand in ("quillrouter", "allyrouter", "uptimerouter", "nytokenexchange")),
)
PERMISSIONS = {
    "dns.changes.create",
    "dns.resourceRecordSets.create",
    "dns.resourceRecordSets.delete",
}


def required_binding(*, trusted_api: bool = False) -> dict:
    records = " || ".join(
        f"resource.name.endsWith('/rrsets/{record}/TXT')" for record in (TRUSTED_RECORDS if trusted_api else RECORDS)
    )
    return {
        "role": ROLE,
        "members": [MEMBER],
        "condition": {
            "title": "trusted-api-acme-txt-only" if trusted_api else "nyte-acme-txt-only",
            "description": ("Only the five Trusted API certificate validation TXT records" if trusted_api
                            else "Only the two NYTE gateway certificate validation TXT records"),
            "expression": "(resource.type == 'dns.googleapis.com/Change') || "
            "(resource.type == 'dns.googleapis.com/ResourceRecordSet' && (" + records + "))",
        },
    }


def updated_policy(current: dict, *, trusted_api: bool = False) -> tuple[dict, bool]:
    if not current.get("etag"):
        raise ValueError("Refusing an IAM update without the current etag")
    desired = required_binding(trusted_api=trusted_api)
    for existing in current.get("bindings", []):
        if existing == desired:
            return copy.deepcopy(current), False
        if existing.get("condition", {}).get("title") == desired["condition"]["title"]:
            raise ValueError("Existing NYTE binding differs; review it instead of overwriting")
    result = copy.deepcopy(current)
    result.setdefault("bindings", []).append(desired)
    result["version"] = max(3, result.get("version", 1))
    return result, True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="Separately authenticated deploy identity")
    parser.add_argument("--trusted-api", action="store_true", help="Select only the five Trusted API TXT records instead of the NYTE grant")
    parser.add_argument("--apply", action="store_true", help="Apply only after explicit IAM approval")
    args = parser.parse_args(argv)
    if args.account.startswith("tr-ops-local@"):
        parser.error("The read-only operations identity must not perform IAM repairs")
    command = ["gcloud", f"--account={args.account}", f"--project={PROJECT}"]

    def run(*parts: str) -> dict:
        result = subprocess.run(
            [*command, *parts, "--format=json"],
            check=True, capture_output=True, text=True, timeout=60,
        )
        return json.loads(result.stdout)

    role = run("iam", "roles", "describe", "confidentialAcmeTxtWriter")
    if role.get("deleted") or set(role.get("includedPermissions", [])) != PERMISSIONS:
        raise ValueError("Certificate role must contain exactly the three approved DNS permissions")
    current = run("dns", "managed-zones", "get-iam-policy", ZONE)
    binding = required_binding(trusted_api=args.trusted_api)
    policy, changed = updated_policy(current, trusted_api=args.trusted_api)
    if not changed:
        print("Certificate TXT grant already matches; no change")
        return 0
    print(json.dumps({"zone": ZONE, "add_binding": binding}, indent=2))
    if not args.apply:
        print("Dry run only. Explicit IAM approval is required before --apply.")
        return 0
    # Preserve the fetched etag so a concurrent policy edit makes this fail closed.
    with tempfile.TemporaryDirectory(prefix="nyte-acme-iam-") as directory:
        path = Path(directory) / "policy.json"
        path.write_text(json.dumps(policy))
        applied = run("dns", "managed-zones", "set-iam-policy", ZONE, "--policy-file", str(path), "--quiet")
    if binding not in applied.get("bindings", []):
        raise RuntimeError("IAM response did not confirm the exact certificate TXT binding")
    print("Applied the scoped TXT grant; certificates and attestation still need verification")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
