"""Read-only release preflight. Never acquire a lease or change an IAM policy."""

import argparse
import json
import re
import subprocess
import sys

PROJECT = "quill-cloud-proxy"
BUCKET = "quill-cloud-proxy-acme-sealed-v1"
KEY = "acme-workload-wrap-v2"
PRINCIPAL = ("principalSet://iam.googleapis.com/projects/44325983244/locations/global/"
             "workloadIdentityPools/trustedrouter-batch/attribute.image_digest/")
OBJECTS = f"resource.name.startsWith('projects/_/buckets/{BUCKET}/objects/')"


def has_binding(policy, role, member, expression):
    for binding in policy.get("bindings", []):
        if binding.get("role") != role or member not in binding.get("members", []):
            continue
        if expression is None:
            if "condition" not in binding:
                return True
        elif binding.get("condition", {}).get("expression") == expression:
            return True
    return False


def policy(*args):
    output = subprocess.check_output(
        ["gcloud", *args, f"--project={PROJECT}", "--format=json"], timeout=30,
    )
    return json.loads(output)


def check(digest):
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("expected an immutable SHA-256 image digest")
    member = PRINCIPAL + digest
    bucket = policy("storage", "buckets", "get-iam-policy", f"gs://{BUCKET}")
    key = policy("kms", "keys", "get-iam-policy", KEY, "--keyring=trusted-router-tls",
                 "--location=us-central1")
    checks = (
        (BUCKET, has_binding(bucket, "roles/storage.objectUser", member, OBJECTS)),
        (KEY, has_binding(key, "roles/cloudkms.cryptoKeyEncrypterDecrypter", member, None)),
    )
    missing = [resource for resource, present in checks if not present]
    if missing:
        raise ValueError(f"{digest}: missing reviewed TLS binding on {', '.join(missing)}. "
                         "Stop before drain; see docs/runbooks/gcp-tls-cache-cutover.md.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("digest")
    try:
        check(parser.parse_args().digest)
    except (ValueError, subprocess.SubprocessError) as exc:
        sys.exit(str(exc))
    print("Exact TLS cache and key bindings are present; live custody and attestation gates still apply.")
