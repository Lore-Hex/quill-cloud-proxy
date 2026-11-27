"""Select the reviewed AWS TLS relay for an exact EIF release; never use tags."""

import argparse
import json
import re
import subprocess
from pathlib import Path

PLAN = "tools/aws-secrets/tls-cache-parent.json"
REGIONS = {"eu-west-1", "eu-west-3"}
SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def select(plan: dict, release_tree: str, serving: dict, region: str) -> str:
    if set(plan) != {"parent_tree", "from", "image"} or not SHA.fullmatch(release_tree):
        raise ValueError("invalid TLS parent plan or source tree")
    if plan["parent_tree"] != release_tree:
        raise ValueError("parent source changed; review a new immutable image")
    origins, image = plan["from"], plan["image"]
    if not isinstance(origins, dict) or set(origins) != REGIONS or region not in REGIONS:
        raise ValueError("invalid regional parent transition")
    if not all(isinstance(d, str) and DIGEST.fullmatch(d) for d in [image, *origins.values()]):
        raise ValueError("parent images must be immutable digests")
    if serving.get("region") != region or serving.get("parent_digest") not in (origins[region], image):
        raise ValueError("serving parent is not covered by the reviewed transition")
    return image


def checked_image(source: str, serving: dict, region: str) -> str:
    if not SHA.fullmatch(source):
        raise ValueError("release must be a full commit ID")
    plan = subprocess.check_output(["git", "show", f"{source}:{PLAN}"])
    if plan != subprocess.check_output(["git", "show", f"HEAD:{PLAN}"]):
        raise ValueError("release parent plan differs from current rollout policy")
    tree = subprocess.check_output(["git", "rev-parse", f"{source}:parent"], text=True).strip()
    return select(json.loads(plan), tree, serving, region)


def verify_registry(region: str, image: str) -> None:
    records = json.loads(subprocess.check_output([
        "aws", "ecr", "describe-images", "--region", region, "--registry-id", "330422590279",
        "--repository-name", "quill-parent", "--image-ids", f"imageDigest={image}",
        "--output", "json", "--no-cli-pager",
    ], timeout=45))["imageDetails"]
    if len(records) != 1 or any(records[0].get(k) != v for k, v in {
        "registryId": "330422590279", "repositoryName": "quill-parent", "imageDigest": image,
        "imageManifestMediaType": "application/vnd.oci.image.manifest.v1+json",
    }.items()):
        raise ValueError("reviewed parent manifest not verified in regional registry")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", required=True)
    p.add_argument("--region", required=True, choices=sorted(REGIONS))
    p.add_argument("--serving", type=Path, required=True)
    args = p.parse_args()
    image = checked_image(args.source, json.loads(args.serving.read_bytes()), args.region)
    verify_registry(args.region, image)
    print(image)


if __name__ == "__main__":
    main()
