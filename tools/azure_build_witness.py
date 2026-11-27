"""Bind a CI-built ACI template to the measurement captured from that region.

Publish only the four identifiers below, never the template or its environment.
The rollout signs the witness; the separate trust-record publisher verifies it.
"""
import argparse
import base64
import hashlib
import json
import re
import subprocess
from pathlib import Path


IDENTITY = "https://github.com/Lore-Hex/quill-cloud-proxy/.github/workflows/rollout-azure-gateway.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
LEGACY = {
    ("quill-enclave-uaenorth.uaenorth.azurecontainer.io", "7cf7e3489d4c55281efbe7919c948e324c46b30a", "sha256:aef49ca2fb69f8b4ea8e70c6bf6dc26423db45e0bc6a3d9b98073263ac1f3ea0", "7f0296a0c06a066ac75650507068f735d63853228241947518844b6802fd6b93"),
    ("quill-enclave-australiaeast.australiaeast.azurecontainer.io", "7cf7e3489d4c55281efbe7919c948e324c46b30a", "sha256:e6a7bf64a73e3b7666fe7f2da07e7edee7cf59916a31ae9ee1c44e19ea8c094b", "8e5b1b31f65cbcc8be6c216a1355dac66015d21d5ec1908e77788d48e574b16e"),
}
FIELDS = ("origin_hostname", "source_commit", "image_digest", "hostdata")


def fields(region):
    value = {k: region[k] for k in FIELDS}
    for k, pattern in zip(FIELDS, (r"[a-z0-9.-]+\.azurecontainer\.io", r"[a-f0-9]{40}", r"sha256:[a-f0-9]{64}", r"[a-f0-9]{64}")):
        if not isinstance(value[k], str) or not re.fullmatch(pattern, value[k]):
            raise ValueError("invalid Azure release field: " + k)
    if region.get("image_build_commit") != value["source_commit"]:
        raise ValueError("regional build commit does not match source")
    return value


def create(work, region, sha):
    value = fields(region)
    template = json.loads((work / "template.json").read_text())
    groups = [g for g in template["resources"] if g["type"].lower() == "microsoft.containerinstance/containergroups"]
    group, = groups
    props = group["properties"]
    workload, = [c for c in props["containers"] if c["name"] == "quill-enclave"]
    policy = base64.b64decode(props["confidentialComputeProperties"]["ccePolicy"], validate=True)
    image = workload["properties"]["image"]
    if not policy or hashlib.sha256(policy).hexdigest() != value["hostdata"]:
        raise ValueError("deployed policy does not match regional attestation")
    if props["ipAddress"]["dnsNameLabel"] + "." + group["location"] + ".azurecontainer.io" != value["origin_hostname"]:
        raise ValueError("template and attested region differ")
    if sha != value["source_commit"] or any(
        (work / name).read_text().strip() != sha for name in ("build-commit.txt", "template-build-commit.txt")
    ):
        raise ValueError("checkout and build source differ")
    if image.partition("@")[2] != value["image_digest"] or (work / "image-digest.txt").read_text().strip() != value["image_digest"]:
        raise ValueError("build, template and regional image digest differ")
    return value


def path_for(directory, value):
    return directory / "azure-builds" / (value["hostdata"] + ".json")


def verify(directory, region):
    value = fields(region)
    path = path_for(directory, value)
    if not path.exists() and tuple(value[k] for k in FIELDS) in LEGACY:
        return "legacy: operator assertion only"
    if json.loads(path.read_text()) != value:
        raise ValueError("Azure build witness and regional release differ")
    subprocess.run(["cosign", "verify-blob", "--new-bundle-format", "--bundle", str(path) + ".bundle",
                    "--certificate-identity", IDENTITY, "--certificate-oidc-issuer", ISSUER, str(path)],
                   check=True, timeout=120)
    return "verified rollout build witness"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("sign", "verify"))
    parser.add_argument("--record", type=Path, default=Path("trust-page/trust/azure-release.json"))
    parser.add_argument("--work", type=Path)
    parser.add_argument("--hostdata")
    parser.add_argument("--sha")
    args = parser.parse_args()
    regions = json.loads(args.record.read_text())["regions"]
    if not regions:
        raise ValueError("no Azure regions in release")
    if args.operation == "sign":
        region, = [r for r in regions if r["hostdata"] == args.hostdata]
        value = create(args.work, region, args.sha)
        path = path_for(args.record.parent, value)
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
        subprocess.run(["cosign", "sign-blob", "--yes", "--new-bundle-format", "--bundle",
                        str(path) + ".bundle", str(path)], check=True, timeout=120)
        print(verify(args.record.parent, region))
    else:
        for region in regions:
            print(region["origin_hostname"], verify(args.record.parent, region))


if __name__ == "__main__":
    main()
