#!/usr/bin/env python3
"""Build the complete measured OCI image from committed source, not a worktree.

All compilation/serialization runs in digest-pinned client, frontend and BuildKit
containers. Signatures and invocation-specific provenance stay outside the image.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTITY = "https://github.com/Lore-Hex/quill-cloud-proxy/.github/workflows/publish-trust-gcp.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
AWS_ARGS = {
    "BUILD_TAGS": "cloud_aws,llm_multi",
    "QUILL_TLS_MODE": "acme",
    "QUILL_API_HOST": "api-aws.trustedrouter.com",
    "QUILL_ACME_DNS_GCP_PROJECT": "",
    "QUILL_ACME_DNS_MANAGED_ZONE": "",
}


def run(*args: str, **kwargs) -> str:
    return subprocess.check_output(args, text=True, **kwargs).strip()


def source_commit(ref: str) -> str:
    return run("git", "-C", str(ROOT), "rev-parse", "--verify", f"{ref}^{{commit}}")


def require_clean() -> None:
    if run("git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("refusing dirty source; commit changes or use a clean worktree")


def build_args(plane: str, values: list[str]) -> dict[str, str]:
    result = dict(AWS_ARGS) if plane == "aws" else {}
    for value in values:
        key, sep, item = value.partition("=")
        if plane != "aws" or not sep or key not in AWS_ARGS:
            raise ValueError(f"unsupported build argument: {key}")
        result[key] = item
    return result


def archive_source(commit: str, destination: Path) -> None:
    # No .git, credentials, generated files or untracked artifacts enter COPY . .
    archive = subprocess.check_output(["git", "-C", str(ROOT), "archive", commit])
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        source.extractall(destination, filter="data")


def client_image(context: Path) -> str:
    text = (context / "tools/reproducible-build.env").read_text()
    match = re.search(r"^REPRO_CLIENT='([^']+@sha256:[0-9a-f]{64})'$", text, re.MULTILINE)
    if match is None:
        raise ValueError("missing immutable Docker client pin")
    return match[1]


def docker_socket() -> str:
    host = os.environ.get("DOCKER_HOST") or run(
        "docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"
    )
    if not host.startswith("unix://"):
        raise ValueError("use a local Unix Docker socket on an isolated build host")
    return host.removeprefix("unix://")


def image_digest(metadata: dict) -> str:
    digest = metadata.get("containerimage.digest", "")
    if not DIGEST.fullmatch(digest):
        raise ValueError("builder did not return a complete image digest")
    return digest


def archive_digest(path: Path) -> str:
    # OCI archive's index is transport packaging. The single image manifest is
    # what is pushed/attested; reject indexes containing provenance or platforms.
    with tarfile.open(path) as archive:
        index = json.load(archive.extractfile("index.json"))
        manifests = index["manifests"]
        if len(manifests) != 1 or manifests[0]["mediaType"] != "application/vnd.oci.image.manifest.v1+json":
            raise ValueError("expected exactly one runnable OCI image manifest")
        digest = manifests[0]["digest"]
        if not DIGEST.fullmatch(digest):
            raise ValueError("invalid image manifest digest")
        manifest = archive.extractfile("blobs/sha256/" + digest.split(":")[1]).read()
        if "sha256:" + hashlib.sha256(manifest).hexdigest() != digest:
            raise ValueError("corrupt OCI manifest")
        content = json.loads(manifest)
        for descriptor in [content["config"], *content["layers"]]:
            blob_digest = descriptor["digest"]
            if not DIGEST.fullmatch(blob_digest):
                raise ValueError("invalid OCI blob digest")
            blob = archive.extractfile("blobs/sha256/" + blob_digest.split(":")[1])
            if "sha256:" + hashlib.file_digest(blob, "sha256").hexdigest() != blob_digest:
                raise ValueError("corrupt OCI image content")
        return digest


def build(plane: str, commit: str, output: Path, values: list[str], push: str | None = None) -> dict:
    args = build_args(plane, values)
    output.mkdir(parents=True, exist_ok=False)
    epoch = run("git", "-C", str(ROOT), "show", "-s", "--format=%ct", commit)
    with tempfile.TemporaryDirectory(prefix="tr-repro-source-") as temp:
        context = Path(temp)
        archive_source(commit, context)
        client = client_image(context)
        command = ["docker", "run", "--rm", "--env", "DOCKER_HOST=unix:///var/run/docker.sock",
                   "--volume", f"{docker_socket()}:/var/run/docker.sock",
                   "--volume", f"{context}:/workspace:ro", "--volume", f"{output.resolve()}:/output"]
        config = Path(os.environ.get("DOCKER_CONFIG", str(Path.home() / ".docker")))
        if (config / "config.json").is_file():
            auth = context / "client-auth"
            auth.mkdir(mode=0o700)
            # Host-specific contexts/keychain helper binaries do not exist in
            # the pinned client. Release jobs use short-lived docker-login auth.
            credentials = json.loads((config / "config.json").read_text())
            (auth / "config.json").write_text(json.dumps({"auths": credentials.get("auths", {})}))
            (auth / "config.json").chmod(0o600)
            # Only the credential file is shared. Buildx writes root-owned
            # private state; keep it inside the disposable client container.
            command += ["--volume", f"{auth / 'config.json'}:/root/.docker/config.json:ro"]
        target = f"type=image,name={push},push=true" if push else "type=oci,dest=/output/image.tar"
        command += ["--entrypoint", "sh", client, "/workspace/tools/build-enclave-context.sh",
                    plane, commit, epoch, target]
        for key, value in sorted(args.items()):
            command += ["--build-arg", f"{key}={value}"]
        subprocess.run(command, check=True)
        metadata = json.loads((output / "build-metadata.json").read_text())
        digest = image_digest(metadata) if push else archive_digest(output / "image.tar")
        record = {"schema": "trustedrouter-reproducible-image/1", "source_commit": commit,
                  "source_date_epoch": int(epoch), "plane": plane, "platform": "linux/amd64",
                  "build_args": args, "image_digest": digest, "client_image": client,
                  "image_reference": push}
        (output / "reproduction.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        return record


def compare(records: list[dict]) -> str:
    if len(records) != 2:
        raise ValueError("two independent build records are required")
    for field in ("schema", "source_commit", "source_date_epoch", "plane", "platform", "build_args", "image_digest", "client_image"):
        if records[0][field] != records[1][field]:
            raise ValueError(f"reproduction mismatch: {field}; do not publish or deploy")
    if not DIGEST.fullmatch(records[0]["image_digest"]):
        raise ValueError("invalid compared image digest")
    return records[0]["image_digest"]


def promote(records: list[dict], image: str, expected_commit: str | None = None) -> str:
    digest = compare(records)
    if expected_commit is not None and records[0]["source_commit"] != expected_commit:
        raise ValueError("build records belong to a different release commit")
    source = records[0]["image_reference"]
    if not source:
        raise ValueError("promotion requires registry build records")
    repository = source.rsplit(":", 1)[0]
    subprocess.run(["docker", "buildx", "imagetools", "create", "--prefer-index=false",
                    "--tag", image, f"{repository}@{digest}"], check=True)
    actual = run("docker", "buildx", "imagetools", "inspect", image, "--format", "{{.Manifest.Digest}}")
    if actual != digest:
        raise ValueError("registry promotion changed the verified image digest")
    return digest


def require_safe_cosign() -> None:
    version = json.loads(run("cosign", "version", "--json"))["gitVersion"]
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        raise ValueError("unsupported cosign version")
    parts = tuple(map(int, match.groups()))
    if not ((parts[0] == 2 and parts >= (2, 6, 5)) or (parts[0] == 3 and parts >= (3, 1, 3))):
        raise ValueError("cosign 2.6.5+ or 3.1.3+ required for safe legacy identity verification")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("build", "release"):
        child = sub.add_parser(name)
        child.add_argument("--plane", choices=("gcp", "aws", "azure"), required=True)
        child.add_argument("--commit", default="HEAD")
        child.add_argument("--output-dir", type=Path, required=True)
        child.add_argument("--build-arg", action="append", default=[])
        child.add_argument("--image", required=name == "release")
    child = sub.add_parser("promote")
    child.add_argument("--record", type=Path, action="append", required=True)
    child.add_argument("--image", required=True)
    child.add_argument("--commit", default="HEAD")
    child = sub.add_parser("verify")
    child.add_argument("--trust-url", default="https://trust.trustedrouter.com/trust/gcp-release.json")
    child.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "promote":
        print(promote([json.loads(p.read_text()) for p in args.record], args.image, source_commit(args.commit)))
        return
    require_clean()
    if args.command == "verify":
        require_safe_cosign()
        # The authenticated record, not an unsigned web response, selects source.
        with tempfile.TemporaryDirectory(prefix="tr-release-signature-") as temp:
            record = Path(temp) / "release.json"
            bundle = Path(temp) / "release.json.bundle"
            for url, path in ((args.trust_url, record), (args.trust_url + ".bundle", bundle)):
                if not url.startswith("https://"):
                    raise ValueError("release records require HTTPS")
                with urllib.request.urlopen(url, timeout=30) as response:
                    payload = response.read(4_000_001)
                    if len(payload) > 4_000_000:
                        raise ValueError("oversized release record")
                    path.write_bytes(payload)
            subprocess.run(["cosign", "verify-blob", "--bundle", str(bundle),
                            "--certificate-identity", IDENTITY,
                            "--certificate-oidc-issuer", ISSUER, str(record)], check=True)
            release = json.loads(record.read_text())
        if release.get("reproducible_build", {}).get("schema") != "trustedrouter-reproducible-image/1":
            raise ValueError("this release predates whole-image reproducibility; no full-image verification claim")
        commit = source_commit(release["source_commit"])
        result = build("gcp", commit, args.output_dir, [])
        if result["image_digest"] != release["image_digest"]:
            raise ValueError("REBUILD MISMATCH: do not trust this release")
        print(f"VERIFIED complete OCI image {result['image_digest']} from {commit}")
        print("Next: verify fresh live attestation and its TLS binding against this digest.")
        return
    commit = source_commit(args.commit)
    if args.command == "build":
        result = build(args.plane, commit, args.output_dir, args.build_arg, args.image)
        print(result["image_digest"])
    else:
        records = [build(args.plane, commit, args.output_dir / str(i), args.build_arg,
                         args.image + f"-repro-{i}") for i in (1, 2)]
        print(promote(records, args.image, commit))


if __name__ == "__main__":
    main()
