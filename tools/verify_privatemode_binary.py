#!/usr/bin/env python3
"""Rebuild the pinned proxy without the vendor cache; never execute its image."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "https://github.com/edgelesssys/privatemode-public.git"
COMMIT = "17ad265a79a39f30596ae2f12ec64ccbd9127275"
IMAGE = "ghcr.io/edgelesssys/privatemode/privatemode-proxy:v1.59.0@sha256:3cd4da0ee6ceee91ca84dde4e3e3f0e94e8b354d7c1d46987e4331a5c2f8bcff"
NIX = "nixos/nix:2.31.2@sha256:29fc5fe207f159ceb0143c25c19c774062fee02ce5eda118f3067547b3054894"
TARGET = "path:/src#legacyPackages.x86_64-linux.privatemode-proxy.bin"
DOCKERFILES = ("Dockerfile.enclave", "Dockerfile.enclave.gcp.multi", "Dockerfile.enclave.azure.multi")


def expected_digest(root: Path = ROOT) -> str:
    text = (root / "enclave-go/internal/privatemode/proxy.sha256").read_text()
    match = re.fullmatch(r"([0-9a-f]{64})  privatemode-proxy\n", text)
    if match is None:
        raise ValueError("invalid Privatemode executable checksum pin")
    for name in DOCKERFILES:
        dockerfile = (root / "enclave-go" / name).read_text()
        if f"FROM {IMAGE} AS privatemode\n" not in dockerfile:
            raise ValueError(f"{name}: vendor image differs from source-verification recipe")
        if "COPY --from=builder /out/privatemode-proxy /privatemode-proxy" not in dockerfile:
            raise ValueError(f"{name}: final image must copy the checksum-verified executable")
        if "sha256sum -c /src/internal/privatemode/proxy.sha256" not in dockerfile:
            raise ValueError(f"{name}: missing executable checksum verification")
    return match[1]


def digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def compare(rebuilt: Path, vendor: Path, expected: str) -> dict:
    actual = {"rebuilt_sha256": digest(rebuilt), "vendor_sha256": digest(vendor)}
    if any(value != expected for value in actual.values()):
        raise ValueError(f"Privatemode source/binary mismatch; do not release: {actual}")
    return actual


def build_command(source: Path, output: Path, name: str) -> list[str]:
    # No host credentials/socket. Nix uses its unprivileged builder accounts.
    # The outer container is the sandbox; syscall filtering is incompatible
    # with some amd64 emulators. These settings never reach the runtime image.
    script = (
        'nix --extra-experimental-features "nix-command flakes" '
        '--option sandbox false --option filter-syscalls false '
        '--option accept-flake-config false '
        '--option substituters https://cache.nixos.org '
        f'build {TARGET} --out-link /tmp/rebuilt --print-build-logs '
        '&& cp /tmp/rebuilt/bin/privatemode-proxy /out/privatemode-proxy'
    )
    return ["docker", "run", "--rm", "--name", name, "--platform", "linux/amd64",
            "--security-opt", "no-new-privileges",
            "--mount", f"type=bind,source={source},target=/src,readonly",
            "--mount", f"type=bind,source={output},target=/out", NIX, "sh", "-c", script]


def verify(output: Path) -> dict:
    expected = expected_digest()
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    name = "tr-privatemode-verify-" + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix="tr-privatemode-source-") as temp:
        source = Path(temp) / "source"
        subprocess.run(["git", "init", "--quiet", str(source)], check=True)
        subprocess.run(["git", "-C", str(source), "fetch", "--depth=1", SOURCE, COMMIT], check=True)
        subprocess.run(["git", "-C", str(source), "checkout", "--quiet", "--detach", COMMIT], check=True)
        actual = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        if actual != COMMIT:
            raise ValueError("wrong Privatemode source revision")
        try:
            with (output / "build.log").open("wb") as log:
                subprocess.run(build_command(source, output, name), check=True, stdout=log, stderr=subprocess.STDOUT)
        finally:
            subprocess.run(["docker", "rm", "--force", name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # create/cp do not start the vendor container, including its entrypoint.
    container = name + "-vendor"
    try:
        subprocess.run(["docker", "create", "--name", container, "--platform", "linux/amd64",
                        "--network", "none", "--entrypoint", "/not-executed", IMAGE], check=True)
        subprocess.run(["docker", "cp", "-L", f"{container}:/bin/privatemode-proxy",
                        str(output / "vendor-proxy")], check=True)
    finally:
        subprocess.run(["docker", "rm", container], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    result = {
        "schema": "trustedrouter-privatemode-source/1", "source_repository": SOURCE,
        "source_commit": COMMIT, "vendor_image": IMAGE, "build_image": NIX,
        "target": TARGET, "substituters": ["https://cache.nixos.org"],
        "platform": "linux/amd64", **compare(output / "privatemode-proxy", output / "vendor-proxy", expected),
    }
    (output / "verification.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.output_dir), indent=2))
