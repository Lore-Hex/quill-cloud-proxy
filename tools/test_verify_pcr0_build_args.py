"""Independent rebuilds must match the protected-main EIF publisher.

PCR0 measures the enclave image file, and the build args are baked into that
image. If the reproducible-build script and the real release script disagree on
even one arg, the script yields a PCR0 that can never match what is published —
and a third party running it sees a mismatch that looks like tampering.

This is not hypothetical. verify-pcr0.sh spent its whole life building from a
directory (`enclave/`) that has never existed in this repository, so the one
tool offering independent verification could not run at all. Nothing caught it
because nothing tested it.

Run: python3 tools/test_verify_pcr0_build_args.py
"""

from __future__ import annotations

import re
import shlex
import unittest
from pathlib import Path

import yaml

TOOLS = Path(__file__).resolve().parent
REPO_ROOT = TOOLS.parent
RELEASE = REPO_ROOT / ".github/workflows/publish-aws-eif.yml"
VERIFY = TOOLS / "verify-pcr0.sh"

# Every build input that lands in the measurement.
MEASURED_ARGS = (
    "BUILD_TAGS", "QUILL_TLS_MODE", "QUILL_API_HOST", "PLATFORM",
    "QUILL_ACME_DNS_GCP_PROJECT", "QUILL_ACME_DNS_MANAGED_ZONE",
)


def _assignments(script: Path) -> dict[str, str]:
    """Top-level NAME="value" assignments, ignoring ${VAR:-default} indirection."""
    found: dict[str, str] = {}
    for line in script.read_text().splitlines():
        match = re.match(r'^(\w+)="([^"$]*)"', line.strip())
        if match:
            found.setdefault(match.group(1), match.group(2))
    return found


def _ci_build() -> str:
    steps = yaml.safe_load(RELEASE.read_text())["jobs"]["publish"]["steps"]
    return next(step["run"] for step in steps if "docker buildx build" in step.get("run", ""))


def _ci_arguments() -> dict[str, str]:
    args = shlex.split(_ci_build().replace("\\\n", " "))
    result = {"PLATFORM": args[args.index("--platform") + 1]}
    for index, value in enumerate(args):
        if value == "--build-arg":
            name, setting = args[index + 1].split("=", 1)
            result[name] = setting
    return result


class VerifyPcr0BuildArgs(unittest.TestCase):
    def test_native_builder_cross_compiles_for_target_architecture(self) -> None:
        dockerfile = (REPO_ROOT / "enclave-go/Dockerfile.enclave").read_text()
        self.assertRegex(dockerfile, r"(?m)^FROM --platform=\$BUILDPLATFORM golang:[^\s]+ AS builder$")
        self.assertIn("ARG TARGETARCH=amd64", dockerfile)
        self.assertIn("ENV CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH}", dockerfile)
        # Go stages run natively and cross-compile; the Rust and Node helpers
        # use the target platform (native or emulated). The final
        # runtime must retain Docker's requested target architecture.
        stages = [line for line in dockerfile.splitlines() if line.startswith("FROM ")]
        self.assertEqual(len(stages), 5)
        self.assertRegex(stages[0], r"^FROM --platform=\$BUILDPLATFORM golang:[^\s]+ AS privatemode$")
        self.assertRegex(stages[1], r"^FROM rust:1\.94\.1-alpine@sha256:[0-9a-f]{64} AS maple$")
        self.assertRegex(stages[2], r"^FROM --platform=\$BUILDPLATFORM golang:[^\s]+ AS builder$")
        self.assertEqual(dockerfile.count("ARG TARGETARCH=amd64"), 2)
        self.assertEqual(dockerfile.count("ENV CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH}"), 2)
        self.assertRegex(stages[3], r"^FROM node:24-bookworm-slim@sha256:[0-9a-f]{64} AS rampart$")
        self.assertEqual(stages[4], "FROM scratch")
        self.assertIn("COPY --from=rampart /rootfs/ /", dockerfile)
        self.assertIn("COPY --from=maple /out/maple-transport /maple-transport", dockerfile)

    def test_every_gateway_packages_the_verified_target_platform_rampart_worker(self) -> None:
        for name in (
            "Dockerfile.enclave",
            "Dockerfile.enclave.gcp",
            "Dockerfile.enclave.gcp.anthropic",
            "Dockerfile.enclave.gcp.multi",
            "Dockerfile.enclave.azure.multi",
        ):
            with self.subTest(dockerfile=name):
                dockerfile = (REPO_ROOT / "enclave-go" / name).read_text()
                self.assertRegex(
                    dockerfile,
                    r"(?m)^FROM node:24-bookworm-slim@sha256:[0-9a-f]{64} AS rampart$",
                )
                self.assertIn("RUN npm ci --ignore-scripts", dockerfile)
                self.assertIn("RUN node model.mjs && npm test && sh rootfs.sh", dockerfile)
                self.assertIn("COPY --from=rampart /rootfs/ /", dockerfile)

    def test_azure_source_build_uses_acr_compatible_syntax_and_verifies_archive(self) -> None:
        dockerfile = (REPO_ROOT / "enclave-go/Dockerfile.enclave.azure.multi").read_text()
        recipe = (REPO_ROOT / "enclave-go/third_party/privatemode/build.sh").read_text()
        self.assertNotIn("FROM --platform", dockerfile)
        self.assertNotIn("ADD --checksum", dockerfile)
        self.assertEqual(dockerfile.count("ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64"), 2)
        self.assertIn("RUN curl --fail --show-error --silent --location --retry 3 --max-time 300", dockerfile)
        self.assertIn("RUN bash third_party/privatemode/build.sh /tmp/privatemode-source.tar.gz", dockerfile)
        self.assertIn("sha256sum -c -", recipe)
        self.assertLess(recipe.index("sha256sum -c -"), recipe.index("tar -xzf"))

    def test_measured_build_args_match_the_release_script(self) -> None:
        release = _ci_arguments()
        verify = _assignments(VERIFY)
        for name in MEASURED_ARGS:
            self.assertIn(name, release, f"{RELEASE.name} no longer defines {name}")
            self.assertIn(name, verify, f"{VERIFY.name} no longer defines {name}")
            self.assertEqual(
                verify[name],
                release[name],
                f"{name} differs between the release and verify scripts. A "
                "reproducible build with different args yields a different PCR0, "
                "which reads as tampering to whoever runs it.",
            )

    def test_source_revision_reads_an_assigned_repo_root(self) -> None:
        # SOURCE_REVISION is linked into the binary (ShadowBuildRevision), so it
        # is measured. release-aws-enclave.sh once read "$REPO_ROOT" without
        # assigning it: under set -u the command substitution failed inside the
        # argument and the image built with SOURCE_REVISION empty.
        for script in (VERIFY,):
            text = script.read_text()
            self.assertIn(
                '--build-arg "SOURCE_REVISION=$(git -C "$REPO_ROOT" rev-parse HEAD)"',
                text,
                script.name,
            )
            assigned = re.search(r'(?m)^REPO_ROOT="', text) is not None
            self.assertTrue(assigned, f"{script.name} reads $REPO_ROOT without assigning it")
        self.assertEqual(_ci_arguments()["SOURCE_REVISION"], "$GITHUB_SHA")
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', _ci_build())

    def test_all_measured_arguments_are_passed_to_both_builds(self) -> None:
        for script in (VERIFY,):
            text = script.read_text()
            for name in MEASURED_ARGS:
                flag = (f'--platform "${name}"' if name == "PLATFORM"
                        else f'--build-arg "{name}=${{{name}}}"')
                self.assertIn(flag, text, f"{script.name} defines but does not pass {name}")

    def test_verify_script_builds_from_paths_that_exist(self) -> None:
        text = VERIFY.read_text()
        dockerfile = re.search(r"--file (\S+)", text)
        self.assertIsNotNone(dockerfile, "verify-pcr0.sh no longer names a Dockerfile")
        assert dockerfile is not None
        self.assertTrue(
            (REPO_ROOT / dockerfile.group(1)).is_file(),
            f"{dockerfile.group(1)} does not exist; the verification path is broken",
        )
        # The build context must exist too — the original defect was a `cd` into
        # a directory that was never in the repository.
        for match in re.finditer(r'cd "\$REPO_ROOT(/[^"]*)?"', text):
            target = REPO_ROOT / (match.group(1) or "").lstrip("/")
            self.assertTrue(
                target.is_dir(), f"verify-pcr0.sh cd's into a missing directory: {target}"
            )

    def test_compares_against_authenticated_ci_measurement(self) -> None:
        text = VERIFY.read_text()
        self.assertIn('aws_eif_manifest.py" verify --manifest "$AWS_EIF_MANIFEST"', text)
        self.assertIn('--signature "$AWS_EIF_SIGNATURE" --expected-source', text)
        self.assertIn('if [ "$PCR0" != "$EXPECTED_PCR0" ]', text)
        self.assertIn('docker pull "$BUILDER_IMAGE"', text)
        self.assertNotIn('sudo nitro-cli', text)
        self.assertNotIn('PUBLISHED_FILE=', text)


class PublishedMeasurementsAgreeAcrossPaths(unittest.TestCase):
    """The same measurement must not be published twice with different values."""

    def test_legacy_pcr0_matches_the_canonical_record(self) -> None:
        import json

        record = json.loads((REPO_ROOT / "trust-page/trust/aws-release.json").read_text())
        canonical = (REPO_ROOT / "trust-page/trust/pcr0-aws.txt").read_text().strip()
        legacy = (REPO_ROOT / "trust-page/pcr0.txt").read_text().strip()
        self.assertEqual(canonical, record["pcr0"])
        self.assertEqual(
            legacy,
            record["pcr0"],
            "trust-page/pcr0.txt disagrees with the current AWS record. Two paths "
            "publishing different measurements is the defect that shipped for "
            "months; re-run tools/capture-plane-measurements.py --write.",
        )

    def test_primary_measurement_is_in_its_own_accepted_set(self) -> None:
        import json

        for name, scalar, accepted in (
            ("aws-release.json", "pcr0", "accepted_pcr0s"),
            ("azure-release.json", "hostdata", "accepted_hostdata"),
        ):
            record = json.loads((REPO_ROOT / "trust-page/trust" / name).read_text())
            self.assertIn(
                record[scalar],
                record[accepted],
                f"{name}: the value expected to be serving is absent from its own "
                "accepted set, so a verifier following this record would reject the "
                "enclave that is answering.",
            )


if __name__ == "__main__":
    unittest.main()
