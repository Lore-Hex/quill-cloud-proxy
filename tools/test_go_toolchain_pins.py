"""Keep CI and shipped Go binaries on the reviewed security-patched toolchains."""
from pathlib import Path
import re
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.26.11"
BUILDERS = {
    "builder": "golang:1.26.11-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0",
    "privatemode": "golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea",
}


class GoToolchainPinsTest(unittest.TestCase):
    def test_modules_use_patched_toolchain(self):
        for name in ("go.mod", "sidecar/go.mod"):
            with self.subTest(module=name):
                content = (ROOT / "enclave-go" / name).read_text()
                self.assertEqual(re.findall(r"^go (\S+)$", content, re.M), [VERSION])

    def test_all_go_image_stages_are_pinned_and_patched(self):
        stages = []
        for path in sorted((ROOT / "enclave-go").glob("Dockerfile*")):
            for line in path.read_text().splitlines():
                if not line.startswith("FROM ") or "golang:" not in line:
                    continue
                match = re.fullmatch(r"FROM (?:--platform=\$BUILDPLATFORM )?(golang:\S+) AS (\S+)", line)
                with self.subTest(dockerfile=path.name, line=line):
                    self.assertIsNotNone(match)
                    image, stage = match.groups()
                    self.assertIn(stage, BUILDERS)
                    self.assertEqual(image, BUILDERS[stage])
                    stages.append(stage)
        self.assertEqual(stages.count("builder"), 6)
        self.assertEqual(stages.count("privatemode"), 3)

    def test_ci_and_release_toolchains_match_modules(self):
        found = []
        for name in ("ci.yml", "deploy-enclave-gcp.yml"):
            workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
            for job in workflow["jobs"].values():
                for step in job.get("steps", []):
                    if step.get("uses", "").startswith("actions/setup-go@"):
                        with self.subTest(workflow=name, step=step):
                            self.assertEqual(step["with"]["go-version"], VERSION)
                            found.append(name)
        self.assertEqual(found.count("ci.yml"), 2)
        self.assertEqual(found.count("deploy-enclave-gcp.yml"), 1)


if __name__ == "__main__":
    unittest.main()
