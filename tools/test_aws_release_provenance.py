import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


class TestProvenance(unittest.TestCase):
    def test_pair_must_share_one_verified_statement(self):
        source, eif = "1" * 40, "2" * 64
        with tempfile.TemporaryDirectory() as path:
            d = Path(path)
            manifest = d / "manifest.json"
            manifest.write_text(json.dumps({"source_commit": source, "eif_sha256": eif}))
            m = {"name": "manifest.json", "digest": {"sha256": hashlib.sha256(manifest.read_bytes()).hexdigest()}}
            e = {"name": "enclave.eif", "digest": {"sha256": eif}}
            bad = {"name": "enclave.eif", "digest": {"sha256": "a" * 64}}
            (d / "git").write_text('#!/bin/sh\n[ "$1" = cat-file ] || exit "$HISTORIC"\n')
            (d / "gh").write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$D/args"\ncat "$D/response"\nexit "$FAIL"\n')
            (d / "git").chmod(0o700)
            (d / "gh").chmod(0o700)
            for pairs, fail, historic, ok in [
                ([[m, e]], 0, 1, True), ([[m, bad]], 0, 1, False),
                ([[m], [e]], 0, 1, False), ([], 0, 1, False),
                ([[m, e]], 1, 1, False), ([], 1, 0, True),
            ]:
                with self.subTest(pairs=pairs, fail=fail, historic=historic):
                    (d / "args").unlink(missing_ok=True)
                    (d / "response").write_text(json.dumps([
                        {"verificationResult": {"statement": {"subject": pair}}} for pair in pairs]))
                    env = dict(os.environ, PATH=str(d) + ":" + os.environ["PATH"],
                               D=path, HISTORIC=str(historic), FAIL=str(fail))
                    p = subprocess.run(["bash", str(ROOT / "tools/verify-aws-release-provenance.sh"),
                                        source, str(manifest)], env=env, capture_output=True, timeout=10)
                    self.assertEqual(p.returncode == 0, ok, p.stderr)
                    if historic:
                        args = (d / "args").read_text().splitlines()
                        self.assertIn("--deny-self-hosted-runners", args)
                        for k, v in {"--source-digest": source, "--source-ref": "refs/heads/main",
                                     "--predicate-type": "https://slsa.dev/provenance/v1",
                                     "--repo": "Lore-Hex/quill-cloud-proxy",
                                     "--signer-workflow": "Lore-Hex/quill-cloud-proxy/.github/workflows/publish-aws-eif.yml"}.items():
                            self.assertEqual(args[args.index(k) + 1], v)
                    else:
                        self.assertFalse((d / "args").exists())

    def test_no_eif_uploaded_or_cloud_credentials_in_attesting_job(self):
        workflows = ROOT / ".github/workflows"
        w = yaml.safe_load((workflows / "publish-aws-eif.yml").read_text())
        job = w["jobs"]["build-provenance"]
        self.assertEqual(job["needs"], "publish")
        self.assertEqual(job["permissions"], {"contents": "read", "id-token": "write",
                                              "attestations": "write"})
        actions = [step["uses"] for step in job["steps"] if "uses" in step]
        self.assertEqual(len(actions), 1)
        self.assertRegex(actions[0], r"^actions/attest@[0-9a-f]{40}$")
        self.assertNotIn("upload-artifact", str(w["jobs"]))
        preflight = yaml.safe_load((workflows / "rollout-aws-gateway.yml").read_text())["jobs"]["preflight"]
        steps = preflight["steps"]
        gate = next(s for s in steps if "verify-aws-release-provenance.sh" in s.get("run", ""))
        self.assertNotIn("if", gate)
        self.assertNotIn("continue-on-error", gate)
        self.assertLess(next(i for i,s in enumerate(steps) if "fetch-release --source" in s.get("run","")),
                        steps.index(gate))
