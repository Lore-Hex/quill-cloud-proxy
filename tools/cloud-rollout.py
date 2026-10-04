#!/usr/bin/env python3
"""Use the reviewed control-plane coordinator; never maintain a second protocol.

The commit and content digest are updated together after coordinator review.
Local gh authentication or CI's cross-repository token supplies read access.
No provider secrets or application data pass through this bootstrap.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def main() -> int:
    pin = json.loads(Path(__file__).with_name("cloud-rollout-source.json").read_text())
    if not re.fullmatch(r"[a-f0-9]{40}", pin["commit"]) or not re.fullmatch(r"[a-f0-9]{64}", pin["sha256"]):
        raise RuntimeError("invalid coordinator source pin")
    result = subprocess.run([
        "gh", "api", "-H", "Accept: application/vnd.github.raw+json",
        "repos/Lore-Hex/quill-router/contents/scripts/deploy/cloud_rollout.py?ref=" + pin["commit"],
    ], check=True, capture_output=True, timeout=60)
    if hashlib.sha256(result.stdout).hexdigest() != pin["sha256"]:
        raise RuntimeError("coordinator content does not match reviewed pin")
    env = {**os.environ, "TR_DEPLOY_COMPONENT": "gateway"}
    # Unique private temporary directory: never execute an unverified cache.
    with tempfile.TemporaryDirectory(prefix="tr-release-guard-") as directory:
        script = Path(directory) / "cloud_rollout.py"
        script.write_bytes(result.stdout)
        return subprocess.run([sys.executable, str(script), *sys.argv[1:]], env=env, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
