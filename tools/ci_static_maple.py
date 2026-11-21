"""Reuse only a recent successful main CI build of the exact static Maple target.

The archive used for the key is also the entire Docker build context: adding
an undeclared COPY cannot succeed by silently reading the rest of the checkout.
No binaries or cached test outputs are downloaded.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DF = "Dockerfile.enclave.gcp.multi"
PATHS = ["maple-transport", DF, ".dockerignore", DF + ".dockerignore"]
BUILD = ["docker", "build", "--platform", "linux/amd64", "--target", "maple", "-f", DF, "-"]


def context(root, tar):
    # Tree (not commit) and a fixed mtime keep unrelated commits out of the
    # key. Archive only tracked inputs; native Cargo tests generate other files.
    tree = "HEAD:enclave-go"
    tracked = subprocess.check_output(
        ["git", "ls-tree", "--name-only", tree, "--", *PATHS], cwd=root, text=True
    ).splitlines()
    if not {"maple-transport", DF, ".dockerignore"}.issubset(tracked):
        raise ValueError("missing required Maple build input")
    with tar.open("wb") as out:
        subprocess.run(["git", "archive", "--format=tar", "--mtime=2000-01-01T00:00:00Z",
                        tree, "--", *tracked], cwd=root, stdout=out, check=True)
    digest = hashlib.sha256(Path(__file__).read_bytes())
    digest.update(tar.read_bytes())
    return "maple-static-amd64-" + digest.hexdigest()


def verified_run(artifacts, runs, repo, receipt, now):
    eligible = {(r["id"], r["head_sha"]) for r in runs
                if r["event"] == "push" and r["head_branch"] == "main"
                and r["status"] == "completed" and r["conclusion"] == "success"
                and r["path"] == ".github/workflows/ci.yml"
                and r["head_repository"]["full_name"] == repo}
    for a in artifacts:
        if a["name"] != receipt or a["expired"]:
            continue
        age = now - dt.datetime.fromisoformat(a["created_at"].replace("Z", "+00:00"))
        run = a["workflow_run"]
        if dt.timedelta() <= age < dt.timedelta(days=1) and (run["id"], run["head_sha"]) in eligible:
            return run["id"]
    return ""


def find_receipt(repo, receipt):
    def get(path):
        return json.loads(subprocess.check_output(["gh", "api", f"repos/{repo}/actions/{path}"],
                                                 timeout=12))
    try:
        artifacts = get(f"artifacts?name={receipt}&per_page=50")["artifacts"]
        if not artifacts:
            return ""
        runs = get("workflows/ci.yml/runs?branch=main&event=push&status=success&per_page=50")
        return verified_run(artifacts, runs["workflow_runs"], repo, receipt, dt.datetime.now(dt.timezone.utc))
    except (OSError, subprocess.SubprocessError, KeyError, TypeError, ValueError):
        print("No verifiable receipt available; building locally.")
        return ""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "build"])
    args = parser.parse_args()
    tmp = Path(os.environ["RUNNER_TEMP"])
    tar = tmp / "maple-image.tar"
    if args.command == "build":
        with tar.open("rb") as inp:
            subprocess.run(BUILD, stdin=inp, check=True)
        return
    receipt = context(ROOT, tar)
    run = find_receipt(os.environ["GITHUB_REPOSITORY"], receipt)
    print(f"Static build: verified by main run {run}" if run else "Static build: fresh build required")
    (tmp / "maple-image.sha256").write_text(receipt + "\n")
    with open(os.environ["GITHUB_OUTPUT"], "a") as out:
        print(f"receipt={receipt}\nverified_run={run}", file=out)


if __name__ == "__main__":
    main()
