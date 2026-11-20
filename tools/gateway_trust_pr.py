#!/usr/bin/env python3
"""Land one gateway trust-record change through a pull request, then wait.

The AWS and Azure gateway rollout workflows change only their own plane's
trust-page files. GCP's release workflow pushes its records straight to main
with TRUST_PUSH_TOKEN; these workflows keep that authority (the same token
opens and merges the PR) but send the change through main's required checks
first, so the trust-page validation and the parent suite see the exact tree
before the plane's signing workflow does.

    open-and-merge   commit the named paths on a fresh branch from origin/main,
                     open a PR, keep it current with main (main's protection is
                     strict and GCP's bot commits land often), wait for every
                     check, squash-merge, and print the merge commit.
    wait-signed      wait for the plane's signing workflow run on a commit at
                     or after the merge to succeed.

Nothing here reads a secret value; GH_TOKEN comes from the environment.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = "Lore-Hex/quill-cloud-proxy"
# A plane's rollout may change only its own trust files.
PLANE_PATHS = {
    "aws": (
        "trust-page/trust/aws-release.json",
        "trust-page/trust/accepted-pcr0s-aws.txt",
        "trust-page/trust/pcr0-aws.txt",
        "trust-page/trust/eif/",
        "trust-page/aws-release.json",
        "trust-page/accepted-pcr0s-aws.txt",
        "trust-page/pcr0-aws.txt",
        "trust-page/eif/",
        "trust-page/pcr0.txt",
    ),
    "azure": (
        "trust-page/trust/azure-release.json",
        "trust-page/trust/hostdata-azure.txt",
        "trust-page/trust/accepted-hostdata-azure.txt",
        "trust-page/azure-release.json",
        "trust-page/hostdata-azure.txt",
        "trust-page/accepted-hostdata-azure.txt",
    ),
}
SIGNER = {"aws": "publish-trust-aws.yml", "azure": "publish-trust-azure.yml"}
BRANCH = re.compile(r"bot/(aws|azure)-trust-[a-z0-9-]{1,80}")


def run(*args: str, capture: bool = True, check: bool = True) -> str:
    result = subprocess.run(args, check=check, text=True, timeout=300,
                            stdout=subprocess.PIPE if capture else None)
    return (result.stdout or "").strip() if capture else ""


def changed_paths() -> list[str]:
    out = run("git", "status", "--porcelain", "--untracked-files=all")
    return sorted(line[3:] for line in out.splitlines() if line.strip())


def allowed(plane: str, path: str) -> bool:
    return any(path == p or (p.endswith("/") and path.startswith(p)) for p in PLANE_PATHS[plane])


def require_only_plane_changes(plane: str, paths: list[str]) -> None:
    stray = [p for p in paths if not allowed(plane, p)]
    if stray:
        raise SystemExit(f"refusing: {plane} trust PR would change other files: {stray}")
    if not paths:
        raise SystemExit("refusing: no trust-record change to propose")


def pr_state(number: int) -> dict:
    return json.loads(run("gh", "pr", "view", str(number), "--repo", REPO, "--json",
                          "state,mergeStateStatus,mergeCommit,headRefOid,statusCheckRollup"))


def checks_verdict(rollup: list[dict]) -> str:
    """'pending', 'success' or 'failure' over every check on the head commit."""
    if not rollup:
        return "pending"
    verdict = "success"
    for check in rollup:
        status = (check.get("status") or "").upper()
        conclusion = (check.get("conclusion") or check.get("state") or "").upper()
        if check.get("__typename") == "StatusContext":
            if conclusion in {"PENDING", "EXPECTED", ""}:
                verdict = "pending"
            elif conclusion != "SUCCESS":
                return "failure"
            continue
        if status != "COMPLETED":
            verdict = "pending"
        elif conclusion not in {"SUCCESS", "SKIPPED", "NEUTRAL"}:
            return "failure"
    return verdict


def open_and_merge(plane: str, branch: str, title: str, body: str, timeout: int) -> str:
    if not BRANCH.fullmatch(branch) or not branch.startswith(f"bot/{plane}-trust-"):
        raise SystemExit(f"refusing: branch {branch!r} is not a bot/{plane}-trust-* name")
    paths = changed_paths()
    require_only_plane_changes(plane, paths)
    run("git", "checkout", "-b", branch, capture=False)
    run("git", "add", "--", *paths, capture=False)
    run("git", "-c", "user.name=github-actions[bot]",
        "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
        "commit", "-m", title, capture=False)
    run("git", "push", "origin", f"HEAD:refs/heads/{branch}", capture=False)
    url = run("gh", "pr", "create", "--repo", REPO, "--base", "main", "--head", branch,
              "--title", title, "--body", body)
    number = int(url.rstrip("/").rsplit("/", 1)[1])
    print(f"opened {url}", file=sys.stderr)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = pr_state(number)
        if state["state"] == "MERGED":
            return state["mergeCommit"]["oid"]
        if state["state"] != "OPEN":
            raise SystemExit(f"PR #{number} is {state['state']}; refusing to continue")
        verdict = checks_verdict(state.get("statusCheckRollup") or [])
        merge_state = state.get("mergeStateStatus")
        if verdict == "failure":
            raise SystemExit(f"PR #{number}: a check failed on {state['headRefOid']}; not merging")
        if merge_state == "BEHIND":
            # Strict protection: bring the branch up to date and wait again.
            run("gh", "api", "-X", "PUT", f"repos/{REPO}/pulls/{number}/update-branch",
                "-f", f"expected_head_sha={state['headRefOid']}", check=False)
        elif merge_state == "DIRTY":
            raise SystemExit(f"PR #{number} conflicts with main; refusing to resolve automatically")
        elif verdict == "success" and merge_state in {"CLEAN", "HAS_HOOKS", "UNSTABLE"}:
            run("gh", "pr", "merge", str(number), "--repo", REPO, "--squash", "--delete-branch",
                "--match-head-commit", state["headRefOid"], check=False)
        time.sleep(30)
    raise SystemExit(f"PR #{number} did not merge within {timeout}s")


def wait_signed(plane: str, merge_sha: str, timeout: int) -> None:
    """Wait for the signer to succeed on the merge commit (or a descendant)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        runs = json.loads(run("gh", "run", "list", "--repo", REPO, "--workflow", SIGNER[plane],
                              "--branch", "main", "--limit", "20", "--json",
                              "databaseId,headSha,status,conclusion"))
        for item in runs:
            if item["headSha"] != merge_sha:
                continue
            if item["status"] == "completed":
                if item["conclusion"] == "success":
                    print(f"{SIGNER[plane]} run {item['databaseId']} signed {merge_sha}")
                    return
                raise SystemExit(f"{SIGNER[plane]} run {item['databaseId']} concluded {item['conclusion']}")
        time.sleep(20)
    raise SystemExit(f"{SIGNER[plane]} did not sign {merge_sha} within {timeout}s")


PUBLIC_RECORD = {
    "aws": "https://trust.trustedrouter.com/trust/aws-release.json",
    "azure": "https://trust.trustedrouter.com/trust/azure-release.json",
}
ISSUER = "https://token.actions.githubusercontent.com"


def wait_public(plane: str, record: Path, timeout: int) -> None:
    """Wait until the public record is byte-identical to `record` and verifies
    under the plane's signing identity. Never trusts a stale CDN copy."""
    import tempfile
    import urllib.request

    expected = record.read_bytes()
    identity = f"https://github.com/{REPO}/.github/workflows/{SIGNER[plane]}@refs/heads/main"
    deadline = time.monotonic() + timeout
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        try:
            with tempfile.TemporaryDirectory(prefix="tr-public-trust-") as directory:
                payload = Path(directory) / "record.json"
                bundle = Path(directory) / "record.json.bundle"
                for url, target in ((PUBLIC_RECORD[plane], payload), (PUBLIC_RECORD[plane] + ".bundle", bundle)):
                    with urllib.request.urlopen(f"{url}?nocache={os.getpid()}-{attempt}", timeout=20) as response:
                        target.write_bytes(response.read(1 << 20))
                if payload.read_bytes() == expected:
                    subprocess.run(["cosign", "verify-blob", "--bundle", str(bundle),
                                    "--certificate-identity", identity,
                                    "--certificate-oidc-issuer", ISSUER, str(payload)],
                                   check=True, timeout=60, stdout=subprocess.DEVNULL)
                    print(f"public {plane} record matches {record} and verifies under {identity}")
                    return
        except (OSError, subprocess.SubprocessError) as exc:
            print(f"public {plane} record not ready ({type(exc).__name__})", file=sys.stderr)
        time.sleep(30)
    raise SystemExit(f"public {plane} record did not match within {timeout}s")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    pr = sub.add_parser("open-and-merge")
    pr.add_argument("--plane", choices=sorted(PLANE_PATHS), required=True)
    pr.add_argument("--branch", required=True)
    pr.add_argument("--title", required=True)
    pr.add_argument("--body-file", type=Path, required=True)
    pr.add_argument("--timeout", type=int, default=5400)
    signed = sub.add_parser("wait-signed")
    signed.add_argument("--plane", choices=sorted(PLANE_PATHS), required=True)
    signed.add_argument("--merge-sha", required=True)
    signed.add_argument("--timeout", type=int, default=1800)
    public = sub.add_parser("wait-public")
    public.add_argument("--plane", choices=sorted(PLANE_PATHS), required=True)
    public.add_argument("--record", type=Path, required=True)
    public.add_argument("--timeout", type=int, default=2700)
    args = parser.parse_args()
    if args.command == "wait-public":
        wait_public(args.plane, args.record, args.timeout)
        return
    if not os.environ.get("GH_TOKEN"):
        raise SystemExit("GH_TOKEN is required")
    if args.command == "open-and-merge":
        print(open_and_merge(args.plane, args.branch, args.title, args.body_file.read_text(), args.timeout))
    else:
        if re.fullmatch(r"[0-9a-f]{40}", args.merge_sha) is None:
            raise SystemExit("--merge-sha must be a full commit id")
        wait_signed(args.plane, args.merge_sha, args.timeout)


if __name__ == "__main__":
    main()
