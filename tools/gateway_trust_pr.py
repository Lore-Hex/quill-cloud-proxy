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
    probe-token      for a rehearsal: ask GitHub whether the token may open a
                     pull request, read a pull request's checks as
                     open-and-merge does, and read the signing workflow's
                     runs, without opening anything. With --expect-refusal
                     the same request must be refused: run with a token that
                     lacks the permission, it shows the question can tell
                     the two apart.

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


REQUIRED_CHECKS = ("parent", "trust-page-validation")


def run(*args: str, capture: bool = True, check: bool = True) -> str:
    # Uncaptured commands print to stderr: stdout carries only the merge SHA.
    result = subprocess.run(args, check=check, text=True, timeout=300,
                            stdout=subprocess.PIPE if capture else sys.stderr)
    return (result.stdout or "").strip() if capture else ""


def parse_porcelain_z(raw: str) -> list[str]:
    """Paths from `git status --porcelain=v1 -z` (no renames expected)."""
    paths = []
    for entry in raw.split("\0"):
        if not entry:
            continue
        if len(entry) < 4 or entry[2] != " ":
            raise SystemExit(f"unexpected git status entry {entry!r}")
        if entry[0] in "RC":
            raise SystemExit("refusing: a rename or copy is not a trust-record change")
        paths.append(entry[3:])
    return sorted(paths)


def changed_paths() -> list[str]:
    raw = subprocess.run(["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
                         check=True, capture_output=True, text=True, timeout=60).stdout
    return parse_porcelain_z(raw)


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
    """'pending', 'success' or 'failure' over every check on the head commit.

    Success also requires main's required contexts to be present and green:
    the merging token can bypass branch protection, so an all-green rollup
    that CI has not populated yet must not read as success."""
    if not rollup:
        return "pending"
    names = {check.get("name") or check.get("context") for check in rollup}
    verdict = "success" if all(name in names for name in REQUIRED_CHECKS) else "pending"
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
        elif verdict == "success" and merge_state == "CLEAN":
            run("gh", "pr", "merge", str(number), "--repo", REPO, "--squash", "--delete-branch",
                "--match-head-commit", state["headRefOid"], check=False)
        time.sleep(30)
    raise SystemExit(f"PR #{number} did not merge within {timeout}s")


def probe_token(expect_refusal: bool = False) -> None:
    """Whether GH_TOKEN may open a pull request here, without opening one.

    The request names a head branch that does not exist. GitHub decides whether
    the caller may open pull requests before it looks at the branch, so a
    permitted token is refused with 422 for the head field, and a token without
    the permission with 403 or 404. Neither answer leaves anything behind.

    That order is GitHub's behaviour, not its documentation, so the rehearsal
    also asks with a token known to lack the permission (expect_refusal) and
    requires the 403 or 404: if GitHub ever looked at the branch first, that
    token would be answered 422 too and this probe would tell nothing.

    A permitted token is then held to the reads open-and-merge depends on: a
    pull request's state with the required checks in its rollup, and the
    signing workflows' runs. Pushing the branch and merging use the write
    access the GCP release workflow already exercises with this token; they
    are not asked about here.
    """
    head = "bot/no-such-branch-" + os.urandom(8).hex()
    answer = subprocess.run(
        ["gh", "api", "-i", "-X", "POST", f"repos/{REPO}/pulls", "-f", "title=permission probe",
         "-f", f"head={head}", "-f", "base=main"],
        check=False, text=True, capture_output=True, timeout=120)
    # Headers and body stay unprinted: only the status and the refused field are read.
    status = re.match(r"HTTP/[0-9.]+ ([0-9]{3})", answer.stdout or "")
    code = status.group(1) if status else "no answer"
    if code.startswith("2"):
        raise SystemExit(f"the probe opened a pull request from {head}; close it and report this")
    if expect_refusal:
        if code not in {"403", "404"}:
            raise SystemExit(f"a token without pull request write was answered HTTP {code}, not refused; "
                             "the probe cannot tell a permitted token from this one")
        print(f"a token without pull request write is refused the request (HTTP {code}); nothing was opened")
        return
    if code != "422" or '"field":"head"' not in (answer.stdout or "").replace(" ", ""):
        raise SystemExit(f"the token may not open a pull request on {REPO} (HTTP {code}); "
                         "it needs Pull requests: write there")
    # open-and-merge reads the pull request it opened, and merges only once
    # the required checks show in that reading. Any merged pull request has them.
    merged = subprocess.run(
        ["gh", "pr", "list", "--repo", REPO, "--state", "merged", "--limit", "1", "--json", "number"],
        check=False, text=True, capture_output=True, timeout=120)
    try:
        number = int(json.loads(merged.stdout)[0]["number"]) if merged.returncode == 0 else 0
        state = pr_state(number) if number else {}
    except (ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError):
        state = {}
    names = {check.get("name") or check.get("context") for check in state.get("statusCheckRollup") or []}
    missing = [name for name in REQUIRED_CHECKS if name not in names]
    if state.get("state") != "MERGED" or missing:
        raise SystemExit(f"the token cannot read a pull request's state with its required checks on {REPO} "
                         f"(not seen: {', '.join(missing) or 'the pull request'}); open-and-merge would wait for "
                         "them until it timed out")
    for workflow in sorted(set(SIGNER.values())):
        listed = subprocess.run(
            ["gh", "run", "list", "--repo", REPO, "--workflow", workflow, "--limit", "1", "--json", "databaseId"],
            check=False, text=True, capture_output=True, timeout=120)
        if listed.returncode != 0:
            raise SystemExit(f"the token may not read {workflow} runs on {REPO}; it needs Actions: read there")
    print("the token may open a pull request, read a pull request's required checks and read the signing "
          "workflows' runs; nothing was opened")


def contains(descendant: str, ancestor: str) -> bool:
    subprocess.run(["git", "fetch", "--quiet", "origin", "main"], check=False, timeout=120)
    return subprocess.run(["git", "merge-base", "--is-ancestor", ancestor, descendant],
                          check=False, capture_output=True, timeout=30).returncode == 0


def wait_signed(plane: str, merge_sha: str, timeout: int) -> None:
    """Wait for the signer to succeed on the merge commit or a descendant.

    The signers share a concurrency group, so a run for the merge commit can be
    cancelled in favour of a newer push; a later successful run that signed a
    tree containing the merge is equally good. A failed run on the merge
    commit itself is fatal."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        runs = json.loads(run("gh", "run", "list", "--repo", REPO, "--workflow", SIGNER[plane],
                              "--branch", "main", "--limit", "30", "--json",
                              "databaseId,headSha,status,conclusion"))
        for item in runs:
            if item["status"] != "completed":
                continue
            if item["headSha"] == merge_sha and item["conclusion"] == "failure":
                raise SystemExit(f"{SIGNER[plane]} run {item['databaseId']} failed on {merge_sha}")
            if item["conclusion"] == "success" and (item["headSha"] == merge_sha or contains(item["headSha"], merge_sha)):
                print(f"{SIGNER[plane]} run {item['databaseId']} signed {item['headSha']} (contains {merge_sha})",
                      file=sys.stderr)
                return
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
    pr.add_argument("--timeout", type=int, default=4500)
    signed = sub.add_parser("wait-signed")
    signed.add_argument("--plane", choices=sorted(PLANE_PATHS), required=True)
    signed.add_argument("--merge-sha", required=True)
    signed.add_argument("--timeout", type=int, default=1500)
    public = sub.add_parser("wait-public")
    public.add_argument("--plane", choices=sorted(PLANE_PATHS), required=True)
    public.add_argument("--record", type=Path, required=True)
    public.add_argument("--timeout", type=int, default=1800)
    probe = sub.add_parser("probe-token")
    probe.add_argument("--expect-refusal", action="store_true")
    args = parser.parse_args()
    if args.command == "wait-public":
        wait_public(args.plane, args.record, args.timeout)
        return
    if not os.environ.get("GH_TOKEN"):
        raise SystemExit("GH_TOKEN is required")
    if args.command == "probe-token":
        probe_token(args.expect_refusal)
    elif args.command == "open-and-merge":
        print(open_and_merge(args.plane, args.branch, args.title, args.body_file.read_text(), args.timeout))
    else:
        if re.fullmatch(r"[0-9a-f]{40}", args.merge_sha) is None:
            raise SystemExit("--merge-sha must be a full commit id")
        wait_signed(args.plane, args.merge_sha, args.timeout)


if __name__ == "__main__":
    main()
