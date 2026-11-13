#!/usr/bin/env python3
"""Bounded GitHub transport for the reviewed Maple release workflow."""

import argparse
import json
import os
import resource
import shutil
import stat
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path

import maple_policy as policy

REPOSITORY = "Lore-Hex/quill-cloud-proxy"
FILES = ("image.eif", "pcr.json", "SHA256SUMS", "handoff.json")
MAX_ARCHIVE = 350 * 1024 * 1024


def gh(*args):
    return subprocess.run(
        ["gh", *args], capture_output=True, check=True, timeout=180
    ).stdout


def api(path):
    return policy.strict_json(gh("api", path))


def unpack(archive: Path, destination: Path) -> None:
    policy.require(archive.stat().st_size <= MAX_ARCHIVE, "artifact archive too large")
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        policy.require(
            sorted(item.filename for item in entries) == sorted(FILES),
            "artifact contains unexpected or duplicate files",
        )
        policy.require(
            sum(item.file_size for item in entries) <= MAX_ARCHIVE,
            "artifact expands beyond bound",
        )
        for item in entries:
            mode = item.external_attr >> 16
            policy.require(
                not stat.S_ISLNK(mode)
                and not item.is_dir()
                and (stat.S_IFMT(mode) in (0, stat.S_IFREG))
                and not item.flag_bits & 1,
                "artifact contains a non-regular file",
            )
        destination.mkdir()
        for item in entries:
            with (
                bundle.open(item) as source,
                (destination / item.filename).open("xb") as out,
            ):
                shutil.copyfileobj(source, out, length=1024 * 1024)


def download(candidate: dict, destination: Path) -> dict:
    source = candidate["source_commit"]
    policy.require(bool(policy.SOURCE_RE.fullmatch(source)), "invalid source commit")
    builds = candidate["build_commits"]
    policy.require(
        isinstance(builds, list)
        and 0 < len(builds) <= 33
        and builds[0] == source
        and len(set(builds)) == len(builds)
        and all(
            isinstance(item, str) and policy.SOURCE_RE.fullmatch(item)
            for item in builds
        ),
        "invalid permitted build commits",
    )
    # A build at the measured source itself is preferred, exactly as before.
    # Otherwise use the final approval-containing build, then earlier ones.
    # policy.verify_build_commit re-checks the chosen commit against the
    # vendor repository before any evidence is produced.
    for build in [source, *reversed(builds[1:])]:
        result = download_build(build, destination)
        if result is not None:
            return dict(result, source_commit=source)
    raise policy.Refused("no successful production build artifact for approved source")


def download_build(source: str, destination: Path) -> dict | None:
    runs = api(
        f"repos/{policy.VENDOR}/actions/workflows/opensecret-eif-release.yml/runs"
        f"?head_sha={source}&status=success&per_page=30"
    )["workflow_runs"]
    name = "opensecret-eif-prod-" + source[:12]
    for run in runs:
        if (
            run["head_sha"] != source
            or run["head_branch"] != "master"
            or run["event"] != "workflow_dispatch"
            or run["conclusion"] != "success"
        ):
            continue
        run_id = run["id"]
        policy.require(type(run_id) is int and run_id > 0, "invalid run ID")
        artifacts = api(
            f"repos/{policy.VENDOR}/actions/runs/{run_id}/artifacts?per_page=100"
        )["artifacts"]
        matches = [
            item for item in artifacts if item["name"] == name and not item["expired"]
        ]
        if not matches:
            continue
        policy.require(len(matches) == 1, "ambiguous build artifact")
        artifact = matches[0]
        policy.require(
            type(artifact["id"]) is int
            and artifact["id"] > 0
            and 0 < artifact["size_in_bytes"] <= MAX_ARCHIVE,
            "invalid artifact",
        )
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "artifact.zip"
            with archive.open("xb") as output:
                subprocess.run(
                    [
                        "gh",
                        "api",
                        f"repos/{policy.VENDOR}/actions/artifacts/{artifact['id']}/zip",
                    ],
                    stdout=output,
                    check=True,
                    timeout=300,
                    preexec_fn=lambda: resource.setrlimit(
                        resource.RLIMIT_FSIZE, (MAX_ARCHIVE, MAX_ARCHIVE)
                    ),
                )
            unpack(archive, destination)
        policy.verify_provenance(destination, source)
        return {"vendor_run_id": run_id, "build_commit": source}
    return None


def report_review(candidate: dict) -> str:
    policy.require(
        candidate["status"] == "review_required", "not a security-review candidate"
    )
    source = candidate["source_commit"]
    policy.require(bool(policy.SOURCE_RE.fullmatch(source)), "invalid source")
    title = "Maple security review required: " + source[:12]
    rows = policy.strict_json(
        gh(
            "issue",
            "list",
            "--repo",
            REPOSITORY,
            "--state",
            "all",
            "--search",
            title + " in:title",
            "--json",
            "title,url",
        )
    )
    for row in rows:
        if row["title"] == title:
            return row["url"]
    body = (
        "The verified-release checker refused automatic promotion. Runtime attestation remains fail-closed.\n\n"
        "Candidate source: https://github.com/MaplePrivacyLabs/Maple/commit/"
        + source
        + "\n\n"
        "Protected paths changed:\n\n```json\n"
        + json.dumps(candidate["security_sensitive_paths"], indent=2)
        + "\n```\n\nReview the exact source and downstream worker identities, independently reproduce the EIF, "
        "verify signed provenance and the history signature, and run positive-pin and wrong-pin controls. "
        "Obtain operator approval before updating the protected baseline. Do not copy live measurements, "
        "accept remote history as policy, add a plaintext path, or enable shared/third-party Maple models.\n"
    )
    return (
        gh("issue", "create", "--repo", REPOSITORY, "--title", title, "--body", body)
        .decode()
        .strip()
    )


def cleanup_artifacts() -> list[int]:
    policy.require(
        os.environ.get("GITHUB_REPOSITORY") == REPOSITORY,
        "cleanup requires the release repository",
    )
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    policy.require(
        run_id.isascii() and run_id.isdigit() and int(run_id) > 0, "invalid run ID"
    )
    rows = api(f"repos/{REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=100")
    policy.require(rows["total_count"] <= 100, "unexpected artifact count")
    deleted = []
    for item in rows["artifacts"]:
        if item["name"] not in {"maple-vendor-artifacts", "maple-reproduced-artifacts"}:
            continue
        artifact_id = item["id"]
        policy.require(
            type(artifact_id) is int and artifact_id > 0, "invalid artifact ID"
        )
        gh(
            "api",
            "--method",
            "DELETE",
            f"repos/{REPOSITORY}/actions/artifacts/{artifact_id}",
        )
        deleted.append(artifact_id)
    return deleted


def validate_pin_checks(directory: Path, pcr: str) -> None:
    positive = policy.strict_json((directory / "valid-pin.json").read_bytes())
    negative = policy.strict_json((directory / "wrong-pin.json").read_bytes())
    policy.require(
        positive.get("ok") is True
        and positive.get("check") == "front_enclave_attestation"
        and positive.get("pcr0") == pcr,
        "positive attestation was not proven",
    )
    policy.require(
        negative.get("ok") is True and negative.get("check") == "changed_pin_rejected",
        "wrong-pin rejection was not proven",
    )


def publish(candidate: dict, evidence: dict, vendor: Path, checks: Path) -> str:
    policy.require(
        os.environ.get("GITHUB_REF") == "refs/heads/main"
        and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY,
        "publication requires the main-branch release workflow",
    )
    policy.require(
        candidate.get("status") == "automatic" and evidence.get("review_only") is False,
        "review-only evidence cannot authorize automatic publication",
    )
    validate_pin_checks(checks, candidate["pcr0"])
    policy.stage(vendor, candidate, evidence)
    branch = "automation/maple-" + candidate["source_commit"][:12]
    existing = policy.strict_json(
        gh(
            "pr",
            "list",
            "--repo",
            REPOSITORY,
            "--state",
            "all",
            "--head",
            branch,
            "--json",
            "url",
        )
    )
    policy.require(
        not existing, "candidate PR already exists; inspect it rather than rewriting it"
    )
    paths = [
        "enclave-go/maple-transport/src/lib.rs",
        "enclave-go/maple-transport/verified-release.json",
    ]
    changed = subprocess.check_output(
        ["git", "diff", "--name-only"], text=True
    ).splitlines()
    policy.require(sorted(changed) == sorted(paths), "unexpected generated patch")
    subprocess.run(["git", "switch", "-c", branch], check=True)
    subprocess.run(["git", "add", "--", *paths], check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=TrustedRouter release bot",
            "-c",
            "user.email=41898282+github-actions[bot]@users.noreply.github.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            (
                "Update independently verified Maple release\n\n"
                "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
            ),
        ],
        check=True,
    )
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    subprocess.run(["gh", "auth", "setup-git"], check=True)
    subprocess.run(
        ["git", "push", "origin", "HEAD:refs/heads/" + branch], check=True, timeout=180
    )
    body = (
        "## Verified routine update\n\n"
        "Protected routing, worker identities, attestation, authentication, cache isolation, dependencies "
        "and build recipes match the reviewed baseline. Only exempt application/documentation or "
        "measurement-history files differ.\n\n"
        "The complete EIF and three companion artifacts reproduced byte for byte without Maple's cache. "
        "Exact source/workflow provenance, signed approval history, positive-pin verification and "
        "wrong-pin rejection passed. No plaintext or third-party route is added.\n\n"
        "```json\n" + json.dumps(evidence, indent=2) + "\n```\n\n"
        "Merge waits for full CI on this exact head. GCP uses the existing staged signed-release workflow. "
        "AWS/Azure still require their measured-image, shared-guard and regional canary release procedure; "
        "a merge is not evidence those fleets have rolled.\n\n"
        "🤖 Generated with [Claude Code](https://claude.com/claude-code)"
    )
    url = (
        gh(
            "pr",
            "create",
            "--repo",
            REPOSITORY,
            "--base",
            "main",
            "--head",
            branch,
            "--title",
            "Update verified Maple release " + candidate["source_commit"][:12],
            "--body",
            body,
        )
        .decode()
        .strip()
    )
    merge_after_ci(url, head)
    return url


def merge_after_ci(url: str, head: str) -> None:
    deadline = time.monotonic() + 2700
    while time.monotonic() < deadline:
        rows = policy.strict_json(
            gh(
                "run",
                "list",
                "--repo",
                REPOSITORY,
                "--workflow",
                "ci.yml",
                "--commit",
                head,
                "--json",
                "databaseId,headSha,status,conclusion",
            )
        )
        if rows and rows[0]["status"] == "completed":
            policy.require(
                rows[0]["headSha"] == head and rows[0]["conclusion"] == "success",
                "full CI failed; automatic merge refused",
            )
            jobs = policy.strict_json(
                gh(
                    "run",
                    "view",
                    str(rows[0]["databaseId"]),
                    "--repo",
                    REPOSITORY,
                    "--json",
                    "jobs",
                )
            )["jobs"]
            policy.require(
                len(jobs) == 11 and all(job["conclusion"] == "success" for job in jobs),
                "full CI has missing or skipped jobs",
            )
            gh(
                "pr",
                "merge",
                url,
                "--squash",
                "--match-head-commit",
                head,
                "--body",
                "Independently reproduced Maple update with unchanged protected source.\n\n"
                "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>",
            )
            return
        time.sleep(20)
    raise policy.Refused("full CI did not finish; PR left unmerged")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=("download", "report-review", "publish", "cleanup")
    )
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--vendor", type=Path)
    parser.add_argument("--checks", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "cleanup":
        print(json.dumps({"deleted_temporary_artifacts": cleanup_artifacts()}))
        return
    policy.require(args.candidate is not None, "candidate is required")
    candidate = policy.strict_json(args.candidate.read_bytes())
    if args.command == "download":
        result = download(candidate, args.destination)
        if args.output:
            args.output.write_text(json.dumps(result) + "\n")
        print(json.dumps(result))
    elif args.command == "report-review":
        print(report_review(candidate))
    else:
        print(
            publish(
                candidate,
                policy.strict_json(args.evidence.read_bytes()),
                args.vendor,
                args.checks,
            )
        )


if __name__ == "__main__":
    main()
