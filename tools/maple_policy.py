#!/usr/bin/env python3
"""Fail-closed release classification and evidence checks for Maple updates.

The signer never executes vendor code. Reproduction runs separately without
credentials; a changed protected tree requires a new reviewed baseline.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BASELINE = REPO / "enclave-go/maple-transport/verified-release.json"
MODEL = "deepseek-v4-1-flash-1017-uncensored"
BACKEND = "https://enclave.trymaple.ai"
VENDOR = "MaplePrivacyLabs/Maple"
SOURCE_RE = re.compile(r"[a-f0-9]{40}")
PCR_RE = re.compile(r"[a-f0-9]{96}")
SHA_RE = re.compile(r"[a-f0-9]{64}")
HISTORY = "services/opensecret/pcrProdHistory.json"
MEASUREMENTS = frozenset(
    {
        HISTORY,
        "services/opensecret/pcrProd.json",
        "services/opensecret/pcrDev.json",
        "services/opensecret/pcrDevHistory.json",
    }
)
WORKFLOW = "https://github.com/MaplePrivacyLabs/Maple/.github/workflows/opensecret-eif-release.yml@refs/heads/master"


class Refused(ValueError):
    pass


def require(value: bool, reason: str) -> None:
    if not value:
        raise Refused(reason)


def strict_json(raw: bytes | str):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate JSON key")
            value[key] = item
        return value

    def constant(_):
        raise Refused("non-finite JSON number")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, check=True, timeout=120
    ).stdout


def blob(repo: Path, source: str, path: str) -> bytes:
    require(bool(SOURCE_RE.fullmatch(source)), "invalid source commit")
    return git(repo, "show", f"{source}:{path}")


def protected(path: str) -> bool:
    # Only application/UI and documentation trees known not to enter the
    # enclave build are exempt. New paths and every build/auth/routing change
    # are protected by default, not guessed safe from a commit message.
    if path in MEASUREMENTS:
        return False
    return not (
        path.startswith(("apps/", "docs/"))
        or path in {"README.md", "AGENTS.md", "LICENSE"}
    )


def boundary(repo: Path, source: str) -> str:
    require(bool(SOURCE_RE.fullmatch(source)), "invalid source commit")
    entries = git(repo, "ls-tree", "-rz", "--full-tree", source).split(b"\0")
    selected = []
    for entry in entries:
        if not entry:
            continue
        _metadata, name = entry.split(b"\t", 1)
        path = name.decode("utf-8", errors="strict")
        require(not any(ord(char) < 32 for char in path), "unsafe source path")
        if protected(path):
            selected.append(entry)
    require(bool(selected), "empty protected source tree")
    return hashlib.sha256(
        b"maple-protected-tree-v1\0" + b"\0".join(selected)
    ).hexdigest()


def classify(repo: Path, source: str, baseline: dict) -> dict:
    require(bool(SOURCE_RE.fullmatch(source)), "invalid source commit")
    require(
        boundary(repo, baseline["source_commit"])
        == baseline["security_boundary_sha256"],
        "reviewed baseline does not match protected source",
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "merge-base",
            "--is-ancestor",
            baseline["source_commit"],
            source,
        ],
        check=True,
        timeout=30,
    )
    observed = boundary(repo, source)
    changed = git(
        repo, "diff", "--name-only", "-z", baseline["source_commit"], source
    ).split(b"\0")
    sensitive = sorted(
        path.decode("utf-8")
        for path in changed
        if path and protected(path.decode("utf-8"))
    )
    return {
        "source_commit": source,
        "security_boundary_sha256": observed,
        "automatic": observed == baseline["security_boundary_sha256"],
        "security_sensitive_paths": sensitive,
    }


def verify_history(
    repo: Path, source: str, approval: str, pcr: str, baseline: dict
) -> None:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    require(bool(PCR_RE.fullmatch(pcr)) and pcr != "0" * 96, "invalid measurement")
    require(bool(SOURCE_RE.fullmatch(approval)), "invalid approval commit")
    require(
        measurement_source(repo, approval) == source,
        "approval is not descended from the attested source through approvals only",
    )
    changed = git(repo, "diff", "--name-only", "-z", source, approval).split(b"\0")
    require(
        all(not path or path.decode("utf-8") in MEASUREMENTS for path in changed),
        "approval commit also changes source",
    )
    before = strict_json(blob(repo, source, HISTORY))
    after = strict_json(blob(repo, approval, HISTORY))
    require(
        isinstance(before, list)
        and isinstance(after, list)
        and len(after) == len(before) + 1
        and after[:-1] == before,
        "measurement history is not append-only",
    )
    entry = after[-1]
    require(entry["PCR0"] == pcr, "approval measurement mismatch")
    raw = base64.b64decode(entry["signature"], validate=True)
    require(len(raw) == 96, "invalid history signature")
    key = serialization.load_der_public_key(
        base64.b64decode(baseline["history_public_key_der"])
    )
    require(
        isinstance(key, ec.EllipticCurvePublicKey)
        and isinstance(key.curve, ec.SECP384R1),
        "unexpected history key",
    )
    signature = utils.encode_dss_signature(
        int.from_bytes(raw[:48], "big"), int.from_bytes(raw[48:], "big")
    )
    key.verify(signature, pcr.encode("ascii"), ec.ECDSA(hashes.SHA384()))


def compare_artifacts(vendor: Path, reproduced: Path, source: str, pcr: str) -> dict:
    files = {}
    for name in ("image.eif", "pcr.json", "SHA256SUMS", "handoff.json"):
        paths = [root / name for root in (vendor, reproduced)]
        require(
            all(path.is_file() and not path.is_symlink() for path in paths),
            "missing or symlinked reproduction artifact",
        )
        hashes = []
        for path in paths:
            with path.open("rb") as handle:
                hashes.append(hashlib.file_digest(handle, "sha256").hexdigest())
        require(hashes[0] == hashes[1], "independent reproduction mismatch: " + name)
        files[name] = hashes[0]
    handoff = strict_json((vendor / "handoff.json").read_bytes())
    measurements = strict_json((vendor / "pcr.json").read_bytes())
    require(
        handoff["source_sha"] == source and handoff["environment"] == "prod",
        "artifact source or environment mismatch",
    )
    require(handoff["eif_sha256"] == files["image.eif"], "EIF hash mismatch")
    require(
        measurements == handoff["measurements"] and measurements["PCR0"] == pcr,
        "artifact measurement mismatch",
    )
    for field in ("PCR0", "PCR1", "PCR2"):
        require(
            bool(PCR_RE.fullmatch(measurements[field]))
            and measurements[field] != "0" * 96,
            "invalid reproduced PCR",
        )
    return files


def verify_provenance_result(rows: list, source: str) -> None:
    require(isinstance(rows, list) and bool(rows), "missing verified provenance")
    for row in rows:
        result = row["verificationResult"]
        certificate = result["signature"]["certificate"]
        require(
            certificate["issuer"] == "https://token.actions.githubusercontent.com"
            and certificate["subjectAlternativeName"] == WORKFLOW
            and certificate["sourceRepositoryURI"] == "https://github.com/" + VENDOR
            and certificate["sourceRepositoryDigest"] == source
            and certificate["buildSignerDigest"] == source
            and certificate["sourceRepositoryRef"] == "refs/heads/master"
            and certificate["sourceRepositoryIdentifier"] == "923138240"
            and certificate["sourceRepositoryOwnerIdentifier"] == "322649754",
            "unexpected attestation signer or source identity",
        )
        require(bool(result["verifiedTimestamps"]), "no witnessed signature timestamp")


def verify_provenance(directory: Path, source: str) -> None:
    # gh performs signature, digest, certificate and transparency verification.
    # Do not interpret an unsigned predicate as proof of the build's identity.
    for name in ("image.eif", "pcr.json"):
        output = subprocess.run(
            [
                "gh",
                "attestation",
                "verify",
                str(directory / name),
                "--repo",
                VENDOR,
                "--cert-identity",
                WORKFLOW,
                "--source-digest",
                source,
                "--signer-digest",
                source,
                "--source-ref",
                "refs/heads/master",
                "--cert-oidc-issuer",
                "https://token.actions.githubusercontent.com",
                "--format",
                "json",
            ],
            capture_output=True,
            check=True,
            timeout=180,
        ).stdout
        verify_provenance_result(strict_json(output), source)


def discover(repo: Path, baseline: dict) -> dict:
    approval = (
        git(repo, "log", "-1", "--format=%H", "origin/master", "--", HISTORY)
        .decode()
        .strip()
    )
    source = measurement_source(repo, approval)
    pcr = strict_json(blob(repo, approval, HISTORY))[-1]["PCR0"]
    verify_history(repo, source, approval, pcr, baseline)
    result = classify(repo, source, baseline)
    result.update(approval_commit=approval, pcr0=pcr)
    result["status"] = (
        "unchanged"
        if source == baseline["source_commit"] and pcr == baseline["pcr0"]
        else "automatic"
        if result["automatic"]
        else "review_required"
    )
    return result


def measurement_source(repo: Path, approval: str) -> str:
    require(bool(SOURCE_RE.fullmatch(approval)), "invalid approval commit")
    current = approval
    # Maple can append the dev approval before the prod approval. Those commits
    # do not change the built code; provenance must still identify the original
    # build source, not the intermediate dev-approval commit.
    for _ in range(32):
        lineage = (
            git(repo, "rev-list", "--parents", "-n", "1", current).decode().split()
        )
        if len(lineage) == 1:
            require(current != approval, "approval has no parent source")
            return current
        parent = lineage[1]
        paths = git(repo, "diff", "--name-only", "-z", parent, current).split(b"\0")
        if not all(not path or path.decode("utf-8") in MEASUREMENTS for path in paths):
            require(current != approval, "approval commit also changes source")
            return current
        current = parent
    raise Refused("approval chain exceeds bound")


def stage(
    repo: Path,
    candidate: dict,
    evidence: dict,
    root: Path = REPO,
    *,
    review_only: bool = False,
) -> None:
    baseline = strict_json((root / BASELINE.relative_to(REPO)).read_bytes())
    require(candidate == discover(repo, baseline), "candidate changed since discovery")
    require(
        candidate["status"] == "automatic" or review_only,
        "security-sensitive update requires approval",
    )
    require(
        evidence["source_commit"] == candidate["source_commit"]
        and evidence["pcr0"] == candidate["pcr0"]
        and evidence["security_boundary_sha256"]
        == candidate["security_boundary_sha256"],
        "evidence does not bind the candidate",
    )
    require(
        evidence.get("reproduction_verified") is True
        and evidence.get("provenance_verified") is True
        and evidence.get("history_verified") is True,
        "incomplete release evidence",
    )
    require(
        SHA_RE.fullmatch(evidence["files"]["image.eif"]) is not None,
        "invalid reproduced image hash",
    )
    lib = root / "enclave-go/maple-transport/src/lib.rs"
    text = lib.read_text()
    expected = 'pub const PCR0: &str = "' + baseline["pcr0"] + '";'
    require(text.count(expected) == 1, "compiled pin differs from reviewed baseline")
    lib.write_text(
        text.replace(expected, 'pub const PCR0: &str = "' + candidate["pcr0"] + '";')
    )
    updated = dict(baseline)
    updated.update(
        source_commit=candidate["source_commit"],
        approval_commit=candidate["approval_commit"],
        pcr0=candidate["pcr0"],
        eif_sha256=evidence["files"]["image.eif"],
        evidence=evidence,
    )
    (root / BASELINE.relative_to(REPO)).write_text(json.dumps(updated, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=("boundary", "classify", "discover", "verify", "stage")
    )
    parser.add_argument("--vendor", type=Path, required=True)
    parser.add_argument("--source")
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--reproduced", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--review-only",
        action="store_true",
        help="local qualification only; never permits automatic publication",
    )
    args = parser.parse_args()
    baseline = strict_json(BASELINE.read_bytes())
    if args.command == "boundary":
        result = boundary(args.vendor, args.source)
    elif args.command == "classify":
        result = classify(args.vendor, args.source, baseline)
    elif args.command == "discover":
        result = discover(args.vendor, baseline)
    elif args.command == "stage":
        stage(
            args.vendor,
            strict_json(args.candidate.read_bytes()),
            strict_json(args.evidence.read_bytes()),
            review_only=args.review_only,
        )
        result = {"staged": True, "review_only": args.review_only}
    else:
        candidate = strict_json(args.candidate.read_bytes())
        require(candidate == discover(args.vendor, baseline), "candidate is stale")
        require(
            candidate["status"] == "automatic" or args.review_only,
            "security-sensitive update requires approval",
        )
        files = compare_artifacts(
            args.artifacts,
            args.reproduced,
            candidate["source_commit"],
            candidate["pcr0"],
        )
        verify_provenance(args.artifacts, candidate["source_commit"])
        result = {
            "source_commit": candidate["source_commit"],
            "pcr0": candidate["pcr0"],
            "security_boundary_sha256": candidate["security_boundary_sha256"],
            "reproduction_verified": True,
            "provenance_verified": True,
            "history_verified": True,
            "review_only": args.review_only,
            "files": files,
        }
    encoded = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
