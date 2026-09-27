#!/usr/bin/env python3
"""Check that each trust file published at two paths is the same file at both.

trust-page/ publishes the plane documents twice, at trust-page/<name> and at
trust-page/trust/<name>. Two paths serving different measurements is how
trust-page/pcr0.txt stayed wrong for months, so every publisher runs this
before publishing: publish-trust-page.yml before Pages, the S3 mirror's
publisher before syncing, and CI on every commit.

The rule: each document in REQUIRED exists at both paths, and every file that
exists at both paths, bundles included, is byte-identical at both. A bundle may
exist at one path only, because a new document's bundle lands one commit after
it. The tree may hold no symbolic link: the publishers follow links, which
this check does not walk.

Run: python3 tools/check-trust-copies.py [trust-page]
"""

from __future__ import annotations

import sys
from pathlib import Path

REQUIRED = (
    "gcp-release.json",
    "image-digest-gcp.txt",
    "image-reference-gcp.txt",
    "accepted-image-digests-gcp.txt",
    "accepted-image-references-gcp.txt",
    "gcp/stage-d-accepted.json",
    "aws-release.json",
    "pcr0-aws.txt",
    "accepted-pcr0s-aws.txt",
    "azure-release.json",
    "hostdata-azure.txt",
    "accepted-hostdata-azure.txt",
)


def problems(site: Path) -> list[str]:
    nested_root = site / "trust"
    # The publishers follow symbolic links, which the walk below does not
    # descend into, so the tree may hold none.
    found = [f"{path} is a symbolic link" for path in sorted(site.rglob("*")) if path.is_symlink()]
    found += [
        f"missing {path}"
        for name in REQUIRED
        for path in (site / name, nested_root / name)
        if not path.is_file()
    ]
    for nested in sorted(path for path in nested_root.rglob("*") if path.is_file()):
        top = site / nested.relative_to(nested_root)
        if top.is_file() and top.read_bytes() != nested.read_bytes():
            found.append(f"{top} and {nested} differ")
    return found


def main(argv: list[str]) -> int:
    site = Path(argv[1]) if len(argv) > 1 else Path("trust-page")
    found = problems(site)
    for problem in found:
        print(problem, file=sys.stderr)
    if found:
        return 1
    print(f"every file {site} publishes at two paths matches")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
