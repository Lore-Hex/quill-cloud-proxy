#!/usr/bin/env python3
"""Check that each trust document published beside a bundle is signed by it.

A document at trust-page/<path> is published with its cosign bundle at
trust-page/<path>.bundle. A commit that changes a document still carries the
previous bundle until that plane's signer, publish-trust-<plane>.yml, re-signs
it and commits the new one. Publishing in between would serve a bundle for
different bytes, so both publishers run this first and publish nothing when it
fails: publish-trust-page.yml before Pages, and the S3 mirror's publisher before
syncing. The signer's completion runs publish-trust-page.yml again.

The rule: every bundle under trust-page/ sits beside a document that one
plane's signer signs (SIGNED_BY), holds exactly one signing certificate that
`openssl x509` parses and no bare public key, and `cosign verify-blob` accepts
the document with that bundle under that plane's workflow identity. A bundle
beside a document no signer signs fails, since no identity can be chosen for
it. The tree may hold no symbolic link, since the publishers follow links
this check does not walk. cosign up to 2.6.4 accepted a legacy bundle holding
a public key without checking the identity (GHSA-fx35-mq7g-6g98); the
publishers install 2.6.5, and the certificate check refuses such a bundle
before cosign sees it.

Run: python3 tools/check-trust-signatures.py [trust-page]
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import subprocess
import sys
from pathlib import Path

ISSUER = "https://token.actions.githubusercontent.com"
IDENTITY = (
    "https://github.com/Lore-Hex/quill-cloud-proxy/.github/workflows/"
    "publish-trust-{plane}.yml@refs/heads/main"
)
# The documents each plane's signer signs, as paths under trust-page/, in the
# signers' own bash glob syntax. The AWS and Azure signers also copy each
# trust/ bundle beside the root copy of its document; the GCP signer copies the
# Stage D policy's bundle to trust/gcp/.
SIGNED_BY = {
    "gcp": (
        "trust/gcp-release.json",
        "trust/image-digest-gcp.txt",
        "trust/image-reference-gcp.txt",
        "trust/accepted-image-digests-gcp.txt",
        "trust/accepted-image-references-gcp.txt",
        "gcp/stage-d-accepted.json",
        "trust/gcp/stage-d-accepted.json",
    ),
    "aws": (
        "trust/aws-release.json",
        "trust/pcr0-aws.txt",
        "trust/accepted-pcr0s-aws.txt",
        "trust/retractions/*.json",
        "pcr0.txt",
        "aws-release.json",
        "pcr0-aws.txt",
        "accepted-pcr0s-aws.txt",
    ),
    "azure": (
        "trust/azure-release.json",
        "trust/hostdata-azure.txt",
        "trust/accepted-hostdata-azure.txt",
        "azure-release.json",
        "hostdata-azure.txt",
        "accepted-hostdata-azure.txt",
    ),
}


def _glob(pattern: str) -> re.Pattern[str]:
    """pattern as bash expands it: * stays within one path component and
    does not match a leading dot."""
    components = []
    for component in pattern.split("/"):
        regex = "".join("[^/]*" if char == "*" else re.escape(char) for char in component)
        components.append((r"(?!\.)" if component.startswith("*") else "") + regex)
    return re.compile("/".join(components) + r"\Z")


def plane_of(document: str) -> str | None:
    """The plane whose signer signs the document at this path under trust-page/."""
    for plane, patterns in SIGNED_BY.items():
        if any(_glob(pattern).match(document) for pattern in patterns):
            return plane
    return None


_PEM_BLOCK = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.DOTALL)


def _certificate_der(bundle: dict) -> bytes | None:
    """The DER of the bundle's one signing certificate, if that is what it holds.

    A legacy bundle's "cert" must base64-decode to text whose one complete PEM
    block is a CERTIFICATE; text outside PEM blocks is ignored, as a PEM parser
    ignores it. A new-format bundle must hold a certificate, or a certificate
    chain, and no public key. The caller has openssl parse the DER.
    """
    try:
        if "mediaType" in bundle:
            material = bundle.get("verificationMaterial") or {}
            if "publicKey" in material:
                return None
            if "certificate" in material:
                raw = material["certificate"]["rawBytes"]
            else:
                raw = material["x509CertificateChain"]["certificates"][0]["rawBytes"]
            return base64.b64decode(raw, validate=True) or None
        pem = base64.b64decode(bundle["cert"], validate=True)
        blocks = list(_PEM_BLOCK.finditer(pem))
        if len(blocks) != 1 or blocks[0].group(1) != b"CERTIFICATE":
            return None
        return base64.b64decode(b"".join(blocks[0].group(2).split()), validate=True) or None
    except (KeyError, IndexError, TypeError, AttributeError, binascii.Error, ValueError):
        return None


def _verify(bundle: Path, document: Path, plane: str, cosign: str, openssl: str) -> str | None:
    try:
        content = json.loads(bundle.read_text())
    except ValueError:
        return f"{bundle} is not a cosign bundle"
    der = _certificate_der(content) if isinstance(content, dict) else None
    try:
        parsed = der is not None and subprocess.run(
            [openssl, "x509", "-inform", "DER", "-noout"],
            input=der,
            capture_output=True,
            timeout=30,
        ).returncode == 0
    except FileNotFoundError:
        return f"cannot verify {bundle}: {openssl} is not installed"
    if not parsed:
        return f"{bundle} carries no signing certificate"
    new_format = "mediaType" in content
    command = [cosign, "verify-blob"]
    if new_format:
        command.append("--new-bundle-format")
    command += [
        "--bundle",
        str(bundle),
        "--certificate-identity",
        IDENTITY.format(plane=plane),
        "--certificate-oidc-issuer",
        ISSUER,
        str(document),
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        return f"cannot verify {bundle}: {cosign} is not installed"
    if result.returncode == 0:
        return None
    reason = (result.stderr.strip().splitlines() or ["no output"])[-1]
    return f"{document} is not signed by {bundle} under publish-trust-{plane}.yml: {reason}"


def problems(site: Path, cosign: str = "cosign", openssl: str = "openssl") -> list[str]:
    # Pages packaging and aws s3 sync both follow symbolic links, while the
    # walk below does not descend into them: what a link reaches would be
    # published unchecked, so the tree may hold none.
    found = [
        f"{path} is a symbolic link" for path in sorted(site.rglob("*")) if path.is_symlink()
    ]
    for bundle in sorted(site.rglob("*.bundle")):
        document = bundle.with_name(bundle.name.removesuffix(".bundle"))
        relative = document.relative_to(site).as_posix()
        plane = plane_of(relative)
        if plane is None:
            found.append(f"{bundle}: no signer signs {relative}")
        elif not document.is_file():
            found.append(f"{bundle}: {document} is missing")
        elif (problem := _verify(bundle, document, plane, cosign, openssl)) is not None:
            found.append(problem)
    return found


def main(argv: list[str]) -> int:
    site = Path(argv[1]) if len(argv) > 1 else Path("trust-page")
    found = problems(site)
    for problem in found:
        print(problem, file=sys.stderr)
    if found:
        print(
            "Publish nothing yet: a changed document is published once its plane's "
            "signer has re-signed it, and that signer's completion republishes.",
            file=sys.stderr,
        )
        return 1
    count = len(list(site.rglob("*.bundle")))
    print(f"every one of the {count} bundles under {site} signs its document")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
