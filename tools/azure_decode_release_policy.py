#!/usr/bin/env python3
"""Decode a Key Vault SKR release policy into plain JSON on stdout.

Usage: azure_decode_release_policy.py <file-containing-the-raw-value>

WHY THIS IS A SEPARATE FILE

`az keyvault key show --query releasePolicy.encodedPolicy -o tsv` does NOT
return base64, despite the field name. This CLI hands back a **Python bytes
repr** — the literal characters:

    b'{"version":"1.0.0","anyOf":[...]}'

Running that through `base64 -d` yields nothing at all. In deploy-azure-aci.sh
that empty result was indistinguishable from "this key has no policy yet", so
the multi-region carry-over would have concluded there was nothing to preserve
and rendered a policy containing only the deploying region's clauses — silently
revoking every other region's access to the bootstrap key. Those regions keep
serving until their next cold start and then never come back.

It lives in its own file rather than inline in the shell because the value
contains quotes, braces and backslashes: passing it through argv or a heredoc
means fighting two layers of quoting, and `python3 -` already consumes stdin for
its script. A file path has none of those hazards. Two separate attempts at the
inline version both failed silently in exactly the direction that loses data,
which is the argument for this shape.

EXIT CODES

    0  a policy was decoded and is valid JSON; it is written to stdout
    1  the input could not be decoded, or is not JSON

Callers MUST treat exit 1 as fatal when the key is known to have a policy.
"Could not read it" and "there is nothing there" are different facts, and only
the second one is safe to act on.
"""

from __future__ import annotations

import ast
import base64
import json
import sys


def decode(raw: str) -> str:
    """Return the policy JSON text from any shape the CLI might emit."""
    raw = raw.strip()
    if not raw or raw == "None":
        raise ValueError("empty")

    # Shape 1: Python bytes repr. What the current CLI actually returns.
    if raw[:2] in ("b'", 'b"'):
        try:
            value = ast.literal_eval(raw)
        except (SyntaxError, ValueError):
            pass
        else:
            if isinstance(value, bytes):
                return value.decode("utf-8")
            if isinstance(value, str):
                return value

    # Shape 2: real base64, which the field name implies and other CLI
    # versions emit. Padding is restored because tsv output strips it.
    try:
        return base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8")
    except Exception:  # noqa: BLE001 - any decode failure falls through
        pass

    # Shape 3: already-plain JSON.
    return raw


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <file>", file=sys.stderr)
        return 2
    try:
        with open(argv[1], encoding="utf-8") as handle:
            raw = handle.read()
    except OSError as exc:
        print(f"cannot read {argv[1]}: {exc}", file=sys.stderr)
        return 1

    try:
        text = decode(raw)
    except ValueError:
        # Genuinely empty. The caller distinguishes this from a read failure by
        # checking the file was non-empty before invoking us.
        return 1

    try:
        parsed = json.loads(text)
    except ValueError as exc:
        print(f"decoded value is not JSON: {exc}", file=sys.stderr)
        return 1
    if not isinstance(parsed, dict) or "anyOf" not in parsed:
        print("decoded JSON is not a release policy (no anyOf)", file=sys.stderr)
        return 1

    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
