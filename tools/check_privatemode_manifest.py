#!/usr/bin/env python3
"""Alert on upstream policy drift without accepting or modifying any pins."""
import hashlib
import json
from pathlib import Path
import sys
import urllib.request

URL = "https://cdn.confidential.cloud/privatemode/v2/manifest.json"
PIN = Path(__file__).resolve().parents[1] / "enclave-go/internal/privatemode/manifest.json"
MAX_BYTES = 1024 * 1024


def compare(pinned: bytes, live: bytes) -> dict:
    if not live or len(live) > MAX_BYTES:
        raise ValueError("invalid manifest size")
    document = json.loads(live)
    if not isinstance(document, dict) or not isinstance(document.get("Policies"), dict):
        raise ValueError("invalid manifest shape")
    return {
        "match": live == pinned,
        "pinned_sha256": hashlib.sha256(pinned).hexdigest(),
        "upstream_sha256": hashlib.sha256(live).hexdigest(),
    }


def main() -> int:
    try:
        request = urllib.request.Request(URL, headers={"Cache-Control": "no-cache"})
        with urllib.request.urlopen(request, timeout=30) as response:
            result = compare(PIN.read_bytes(), response.read(MAX_BYTES + 1))
    except Exception:
        print("::error::Privatemode manifest check unavailable; pins unchanged")
        return 1
    print(json.dumps(result, sort_keys=True))
    if not result["match"]:
        print("::error::Privatemode deployment changed. Review source, reproduce policies, "
              "and test encrypted inference before updating the pinned manifest. "
              "Do not enable runtime refresh or plaintext fallback.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
