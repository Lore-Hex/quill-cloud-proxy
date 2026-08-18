#!/usr/bin/env python3
"""Resolve the deploy's secret values from the operator's own files.

There is no cloud read here. Every cloud is provisioned from these files, so no
cloud is a hub another one needs in order to come up.

TWO SOURCES, because the values are two different shapes
========================================================

1. A shell-style env file (default ~/.quill_cloud_keys.private) holding the
   provider API keys. They are short single-line tokens and already live there.
   Its names are the operator's own (CLAUDE_API_KEY), not the deploy's
   (trustedrouter-anthropic-api-key), so PROVIDER_KEY_ALIASES maps between them.

2. A directory of one file per secret (default ~/.quill-secrets/), named for the
   logical secret. Prompts are multi-KB documents with newlines and quotes;
   putting them in an env file means escaping them, and an escaping bug in a
   prompt is a silent behaviour change rather than a loud failure. The
   device-key blob is JSON for the same reason.

A file in the directory always WINS over the env file. The directory is the more
specific statement, and a rotation that lands in one place should not be shadowed
by a stale value in the other.

Values are returned to the caller and never logged. Callers print names.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

#: Operator's env-file name -> the deploy's logical secret name.
#:
#: Explicit rather than derived. A rule like "strip the prefix and lowercase it"
#: gets CLAUDE_API_KEY -> claude, which is not what anthropic's key is called
#: here, and the failure is a provider silently missing from a cloud rather than
#: an error. Anything not in this table is simply not a bundle input.
PROVIDER_KEY_ALIASES: dict[str, str] = {
    "CLAUDE_API_KEY": "trustedrouter-anthropic-api-key",
    "CHATGPT_API_KEY": "trustedrouter-openai-api-key",
    "GEMINI_API_KEY": "trustedrouter-gemini-api-key",
    "CEREBRAS_API_KEY": "trustedrouter-cerebras-api-key",
    "MISTRAL_API_KEY": "trustedrouter-mistral-api-key",
    "DEEPSEEK_API_KEY": "trustedrouter-deepseek-api-key",
    "KIMI_API_KEY": "trustedrouter-kimi-api-key",
    "ZAI_API_KEY": "trustedrouter-zai-api-key",
    "TOGETHER_API_KEY": "trustedrouter-together-api-key",
    "VENICE_API_KEY": "trustedrouter-venice-api-key",
    "PHALA_CONFIDENTIAL_API_KEY": "trustedrouter-phala-confidential-api-key",
    "SILICON_FLOW_API_KEY": "trustedrouter-siliconflow-api-key",
    "NOVITA_API_KEY": "trustedrouter-novita-api-key",
    "TINFOIL_API_KEY": "trustedrouter-tinfoil-api-key",
    "GROK_API_KEY": "trustedrouter-grok-api-key",
    "GMI_API_KEY": "trustedrouter-gmi-api-key",
    "XIAOMI_API_KEY": "trustedrouter-xiaomi-api-key",
    "DEEPINFRA_API_KEY": "trustedrouter-deepinfra-api-key",
    "LIGHTNING_API_KEY": "trustedrouter-lightning-api-key",
    "NEBIUS_API_KEY": "trustedrouter-nebius-api-key",
    "MINIMAX_API_KEY": "trustedrouter-minimax-api-key",
    "PARASAIL_API_KEY": "trustedrouter-parasail-api-key",
    "COHERE_API_KEY": "trustedrouter-cohere-api-key",
    "VOYAGE_API_KEY": "trustedrouter-voyage-api-key",
    "FIREWORKS_API_KEY": "trustedrouter-fireworks-api-key",
    "FRIENDLI_API_KEY": "trustedrouter-friendli-api-key",
    "BASETEN_API_KEY": "trustedrouter-baseten-api-key",
    "MAKORA_API_KEY": "trustedrouter-makora-api-key",
    "WAFER_API_KEY": "trustedrouter-wafer-api-key",
    "CRUSOE_API_KEY": "trustedrouter-crusoe-api-key",
    "THINKING_MACHINES_API_KEY": "trustedrouter-thinking-machines-api-key",
    "OPENROUTER_API_KEY": "quill-openrouter-key",
    # Control-plane secrets. AWS needs these; Azure's enclave bundle does not.
    "STRIPE_SECRET_KEY": "trustedrouter-stripe-secret-key",
    "STRIPE_WEBHOOK_SECRET": "trustedrouter-stripe-webhook-secret",
    "SENTRY_DSN": "trustedrouter-sentry-dsn",
    "GOOGLE_CLIENT_ID": "trustedrouter-google-client-id",
    "GOOGLE_CLIENT_SECRET": "trustedrouter-google-client-secret",
    "GITHUB_CLIENT_ID": "trustedrouter-github-client-id",
    "GITHUB_CLIENT_SECRET": "trustedrouter-github-client-secret",
    "PAYPAL_CLIENT_ID": "trustedrouter-paypal-client-id",
    "PAYPAL_CLIENT_SECRET": "trustedrouter-paypal-client-secret",
    "PAYPAL_WEBHOOK_ID": "trustedrouter-paypal-webhook-id",
    "PHALA_API_KEY": "trustedrouter-phala-api-key",
    "AXIOM_API_TOKEN": "trustedrouter-axiom-api-token",
    "TR_SYNTHETIC_MONITOR_API_KEY": "trustedrouter-synthetic-monitor-api-key",
    "TR_API_KEY_FOR_SELF_HEAL": "trustedrouter-tr-api-key-for-self-heal",
    "CLOUDFLARE_API_TOKEN": "cloudflare-api-token",
    # ASSUMPTION worth checking: the env file holds TWO zone ids
    # (CLOUDFLARE_ZONE_ID_TRUSTEDROUTER and _QUILLROUTER) while the deploy asks
    # for one unqualified "cloudflare-zone-id". Mapped to the trustedrouter.com
    # zone because that is the domain the enclave fleet publishes under. If DNS
    # reconciliation ever edits the wrong zone, this line is why.
    "CLOUDFLARE_ZONE_ID_TRUSTEDROUTER": "cloudflare-zone-id",
}

DEFAULT_KEYS_FILE = Path.home() / ".quill_cloud_keys.private"
DEFAULT_SECRETS_DIR = Path.home() / ".quill-secrets"

_BUNDLE_SECRET_ENV = "QUILL_AZURE_BUNDLE_SECRET"
_BUNDLE_ENTRY_ENVS = ("QUILL_AZURE_SA_KEY_ENTRY",)

#: Extensions stripped when matching a file to a logical name, so
#: `trustedrouter-advisor-prompt-v1.txt` resolves to that secret.
_STRIPPABLE = (".txt", ".json", ".md", ".prompt", ".secret")


def parse_env_file(path: Path) -> dict[str, str]:
    """Read KEY=value lines. Tolerant of `export`, quotes and comments."""
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text().splitlines():
        match = re.match(r'\s*(?:export\s+)?([A-Za-z0-9_]+)\s*=\s*(.*)$', line)
        if not match:
            continue
        name, raw = match.group(1), match.group(2).strip()
        if raw[:1] in ("'", '"') and raw[-1:] == raw[:1] and len(raw) >= 2:
            raw = raw[1:-1]
        values[name] = raw
    return values


def read_secrets_dir(path: Path) -> dict[str, str]:
    """One file per secret, named for the logical secret."""
    values: dict[str, str] = {}
    if not path.is_dir():
        return values
    for entry in sorted(path.iterdir()):
        if not entry.is_file() or entry.name.startswith("."):
            continue
        name = entry.name
        for ext in _STRIPPABLE:
            if name.endswith(ext):
                name = name[: -len(ext)]
                break
        # Trailing newlines are what a text editor adds, not part of the secret.
        # A prompt keeps its internal newlines; a token loses the stray one that
        # would otherwise become a 401 that reads as a bad key.
        values[name] = entry.read_text().rstrip("\n")
    return values


def required_bundle_names(deploy_env: dict[str, object]) -> list[str]:
    """Return every logical secret name measured into an Azure deployment."""
    names = {
        str(value).strip()
        for env_name, value in deploy_env.items()
        if env_name.startswith("QUILL_")
        and env_name.endswith("_SECRET")
        and env_name != _BUNDLE_SECRET_ENV
        and str(value).strip()
    }
    # These variables name bundle entries but intentionally do not end in
    # _SECRET. Omitting one can boot a valid enclave with broken runtime
    # dependencies, so keep the exception explicit and tested.
    for env_name in _BUNDLE_ENTRY_ENVS:
        value = str(deploy_env.get(env_name, "")).strip()
        if value:
            names.add(value)
    return sorted(names)


def resolve(
    required: list[str],
    *,
    keys_file: Path = DEFAULT_KEYS_FILE,
    secrets_dir: Path = DEFAULT_SECRETS_DIR,
) -> tuple[dict[str, str], list[str], dict[str, str]]:
    """Return (values, missing, provenance) for the requested logical names."""
    env_values = parse_env_file(keys_file)
    dir_values = read_secrets_dir(secrets_dir)

    from_env: dict[str, str] = {}
    for env_name, logical in PROVIDER_KEY_ALIASES.items():
        raw = env_values.get(env_name, "")
        if raw.strip():
            from_env[logical] = raw

    values: dict[str, str] = {}
    provenance: dict[str, str] = {}
    missing: list[str] = []
    for name in required:
        # The directory wins: it is the more specific statement, and a rotation
        # landing there must not be shadowed by a stale line in the env file.
        if dir_values.get(name, "").strip():
            values[name] = dir_values[name]
            provenance[name] = f"dir:{secrets_dir.name}"
        elif from_env.get(name, "").strip():
            values[name] = from_env[name]
            provenance[name] = f"env:{keys_file.name}"
        else:
            missing.append(name)
    return values, missing, provenance


def main() -> int:
    if len(sys.argv) == 4 and sys.argv[1] == "--required-from-env":
        deploy_env = json.load(open(sys.argv[2]))
        if not isinstance(deploy_env, dict):
            print("deploy env must be a JSON object", file=sys.stderr)
            return 2
        json.dump(required_bundle_names(deploy_env), open(sys.argv[3], "w"))
        return 0
    if len(sys.argv) < 3:
        print(
            "usage: quill_secret_sources.py NEEDED_JSON OUT_JSON "
            "[KEYS_FILE] [SECRETS_DIR]\n"
            "   or: quill_secret_sources.py --required-from-env ENV_JSON OUT_JSON",
            file=sys.stderr,
        )
        return 2
    needed = sorted(json.load(open(sys.argv[1])))
    keys_file = Path(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_KEYS_FILE
    secrets_dir = Path(sys.argv[4]) if len(sys.argv) > 4 else DEFAULT_SECRETS_DIR

    values, missing, provenance = resolve(
        needed, keys_file=keys_file, secrets_dir=secrets_dir
    )
    json.dump(values, open(sys.argv[2], "w"))

    from collections import Counter
    counts = Counter(provenance.values())
    print(f"    required : {len(needed)}")
    print(f"    resolved : {len(values)}  ({', '.join(f'{v} from {k}' for k, v in sorted(counts.items())) or 'none'})")
    if missing:
        print(f"    MISSING  : {missing}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
