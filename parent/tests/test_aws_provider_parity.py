"""Every provider the enclave can route must be reachable on AWS, or be
explicitly, deliberately exempt.

secrets.go is the one binding table the multi-provider enclave routes from; on
GCP and Azure the deploy fetches a key for each entry. On AWS the keys come a
different way — parent/src/quill_parent/bootstrap_server.py reads each from AWS
Secrets Manager over vsock — and that list drifted: providers added to
secrets.go (live on GCP + Azure) were never added to the AWS parent, so they
were silently dark on AWS. Unlike Azure's sealed bundle, a missing AWS secret
does not crash the enclave (the parent returns None and the provider is
skipped), so the failure is invisible: the enclave boots healthy and 401s at
runtime only on AWS, only for those providers, only when a customer routes to
one. This is the AWS analog of enclave-go's provider_parity_test.go, which pins
GCP and Azure together but says nothing about AWS.

The rule: every provider=true binding in secrets.go must be either fetched by
the AWS parent (_PROVIDER_KEYS) or named in AWS_EXEMPT with a reason. A new
provider added to secrets.go and forgotten on AWS fails this test at merge.

If this fails with a provider in "unreachable on AWS": wire it into
bootstrap_server._PROVIDER_KEYS and tools/sync-secrets-to-aws.sh (then provision
its key in AWS Secrets Manager), OR add it to AWS_EXEMPT with a reason if it is
deliberately not served on AWS. Do NOT add a provider to AWS_EXEMPT to silence
the test if it should actually be reachable — that re-creates the exact
silent-dark bug.

Run: python3 -m pytest parent/tests/test_aws_provider_parity.py
"""

from __future__ import annotations

import re
from pathlib import Path

from quill_parent import bootstrap_server

_REPO = Path(__file__).resolve().parents[2]
_SECRETS_GO = _REPO / "enclave-go" / "internal" / "bootstrap" / "secrets.go"
_TYPES_GO = _REPO / "enclave-go" / "internal" / "types" / "types.go"

# Providers routable by the enclave but deliberately NOT served on AWS, each
# with the reason it is exempt. The AWS enclave build ships no media (image /
# video) adapter — its media consumers read only Grok/OpenAI/Venice — so the
# media-only providers below have nothing to answer on AWS even if their key
# were present. Keep this list to genuine design exemptions: an entry here is a
# promise that the provider is unreachable on AWS ON PURPOSE.
AWS_EXEMPT: dict[str, str] = {
    "bfl_api_key": "media-only (image); no AWS media adapter",
    "decart_api_key": "media-only (image/video); no AWS media adapter",
    "kling_api_key": "media-only (video); no AWS media adapter",
    "ltx_api_key": "media-only (video); no AWS media adapter",
    "openai_video_api_key": "media-only (Sora video); no AWS media adapter",
    "recraft_api_key": "media-only (image); no AWS media adapter",
    "runway_api_key": "media-only (video); no AWS media adapter",
    "cloudflare_workers_ai_api_key": (
        "needs a companion account_id that GCP sources from a plain env var "
        "(QUILL_CLOUDFLARE_WORKERS_AI_ACCOUNT_ID); that plumbing does not exist "
        "on the AWS parent yet. Wire the account_id through bootstrap_server "
        "before removing this exemption."
    ),
}


def _go_field_to_json() -> dict[str, str]:
    text = _TYPES_GO.read_text(encoding="utf-8")
    return {m.group(1): m.group(2) for m in re.finditer(r'(\w+)\s+string\s+`json:"([^",]+)', text)}


def _routable_provider_json_fields() -> set[str]:
    """The json field of every provider=true binding in secrets.go.

    Text-parsed rather than imported: secrets.go is Go behind a build tag and
    cannot be linked into a Python test, and the same reason provider_parity_
    test.go reads its siblings as text.
    """
    secrets = _SECRETS_GO.read_text(encoding="utf-8")
    field_to_json = _go_field_to_json()
    binding = re.compile(
        r'\{\[\]string\{"QUILL_[A-Z0-9_]+_SECRET"[^}]*\},\s*"[^"]+",\s*'
        r"(true|false),\s*func\(b \*types\.BootstrapData, v string\) \{ (b\.\w+) = v"
    )
    fields: set[str] = set()
    for is_provider, setter in binding.findall(secrets):
        if is_provider != "true":
            continue
        go_field = setter.split(".", 1)[1]
        fields.add(field_to_json.get(go_field, go_field))
    return fields


def _aws_fetched_fields() -> set[str]:
    return {field for field, _suffix in bootstrap_server._PROVIDER_KEYS}


def test_every_routable_provider_is_reachable_on_aws_or_exempt() -> None:
    routable = _routable_provider_json_fields()
    assert routable, "parsed no provider bindings from secrets.go — did the shape change?"
    fetched = _aws_fetched_fields()

    unreachable = sorted(routable - fetched - set(AWS_EXEMPT))
    assert unreachable == [], (
        "these providers are routable by the enclave but unreachable on AWS "
        "(silently dark: healthy boot, 401 at runtime only on AWS): "
        f"{unreachable}. Wire each into bootstrap_server._PROVIDER_KEYS + "
        "tools/sync-secrets-to-aws.sh, or add it to AWS_EXEMPT with a reason if "
        "it is deliberately not served on AWS."
    )


def test_exempt_list_has_no_stragglers() -> None:
    """An exemption must name a real routable provider that is genuinely not
    fetched. Once a provider IS wired to AWS, its exemption is stale and must be
    removed, or the list rots into a place bugs hide."""
    routable = _routable_provider_json_fields()
    fetched = _aws_fetched_fields()

    not_a_provider = sorted(set(AWS_EXEMPT) - routable)
    assert not_a_provider == [], (
        f"AWS_EXEMPT names things that are not provider=true bindings in "
        f"secrets.go: {not_a_provider}"
    )
    now_reachable = sorted(set(AWS_EXEMPT) & fetched)
    assert now_reachable == [], (
        f"these are in AWS_EXEMPT but ARE fetched by the AWS parent now — the "
        f"exemption is stale, remove it: {now_reachable}"
    )


def test_every_exemption_states_a_reason() -> None:
    blank = sorted(name for name, reason in AWS_EXEMPT.items() if not reason.strip())
    assert blank == [], f"AWS_EXEMPT entries with no reason: {blank}"
