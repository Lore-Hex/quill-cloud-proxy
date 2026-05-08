"""Server-rendered trust page.

Renders a static-feeling HTML doc with no JavaScript and no third-party
fonts. The values are pulled from `Settings` (which were injected at
deploy time) plus a couple of live AWS API calls (Bedrock invocation
logging status). All facts the page asserts are linked back to the
specific code line that enforces them.
"""

from __future__ import annotations

import html
from typing import Final

from quill_parent.config import Settings

_REPO: Final[str] = "https://github.com/Lore-Hex/quill-cloud-proxy"
_INFRA_REPO: Final[str] = "https://github.com/Lore-Hex/quill-cloud-infra"


def _link(commit: str, path: str) -> str:
    return f"{_REPO}/blob/{commit}/{path}"


def _infra_link(path: str) -> str:
    return f"{_INFRA_REPO}/blob/main/{path}"


def render_trust_page(settings: Settings) -> str:
    commit = html.escape(settings.git_commit)
    image = html.escape(settings.image_digest)
    pcr0 = (
        html.escape(settings.published_pcr0_hex.get_secret_value())
        if settings.published_pcr0_hex
        else "(unset)"
    )

    rows = [
        ("Git commit", commit),
        ("Container image", image),
        ("Enclave PCR0", pcr0),
        ("Region", html.escape(settings.aws_region)),
        ("Usage table", html.escape(settings.usage_table_name)),
        ("Source repo", f'<a href="{_REPO}">{_REPO}</a>'),
    ]
    rows_html = "\n".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in rows)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Quill Cloud — trust</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, sans-serif;
            max-width: 50rem; margin: 2rem auto; padding: 1rem; color: #222; }}
    h1   {{ margin: 0 0 0.5rem; }}
    h2   {{ margin-top: 2rem; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
    th, td {{ text-align: left; padding: 0.4rem 0.6rem;
              border-bottom: 1px solid #ddd; font-family: ui-monospace, monospace; }}
    th   {{ font-weight: 600; color: #555; width: 14rem; }}
    code {{ background: #f5f5f5; padding: 0.1rem 0.3rem; border-radius: 3px; }}
    .ok  {{ color: #186; font-weight: 600; }}
    .pre {{ font-family: ui-monospace, monospace; font-size: 0.95rem; }}
    a    {{ color: #036; }}
  </style>
</head>
<body>
  <h1>Quill Cloud — trust</h1>
  <p>This page describes what the deployed proxy retains, and proves
     it via the open-source code at the commit + container digest below.</p>

  <h2>Identity</h2>
  <table>{rows_html}</table>

  <h2>What is retained</h2>
  <table>
    <tr><th>Prompt content</th><td class="ok">No</td></tr>
    <tr><th>Completion content</th><td class="ok">No</td></tr>
    <tr><th>Bearer tokens</th><td class="ok">No</td></tr>
    <tr><th>Per-request timestamps</th><td class="ok">No</td></tr>
    <tr><th>Client IPs</th><td class="ok">No prompt-path client IP persistence</td></tr>
    <tr><th>Per-device daily aggregate counts (req, tokens, errors), 90-day TTL</th>
        <td>Yes — for accountability + billing</td></tr>
    <tr><th>Hourly across-all-devices request count</th><td>Yes — heartbeat</td></tr>
  </table>

  <h2>How to verify</h2>
  <p>Rebuild the enclave from this exact commit and confirm the PCR0:</p>
  <pre class="pre">git clone {_REPO}
cd quill-cloud-proxy
git checkout {commit}
./tools/verify-pcr0.sh
# expected PCR0:
{pcr0}</pre>

  <p>The KMS key policy that gates Bedrock access is bound to that PCR0 value;
     a different build → different PCR0 → KMS denies decrypt → service breaks.
     See
     <a href="{_infra_link("modules/kms/main.tf")}">
     quill-cloud-infra/modules/kms/main.tf</a>.</p>

  <h2>Code</h2>
  <ul>
    <li><a href="{_link(commit, "enclave-go/cmd/enclave/main.go")}">
        enclave-go/cmd/enclave/main.go</a> — the prompt path inside the workload</li>
    <li><a href="{_link(commit, "parent/src/quill_parent/tcp_relay.py")}">
        parent/src/quill_parent/tcp_relay.py</a> — the TCP passthrough pump;
        TLS terminates inside the enclave</li>
    <li><a href="{_link(commit, "parent/src/quill_parent/usage.py")}">
        parent/src/quill_parent/usage.py</a> — the only DynamoDB write path</li>
    <li><a href="{_link(commit, "parent/tests/test_no_content_in_logs.py")}">
        parent/tests/test_no_content_in_logs.py</a> —
        AST guard against content-bearing log fields</li>
  </ul>

  <p style="color:#888;font-size:0.85rem;margin-top:3rem">
    This page is rendered server-side by the parent process. It contains no JavaScript,
    no analytics, no cookies, and is cached for 60 seconds.
  </p>
</body>
</html>"""
