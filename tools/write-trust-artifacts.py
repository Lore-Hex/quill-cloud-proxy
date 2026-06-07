#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any

CONTROL_PLANE_REPO = "https://github.com/Lore-Hex/quill-router"
ATTESTED_GATEWAY_REPO = "https://github.com/Lore-Hex/quill-cloud-proxy"
CLOUD_INFRA_REPO = "https://github.com/Lore-Hex/quill-cloud-infra"
QUILL_REPO = "https://github.com/Lore-Hex/quill"
PYTHON_SDK_REPO = "https://github.com/Lore-Hex/trusted-router-py"
JAVASCRIPT_SDK_REPO = "https://github.com/Lore-Hex/trusted-router-js"


def release_payload(commit: str, image_reference: str, image_digest: str) -> dict[str, Any]:
    return {
        "platform": "gcp-confidential-space",
        "source_repo": ATTESTED_GATEWAY_REPO,
        "source_repositories": {
            "control_plane": CONTROL_PLANE_REPO,
            "attested_gateway": ATTESTED_GATEWAY_REPO,
            "cloud_infra": CLOUD_INFRA_REPO,
            "quill": QUILL_REPO,
            "python_sdk": PYTHON_SDK_REPO,
            "javascript_sdk": JAVASCRIPT_SDK_REPO,
        },
        "commit": commit,
        "source_commit": commit,
        "image_reference": image_reference,
        "image_digest": image_digest,
        "attestation_issuer": "https://confidentialcomputing.googleapis.com",
        "attestation_audience": "quill-cloud",
        "api_base_url": "https://api.trustedrouter.com/v1",
        "tls": {
            "mode": "acme-inside-confidential-space",
            "hostname": "api.trustedrouter.com",
        },
        "data_policy": {
            "prompt_output_storage": False,
            "control_plane_prompt_access": False,
        },
        "released_by": "github-actions:deploy-enclave-gcp",
    }


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def trust_html(release: dict[str, Any]) -> str:
    release_json = html.escape(json.dumps(release, indent=2, sort_keys=True) + "\n")
    digest = html.escape(str(release["image_digest"]))
    image = html.escape(str(release["image_reference"]))
    source = html.escape(str(release["source_commit"]))
    api = html.escape(str(release["api_base_url"]))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>TrustedRouter Trust</title>
  <meta name="description" content="Verify that api.trustedrouter.com runs the published open-source attested workload.">
  <style>
    :root {{
      color-scheme: light;
      --ink:#172027; --muted:#5c6974; --line:#d8e1e8; --bg:#f6f8fa;
      --panel:#ffffff; --green:#11724c; --blue:#2355a6; --nav:#101820;
    }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; font-family:ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color:var(--ink); background:var(--bg); }}
    header {{ border-bottom:1px solid var(--line); background:#fff; position:sticky; top:0; z-index:3; }}
    nav {{ max-width:1120px; margin:0 auto; padding:14px 22px; display:flex; align-items:center; justify-content:space-between; gap:16px; }}
    a {{ color:var(--blue); text-decoration:none; }}
    .brand {{ font-weight:800; color:var(--ink); display:flex; align-items:center; gap:10px; }}
    .mark {{ width:30px; height:30px; border-radius:7px; background:linear-gradient(135deg,#2c6ecb,#19a06d); display:grid; place-items:center; font-size:13px; color:#fff; }}
    .links {{ display:flex; gap:14px; flex-wrap:wrap; font-size:14px; }}
    .wrap {{ max-width:1120px; margin:0 auto; padding:34px 22px 56px; display:grid; gap:18px; }}
    .hero {{ display:grid; grid-template-columns:minmax(0,1.15fr) minmax(300px,.85fr); gap:20px; align-items:start; }}
    h1 {{ font-size:42px; line-height:1.08; margin:0 0 12px; letter-spacing:0; }}
    h2 {{ font-size:17px; margin:0 0 12px; letter-spacing:0; }}
    p {{ color:var(--muted); line-height:1.55; margin:0 0 14px; }}
    code {{ background:#edf2f6; border:1px solid #d7e0e7; border-radius:6px; padding:2px 6px; font-size:.92em; overflow-wrap:anywhere; }}
    .panel {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:18px; min-width:0; }}
    .grid {{ display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:16px; }}
    .status {{ display:inline-flex; align-items:center; gap:8px; font-weight:700; color:var(--green); }}
    .dot {{ width:9px; height:9px; border-radius:50%; background:var(--green); }}
    .kv {{ display:grid; gap:12px; margin-top:8px; }}
    .label {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:0; margin-bottom:3px; }}
    .value {{ font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:13px; overflow-wrap:anywhere; }}
    .repo-list {{ display:grid; gap:12px; margin:0; }}
    .repo-list p {{ margin:3px 0 0; }}
    .checks {{ list-style:none; padding:0; margin:0; display:grid; gap:10px; }}
    .checks li {{ display:flex; gap:10px; color:#2d3742; line-height:1.4; }}
    .check {{ color:var(--green); font-weight:800; font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    pre {{ white-space:pre-wrap; overflow-wrap:anywhere; background:#101820; color:#eef6ff; border-radius:8px; padding:16px; margin:0; font-size:13px; line-height:1.45; }}
    .warn {{ border-color:#ead49b; background:#fff8e4; color:#5a3b00; }}
    .warn p {{ color:#5a3b00; }}
    @media (max-width:850px) {{
      .hero, .grid {{ grid-template-columns:1fr; }}
      nav {{ align-items:flex-start; flex-direction:column; }}
      h1 {{ font-size:31px; }}
    }}
  </style>
</head>
<body>
  <header>
    <nav>
      <a class="brand" href="https://trustedrouter.com"><span class="mark">TR</span><span>TrustedRouter</span></a>
      <div class="links"><a href="{CONTROL_PLANE_REPO}">Control repo</a><a href="{ATTESTED_GATEWAY_REPO}">Gateway repo</a><a href="{CLOUD_INFRA_REPO}">Infra repo</a><a href="{QUILL_REPO}">Quill repo</a><a href="/trust/gcp-release.json">gcp-release.json</a><a href="{api}">API</a><a href="https://trustedrouter.com">Console</a></div>
    </nav>
  </header>
  <main class="wrap">
    <section class="hero">
      <div class="panel">
        <p class="status"><span class="dot"></span>Trust boundary</p>
        <h1>Verify that the hosted API runs the published open-source workload.</h1>
        <p><code>api.trustedrouter.com</code> is the prompt path (<code>api.quillrouter.com</code> is a permanent alias to the same attested endpoint). Public TLS terminates inside the measured GCP Confidential Space workload. The TrustedRouter control plane does not serve production inference routes and does not receive prompt or output bodies.</p>
        <p>Clients can fetch live attestation, verify issuer/audience/digest, and compare the measured image digest with the release data published here.</p>
      </div>
      <aside class="panel">
        <h2>Current GCP Workload</h2>
        <div class="kv">
          <div><div class="label">Source commit</div><div class="value">{source}</div></div>
          <div><div class="label">Image</div><div class="value">{image}</div></div>
          <div><div class="label">Digest</div><div class="value">{digest}</div></div>
          <div><div class="label">Attested gateway repo</div><div class="value"><a href="{ATTESTED_GATEWAY_REPO}">Lore-Hex/quill-cloud-proxy</a></div></div>
          <div><div class="label">API base</div><div class="value">{api}</div></div>
        </div>
      </aside>
    </section>
    <section class="grid" aria-label="Verification checklist">
      <div class="panel">
        <h2>Client Verification</h2>
        <ul class="checks">
          <li><span class="check">OK</span><span>Fetch <code>https://api.trustedrouter.com/attestation</code> over normal public TLS.</span></li>
          <li><span class="check">OK</span><span>Verify the JWT issuer is <code>https://confidentialcomputing.googleapis.com</code>.</span></li>
          <li><span class="check">OK</span><span>Verify the audience is <code>quill-cloud</code>.</span></li>
          <li><span class="check">OK</span><span>Compare the attested image digest with this page.</span></li>
          <li><span class="check">OK</span><span>Check the TLS certificate fingerprint is bound into the attestation nonce.</span></li>
        </ul>
      </div>
      <div class="panel">
        <h2>Published Files</h2>
        <p><a href="/trust/image-digest-gcp.txt">image-digest-gcp.txt</a></p>
        <p><a href="/trust/image-reference-gcp.txt">image-reference-gcp.txt</a></p>
        <p><a href="/trust/gcp-release.json">gcp-release.json</a></p>
      </div>
      <div class="panel warn">
        <h2>DNS Requirement</h2>
        <p><code>api.trustedrouter.com</code> (and its <code>api.quillrouter.com</code> alias) must remain DNS-only or TCP-passthrough. TLS termination by a CDN would break the hosted-code trust claim because the prompt path certificate key must remain inside the measured workload.</p>
      </div>
    </section>
    <section class="grid">
      <div class="panel"><h2>No Prompt Logs</h2><p>Prompt/output storage is disabled. Generation content endpoint returns a compatible <code>content_not_stored</code> response.</p></div>
      <div class="panel">
        <h2>Hosted Open Source</h2>
        <div class="repo-list">
          <div><a href="{CONTROL_PLANE_REPO}">Lore-Hex/quill-router</a><p>Control plane, billing, keys, compatibility routes, dashboard, and trust page.</p></div>
          <div><a href="{ATTESTED_GATEWAY_REPO}">Lore-Hex/quill-cloud-proxy</a><p>Attested prompt gateway, release digest, and Confidential Space verification path.</p></div>
          <div><a href="{CLOUD_INFRA_REPO}">Lore-Hex/quill-cloud-infra</a><p>Cloud deployment scripts, measured workload bringup, and trust publication flow.</p></div>
          <div><a href="{QUILL_REPO}">Lore-Hex/quill</a><p>Open-source Quill client, device, bootstrap, and attestation-facing code.</p></div>
          <div><a href="{PYTHON_SDK_REPO}">Lore-Hex/trusted-router-py</a><p>Python SDK repository for attestation-aware client helpers.</p></div>
          <div><a href="{JAVASCRIPT_SDK_REPO}">Lore-Hex/trusted-router-js</a><p>JavaScript SDK repository for browser and Node integrations.</p></div>
        </div>
      </div>
      <div class="panel"><h2>Fail Closed</h2><p>If attestation, billing authorization, or the gateway contract is unavailable, the prompt path should fail rather than silently downgrade to a non-attested route.</p></div>
    </section>
    <section class="panel">
      <h2>Machine-readable release</h2>
      <pre>{release_json}</pre>
    </section>
  </main>
</body>
</html>"""


def write_artifacts(out_dir: Path, release: dict[str, Any]) -> None:
    release_json = json.dumps(release, indent=2, sort_keys=True) + "\n"
    digest = str(release["image_digest"]) + "\n"
    reference = str(release["image_reference"]) + "\n"
    write_text(out_dir / "gcp-release.json", release_json)
    write_text(out_dir / "image-digest-gcp.txt", digest)
    write_text(out_dir / "image-reference-gcp.txt", reference)
    write_text(out_dir / "trust" / "gcp-release.json", release_json)
    write_text(out_dir / "trust" / "image-digest-gcp.txt", digest)
    write_text(out_dir / "trust" / "image-reference-gcp.txt", reference)
    write_text(out_dir / "index.html", trust_html(release))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", default="trust-page")
    parser.add_argument("--commit", required=True)
    parser.add_argument("--image-reference", required=True)
    parser.add_argument("--image-digest", required=True)
    args = parser.parse_args()
    write_artifacts(
        Path(args.out_dir),
        release_payload(args.commit, args.image_reference, args.image_digest),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
