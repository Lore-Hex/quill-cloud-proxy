#!/usr/bin/env python3
# /// script
# dependencies = ["cryptography>=42"]
# requires-python = ">=3.11"
# ///
"""Seal the Azure bootstrap secret bundle for the confidential container group.

This is the PRODUCER for the envelope that
`enclave-go/internal/bootstrap/bootstrap_azure.go` opens with an SKR-released
key. The two files are one wire contract with two implementations, and the
contract is verified by a real round trip in
`enclave-go/internal/bootstrap/azure_envelope_roundtrip_test.go`: that test
runs THIS script and feeds its output to THAT decryptor. If either side moves
— OAEP digest, field names, base64 dialect, GCM tag placement — the test fails
before a deploy can.

WHAT THIS PRODUCES
------------------
One Key Vault secret whose value is:

    {"v":1,"alg":"RSA-OAEP-256+A256GCM",
     "enc_key":b64(RSA-OAEP-SHA256(content_key)),
     "nonce":b64(12 random bytes),
     "ciphertext":b64(AES-256-GCM(bundle_json))}

`bundle_json` is a flat JSON object of LOGICAL SECRET NAME -> VALUE. The names
are the values of the container group's QUILL_*_SECRET env vars: cloud-neutral
logical names shared by each cloud adapter, which lets the adapters share the
binding table in internal/bootstrap/secrets.go.

    { "trustedrouter-anthropic-api-key": "sk-ant-...",
      "quill-device-keys": "[{\\"key_hash\\":...}]",
      "tr-azure-acme-cache-key": "<base64 32-byte key>" }

WHY RSA-OAEP AT ALL, AND WHY ONLY THE PUBLIC HALF IS NEEDED HERE
----------------------------------------------------------------
Key Vault holds an exportable RSA-HSM key whose RELEASE policy requires an MAA
token asserting this container group's CCE policy hash. Only an attested
workload gets the PRIVATE half, so only an attested workload can open the
bundle. Sealing needs only the PUBLIC half, which Key Vault serves to anyone
with keys/get. That asymmetry is deliberate and is spelled out at length in
bootstrap_azure.go: this envelope gives CONFIDENTIALITY, not INTEGRITY. Anyone
with secrets/set on the vault can seal a bundle of their own to the same public
key and the enclave cannot tell it from yours. Administer "Key Vault Secrets
Officer" as the trusted role it is, and pin QUILL_AZURE_BUNDLE_VERSION in the
deploy so the CCE-measured env names one immutable version.

WHAT IT REFUSES TO DO
---------------------
It will not seal a bundle that would fail to boot. Given the container group's
env (--deploy-env), it computes exactly which bundle keys the enclave will ask
for and fails if any is missing or blank, because the enclave's own reaction to
a missing entry is os.Exit(1) after a full SNP report + MAA exchange + Key
Vault round trip — a slow, expensive, remote way to discover a typo.

USAGE
-----
Offline (no Azure at all; wraps to a PEM public key, writes a file):

    ./tools/azure-seal-bundle.py \\
        --deploy-env  aci-env.json \\
        --values      secrets.json \\
        --public-key-pem wrap.pub.pem \\
        --out         bundle.enc.json

Against the real vault (fetches the public half, uploads the sealed blob):

    ./tools/deploy-azure-aci.sh print-env > aci-env.json
    ./tools/azure-seal-bundle.py \\
        --deploy-env  aci-env.json \\
        --values      secrets.json \\
        --vault       trquillkv \\
        --key-name    tr-bootstrap-wrap \\
        --upload-secret tr-bootstrap-bundle

`--deploy-env` and `--values` each accept a path, `-` for stdin, or `env` /
`env:NAME` to read the process environment (see _load_json_source). The Azure
calls shell out to `az`, which the operator has already authenticated; this
script never handles an Azure credential itself.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

# ---------------------------------------------------------------------------
# The binding table — a MIRROR of secretBindings in
# enclave-go/internal/bootstrap/secrets.go.
#
# It is duplicated rather than derived because the two languages have no shared
# runtime, and it is kept honest by TestSealerBindingTableMatchesSecretBindings,
# which runs `--print-bindings` and compares entry for entry, IN ORDER, in both
# directions. Add a provider to secrets.go without adding it here (or vice
# versa) and that test fails — which is the whole reason the table is exported
# through a flag instead of living only in this file's head.
#
# Each entry is (env var names in priority order, label, counts as a provider).
# The label matches the Go one so a seal-time error and a boot-time error name
# the same thing.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Binding:
    envs: tuple[str, ...]
    label: str
    provider: bool


BINDINGS: tuple[Binding, ...] = (
    Binding(("QUILL_OPENROUTER_SECRET",), "openrouter key", True),
    Binding(("QUILL_ANTHROPIC_SECRET",), "anthropic key", True),
    Binding(("QUILL_OPENAI_SECRET",), "openai key", True),
    Binding(("QUILL_GEMINI_SECRET",), "gemini key", True),
    Binding(("QUILL_CEREBRAS_SECRET",), "cerebras key", True),
    Binding(("QUILL_DEEPSEEK_SECRET",), "deepseek key", True),
    Binding(("QUILL_MISTRAL_SECRET",), "mistral key", True),
    Binding(("QUILL_KIMI_SECRET",), "kimi key", True),
    Binding(("QUILL_ZAI_SECRET",), "zai key", True),
    Binding(("QUILL_TOGETHER_SECRET",), "together key", True),
    Binding(("QUILL_FIREWORKS_SECRET",), "fireworks key", True),
    Binding(("QUILL_COHERE_SECRET",), "cohere key", True),
    Binding(("QUILL_VOYAGE_SECRET",), "voyage key", True),
    Binding(("QUILL_GROK_SECRET",), "grok key", True),
    Binding(("QUILL_NOVITA_SECRET",), "novita key", True),
    Binding(("QUILL_PHALA_SECRET",), "phala key", True),
    Binding(("QUILL_SILICONFLOW_SECRET",), "siliconflow key", True),
    Binding(("QUILL_TINFOIL_SECRET",), "tinfoil key", True),
    Binding(("QUILL_VENICE_SECRET",), "venice key", True),
    Binding(("QUILL_PARASAIL_SECRET",), "parasail key", True),
    Binding(("QUILL_LIGHTNING_SECRET",), "lightning key", True),
    Binding(("QUILL_GMI_SECRET",), "gmi key", True),
    Binding(("QUILL_DEEPINFRA_SECRET",), "deepinfra key", True),
    Binding(("QUILL_FRIENDLI_SECRET",), "friendli key", True),
    Binding(("QUILL_BASETEN_SECRET",), "baseten key", True),
    Binding(("QUILL_THINKING_MACHINES_SECRET",), "thinking machines key", True),
    Binding(("QUILL_WAFER_SECRET",), "wafer key", True),
    Binding(("QUILL_CRUSOE_SECRET",), "crusoe key", True),
    Binding(("QUILL_MAKORA_SECRET",), "makora key", True),
    Binding(("QUILL_NEBIUS_SECRET",), "nebius key", True),
    Binding(("QUILL_MINIMAX_SECRET",), "minimax key", True),
    Binding(("QUILL_XIAOMI_SECRET",), "xiaomi key", True),
    # Kept in step with secrets.go by TestSealerBindingTableMatchesSecretBindings.
    Binding(("QUILL_ALIBABA_SECRET",), "alibaba key", True),
    Binding(("QUILL_ATLAS_CLOUD_SECRET",), "atlas cloud key", True),
    Binding(("QUILL_CHUTES_SECRET",), "chutes key", True),
    Binding(("QUILL_CLOUDFLARE_WORKERS_AI_SECRET",), "cloudflare workers ai key", True),
    Binding(("QUILL_DIGITALOCEAN_SECRET",), "digitalocean key", True),
    Binding(("QUILL_ENGY_SECRET",), "engy key", True),
    Binding(("QUILL_DATABRICKS_SECRET",), "databricks token", True),
    Binding(("QUILL_DATABRICKS_HOST_SECRET",), "databricks host", False),
    Binding(("QUILL_EXA_SECRET",), "exa key", True),
    Binding(("QUILL_INCEPTRON_SECRET",), "inceptron key", True),
    Binding(("QUILL_KLING_SECRET",), "kling key", True),
    Binding(("QUILL_LTX_SECRET",), "ltx key", True),
    Binding(("QUILL_MORPH_SECRET",), "morph key", True),
    Binding(("QUILL_NEUROMETRIC_SECRET",), "neurometric key", True),
    Binding(("QUILL_PEARL_SECRET",), "pearl key", True),
    Binding(("QUILL_OPENAI_VIDEO_SECRET",), "openai video key", True),
    Binding(("QUILL_RUNWAY_SECRET",), "runway key", True),
    Binding(("QUILL_STREAMLAKE_SECRET",), "streamlake key", True),
    Binding(("QUILL_TELNYX_SECRET",), "telnyx key", True),
    Binding(("QUILL_ZERO_G_SECRET",), "zero g key", True),
    Binding(("QUILL_SYNTH_PANEL_PROMPT_SECRET",), "synth panel prompt", False),
    Binding(("QUILL_SYNTH_SYNTHESIS_PROMPT_SECRET",), "synth synthesis prompt", False),
    Binding(("QUILL_SYNTH_CODE_PANEL_PROMPT_SECRET",), "synth-code panel prompt", False),
    Binding(("QUILL_SYNTH_CODE_SYNTHESIS_PROMPT_SECRET",), "synth-code synthesis prompt", False),
    Binding(
        ("QUILL_ADVISOR_WORKER_PROMPT_SECRET", "QUILL_SOCRATES_WORKER_PROMPT_SECRET"),
        "advisor worker prompt",
        False,
    ),
    Binding(
        ("QUILL_ADVISOR_PROMPT_SECRET", "QUILL_SOCRATES_ADVISOR_PROMPT_SECRET"),
        "advisor prompt",
        False,
    ),
    Binding(("QUILL_TRUSTEDROUTER_INTERNAL_SECRET",), "trustedrouter internal token", False),
    Binding(("QUILL_ACME_FALLBACK_EAB_SECRET",), "acme fallback eab", False),
)

# Envelope constants. These MUST equal envelopeAlg / envelopeVersion /
# envelopeContentKeyBytes in bootstrap_azure.go; the round-trip test is what
# proves they do.
ENVELOPE_VERSION = 1
ENVELOPE_ALG = "RSA-OAEP-256+A256GCM"
CONTENT_KEY_BYTES = 32
GCM_NONCE_BYTES = 12

# Env vars bootstrap_azure.go / secrets.go read that are not part of the
# binding table but still name a BUNDLE ENTRY.
DEVICE_KEYS_ENV = "QUILL_DEVICE_KEYS_SECRET"
AZURE_CACHE_KEY_ENV = "QUILL_AZURE_ACME_CACHE_KEY_SECRET"

# Env vars that must be present for the enclave to boot at all. Checked here so
# a broken deploy fails at the operator's desk instead of after an SNP report,
# an MAA exchange and a Key Vault round trip inside a confidential container.
REQUIRED_ENV = (
    "QUILL_GCP_PROJECT_ID",
    DEVICE_KEYS_ENV,
    "QUILL_AZURE_MAA_ENDPOINT",
    "QUILL_AZURE_AKV_ENDPOINT",
    "QUILL_AZURE_SKR_KEY_ID",
    "QUILL_AZURE_BUNDLE_SECRET",
    AZURE_CACHE_KEY_ENV,
)


def fail(message: str) -> NoReturn:
    print(f"[FAIL] {message}", file=sys.stderr)
    raise SystemExit(1)


# ---------------------------------------------------------------------------
# inputs
# ---------------------------------------------------------------------------


def _load_json_source(spec: str, what: str) -> dict[str, str]:
    """Read a JSON object of string -> string from a path, stdin, or the env.

    Three forms, because the two callers want different ones and neither should
    have to shuttle secrets through a temp file it then has to remember to
    delete:

        PATH        read that file
        -           read stdin
        env         use this process's own environment (deploy env only)
        env:NAME    parse the JSON held in environment variable NAME
    """
    if spec == "env":
        return {k: v for k, v in os.environ.items()}
    if spec.startswith("env:"):
        name = spec[len("env:") :]
        raw = os.environ.get(name)
        if raw is None:
            fail(f"{what}: environment variable {name} is not set")
        text = raw
    elif spec == "-":
        text = sys.stdin.read()
    else:
        path = Path(spec)
        if not path.is_file():
            fail(f"{what}: {spec} is not a file")
        text = path.read_text(encoding="utf-8")

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        # Never echo the text: for --values it is every secret this system has.
        fail(f"{what}: not valid JSON ({len(text)} chars; content withheld): {exc}")
    if not isinstance(parsed, dict):
        fail(f"{what}: JSON is a {type(parsed).__name__}, want an object of name -> value")
    out: dict[str, str] = {}
    for key, value in parsed.items():
        if not isinstance(value, str):
            # A JSON object/array/number here is almost always a nested secret
            # that someone meant to pass as text. Say so precisely — the enclave
            # would report it as a missing entry, which sends the operator to
            # the wrong file.
            fail(
                f"{what}: entry {key!r} is a {type(value).__name__}, not a string. "
                "Bundle values are opaque strings; JSON-valued secrets (device keys, "
                "structured secrets) must be passed as their serialised text, "
                "e.g. --value-file NAME=path.json"
            )
        out[key] = value
    return out


def _first_set_env(env: dict[str, str], names: tuple[str, ...], label: str) -> str:
    """Mirror of firstSetEnv() in secrets.go: first non-empty value wins.

    The whitespace-only case is an ERROR rather than a skip, exactly as in Go.
    Diverging here would be worse than useless: this tool would happily seal a
    bundle for a deploy the enclave then refuses to boot.
    """
    for name in names:
        value = env.get(name, "")
        if value == "":
            continue
        if value.strip() == "":
            fail(
                f"{label}: {name} is set to whitespace only ({len(value)} chars); "
                "it must name a secret or be unset"
            )
        return value
    return ""


@dataclass(frozen=True)
class RequiredEntry:
    """One bundle key the deployed enclave will ask for, and why.

    `optional` distinguishes "the enclave KNOWS this key and uses it when
    present" from "the enclave DEMANDS it". Both must be known, or the
    unused-values check rejects a value the enclave would happily consume; only
    the demanded ones may block a seal.
    """

    name: str
    label: str
    optional: bool = False


def required_entries(env: dict[str, str]) -> list[RequiredEntry]:
    """Compute exactly which bundle keys this container-group env will demand.

    This is the seal-time twin of resolveSecretConfig + assembleBootstrapData +
    the SA-key require() call in bootstrap_azure.go. It is the reason this tool
    takes the deploy env at all: the bundle's required contents are a FUNCTION
    of the env the CCE policy measures, so they cannot be guessed from a list of
    values.
    """
    for name in REQUIRED_ENV:
        value = env.get(name, "")
        if value == "":
            fail(f"deploy env: {name} is not set (the enclave refuses to boot without it)")
        if value.strip() == "":
            fail(f"deploy env: {name} is set to whitespace only ({len(value)} chars)")

    # The device-key blob is genuinely required: without it the enclave has no
    # identity to serve and dies on first use.
    entries = [
        RequiredEntry(env[DEVICE_KEYS_ENV], "device keys"),
        RequiredEntry(env[AZURE_CACHE_KEY_ENV], "azure acme cache key"),
    ]
    any_provider = False
    for binding in BINDINGS:
        name = _first_set_env(env, binding.envs, binding.label)
        if name == "":
            continue
        if binding.provider:
            any_provider = True
        entries.append(RequiredEntry(name, binding.label))
    if not any_provider:
        fail(
            "deploy env: at least one provider secret env must be set "
            "(a gateway with no LLM backend 500s every request)"
        )

    # A single bundle key named by two different env vars is legal (and
    # harmless), but a name collision between, say, the device-keys secret and a
    # provider secret means one silently overwrites the other's meaning. Report
    # it rather than sealing something ambiguous.
    seen: dict[str, str] = {}
    for entry in entries:
        if entry.name in seen and seen[entry.name] != entry.label:
            fail(
                f"deploy env: bundle key {entry.name!r} is named by two different entries "
                f"({seen[entry.name]!r} and {entry.label!r}); one value cannot serve both"
            )
        seen[entry.name] = entry.label
    return entries


def build_bundle(
    entries: list[RequiredEntry], values: dict[str, str], *, allow_extra: bool
) -> dict[str, str]:
    """Assemble the plaintext bundle, refusing anything that cannot boot.

    The emptiness rule is copied from assembleBootstrapData: a present-but-blank
    secret is a broken deploy, not a disabled provider, because it boots a
    gateway that 401s every request using that key hours after the deploy that
    caused it.
    """
    # Only NON-optional entries can block a seal. Optional ones are still in
    # `entries`, so they count as known and a supplied value is not rejected as
    # unused - the distinction the `optional` flag exists to make.
    missing = [
        entry for entry in entries
        if entry.name not in values and not entry.optional
    ]
    if missing:
        fail(
            "the deploy env names bundle entries that --values does not provide:\n"
            + "\n".join(f"  {entry.name}  ({entry.label})" for entry in missing)
            + "\n  A bundle missing any of these boots an enclave that dies with "
            '"no entry ... in the bundle" AFTER a full attestation round trip.'
        )
    # Only entries actually SUPPLIED can be blank. An optional entry that was
    # never provided is absent, not empty, and the missing-check above has
    # already decided absence is fine for it - indexing every entry here
    # KeyErrors on exactly the optional-and-omitted case that is supported.
    blank = [
        entry for entry in entries
        if entry.name in values and values[entry.name].strip() == ""
    ]
    if blank:
        fail(
            "these bundle entries have empty or whitespace-only values:\n"
            + "\n".join(f"  {entry.name}  ({entry.label})" for entry in blank)
            + "\n  The enclave rejects a present-but-empty secret at boot for the same reason."
        )

    # An optional entry that was never supplied is simply not in the bundle.
    # The enclave treats its absence as a degraded-but-valid posture; putting an
    # empty string there instead would make it "present" and fail at first use.
    bundle = {
        entry.name: values[entry.name]
        for entry in entries
        if entry.name in values
    }

    extra = sorted(set(values) - set(bundle))
    if extra:
        # Default: refuse. A value in the file that no env names is either a
        # secret the deploy forgot to wire (the interesting case) or dead
        # weight the bundle should not carry into the enclave.
        if not allow_extra:
            fail(
                "--values carries entries the deploy env never names:\n"
                + "\n".join(f"  {name}" for name in extra)
                + "\n  Either wire the matching QUILL_*_SECRET into the container group's env, "
                "drop the entry, or pass --allow-unused-values to seal without it."
            )
        print(f"[warn] {len(extra)} unused value(s) omitted from the bundle: {', '.join(extra)}", file=sys.stderr)
    return bundle


def sanity_check_structured_entries(env: dict[str, str], bundle: dict[str, str]) -> None:
    """Validate structured/key entries before a broken bundle reaches Azure.

    A device blob that lost its closing bracket or a malformed cache key is
    invisible in a bundle of opaque strings, and its symptom is an enclave that
    attests correctly and then exits — the single most expensive place to find
    a copy-paste error.
    """
    devices_key = env[DEVICE_KEYS_ENV]
    try:
        devices = json.loads(bundle[devices_key])
    except json.JSONDecodeError as exc:
        fail(f"device keys entry {devices_key!r} is not valid JSON: {exc}")
    if not isinstance(devices, list):
        fail(
            f"device keys entry {devices_key!r} is a {type(devices).__name__}; "
            "the enclave unmarshals it into []DeviceConfig, so it must be a JSON array"
        )

    cache_key_name = env.get(AZURE_CACHE_KEY_ENV, "")
    if cache_key_name:
        try:
            cache_key = base64.b64decode(bundle[cache_key_name], validate=True)
        except (KeyError, ValueError) as exc:
            fail(f"azure acme cache key {cache_key_name!r} is not valid base64: {exc}")
        if len(cache_key) != 32:
            fail(
                f"azure acme cache key {cache_key_name!r} is {len(cache_key)} bytes; "
                "AES-256-GCM requires exactly 32"
            )


# ---------------------------------------------------------------------------
# the envelope
# ---------------------------------------------------------------------------


def seal(public_key: Any, payload: bytes) -> dict[str, Any]:
    """Produce the envelope bootstrap_azure.go's decryptEnvelope() opens.

    Every choice here is pinned by the Go side and by the round-trip test:

      * RSA-OAEP with SHA-256 as BOTH the digest and MGF1, no label. Go calls
        rsa.DecryptOAEP(sha256.New(), ..., nil). Key Vault calls this
        RSA-OAEP-256.
      * A 32-byte content key. Go checks the unwrapped length explicitly
        because aes.NewCipher would otherwise accept 16 or 24 and make the
        "A256" in the alg string decorative.
      * A 12-byte nonce, the GCM default Go's cipher.NewGCM expects.
      * AES-GCM output is ciphertext||tag, which is what Go's gcm.Open wants;
        both libraries use that layout, so nothing splits the tag out.
      * Standard base64 WITH padding. Go tolerates four dialects on read, so
        this specific choice is not load-bearing for interop — but the
        round-trip test asserts it anyway, so a change to the encoder here is a
        deliberate, visible act rather than a silent one.
    """
    from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import padding  # noqa: PLC0415
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415

    content_key = os.urandom(CONTENT_KEY_BYTES)
    nonce = os.urandom(GCM_NONCE_BYTES)
    ciphertext = AESGCM(content_key).encrypt(nonce, payload, None)
    enc_key = public_key.encrypt(
        content_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    b64 = lambda raw: base64.b64encode(raw).decode("ascii")  # noqa: E731
    return {
        "v": ENVELOPE_VERSION,
        "alg": ENVELOPE_ALG,
        "enc_key": b64(enc_key),
        "nonce": b64(nonce),
        "ciphertext": b64(ciphertext),
    }


# ---------------------------------------------------------------------------
# the public half of the wrapping key
# ---------------------------------------------------------------------------


def _az(args: list[str], *, what: str) -> Any:
    """Run `az ... -o json` and parse it.

    Shelling out to the operator's already-authenticated az CLI, rather than
    importing an Azure SDK, keeps this tool's dependency surface at
    `cryptography` and keeps every Azure credential outside this process.
    """
    try:
        completed = subprocess.run(
            ["az", *args, "-o", "json"],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        fail(f"{what}: the `az` CLI is not on PATH (needed for --vault; use --public-key-pem to work offline)")
    if completed.returncode != 0:
        fail(f"{what}: az exited {completed.returncode}: {completed.stderr.strip()}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        fail(f"{what}: az output is not JSON: {exc}")


def public_key_from_pem(path: Path) -> Any:
    from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: PLC0415
    from cryptography.hazmat.primitives.serialization import load_pem_public_key  # noqa: PLC0415

    try:
        key = load_pem_public_key(path.read_bytes())
    except Exception as exc:  # noqa: BLE001 - any parse failure is the same verdict
        fail(f"--public-key-pem {path}: not a PEM public key: {exc}")
    if not isinstance(key, rsa.RSAPublicKey):
        fail(f"--public-key-pem {path}: is a {type(key).__name__}, want an RSA public key")
    return key


def public_key_from_vault(vault: str, key_name: str, key_version: str | None) -> Any:
    """Fetch the PUBLIC half of the SKR key. No release policy is involved.

    Key Vault serves public key material to any principal with keys/get; the
    release policy governs the PRIVATE half. So this call works with ordinary
    operator credentials and is not, and must not be mistaken for, an
    attestation step.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: PLC0415

    args = ["keyvault", "key", "show", "--vault-name", vault, "--name", key_name]
    if key_version:
        args += ["--version", key_version]
    document = _az(args, what=f"fetch public key {key_name} from {vault}")
    jwk = document.get("key") if isinstance(document, dict) else None
    if not isinstance(jwk, dict):
        fail(f"key {key_name} in {vault}: response has no `key` object")
    kty = jwk.get("kty")
    if kty not in ("RSA", "RSA-HSM"):
        fail(f"key {key_name} in {vault}: kty={kty!r}, want RSA or RSA-HSM")
    try:
        modulus = int.from_bytes(_b64url(jwk["n"]), "big")
        exponent = int.from_bytes(_b64url(jwk["e"]), "big")
    except (KeyError, ValueError) as exc:
        fail(f"key {key_name} in {vault}: JWK is missing or malformed n/e: {exc}")
    print(
        f"[ok] wrapping to {kty} key {key_name} ({modulus.bit_length()} bits) "
        f"version {document.get('key', {}).get('kid', '?').rsplit('/', 1)[-1]}",
        file=sys.stderr,
    )
    return rsa.RSAPublicNumbers(exponent, modulus).public_key()


def _b64url(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded)


def upload_secret(vault: str, secret_name: str, envelope_text: str) -> None:
    """Store the sealed blob as a Key Vault secret and print the new version.

    The value goes through a 0600 temp file rather than argv: it is only
    ciphertext, but a 40 KB blob in the process table is a bad habit to build,
    and `az keyvault secret set --file` is the supported path for one.
    """
    with tempfile.TemporaryDirectory() as workdir:
        blob = Path(workdir) / "bundle.enc.json"
        blob.write_text(envelope_text, encoding="utf-8")
        blob.chmod(0o600)
        document = _az(
            [
                "keyvault",
                "secret",
                "set",
                "--vault-name",
                vault,
                "--name",
                secret_name,
                "--file",
                str(blob),
                "--encoding",
                "utf-8",
                "--content-type",
                "application/json",
            ],
            what=f"upload {secret_name} to {vault}",
        )
    identifier = document.get("id", "") if isinstance(document, dict) else ""
    version = identifier.rsplit("/", 1)[-1] if identifier else "?"
    print(f"[ok] uploaded {secret_name} to {vault}, version {version}")
    print(
        "\nPin it in the deploy so the CCE policy measures ONE immutable bundle:\n"
        f"  QUILL_AZURE_BUNDLE_VERSION={version}\n"
        "Changing it changes the container group's env, which changes the CCE policy hash,\n"
        "which changes hostdata — so the SKR key must be re-bound (tools/deploy-azure-aci.sh bind).",
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--print-bindings",
        action="store_true",
        help="dump the binding table as JSON and exit (consumed by the Go drift test)",
    )
    parser.add_argument(
        "--deploy-env",
        help="JSON object of the container group's env: path, '-' for stdin, "
        "'env' for this process's environment, or 'env:NAME'. "
        "`tools/deploy-azure-aci.sh print-env` emits exactly this.",
    )
    parser.add_argument(
        "--values",
        help="JSON object of secret name -> value: path, '-', 'env', or 'env:NAME'.",
    )
    parser.add_argument(
        "--value-file",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="read one entry's value from a file (repeatable). Wins over --values. "
        "Use for the device blob and multiline prompts.",
    )
    parser.add_argument(
        "--allow-unused-values",
        action="store_true",
        help="seal even though --values holds entries the deploy env never names.",
    )
    parser.add_argument("--public-key-pem", help="wrap to this RSA public key PEM (offline; no Azure).")
    parser.add_argument("--vault", help="Key Vault name holding the SKR key (and the bundle secret).")
    parser.add_argument("--key-name", help="SKR key name, e.g. tr-bootstrap-wrap.")
    parser.add_argument("--key-version", help="pin one key version (default: current).")
    parser.add_argument("--out", help="write the envelope JSON here ('-' for stdout).")
    parser.add_argument("--upload-secret", help="Key Vault secret name to store the envelope in.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.print_bindings:
        json.dump(
            [
                {"envs": list(binding.envs), "label": binding.label, "provider": binding.provider}
                for binding in BINDINGS
            ],
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
        return 0

    if not args.deploy_env:
        fail("--deploy-env is required (the bundle's contents are a function of the container group's env)")
    if not args.values and not args.value_file:
        fail("--values or --value-file is required")
    if bool(args.public_key_pem) == bool(args.vault):
        fail("give exactly one of --public-key-pem (offline) or --vault (fetch the public half from Key Vault)")
    if args.vault and not args.key_name:
        fail("--vault requires --key-name")
    if args.upload_secret and not args.vault:
        fail("--upload-secret requires --vault (that is where the secret is written)")
    if not args.out and not args.upload_secret:
        fail("nothing to do: pass --out to write the envelope, --upload-secret to store it, or both")

    env = _load_json_source(args.deploy_env, "--deploy-env")
    values = _load_json_source(args.values, "--values") if args.values else {}
    for spec in args.value_file:
        name, sep, path = spec.partition("=")
        if not sep or not name or not path:
            fail(f"--value-file must be NAME=PATH (got {spec!r})")
        source = Path(path)
        if not source.is_file():
            fail(f"--value-file {name}: {path} is not a file")
        values[name] = source.read_text(encoding="utf-8")

    entries = required_entries(env)
    bundle = build_bundle(entries, values, allow_extra=args.allow_unused_values)
    sanity_check_structured_entries(env, bundle)

    # sort_keys so the same inputs produce the same plaintext bytes; the
    # ciphertext still differs every run (fresh content key + nonce), which is
    # correct — a deterministic ciphertext under a fixed key would leak
    # "nothing changed" to anyone watching the vault.
    payload = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")

    if args.public_key_pem:
        public_key = public_key_from_pem(Path(args.public_key_pem))
    else:
        public_key = public_key_from_vault(args.vault, args.key_name, args.key_version)

    envelope_text = json.dumps(seal(public_key, payload), separators=(",", ":"))

    print(
        f"[ok] sealed {len(bundle)} entries ({len(payload)} plaintext bytes, "
        f"{len(envelope_text)} envelope bytes) as {ENVELOPE_ALG}",
        file=sys.stderr,
    )
    for entry in sorted(entries, key=lambda item: item.name):
        print(f"       {entry.name}  ({entry.label})", file=sys.stderr)

    if args.out:
        if args.out == "-":
            sys.stdout.write(envelope_text + "\n")
        else:
            destination = Path(args.out)
            destination.write_text(envelope_text, encoding="utf-8")
            destination.chmod(0o600)
            print(f"[ok] wrote {destination}", file=sys.stderr)
    if args.upload_secret:
        upload_secret(args.vault, args.upload_secret, envelope_text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
