//go:build cloud_azure

// Package bootstrap: Azure confidential-container variant.
//
// See bootstrap_aws.go for the per-cloud-file layout pattern this package
// follows. Each cloud has its own bootstrap_<cloud>.go with a matching
// `//go:build` tag and a single exported Fetch(ctx).
//
// Shape: this is the GCP shape, not the AWS shape
// ===============================================
// A Nitro enclave has no network, so its parent fetches every secret and ships
// plaintext over vsock. An Azure confidential container has ordinary
// networking, so — like Confidential Space — it fetches its own secrets and no
// unattested process ever holds them.
//
// Azure reads AZURE Key Vault. It does not call Google.
// =====================================================
// This adapter used to SKR-release a wrapping key, unwrap a GCP service-account
// key with it, mint a Google OAuth token, and then pull ~39 secrets from Google
// Secret Manager. That made an Azure boot depend on Google being reachable,
// which voids the independence that is the entire reason a second cloud exists:
// a Google outage would take down the cloud whose job is to survive one.
//
// Azure now keeps its OWN copies. Key rotation is infrequent, so a second copy
// is an accepted cost — the same trade already made on AWS, where the provider
// secrets were replicated into eu-west-3 Secrets Manager rather than having the
// AWS enclave call Google.
//
// Where the trust actually comes from
// ===================================
// Secrets must be reachable ONLY by attested code running the expected
// workload. On Nitro that is KMS RecipientAttestation; on Confidential Space it
// is workload identity federation. On Azure it is Secure Key Release (SKR):
//
//	Key Vault Premium holds an exportable RSA-HSM key whose *release policy*
//	requires an MAA token asserting
//	    x-ms-attestation-type       = sevsnpvm
//	    x-ms-compliance-status      = azure-compliant-uvm
//	    x-ms-sevsnpvm-is-debuggable = false
//	    x-ms-sevsnpvm-hostdata      = the CCE policy hash of THIS container group
//	from the one MAA authority named in the policy. The skr sidecar produces
//	that token from the hardware SNP report and exchanges it at the vault; the
//	vault hands back the private key only if every claim matches.
//
// MEASURED, not assumed (2026-08-03, real SEV-SNP container group, UAE North):
// with the same workload, identity, vault and run, a key bound to THIS
// measurement was RELEASED and a key bound to a DIFFERENT workload's
// measurement was REFUSED with 403. The gate is real hardware, not policy
// paperwork.
//
// Why the bundle is encrypted rather than just ACL'd to the identity
// ==================================================================
// The container group's managed identity can read the bundle secret from Key
// Vault. That alone is a WEAKER gate than the one above: an identity is
// attached to a container group, not to a measurement, so anything able to
// present that identity — an operator with the right RBAC role, a future
// container in the same group, a compromised deploy pipeline — could read the
// plaintext, and the SEV-SNP measurement would stop mattering.
//
// So the vault secret holds CIPHERTEXT: a hybrid envelope that only the
// SKR-released key opens. The managed identity is reduced to a transport
// credential for an inert blob. Both properties then hold at once — the enclave
// makes no Google call, AND the secrets are readable only by a workload whose
// measurement satisfies the release policy.
//
// Boot sequence
// =============
//  1. validate env (no I/O — a misconfigured deploy must fail before it can
//     blame the network)
//  2. POST the skr sidecar         -> RSA private key as JWK   [attested]
//  3. GET  IMDS                    -> managed-identity token for Key Vault
//  4. GET  {vault}/secrets/{name}  -> the encrypted bundle (inert)
//  5. RSA-OAEP+AES-GCM open        -> bundle JSON: secret name -> value
//  6. shared name->field mapping   -> BootstrapData
//
// Required env:
//
//	QUILL_AZURE_MAA_ENDPOINT   e.g. "trquilluaen.uaen.attest.azure.net"
//	QUILL_AZURE_AKV_ENDPOINT   e.g. "trquillkv.vault.azure.net" — the vault
//	                           holding BOTH the SKR key and the bundle secret
//	QUILL_AZURE_SKR_KEY_ID     e.g. "tr-bootstrap-wrap"
//	QUILL_AZURE_BUNDLE_SECRET  e.g. "tr-bootstrap-bundle" — the Key Vault
//	                           secret whose value is the encrypted bundle
//	QUILL_AZURE_SA_KEY_ENTRY   the bundle entry holding the GCP service-account
//	                           key JSON (see "Runtime Google dependency" below)
//	plus everything resolveSecretConfig() requires (QUILL_GCP_PROJECT_ID,
//	QUILL_DEVICE_KEYS_SECRET, >=1 provider secret).
//
// Optional env:
//
//	QUILL_AZURE_SKR_URL        default "http://localhost:8080/key/release";
//	                           must be loopback (see validateSKRURL)
//	QUILL_AZURE_BUNDLE_VERSION pins one immutable Key Vault secret version instead
//	                           of following "current". Unset = current, which is
//	                           what makes silent substitution and silent rollback
//	                           possible; see "What the deploy channel still
//	                           decides" above
//	QUILL_AZURE_MI_CLIENT_ID   user-assigned managed identity client id; required
//	                           by IMDS only when the container group has more
//	                           than one identity attached
//	QUILL_AZURE_REGION         overrides QUILL_GCP_REGION for BootstrapData.Region
//
// None of MAA / AKV / key id / bundle secret has a default, and that is
// deliberate. Defaulting the MAA instance would attest against an authority
// nobody chose — the exact forgery hole the verifier work closed. A missing one
// is a hard error.
//
// Runtime Google dependency — NOT closed by this change
// =====================================================
// BOOT makes no Google call. RUNTIME still does: internal/enclavetls/gcscache.go
// and internal/byokcache/kms_gcp.go both authenticate via
// GOOGLE_APPLICATION_CREDENTIALS (the shared ACME cert cache in GCS, and the
// BYOK KMS unwrapper), and cmd/enclave/main.go writes
// BootstrapData.GCPServiceAccountKeyJSON to tmpfs to populate it. Neither file
// is build-tagged, so both are compiled into the Azure image.
//
// The service-account key therefore rides INSIDE the bundle, as one more entry:
// boot stays Google-free, and the key arrives under the same attestation gate as
// everything else. That is as far as this change can go. FULL independence from
// Google additionally requires an Azure-native control plane — the credit ledger
// (Spanner), the generations store (Bigtable) and the shared ACME cache (GCS)
// would all need Azure homes — which is out of scope here.
//
// What the deploy channel still decides
// =====================================
// SKR gates the key that opens the bundle. WHICH bundle gets opened is decided
// by QUILL_AZURE_BUNDLE_SECRET, and pointing that at a different vault secret is
// deploy configuration on every cloud (GCP picks its identity by attaching a
// service account to the Confidential Space VM). What keeps that honest on Azure
// is that the container group's env-var rules are part of the CCE policy, so
// changing them changes the policy hash, changes x-ms-sevsnpvm-hostdata, and
// fails the workload pin that verify makes mandatory.
//
// What SKR does NOT give you is bundle INTEGRITY. Be precise about this, because
// the obvious reading is wrong and someone will rely on it: sealing a bundle
// needs only the vault key's PUBLIC half, which Key Vault serves to any principal
// with keys/get and which the bundle-producing pipeline holds by construction. A
// release policy governs release of the PRIVATE half; it does not restrict who
// may encrypt TO the public one. The envelope carries no authenticity binding
// either — OAEP uses no label and gcm.Open is called with nil AAD — so a
// principal holding secrets/set on the bundle can seal values of their own to the
// same key and this code cannot tell them from the operator's.
//
// So: CONFIDENTIALITY is enforced by the measurement (only an attested workload
// can open a bundle). INTEGRITY is not — "Key Vault Secrets Officer on this
// vault" is a trusted role, and must be administered as one. Setting
// QUILL_AZURE_BUNDLE_VERSION pins one immutable secret version and closes the
// silent-substitution and silent-rollback window, because the pin lives in the
// CCE-measured env-var set: changing it changes hostdata and the release fails.
// Device keys are separately covered — main.go hashes boot.Devices into the
// attestation document, so a client pinning UserData sees substituted bearer
// tokens. Nothing covers the provider keys, the TR token, or the SA key.
//
// Dependency surface: stdlib only. Linking a heavy dependency chain into this
// binary corrupted the main request loop in a previous rollout (deploy
// 25592563258, see maybeStartAttestSidecar()), which is why the Key Vault and
// IMDS calls below are hand-rolled instead of pulling in the Azure SDK.
package bootstrap

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const (
	// defaultSKRURL — port 8080, MEASURED against skr sidecar 2.7 in UAE
	// North, whose log reads "Listening and serving HTTP on localhost:8080".
	// Some Azure samples say 8284; against this sidecar every request to 8284
	// is refused. attestation_azure.go pins the same port for the same reason.
	defaultSKRURL = "http://localhost:8080/key/release"

	// imdsHost is the Azure Instance Metadata Service. Link-local, so plain
	// HTTP by design: there is no name to put in a certificate and the address
	// is not routable off the host. It is a const so the value cannot be edited
	// away; the var below exists only to be redirected by tests.
	imdsHost = "http://169.254.169.254"

	// imdsAPIVersion is the token endpoint's contract version. 2018-02-01 is
	// the version ACI supports.
	imdsAPIVersion = "2018-02-01"

	// keyVaultResource is the AAD resource (audience) a Key Vault data-plane
	// token must be issued for. A token for any other audience is rejected by
	// the vault with 401, so getting this wrong is loud rather than silent.
	keyVaultResource = "https://vault.azure.net"

	// keyVaultAPIVersion for GET /secrets/{name}.
	keyVaultAPIVersion = "7.4"

	// envelopeAlg / envelopeVersion identify the hybrid wrapping format. See
	// secretEnvelope for why a hybrid format is not optional.
	envelopeAlg     = "RSA-OAEP-256+A256GCM"
	envelopeVersion = 1

	// envelopeContentKeyBytes is what "A256GCM" in envelopeAlg means. It is
	// checked explicitly because aes.NewCipher happily accepts 16 and 24 too,
	// which would let an envelope labelled A256GCM open under AES-128 and make
	// the label decorative.
	envelopeContentKeyBytes = 32

	// maxSKRResponseBytes bounds the released-key read. An RSA-4096 private JWK
	// is ~2.5 KB.
	maxSKRResponseBytes = 64 << 10

	// maxKeyVaultResponseBytes bounds the bundle read. Key Vault caps a secret
	// value at 25 KB; the JSON wrapper and base64 expansion push the worst case
	// to ~40 KB. 1 MiB is generous and still bounded — an unbounded ReadAll on
	// the boot path is an unbounded allocation.
	maxKeyVaultResponseBytes = 1 << 20

	azureTag = "bootstrap/azure"
)

// imdsBaseURL and keyVaultBaseURLOverride are the two test seams in this file,
// following the convention secrets_google.go uses for secretManagerBaseURL:
// unexported, reachable from no env var, flag or request path, and pinned to
// their production values by TestAzureEndpointSeamsDefaultToProduction.
//
// keyVaultBaseURLOverride is empty in production, where the base is derived from
// QUILL_AZURE_AKV_ENDPOINT over https. It exists because httptest serves plain
// HTTP, and the alternative — letting the endpoint env var carry its own scheme
// — would let a deploy send a Key Vault bearer token over cleartext.
var (
	imdsBaseURL             = imdsHost
	keyVaultBaseURLOverride string
)

// Fetch releases the wrapping key under attestation, reads the encrypted
// secret bundle from Key Vault with the container group's managed identity,
// opens the bundle with the released key, and assembles BootstrapData.
//
// Every error below names the step that failed. That is not politeness: the
// worst bug this system has had was a bootstrap that failed silently and left
// the enclave hung with nothing to go on.
func Fetch(ctx context.Context) (*types.BootstrapData, error) {
	// Step 0 — environment, before any I/O.
	cfg, err := resolveSecretConfig(azureTag)
	if err != nil {
		return nil, err
	}
	if region := strings.TrimSpace(os.Getenv("QUILL_AZURE_REGION")); region != "" {
		cfg.region = region
	}
	az, err := resolveAzureConfig()
	if err != nil {
		return nil, err
	}

	// Step 1 — attestation-gated key release. This is the gate: everything
	// below is inert without the key it returns.
	wrappingKey, err := releaseWrappingKey(ctx, newSKRHTTPClient(), az)
	if err != nil {
		return nil, err
	}

	// Step 2 — managed-identity token, then the encrypted bundle. Neither call
	// leaves Azure. Two clients, not one: the legs retry different statuses.
	vaultToken, err := fetchIMDSToken(ctx, newIMDSHTTPClient(), az)
	if err != nil {
		return nil, err
	}
	ciphertext, err := fetchKeyVaultSecret(ctx, newKeyVaultHTTPClient(), az, vaultToken)
	if err != nil {
		return nil, err
	}

	// Step 3 — open the bundle. Only the SKR-released key can do this, which is
	// what keeps the managed identity from being sufficient on its own.
	bundleJSON, err := decryptEnvelope(wrappingKey, ciphertext)
	if err != nil {
		return nil, err
	}
	bundle, err := parseBundle(bundleJSON)
	if err != nil {
		return nil, err
	}

	// Step 4 — the shared name -> BootstrapData mapping, identical to GCP's.
	data, err := assembleBootstrapData(ctx, cfg, azureTag, bundle.resolve)
	if err != nil {
		return nil, err
	}

	// Step 5 — the GCP service-account key, which rides in the bundle like any
	// other secret. main.go writes it to tmpfs and points
	// GOOGLE_APPLICATION_CREDENTIALS at it, because gcscache (shared ACME cache
	// in GCS) and byokcache (KMS unwrapper) still authenticate to Google at
	// RUNTIME. Carrying it in the bundle keeps BOOT free of Google calls; see
	// the "Runtime Google dependency" note in the package comment for what full
	// independence would additionally require.
	saKey, err := bundle.require(az.saKeyEntry, "gcp service-account key")
	if err != nil {
		return nil, err
	}
	data.GCPServiceAccountKeyJSON = saKey
	return data, nil
}

// azureConfig is the validated Azure-side configuration: the Secure Key Release
// parameters plus the Key Vault coordinates of the encrypted bundle.
type azureConfig struct {
	skrURL      string
	maaEndpoint string
	akvEndpoint string
	keyID       string

	bundleSecret  string
	bundleVersion string
	saKeyEntry    string
	miClientID    string
}

func resolveAzureConfig() (azureConfig, error) {
	cfg := azureConfig{
		skrURL:        strings.TrimSpace(os.Getenv("QUILL_AZURE_SKR_URL")),
		maaEndpoint:   strings.TrimSpace(os.Getenv("QUILL_AZURE_MAA_ENDPOINT")),
		akvEndpoint:   strings.TrimSpace(os.Getenv("QUILL_AZURE_AKV_ENDPOINT")),
		keyID:         strings.TrimSpace(os.Getenv("QUILL_AZURE_SKR_KEY_ID")),
		bundleSecret:  strings.TrimSpace(os.Getenv("QUILL_AZURE_BUNDLE_SECRET")),
		bundleVersion: strings.TrimSpace(os.Getenv("QUILL_AZURE_BUNDLE_VERSION")),
		saKeyEntry:    strings.TrimSpace(os.Getenv("QUILL_AZURE_SA_KEY_ENTRY")),
		miClientID:    strings.TrimSpace(os.Getenv("QUILL_AZURE_MI_CLIENT_ID")),
	}
	if cfg.skrURL == "" {
		cfg.skrURL = defaultSKRURL
	}
	// No defaults for any of these. Which MAA instance signs the attestation
	// token, which vault honours it, and which secret is opened are trust
	// decisions — silently picking one would produce a boot that looks attested
	// and is not.
	for _, required := range []struct{ env, value, why string }{
		{"QUILL_AZURE_MAA_ENDPOINT", cfg.maaEndpoint, " (refusing to default the attestation authority)"},
		{"QUILL_AZURE_AKV_ENDPOINT", cfg.akvEndpoint, ""},
		{"QUILL_AZURE_SKR_KEY_ID", cfg.keyID, ""},
		{"QUILL_AZURE_BUNDLE_SECRET", cfg.bundleSecret, " (the Key Vault secret holding the encrypted bundle)"},
		// Required rather than optional: gcscache and byokcache read
		// GOOGLE_APPLICATION_CREDENTIALS at runtime, so a bundle with no SA key
		// boots an enclave that cannot renew its TLS certificate or unwrap a
		// BYOK key — failures that surface hours later, far from their cause.
		{"QUILL_AZURE_SA_KEY_ENTRY", cfg.saKeyEntry, " (the bundle entry holding the GCP service-account key needed by gcscache/byokcache at runtime)"},
	} {
		if required.value == "" {
			return azureConfig{}, fmt.Errorf("%s: azure config: %s is not set%s", azureTag, required.env, required.why)
		}
	}
	if err := validateSKRURL(cfg.skrURL); err != nil {
		return azureConfig{}, err
	}
	if err := validateAKVEndpoint(cfg.akvEndpoint); err != nil {
		return azureConfig{}, err
	}
	return cfg, nil
}

// validateSKRURL refuses an SKR endpoint that is not on this pod's loopback
// interface.
//
// This is the one env var that decides whether attestation happens AT ALL, and
// it used to be an unchecked override. Point it off-box at anything returning
// an RSA JWK and the whole gate evaporates: no SNP report, no MAA exchange, no
// Key Vault call, no hostdata comparison — and then the enclave boots on
// whatever secrets the matching bundle carries while /attestation keeps serving
// a genuine token for the real, unmodified measurement. An attestation that is
// truthful about the code and silent about the credentials the code is running
// on is the worst shape this system can produce, so the substitution is refused
// outright rather than left to deploy discipline.
//
// Loopback is not a heuristic: the skr sidecar is a container in THIS container
// group and answers on localhost. Nothing legitimate points this elsewhere. The
// remaining override is the port, which is what the sidecar version actually
// changes (2.7 = 8080, some samples say 8284).
func validateSKRURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s: azure config: QUILL_AZURE_SKR_URL is not a URL: %w", azureTag, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%s: azure config: QUILL_AZURE_SKR_URL scheme %q (want http or https)", azureTag, parsed.Scheme)
	}
	host := parsed.Hostname()
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("%s: azure config: QUILL_AZURE_SKR_URL host %q is not loopback — the skr sidecar runs in this container group, and an off-box endpoint could hand back a key with no attestation at all (no MAA exchange, no hostdata check)", azureTag, host)
}

// keyVaultHostSuffixes are the DNS suffixes Azure serves Key Vault / Managed HSM
// data planes on, across the public and sovereign clouds. The endpoint must end
// in one of them.
//
// This is an allow-list rather than a syntax check because the alternative
// accepts ANY hostname: with only "no scheme, no path" enforced, a deploy that
// can set one env var simply names its own host and both legs below follow it.
// Adding a cloud means adding a line here, which is a visible change to the set
// of authorities this enclave will hand a bearer token to.
var keyVaultHostSuffixes = []string{
	".vault.azure.net",         // public
	".vault.azure.cn",          // China
	".vault.usgovcloudapi.net", // US Gov
	".vault.microsoftazure.de", // Germany
	".managedhsm.azure.net",    // Managed HSM, public
	".managedhsm.azure.cn",     // Managed HSM, China
	".managedhsm.usgovcloudapi.net",
}

// validateAKVEndpoint requires a bare, recognisable vault hostname.
//
// The value is used twice, and BOTH uses are trust anchors: it is handed to the
// skr sidecar as the vault to release the wrapping key from, and it is the https
// authority this file sends a Key Vault bearer token to. So this is the same
// class of control as validateSKRURL, reached through a different variable, and
// it has to be as strict.
//
// What the previous "no scheme, no path" check missed, both driven end to end:
//
//   - ANY hostname passed. "attacker.example.com" is not a vault, but nothing
//     said so.
//   - USERINFO passed. "trquillkv.vault.azure.net@attacker.example.com" sends the
//     request to attacker.example.com while an ARM template or CCE-policy diff
//     shows a string that begins with the real vault's hostname. That is the
//     dangerous form: it survives review by looking right.
//
// Either one repoints both legs at a host the attacker runs. Leg 1 then returns
// an attacker-chosen private key (the sidecar performs a real SNP report and MAA
// exchange, then asks a "vault" with no release policy, which happily wraps any
// key to the transfer key in the token it was just handed), and leg 2 returns a
// bundle sealed to it. The enclave boots on attacker-supplied device keys and
// provider keys while /attestation keeps serving a truthful document for
// unmodified code — the exact shape validateSKRURL calls the worst this system
// can produce. The real vault is never contacted, so hostdata is never evaluated
// and the CCE-policy mitigation never fires.
func validateAKVEndpoint(endpoint string) error {
	fail := func(why string) error {
		return fmt.Errorf("%s: azure config: QUILL_AZURE_AKV_ENDPOINT %q %s — it must be a bare vault hostname such as \"myvault.vault.azure.net\" (no scheme, no userinfo, no port, no path), because it is both the vault the skr sidecar releases the wrapping key from and the https authority a Key Vault access token is sent to", azureTag, endpoint, why)
	}
	if endpoint == "" {
		return fail("is empty")
	}
	if strings.Contains(endpoint, "://") || strings.ContainsAny(endpoint, "/?#") {
		return fail("has a scheme or a path")
	}
	// Parse it exactly as keyVaultSecretURL will, so what is validated is what
	// is dialled. A syntax check that does not agree with the URL builder is how
	// the userinfo bypass got in.
	parsed, err := url.Parse("https://" + endpoint)
	if err != nil {
		return fail(fmt.Sprintf("is not a valid https authority (%v)", err))
	}
	if parsed.User != nil {
		return fail(fmt.Sprintf("carries userinfo, so the request would actually go to %q", parsed.Host))
	}
	if parsed.Host != endpoint {
		// Catches userinfo, ports, brackets, escapes — anything where the
		// authority the stdlib derives is not the string an operator read.
		return fail(fmt.Sprintf("parses to authority %q, which is not the same string", parsed.Host))
	}
	if parsed.Port() != "" {
		return fail("names a port")
	}
	host := strings.ToLower(parsed.Hostname())
	if net.ParseIP(host) != nil {
		return fail("is an IP address, not a vault hostname")
	}
	for _, suffix := range keyVaultHostSuffixes {
		// A bare suffix ("vault.azure.net") is not a vault, so require a label
		// in front of it as well as the suffix itself.
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
			return nil
		}
	}
	return fail(fmt.Sprintf("is not an Azure Key Vault hostname (want one of %s)", strings.Join(keyVaultHostSuffixes, ", ")))
}

// refuseRedirect is the CheckRedirect for every client on this boot path.
//
// Without it, validateSKRURL and validateAKVEndpoint validate a string that the
// stdlib is then free to walk away from: http.Client follows up to 10 redirects
// and replays the POST body via GetBody, and nothing re-validates a hop. A
// swapped or compromised sidecar image — or a co-located container that wins the
// bind on the loopback port — answers 307 and the "must be loopback" pin is
// gone, with the released key then coming from wherever the Location header
// says. Driven before this was added: Fetch completed a boot against
// "skr.attacker.example", the exact host validateSKRURL refuses, with no MAA
// exchange and no hostdata comparison.
//
// On the Key Vault leg a cross-host redirect does not leak the bearer token
// (net/http strips Authorization when the host changes; a same-host, different-
// PORT hop does forward it, which is stdlib-intended). The reason to refuse
// there is the same as here anyway: the bundle must come from the authority that
// was validated, not from one a response body chose.
//
// Neither endpoint has any legitimate reason to redirect. The skr sidecar is a
// container in this group and Key Vault's data plane answers directly.
func refuseRedirect(req *http.Request, via []*http.Request) error {
	return fmt.Errorf("%s: refusing redirect to %q after %d hop(s): the boot path pins its endpoints (loopback sidecar, IMDS, the configured vault) and a redirect would move the request off a validated authority", azureTag, req.URL.Redacted(), len(via))
}

// bootTransport returns the shared transport with proxying disabled.
//
// http.DefaultTransport carries Proxy: ProxyFromEnvironment, and Go's proxy
// bypass exempts loopback but NOT link-local — measured: with HTTP_PROXY set,
// 169.254.169.254 resolves to the proxy while localhost and 127.0.0.1 do not.
// The IMDS call is plain HTTP and its RESPONSE BODY IS THE TOKEN, so an
// HTTP_PROXY anywhere in the container environment would hand that token to
// whoever the proxy names. Nothing in this repo sets HTTP_PROXY, so this is
// hardening rather than a live bug — but it is the one place where pinning the
// proxy off is both cheap and obviously correct.
//
// The type assertion is what preserves the http.DefaultTransport test seam: when
// a test has substituted a recorder, it is honoured verbatim.
func bootTransport() http.RoundTripper {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return http.DefaultTransport
	}
	clone := base.Clone()
	clone.Proxy = nil
	return clone
}

// newSKRHTTPClient builds the client for the key-release round trip.
//
// 60s rather than the 30s the Azure control-plane calls get: one attempt
// already covers a hardware SNP report, an MAA exchange and a Key Vault call,
// and containers in an ACI group start concurrently — the sidecar may still be
// coming up when the enclave makes its first request. The retries turn that
// startup race into a short wait instead of a crash-loop. A 403 is NOT retried:
// that is the release policy rejecting this measurement, and it will reject it
// again.
func newSKRHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       60 * time.Second,
		CheckRedirect: refuseRedirect,
		Transport:     &retryTransport{base: bootTransport(), attempts: 4, backoff: 500 * time.Millisecond, retryStatus: retryableStatus},
	}
}

// newIMDSHTTPClient builds the client for the managed-identity token.
//
// IMDS is famously slow to answer for the first few seconds of a container
// group's life, and main.go turns a bootstrap error into os.Exit(1): a
// container-group crash-loop that re-runs the SNP report and MAA exchange on
// every restart. That is why this leg retries a wider set of statuses than the
// Key Vault leg — see retryableIMDSStatus.
func newIMDSHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: refuseRedirect,
		Transport:     &retryTransport{base: bootTransport(), attempts: 4, backoff: 250 * time.Millisecond, retryStatus: retryableIMDSStatus},
	}
}

// newKeyVaultHTTPClient builds the client for the single Key Vault fetch.
//
// Separate from the IMDS client purely so the retry predicate can differ: on the
// vault a 403 (RBAC) and a 404 (no such secret) are verdicts, and repeating them
// only delays a boot that is already doomed.
func newKeyVaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: refuseRedirect,
		Transport:     &retryTransport{base: bootTransport(), attempts: 4, backoff: 250 * time.Millisecond, retryStatus: retryableStatus},
	}
}

// retryTransport retries a boot-path request that failed in a way a retry can
// fix. Deliberately narrow, and narrow in a way that differs per leg: what
// counts as retryable is the caller's decision, because the same status means
// different things at IMDS and at Key Vault.
type retryTransport struct {
	base     http.RoundTripper
	attempts int
	backoff  time.Duration
	// retryStatus decides whether a response status is worth another attempt.
	// Required: a nil predicate would silently turn every retry off.
	retryStatus func(int) bool
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	delay := t.backoff
	var (
		resp *http.Response
		err  error
	)
	for attempt := 1; ; attempt++ {
		// RoundTrip must not mutate the caller's request, and a replayed POST
		// needs a fresh body. GetBody is populated by http.NewRequest for the
		// bytes.Reader / strings.Reader bodies this package sends.
		attemptReq := req.Clone(req.Context())
		if req.GetBody != nil {
			body, bodyErr := req.GetBody()
			if bodyErr != nil {
				return nil, bodyErr
			}
			attemptReq.Body = body
		}

		resp, err = t.base.RoundTrip(attemptReq)
		if err == nil && !t.retryStatus(resp.StatusCode) {
			return resp, nil
		}
		if attempt >= t.attempts || req.Context().Err() != nil {
			return resp, err
		}
		if resp != nil {
			// Drain so the connection can be reused, then discard: the caller
			// never sees this response, and on the SKR path its body may be
			// key material.
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
		}
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(delay):
		}
		delay *= 2
	}
}

// retryableStatus is the conservative default: transport errors, 429, and 5xx.
// A 4xx is a verdict (403 from the release policy, 403 from Key Vault RBAC, 404
// for a secret that does not exist) and repeating it only delays a boot that is
// already doomed.
func retryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retryableIMDSStatus additionally retries the statuses IMDS returns while a
// managed identity is still propagating at container-group start.
//
// The default set covered 429 and 5xx and so covered none of them, which made
// the retries miss the exact cold-start race they were added for: IMDS answers
// 400 in that window (see the hint in fetchIMDSToken), and 400 was treated as
// permanent. A managed identity that had not finished propagating produced a
// hard boot failure, os.Exit(1) in main.go, and an ACI restart that re-ran the
// SNP report and MAA exchange — the crash-loop the retries exist to prevent.
// Azure's own IMDS guidance also treats 404 and 410 as retryable.
//
// This is deliberately NOT applied to the Key Vault leg, where 403 and 404 are
// real verdicts about RBAC and about QUILL_AZURE_BUNDLE_SECRET. The cost here is
// bounded: a genuinely unassigned identity now fails after four attempts
// (~1.75s of backoff) instead of one, still naming 400 and what it means.
func retryableIMDSStatus(code int) bool {
	switch code {
	case http.StatusBadRequest, http.StatusNotFound, http.StatusGone:
		return true
	}
	return retryableStatus(code)
}

// ---------------------------------------------------------------------------
// step 1 — attestation-gated key release
// ---------------------------------------------------------------------------

// skrRequest is the body the skr sidecar (mcr.microsoft.com/aci/skr:2.7)
// accepts on POST /key/release.
type skrRequest struct {
	MAAEndpoint string `json:"maa_endpoint"`
	AKVEndpoint string `json:"akv_endpoint"`
	KID         string `json:"kid"`
}

// skrResponse carries the released key. `key` has been observed as a JSON
// *string* holding the JWK; accepting an inline object too costs one branch and
// removes a whole class of sidecar-version breakage.
type skrResponse struct {
	Key json.RawMessage `json:"key"`
}

// releaseWrappingKey asks the sidecar to release the private key.
//
// A 403 here is the system working: it means the running measurement does not
// match the key's release policy. The error deliberately carries the sidecar's
// response body for non-2xx only — on ANY 2xx that body may BE the private key
// and must never reach a log line, an error string, or a wrapped %w chain.
// Gating that echo on "!= 200" rather than "not 2xx" was a real leak: a sidecar
// answering 201 or 202 with the released key printed the whole private JWK into
// the bootstrap error, which main.go writes to stderr and ACI ships to Log
// Analytics — outside the attested boundary.
func releaseWrappingKey(ctx context.Context, httpc *http.Client, cfg azureConfig) (*rsa.PrivateKey, error) {
	body, err := json.Marshal(skrRequest{
		MAAEndpoint: cfg.maaEndpoint,
		AKVEndpoint: cfg.akvEndpoint,
		KID:         cfg.keyID,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: skr release: marshal request: %w", azureTag, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.skrURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%s: skr release: build request for %s: %w", azureTag, cfg.skrURL, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: skr release: POST %s unreachable (is the skr sidecar running in this container group?): %w", azureTag, cfg.skrURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode/100 == 2 {
			// 2xx-but-not-200: unexpected, and the body is still a candidate
			// for key material. Report the status alone.
			return nil, fmt.Errorf("%s: skr release: kid=%q vault=%q maa=%q http %d (expected 200; body withheld because a 2xx body may contain key material)",
				azureTag, cfg.keyID, cfg.akvEndpoint, cfg.maaEndpoint, resp.StatusCode)
		}
		errBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return nil, fmt.Errorf("%s: skr release: http %d and error body unreadable: %w", azureTag, resp.StatusCode, readErr)
		}
		hint := ""
		if resp.StatusCode == http.StatusForbidden {
			hint = " (403 = the release policy rejected this measurement: check x-ms-sevsnpvm-hostdata against the CCE policy hash of the deployed container group)"
		}
		return nil, fmt.Errorf("%s: skr release: kid=%q vault=%q maa=%q http %d%s: %s",
			azureTag, cfg.keyID, cfg.akvEndpoint, cfg.maaEndpoint, resp.StatusCode, hint, errBody)
	}

	// Bounded: an RSA-4096 JWK is a few KB, and an unbounded ReadAll on a
	// misbehaving upstream is an unbounded allocation on the boot path.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxSKRResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("%s: skr release: read response: %w", azureTag, err)
	}
	var decoded skrResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		// Byte count only. The success body holds the released private key, so
		// echoing it to diagnose a parse failure would defeat the entire
		// attestation gate we just passed.
		return nil, fmt.Errorf("%s: skr release: response is not JSON (%d bytes, content-type %q); body withheld because it may contain key material: %w",
			azureTag, len(raw), resp.Header.Get("Content-Type"), err)
	}
	if len(decoded.Key) == 0 {
		return nil, fmt.Errorf("%s: skr release: response JSON has no \"key\" field", azureTag)
	}

	// `key` is normally a JSON string containing the JWK; tolerate an inline
	// object from a future sidecar.
	jwkBytes := []byte(decoded.Key)
	var asString string
	if err := json.Unmarshal(decoded.Key, &asString); err == nil {
		jwkBytes = []byte(asString)
	}

	key, err := parseJWKRSAPrivateKey(jwkBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: skr release: %w", azureTag, err)
	}
	return key, nil
}

// jwkRSAPrivate is the subset of an RSA private JWK we need. dp/dq/qi are
// intentionally absent: Precompute() derives them from p and q, so parsing them
// would only add fields that could disagree with the primes.
type jwkRSAPrivate struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	D   string `json:"d"`
	P   string `json:"p"`
	Q   string `json:"q"`
}

// parseJWKRSAPrivateKey converts the released JWK into an *rsa.PrivateKey.
//
// Errors name the missing/bad field but never its value — every one of these
// fields is key material.
func parseJWKRSAPrivateKey(raw []byte) (*rsa.PrivateKey, error) {
	var jwk jwkRSAPrivate
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, fmt.Errorf("released key is not a JWK object (%d bytes; content withheld): %w", len(raw), err)
	}
	// MEASURED 2026-08-03 against the live skr sidecar 2.7 in Azure UAE North,
	// releasing a Key Vault Premium RSA-HSM key: the response is
	// {"key": "<JWK JSON string>"} — the outer value is a STRING, not an object —
	// and the JWK carries exactly {kty,n,e,d,p,q,dp,dq,qi} with kty="RSA".
	// So an HSM-backed key reports kty RSA, not RSA-HSM, and p/q are present, which
	// is what Precompute() below needs. Both spellings stay accepted because the
	// cost is one comparison and the failure mode is a boot that cannot decrypt.
	//
	// Key Vault spells an HSM-backed RSA key "RSA-HSM"; plain software keys are
	// "RSA". Both release to the same RSA private key.
	if jwk.Kty != "RSA" && jwk.Kty != "RSA-HSM" {
		return nil, fmt.Errorf("released key kty=%q (want RSA or RSA-HSM)", jwk.Kty)
	}
	// Ordered, not a map: a range over a map would report a random one of
	// several missing fields, so the same broken key would produce a different
	// error each boot.
	for _, field := range []struct{ name, value string }{
		{"n", jwk.N}, {"e", jwk.E}, {"d", jwk.D}, {"p", jwk.P}, {"q", jwk.Q},
	} {
		if field.value == "" {
			return nil, fmt.Errorf("released JWK is missing field %q (a public-only JWK cannot decrypt; check the key is marked exportable)", field.name)
		}
	}

	n, err := jwkBigInt(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("released JWK field \"n\": %w", err)
	}
	e, err := jwkBigInt(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("released JWK field \"e\": %w", err)
	}
	d, err := jwkBigInt(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("released JWK field \"d\": %w", err)
	}
	p, err := jwkBigInt(jwk.P)
	if err != nil {
		return nil, fmt.Errorf("released JWK field \"p\": %w", err)
	}
	q, err := jwkBigInt(jwk.Q)
	if err != nil {
		return nil, fmt.Errorf("released JWK field \"q\": %w", err)
	}
	if !e.IsInt64() || e.Int64() <= 0 || e.Int64() > 1<<31-1 {
		return nil, fmt.Errorf("released JWK public exponent out of range")
	}

	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: n, E: int(e.Int64())},
		D:         d,
		Primes:    []*big.Int{p, q},
	}
	key.Precompute()
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("released JWK is not a consistent RSA private key: %w", err)
	}
	return key, nil
}

// jwkBigInt decodes a JOSE base64url big-endian integer. Padding is tolerated
// because not every producer strips it.
func jwkBigInt(value string) (*big.Int, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(value, "="))
	if err != nil {
		return nil, fmt.Errorf("not base64url: %w", err)
	}
	if len(decoded) == 0 {
		return nil, fmt.Errorf("decodes to zero bytes")
	}
	return new(big.Int).SetBytes(decoded), nil
}

// ---------------------------------------------------------------------------
// step 2 — managed identity, then the encrypted bundle
// ---------------------------------------------------------------------------

// fetchIMDSToken asks the Instance Metadata Service for an AAD token scoped to
// the Key Vault data plane, using the container group's managed identity.
//
// This credential is deliberately NOT the security boundary — it only fetches
// ciphertext. See the "Why the bundle is encrypted" note in the package comment.
func fetchIMDSToken(ctx context.Context, httpc *http.Client, cfg azureConfig) (string, error) {
	query := url.Values{}
	query.Set("api-version", imdsAPIVersion)
	query.Set("resource", keyVaultResource)
	if cfg.miClientID != "" {
		// Required when the container group has more than one identity
		// attached; IMDS answers 400 "multiple user-assigned identities" if it
		// has to guess.
		query.Set("client_id", cfg.miClientID)
	}
	endpoint := imdsBaseURL + "/metadata/identity/oauth2/token?" + query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("%s: imds token: build request: %w", azureTag, err)
	}
	// IMDS refuses any request without this header — it is what makes an SSRF
	// through a proxy unable to reach the metadata service by accident.
	req.Header.Set("Metadata", "true")

	resp, err := httpc.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s: imds token: GET %s unreachable (is a managed identity assigned to this container group?): %w", azureTag, imdsBaseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// An IMDS error body is a diagnostic envelope
		// ({"error":"invalid_request","error_description":...}), never a token.
		errBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return "", fmt.Errorf("%s: imds token: http %d and error body unreadable: %w", azureTag, resp.StatusCode, readErr)
		}
		hint := ""
		if resp.StatusCode == http.StatusBadRequest {
			hint = " (400 usually means no managed identity is assigned, or several are and QUILL_AZURE_MI_CLIENT_ID must name one)"
		}
		return "", fmt.Errorf("%s: imds token: for resource %s http %d%s: %s", azureTag, keyVaultResource, resp.StatusCode, hint, errBody)
	}

	var decoded struct {
		AccessToken string `json:"access_token"`
		Resource    string `json:"resource"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxKeyVaultResponseBytes)).Decode(&decoded); err != nil {
		// A 200 body carries the access token; withhold it.
		return "", fmt.Errorf("%s: imds token: 200 response is not JSON (body withheld because it may contain a token): %w", azureTag, err)
	}
	if decoded.AccessToken == "" {
		return "", fmt.Errorf("%s: imds token: response has an empty access_token", azureTag)
	}
	// Check the audience we asked for is the audience we got. This field was
	// parsed and then never read, which made the struct imply a check that did
	// not exist: a token minted for another resource (management.azure.com, say,
	// via a mis-set query or a proxying IMDS) was accepted here and only rejected
	// later by the vault's 401 — an authorization decision deferred to a remote
	// party. Enforced only when the field is present, so an IMDS version that
	// stops echoing it does not become a boot failure. Trailing slashes are
	// normalised because the two spellings are the same audience.
	if got := strings.TrimRight(decoded.Resource, "/"); got != "" && got != strings.TrimRight(keyVaultResource, "/") {
		return "", fmt.Errorf("%s: imds token: issued for resource %q, but this token is only usable against %s — refusing to send it to the vault", azureTag, decoded.Resource, keyVaultResource)
	}
	return decoded.AccessToken, nil
}

// keyVaultSecretURL builds the data-plane URL for the bundle secret.
//
// With QUILL_AZURE_BUNDLE_VERSION unset this requests "current", which is what
// makes both silent substitution (a new version written by anyone holding
// secrets/set) and silent rollback (reinstating a superseded version, and with
// it rotated-out keys) take effect on the next cold start. Setting it appends
// the version segment and pins one immutable value; see the integrity note in
// the package comment for why SKR does not cover this on its own.
func keyVaultSecretURL(cfg azureConfig) string {
	base := keyVaultBaseURLOverride
	if base == "" {
		base = "https://" + cfg.akvEndpoint
	}
	path := "/secrets/" + url.PathEscape(cfg.bundleSecret)
	if cfg.bundleVersion != "" {
		path += "/" + url.PathEscape(cfg.bundleVersion)
	}
	return fmt.Sprintf("%s%s?api-version=%s", strings.TrimSuffix(base, "/"), path, keyVaultAPIVersion)
}

// fetchKeyVaultSecret reads the encrypted bundle.
//
// The 403 hint is the one an operator will actually need: on a vault using RBAC
// the identity needs "Key Vault Secrets User", and on a vault still using access
// policies it needs a `get` permission on secrets. Those are different knobs in
// different blades, and the response body does not say which model the vault is
// in.
func fetchKeyVaultSecret(ctx context.Context, httpc *http.Client, cfg azureConfig, token string) ([]byte, error) {
	endpoint := keyVaultSecretURL(cfg)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: key vault: build request for %s: %w", azureTag, endpoint, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: key vault: GET %s: %w", azureTag, endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Safe to echo: a non-200 body is Azure's error envelope. The 200 path
		// below echoes nothing.
		errBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return nil, fmt.Errorf("%s: key vault: http %d and error body unreadable: %w", azureTag, resp.StatusCode, readErr)
		}
		hint := ""
		switch resp.StatusCode {
		case http.StatusForbidden:
			hint = " (403 = the container group's managed identity cannot read this secret: grant it \"Key Vault Secrets User\" on an RBAC vault, or a `get` secret permission on an access-policy vault)"
		case http.StatusUnauthorized:
			hint = " (401 = the token was rejected: it must be issued for the " + keyVaultResource + " audience)"
		case http.StatusNotFound:
			hint = " (404 = no such secret in this vault: check QUILL_AZURE_BUNDLE_SECRET)"
		}
		return nil, fmt.Errorf("%s: key vault: secret %q in %s http %d%s: %s",
			azureTag, cfg.bundleSecret, cfg.akvEndpoint, resp.StatusCode, hint, errBody)
	}

	var decoded struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxKeyVaultResponseBytes)).Decode(&decoded); err != nil {
		// The 200 body is the encrypted bundle. It is inert without the
		// SKR-released key, but it is not diagnostic either, so withhold it.
		return nil, fmt.Errorf("%s: key vault: 200 response is not JSON (body withheld): %w", azureTag, err)
	}
	if strings.TrimSpace(decoded.Value) == "" {
		return nil, fmt.Errorf("%s: key vault: secret %q has an empty value", azureTag, cfg.bundleSecret)
	}
	return decodeCiphertextBlob([]byte(decoded.Value))
}

// decodeCiphertextBlob normalises whatever the deploy stored into envelope
// bytes: the envelope JSON, or that JSON base64-encoded.
//
// JSON is detected first so a textual envelope is never mistaken for something
// else. Base64 is tried second, with interior whitespace stripped because
// `base64` line-wraps at 76 columns by default and Key Vault stores whatever
// string it was given. Both forms are accepted because the alternative is a
// boot-fatal error over one layer of base64, which sends an incident down the
// wrong path — the operator is told to rotate a vault key that was fine.
func decodeCiphertextBlob(raw []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%s: key vault: secret value is empty", azureTag)
	}
	if trimmed[0] == '{' {
		return trimmed, nil
	}
	if decoded, ok := decodeBase64Any(trimmed); ok {
		return decoded, nil
	}
	return nil, fmt.Errorf("%s: key vault: secret value (%d bytes) is neither a %s envelope JSON object nor base64 of one", azureTag, len(trimmed), envelopeAlg)
}

// decodeBase64Any accepts the four base64 flavours a producer might emit
// (std/raw-std/url/raw-url) after removing line wrapping.
func decodeBase64Any(text []byte) ([]byte, bool) {
	compact := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, string(text))
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := encoding.DecodeString(compact); err == nil {
			return decoded, true
		}
	}
	return nil, false
}

// ---------------------------------------------------------------------------
// step 3 — the envelope, and the bundle inside it
// ---------------------------------------------------------------------------

// secretEnvelope is the hybrid wrapping format for the bundle.
//
// Why hybrid and not a bare RSA-OAEP ciphertext: RSA-OAEP can only encrypt
// k - 2*hLen - 2 bytes, which with SHA-256 is 190 bytes under a 2048-bit key and
// 446 bytes under a 4096-bit key. The bundle is ~40 secrets plus a ~2.3 KB
// service-account key — kilobytes, not hundreds of bytes. A direct OAEP blob of
// one is arithmetically impossible, so the payload rides under AES-256-GCM and
// only the 32-byte content key is OAEP-wrapped. The security property is
// unchanged — the content key is inert without the SKR-released private key.
//
// Produce one with (python, offline, using the vault key's PUBLIC half):
//
//	bundle = json.dumps({name: value, ...}).encode()
//	k  = os.urandom(32); nonce = os.urandom(12)
//	ct = AESGCM(k).encrypt(nonce, bundle, None)
//	ek = pub.encrypt(k, OAEP(mgf1=SHA256, algorithm=SHA256, label=None))
//	json {"v":1,"alg":"RSA-OAEP-256+A256GCM","enc_key":b64(ek),
//	      "nonce":b64(nonce),"ciphertext":b64(ct)}
//
// OAEP parameters are fixed at SHA-256 for both the digest and MGF1, with no
// label. Key Vault calls this RSA-OAEP-256.
//
// This is the SAME wire format the previous single-service-account-key envelope
// used, field for field, so an existing producer only changes what it puts in
// the plaintext.
type secretEnvelope struct {
	V          int    `json:"v"`
	Alg        string `json:"alg"`
	EncKey     string `json:"enc_key"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// decryptEnvelope opens the hybrid envelope with the SKR-released private key.
//
// There is no bare-OAEP fallback. There used to be, when the payload was a
// single service-account key that a 4096-bit key could *almost* hold; a bundle
// never fits, so the fallback could only ever fire on a malformed envelope and
// would then report an OAEP failure for what is actually a JSON problem.
func decryptEnvelope(key *rsa.PrivateKey, blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("%s: bundle decrypt: ciphertext is empty", azureTag)
	}

	var env secretEnvelope
	if err := json.Unmarshal(bytes.TrimSpace(blob), &env); err != nil {
		return nil, fmt.Errorf("%s: bundle decrypt: %d-byte blob is not a %s envelope JSON object: %w", azureTag, len(blob), envelopeAlg, err)
	}
	if env.EncKey == "" {
		return nil, fmt.Errorf("%s: bundle decrypt: envelope has no enc_key", azureTag)
	}
	if env.V != envelopeVersion {
		return nil, fmt.Errorf("%s: bundle decrypt: envelope version %d (this build understands %d)", azureTag, env.V, envelopeVersion)
	}
	if env.Alg != envelopeAlg {
		return nil, fmt.Errorf("%s: bundle decrypt: envelope alg %q (this build understands %q)", azureTag, env.Alg, envelopeAlg)
	}
	// Same four-flavour tolerance decodeCiphertextBlob applies one layer out, and
	// for the same reason stated there: a producer written with Python's
	// urlsafe_b64encode (or any unpadded encoder) would otherwise fail here with
	// "enc_key is not base64", which reads like a corrupt or wrong-key envelope
	// and sends the operator off to rotate a vault key that was fine. Accepting
	// the alternate alphabets costs nothing — the envelope's integrity comes from
	// GCM and OAEP, not from which base64 dialect carried the bytes.
	encKey, ok := decodeBase64Any([]byte(env.EncKey))
	if !ok {
		return nil, fmt.Errorf("%s: bundle decrypt: envelope enc_key is not base64 (tried std/raw-std/url/raw-url)", azureTag)
	}
	nonce, ok := decodeBase64Any([]byte(env.Nonce))
	if !ok {
		return nil, fmt.Errorf("%s: bundle decrypt: envelope nonce is not base64 (tried std/raw-std/url/raw-url)", azureTag)
	}
	ciphertext, ok := decodeBase64Any([]byte(env.Ciphertext))
	if !ok {
		return nil, fmt.Errorf("%s: bundle decrypt: envelope ciphertext is not base64 (tried std/raw-std/url/raw-url)", azureTag)
	}

	contentKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, encKey, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: bundle decrypt: RSA-OAEP-SHA256 unwrap of the content key failed (released key modulus %d bits, enc_key %d bytes; check the envelope was encrypted to the CURRENT vault key with SHA-256/MGF1-SHA256 and no label): %w",
			azureTag, key.N.BitLen(), len(encKey), err)
	}

	// Checked before aes.NewCipher, which accepts 16 and 24 as well and would
	// otherwise let an envelope labelled A256GCM open under AES-128.
	if len(contentKey) != envelopeContentKeyBytes {
		return nil, fmt.Errorf("%s: bundle decrypt: unwrapped content key is %d bytes, but %s means %d",
			azureTag, len(contentKey), envelopeAlg, envelopeContentKeyBytes)
	}
	block, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, fmt.Errorf("%s: bundle decrypt: unwrapped content key is not a valid AES key (%d bytes): %w", azureTag, len(contentKey), err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%s: bundle decrypt: init AES-GCM: %w", azureTag, err)
	}
	// crypto/cipher's gcm.Open PANICS on a wrong-length nonce rather than
	// returning an error, and a panic on the boot path is the "hung with no
	// explanation" failure this package exists to avoid.
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("%s: bundle decrypt: envelope nonce is %d bytes (want %d)", azureTag, len(nonce), gcm.NonceSize())
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: bundle decrypt: AES-GCM open failed — the envelope is corrupt or was not sealed with this content key: %w", azureTag, err)
	}
	return plaintext, nil
}

// secretBundle is the decrypted payload: logical secret name -> value.
//
// The names are the SAME ones the deploy puts in QUILL_*_SECRET and that Google
// Secret Manager uses on the GCP side, which is what lets both clouds share the
// binding table in secrets.go. Producing the bundle is then a mechanical dump of
// those names, and a rename on one cloud is visibly a rename on both.
type secretBundle map[string]string

func parseBundle(plaintext []byte) (secretBundle, error) {
	var bundle secretBundle
	if err := json.Unmarshal(plaintext, &bundle); err != nil {
		// Length only: the plaintext is every secret this system has.
		return nil, fmt.Errorf("%s: bundle parse: decrypted payload (%d bytes) is not a JSON object of secret name -> value; content withheld: %w", azureTag, len(plaintext), err)
	}
	if len(bundle) == 0 {
		return nil, fmt.Errorf("%s: bundle parse: decrypted payload is an empty object — it carries no secrets", azureTag)
	}
	return bundle, nil
}

// resolve is the secretResolver the shared assembly in secrets.go calls. The
// context is unused: everything was fetched in one round trip already.
func (b secretBundle) resolve(_ context.Context, name string) ([]byte, error) {
	value, ok := b[name]
	if !ok {
		return nil, fmt.Errorf("no entry %q in the bundle (bundle has %d entries: %s)", name, len(b), b.names())
	}
	return []byte(value), nil
}

// require reads one entry that is not part of the binding table.
func (b secretBundle) require(name, what string) (string, error) {
	value, ok := b[name]
	if !ok {
		return "", fmt.Errorf("%s: bundle: no entry %q for the %s (bundle has %d entries: %s)", azureTag, name, what, len(b), b.names())
	}
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s: bundle: entry %q for the %s is empty", azureTag, name, what)
	}
	return value, nil
}

// names lists the bundle's KEYS — never its values — so a "which entry is
// missing?" error is actionable without printing a single secret. Sorted so the
// same broken bundle produces the same error every boot.
func (b secretBundle) names() string {
	keys := make([]string, 0, len(b))
	for name := range b {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}
