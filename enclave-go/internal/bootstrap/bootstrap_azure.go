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
// Why the released key unwraps a *Google* credential
// ==================================================
// The enclave needs Google credentials at runtime no matter which cloud it
// runs on (Spanner credit ledger, Bigtable generations, shared ACME cache), and
// all ~40 provider secrets already live in one Google project. Copying them
// into Key Vault would create a second set that drifts. So Key Vault holds
// exactly ONE thing: the key that unwraps a GCP service-account key. Everything
// else comes from Secret Manager through the shared path in secrets_google.go.
//
// The wrapped SA-key blob is not secret-by-obscurity — it is inert without the
// SKR-gated private key, so it travels as plain deploy configuration.
//
// Boot sequence
// =============
//  1. validate env (no I/O — a misconfigured deploy must fail before it can
//     blame the network)
//  2. POST the skr sidecar  -> RSA private key as JWK
//  3. RSA-OAEP-unwrap the SA-key blob
//  4. JWT-bearer exchange at oauth2.googleapis.com -> Google access token
//  5. shared Secret Manager fetch -> BootstrapData
//  6. attach the SA key JSON so cmd/enclave/main.go can write it to tmpfs and
//     point GOOGLE_APPLICATION_CREDENTIALS at it
//
// Required env:
//
//	QUILL_AZURE_MAA_ENDPOINT   e.g. "trquilluaen.uaen.attest.azure.net"
//	QUILL_AZURE_AKV_ENDPOINT   e.g. "trquillkv.vault.azure.net"
//	QUILL_AZURE_SKR_KEY_ID     e.g. "tr-bootstrap-wrap"
//	exactly one of
//	  QUILL_AZURE_SA_KEY_CIPHERTEXT       the envelope, inline
//	  QUILL_AZURE_SA_KEY_CIPHERTEXT_PATH  path to the envelope on disk
//	plus everything resolveSecretConfig() requires (QUILL_GCP_PROJECT_ID,
//	QUILL_DEVICE_KEYS_SECRET, >=1 provider secret).
//
// Both ciphertext forms accept the SAME thing: the envelope JSON, or that JSON
// base64-encoded, or (for a payload small enough) a bare OAEP ciphertext. They
// used to differ — inline was base64-decoded and the path form was not — which
// turned "wrote the string I would have put in the env var into a file" into a
// boot-fatal error that blamed the vault key. See loadSAKeyCiphertext.
//
// Optional env:
//
//	QUILL_AZURE_SKR_URL  default "http://localhost:8080/key/release";
//	                     must be loopback (see validateSKRURL)
//	QUILL_AZURE_REGION   overrides QUILL_GCP_REGION for BootstrapData.Region
//
// None of MAA / AKV / key id has a default, and that is deliberate. Defaulting
// the MAA instance would attest against an authority nobody chose — the exact
// forgery hole the verifier work closed. A missing one is a hard error.
//
// What the deploy channel still decides
// =====================================
// SKR gates the *unwrap key*. Which Google identity gets unwrapped is decided
// by the ciphertext, and that is deploy configuration on every cloud (GCP picks
// it by attaching a service account to the Confidential Space VM; Azure picks it
// by supplying this blob). What keeps that honest on Azure is that the container
// group's env-var rules are part of the CCE policy, so changing them changes the
// policy hash, changes x-ms-sevsnpvm-hostdata, and fails the workload pin that
// verify makes mandatory.
//
// That argument covers the env form and NOT the _PATH form: a CCE policy
// measures the env-var rules but not the CONTENTS of a mounted volume. Prefer
// QUILL_AZURE_SA_KEY_CIPHERTEXT. The path form exists for the mounted-secret
// deploy shape and is measurement-weaker; a deploy that uses it is trusting
// whoever can write that volume.
//
// Dependency surface: stdlib only. Linking a heavy dependency chain into this
// binary corrupted the main request loop in a previous rollout (deploy
// 25592563258, see maybeStartAttestSidecar()), which is why the JWT-bearer
// exchange below is hand-rolled instead of pulling in golang.org/x/oauth2.
package bootstrap

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
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

	// googleTokenEndpoint is the JWT-bearer exchange. Overridden per-request by
	// the SA key's own token_uri when it carries one, which is also how the
	// tests redirect it.
	googleTokenEndpoint = "https://oauth2.googleapis.com/token" // #nosec G101 -- public OAuth token endpoint, not a credential.

	// googleCloudPlatformScope covers Secret Manager plus the Spanner /
	// Bigtable / GCS access the enclave needs later from the same SA key.
	googleCloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

	// saKeyEnvelopeAlg / saKeyEnvelopeVersion identify the hybrid wrapping
	// format. See saKeyEnvelope for why a hybrid format is not optional.
	saKeyEnvelopeAlg     = "RSA-OAEP-256+A256GCM"
	saKeyEnvelopeVersion = 1

	// saKeyContentKeyBytes is what "A256GCM" in saKeyEnvelopeAlg means. It is
	// checked explicitly because aes.NewCipher happily accepts 16 and 24 too,
	// which would let an envelope labelled A256GCM open under AES-128 and make
	// the label decorative.
	saKeyContentKeyBytes = 32

	// maxSKRResponseBytes bounds the released-key read. An RSA-4096 private JWK
	// is ~2.5 KB.
	maxSKRResponseBytes = 64 << 10

	azureTag = "bootstrap/azure"
)

// Fetch releases the wrapping key under attestation, unwraps the GCP service
// account key with it, mints a Google access token, and assembles
// BootstrapData from Google Secret Manager via the shared path.
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
	skr, err := resolveSKRConfig()
	if err != nil {
		return nil, err
	}
	ciphertext, err := loadSAKeyCiphertext()
	if err != nil {
		return nil, err
	}

	// Step 1 — attestation-gated key release.
	wrappingKey, err := releaseWrappingKey(ctx, newSKRHTTPClient(), skr)
	if err != nil {
		return nil, err
	}

	// Step 2 — unwrap the service-account key.
	saKeyJSON, err := decryptSAKey(wrappingKey, ciphertext)
	if err != nil {
		return nil, err
	}

	// Step 3 — exchange it for a Google access token.
	googleHTTP := newGoogleHTTPClient()
	token, err := mintGoogleAccessToken(ctx, googleHTTP, saKeyJSON)
	if err != nil {
		return nil, err
	}

	// Step 4 — the shared Secret Manager path, identical to GCP's.
	data, err := fetchBootstrapSecrets(ctx, googleHTTP, token, cfg, azureTag)
	if err != nil {
		return nil, err
	}

	// Step 5 — hand the SA key to main.go, which writes it to tmpfs and points
	// GOOGLE_APPLICATION_CREDENTIALS at it so every downstream Google client
	// (gcscache, byokcache's KMS unwrapper, the settlement path) authenticates
	// without repeating this dance.
	data.GCPServiceAccountKeyJSON = string(saKeyJSON)
	return data, nil
}

// skrConfig is the validated Secure Key Release configuration.
type skrConfig struct {
	url         string
	maaEndpoint string
	akvEndpoint string
	keyID       string
}

func resolveSKRConfig() (skrConfig, error) {
	cfg := skrConfig{
		url:         strings.TrimSpace(os.Getenv("QUILL_AZURE_SKR_URL")),
		maaEndpoint: strings.TrimSpace(os.Getenv("QUILL_AZURE_MAA_ENDPOINT")),
		akvEndpoint: strings.TrimSpace(os.Getenv("QUILL_AZURE_AKV_ENDPOINT")),
		keyID:       strings.TrimSpace(os.Getenv("QUILL_AZURE_SKR_KEY_ID")),
	}
	if cfg.url == "" {
		cfg.url = defaultSKRURL
	}
	// No defaults for these three. Which MAA instance signs the attestation
	// token, and which vault honours it, are trust decisions — silently
	// picking one would produce a release that looks attested and is not.
	if cfg.maaEndpoint == "" {
		return skrConfig{}, fmt.Errorf("%s: skr config: QUILL_AZURE_MAA_ENDPOINT is not set (refusing to default the attestation authority)", azureTag)
	}
	if cfg.akvEndpoint == "" {
		return skrConfig{}, fmt.Errorf("%s: skr config: QUILL_AZURE_AKV_ENDPOINT is not set", azureTag)
	}
	if cfg.keyID == "" {
		return skrConfig{}, fmt.Errorf("%s: skr config: QUILL_AZURE_SKR_KEY_ID is not set", azureTag)
	}
	if err := validateSKRURL(cfg.url); err != nil {
		return skrConfig{}, err
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
// whatever Google identity the matching ciphertext carries while /attestation
// keeps serving a genuine token for the real, unmodified measurement. An
// attestation that is truthful about the code and silent about the credentials
// the code is running on is the worst shape this system can produce, so the
// substitution is refused outright rather than left to deploy discipline.
//
// Loopback is not a heuristic: the skr sidecar is a container in THIS container
// group and answers on localhost. Nothing legitimate points this elsewhere. The
// remaining override is the port, which is what the sidecar version actually
// changes (2.7 = 8080, some samples say 8284).
func validateSKRURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s: skr config: QUILL_AZURE_SKR_URL is not a URL: %w", azureTag, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%s: skr config: QUILL_AZURE_SKR_URL scheme %q (want http or https)", azureTag, parsed.Scheme)
	}
	host := parsed.Hostname()
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("%s: skr config: QUILL_AZURE_SKR_URL host %q is not loopback — the skr sidecar runs in this container group, and an off-box endpoint could hand back a key with no attestation at all (no MAA exchange, no hostdata check)", azureTag, host)
}

// newSKRHTTPClient builds the client for the key-release round trip.
//
// 60s rather than the 30s the Google calls get: one attempt already covers a
// hardware SNP report, an MAA exchange and a Key Vault call, and containers in
// an ACI group start concurrently — the sidecar may still be coming up when the
// enclave makes its first request. The retries turn that startup race into a
// short wait instead of a crash-loop. A 403 is NOT retried: that is the release
// policy rejecting this measurement, and it will reject it again.
func newSKRHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   60 * time.Second,
		Transport: &retryTransport{base: http.DefaultTransport, attempts: 4, backoff: 500 * time.Millisecond},
	}
}

// newGoogleHTTPClient builds the client for the token exchange and the ~40
// Secret Manager fetches.
//
// 30s, not the 10s the GCP adapter uses, and with retries: on Confidential
// Space these are in-network metadata-adjacent calls, but from UAE North every
// one of them is a cross-cloud WAN round trip. internal/byokcache gives the
// same cross-cloud JWT exchange a 30s client for the same reason. Without the
// retries a single transient 503 anywhere in 41 calls is a boot failure, and
// main.go turns a boot failure into os.Exit(1) — a container-group crash-loop
// that re-runs the SNP report and MAA exchange on every restart.
func newGoogleHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &retryTransport{base: http.DefaultTransport, attempts: 4, backoff: 250 * time.Millisecond},
	}
}

// retryTransport retries a boot-path request that failed in a way a retry can
// fix. Deliberately narrow: transport errors, 429, and 5xx. A 4xx is a verdict
// (403 from the release policy, 403/404 from Secret Manager) and repeating it
// only delays a boot that is already doomed.
type retryTransport struct {
	base     http.RoundTripper
	attempts int
	backoff  time.Duration
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
		if err == nil && !retryableStatus(resp.StatusCode) {
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
func releaseWrappingKey(ctx context.Context, httpc *http.Client, cfg skrConfig) (*rsa.PrivateKey, error) {
	body, err := json.Marshal(skrRequest{
		MAAEndpoint: cfg.maaEndpoint,
		AKVEndpoint: cfg.akvEndpoint,
		KID:         cfg.keyID,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: skr release: marshal request: %w", azureTag, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%s: skr release: build request for %s: %w", azureTag, cfg.url, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: skr release: POST %s unreachable (is the skr sidecar running in this container group?): %w", azureTag, cfg.url, err)
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
// Errors name the missing/!bad field but never its value — every one of these
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

// loadSAKeyCiphertext reads the wrapped SA key from the environment.
//
// Inline and path forms are both supported because the two deploy paths differ:
// an ACI container group carries it as an env var, a mounted secret volume
// carries it as a file. Exactly one must be set — accepting both would leave
// "which one won?" ambiguous during an incident.
//
// Both forms go through decodeCiphertextBlob, so they accept the same bytes.
// They did not always: inline was base64-decoded and the path form was handed
// through raw, so writing the exact string you would have put in the env var
// into a file failed with an error blaming the vault key. That sends an
// incident down the wrong path over one layer of base64.
func loadSAKeyCiphertext() ([]byte, error) {
	inline := strings.TrimSpace(os.Getenv("QUILL_AZURE_SA_KEY_CIPHERTEXT"))
	path := strings.TrimSpace(os.Getenv("QUILL_AZURE_SA_KEY_CIPHERTEXT_PATH"))

	switch {
	case inline == "" && path == "":
		return nil, fmt.Errorf("%s: sa-key ciphertext: set exactly one of QUILL_AZURE_SA_KEY_CIPHERTEXT or QUILL_AZURE_SA_KEY_CIPHERTEXT_PATH", azureTag)
	case inline != "" && path != "":
		return nil, fmt.Errorf("%s: sa-key ciphertext: QUILL_AZURE_SA_KEY_CIPHERTEXT and QUILL_AZURE_SA_KEY_CIPHERTEXT_PATH are both set; set exactly one", azureTag)
	case path != "":
		raw, err := os.ReadFile(path) // #nosec G304 -- path comes from the workload spec, not from a request.
		if err != nil {
			return nil, fmt.Errorf("%s: sa-key ciphertext: read %s: %w", azureTag, path, err)
		}
		blob, err := decodeCiphertextBlob(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: sa-key ciphertext: %s: %w", azureTag, path, err)
		}
		return blob, nil
	default:
		blob, err := decodeCiphertextBlob([]byte(inline))
		if err != nil {
			return nil, fmt.Errorf("%s: sa-key ciphertext: QUILL_AZURE_SA_KEY_CIPHERTEXT: %w", azureTag, err)
		}
		return blob, nil
	}
}

// decodeCiphertextBlob normalises whatever the deploy supplied into envelope
// bytes: the envelope JSON, that JSON base64-encoded, or a bare OAEP ciphertext.
//
// The order matters. JSON is detected first so a textual envelope is never
// mistaken for something else. Base64 is tried second, with interior whitespace
// stripped because `base64` line-wraps at 76 columns by default. Anything else
// is returned EXACTLY as read — in particular NOT whitespace-trimmed, because
// OAEP output is uniform binary and ~4.6% of ciphertexts begin or end with a
// byte that happens to be ASCII whitespace. Trimming those silently shortened
// the blob and produced a decrypt failure telling the operator to rotate a
// vault key that was fine.
func decodeCiphertextBlob(raw []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("is empty")
	}
	if trimmed[0] == '{' {
		return trimmed, nil
	}
	if decoded, ok := decodeBase64Any(trimmed); ok {
		return decoded, nil
	}
	return raw, nil
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

// saKeyEnvelope is the hybrid wrapping format for the service-account key.
//
// Why hybrid and not a bare RSA-OAEP ciphertext: RSA-OAEP can only encrypt
// k - 2*hLen - 2 bytes, which with SHA-256 is 190 bytes under a 2048-bit key and
// 446 bytes under a 4096-bit key. A GCP service-account key JSON is ~2.3 KB. A
// direct OAEP blob of one is arithmetically impossible, so the payload rides
// under AES-256-GCM and only the 32-byte content key is OAEP-wrapped. The
// security property is unchanged — the content key is inert without the
// SKR-released private key.
//
// Produce one with (openssl/python, offline, using the vault key's PUBLIC half):
//
//	k  = os.urandom(32); nonce = os.urandom(12)
//	ct = AESGCM(k).encrypt(nonce, sa_key_json_bytes, None)
//	ek = pub.encrypt(k, OAEP(mgf1=SHA256, algorithm=SHA256, label=None))
//	json {"v":1,"alg":"RSA-OAEP-256+A256GCM","enc_key":b64(ek),
//	      "nonce":b64(nonce),"ciphertext":b64(ct)}
//
// OAEP parameters are fixed at SHA-256 for both the digest and MGF1, with no
// label. Key Vault calls this RSA-OAEP-256.
type saKeyEnvelope struct {
	V          int    `json:"v"`
	Alg        string `json:"alg"`
	EncKey     string `json:"enc_key"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// decryptSAKey unwraps the service-account key with the released private key.
//
// Accepts the hybrid envelope above, or — for a payload small enough to fit —
// a bare RSA-OAEP-SHA256 ciphertext. Detection is unambiguous: the envelope is
// a JSON object carrying enc_key, and a raw OAEP ciphertext never is.
func decryptSAKey(key *rsa.PrivateKey, blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("%s: sa-key decrypt: ciphertext is empty", azureTag)
	}

	var env saKeyEnvelope
	if err := json.Unmarshal(bytes.TrimSpace(blob), &env); err == nil && env.EncKey != "" {
		return decryptSAKeyEnvelope(key, env)
	}

	// Bare OAEP fallback.
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, blob, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: sa-key decrypt: %d-byte blob is neither a %s envelope nor a bare RSA-OAEP-SHA256 ciphertext this key can open (modulus %d bits; check it was encrypted to the CURRENT %s public key with SHA-256/MGF1-SHA256 and no label): %w",
			azureTag, len(blob), saKeyEnvelopeAlg, key.N.BitLen(), saKeyEnvelopeAlg, err)
	}
	return plaintext, nil
}

func decryptSAKeyEnvelope(key *rsa.PrivateKey, env saKeyEnvelope) ([]byte, error) {
	if env.V != saKeyEnvelopeVersion {
		return nil, fmt.Errorf("%s: sa-key decrypt: envelope version %d (this build understands %d)", azureTag, env.V, saKeyEnvelopeVersion)
	}
	if env.Alg != saKeyEnvelopeAlg {
		return nil, fmt.Errorf("%s: sa-key decrypt: envelope alg %q (this build understands %q)", azureTag, env.Alg, saKeyEnvelopeAlg)
	}
	encKey, err := base64.StdEncoding.DecodeString(env.EncKey)
	if err != nil {
		return nil, fmt.Errorf("%s: sa-key decrypt: envelope enc_key is not base64: %w", azureTag, err)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("%s: sa-key decrypt: envelope nonce is not base64: %w", azureTag, err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%s: sa-key decrypt: envelope ciphertext is not base64: %w", azureTag, err)
	}

	contentKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, encKey, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: sa-key decrypt: RSA-OAEP-SHA256 unwrap of the content key failed (released key modulus %d bits, enc_key %d bytes; check the envelope was encrypted to the CURRENT vault key with SHA-256/MGF1-SHA256 and no label): %w",
			azureTag, key.N.BitLen(), len(encKey), err)
	}

	// Checked before aes.NewCipher, which accepts 16 and 24 as well and would
	// otherwise let an envelope labelled A256GCM open under AES-128.
	if len(contentKey) != saKeyContentKeyBytes {
		return nil, fmt.Errorf("%s: sa-key decrypt: unwrapped content key is %d bytes, but %s means %d",
			azureTag, len(contentKey), saKeyEnvelopeAlg, saKeyContentKeyBytes)
	}
	block, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, fmt.Errorf("%s: sa-key decrypt: unwrapped content key is not a valid AES key (%d bytes): %w", azureTag, len(contentKey), err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%s: sa-key decrypt: init AES-GCM: %w", azureTag, err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("%s: sa-key decrypt: envelope nonce is %d bytes (want %d)", azureTag, len(nonce), gcm.NonceSize())
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: sa-key decrypt: AES-GCM open failed — the envelope is corrupt or was not sealed with this content key: %w", azureTag, err)
	}
	return plaintext, nil
}

// serviceAccountKey is the subset of a Google SA key JSON needed to sign the
// bearer assertion.
type serviceAccountKey struct {
	Type        string `json:"type"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

// mintGoogleAccessToken runs the JWT-bearer flow: sign an RS256 assertion with
// the service-account key, POST it to Google's token endpoint, get an access
// token scoped to cloud-platform.
//
// Hand-rolled on stdlib crypto by design — see the dependency note in the
// package comment. The identical flow exists as unexported helpers in
// internal/enclavetls and internal/byokcache, but both read the key from a file
// path and cache expiry on a long-lived token source; bootstrap holds the key
// in memory, needs exactly one token, and must not depend on either package.
func mintGoogleAccessToken(ctx context.Context, httpc *http.Client, saKeyJSON []byte) (string, error) {
	var sa serviceAccountKey
	if err := json.Unmarshal(saKeyJSON, &sa); err != nil {
		// Length only: the decrypted bytes are the credential.
		return "", fmt.Errorf("%s: google token: decrypted sa-key is not JSON (%d bytes; content withheld): %w", azureTag, len(saKeyJSON), err)
	}
	if sa.Type != "service_account" {
		return "", fmt.Errorf("%s: google token: sa-key type %q (want service_account)", azureTag, sa.Type)
	}
	if sa.ClientEmail == "" || sa.PrivateKey == "" {
		return "", fmt.Errorf("%s: google token: sa-key is missing client_email or private_key", azureTag)
	}

	signer, err := parsePEMRSAPrivateKey(sa.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("%s: google token: sa-key private_key: %w", azureTag, err)
	}

	tokenURI := sa.TokenURI
	if tokenURI == "" {
		tokenURI = googleTokenEndpoint
	}

	now := time.Now()
	header := `{"alg":"RS256","typ":"JWT"}`
	claims := fmt.Sprintf(
		`{"iss":%q,"scope":%q,"aud":%q,"exp":%d,"iat":%d}`,
		sa.ClientEmail, googleCloudPlatformScope, tokenURI, now.Add(time.Hour).Unix(), now.Unix(),
	)
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(header)) +
		"." + base64.RawURLEncoding.EncodeToString([]byte(claims))
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, signer, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("%s: google token: sign assertion: %w", azureTag, err)
	}
	assertion := signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("%s: google token: build request for %s: %w", azureTag, tokenURI, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpc.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s: google token: POST %s: %w", azureTag, tokenURI, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Google's non-200 body is an OAuth error envelope
		// ({"error":"invalid_grant",...}) — diagnostic, never credential.
		errBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 2048))
		if readErr != nil {
			return "", fmt.Errorf("%s: google token: jwt-bearer exchange http %d and error body unreadable: %w", azureTag, resp.StatusCode, readErr)
		}
		return "", fmt.Errorf("%s: google token: jwt-bearer exchange for %s http %d: %s", azureTag, sa.ClientEmail, resp.StatusCode, errBody)
	}

	var decoded struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		// A 200 body carries the access token; withhold it.
		return "", fmt.Errorf("%s: google token: 200 response is not JSON (body withheld because it may contain a token): %w", azureTag, err)
	}
	if decoded.AccessToken == "" {
		return "", fmt.Errorf("%s: google token: jwt-bearer exchange returned an empty access_token", azureTag)
	}
	return decoded.AccessToken, nil
}

// parsePEMRSAPrivateKey decodes a PEM-encoded RSA key in either PKCS#1 or
// PKCS#8 form. Google issues PKCS#8 ("PRIVATE KEY"); PKCS#1 is accepted because
// re-wrapped keys occasionally arrive that way.
func parsePEMRSAPrivateKey(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse pkcs1: %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse pkcs8: %w", err)
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("pkcs8 key is %T, want *rsa.PrivateKey", parsed)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}
