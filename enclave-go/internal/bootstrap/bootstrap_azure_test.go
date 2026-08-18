//go:build cloud_azure

package bootstrap

import (
	"bytes"
	"context"
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
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// These tests exercise the REAL crypto: a genuine RSA keypair is generated, a
// genuine hybrid envelope is sealed to it, and Fetch's OAEP unwrap has to open
// it. Stubbing the decrypt would leave the OAEP parameters (SHA-256 digest,
// MGF1-SHA256, nil label) unverified, and getting those wrong is exactly the
// class of mistake that only shows up against real hardware — the same way the
// first draft of attestation_azure.go used SHA-512 and would never have
// verified a single token.
//
// The three endpoints Fetch talks to are all in Azure: the skr sidecar
// (loopback), IMDS, and Key Vault. There is no Google endpoint, and
// TestFetchMakesNoCallToGoogle drives that rather than asserting it in prose.

// The *Secret constants below are secret NAMES, not secret values — the whole
// point of the binding table is that a name is a public coordinate and only the
// bundle carries values. gosec's G101 heuristic cannot tell the two apart, and
// these had to be annotated when cloud_azure joined the CI lint matrix.
const (
	testSAEmail       = "tr-azure@quill-cloud-proxy.iam.gserviceaccount.com"
	testProject       = "quill-cloud-proxy"
	testDevicesSecret = "tr-device-keys"        // #nosec G101 -- secret NAME, not a credential.
	testORSecret      = "tr-openrouter-key"     // #nosec G101 -- secret NAME, not a credential.
	testAnthSecret    = "tr-anthropic-key"      // #nosec G101 -- secret NAME, not a credential.
	testBundleSecret  = "tr-bootstrap-bundle"   // #nosec G101 -- Key Vault secret NAME, not a credential.
	testSAKeyEntry    = "tr-cross-cloud-sa-key" // #nosec G101 -- bundle entry NAME, not a credential.
	testAKVEndpoint   = "trquillkv.vault.azure.net"
	testMAAEndpoint   = "trquilluaen.uaen.attest.azure.net"
	testSKRKeyID      = "tr-bootstrap-wrap"
	// Not a real token: a fixture string the fake IMDS hands back so the fake
	// vault can check the Authorization header.
	testVaultToken = "eyJ0eXAiOiJKV1QTEST-MANAGED-IDENTITY-TOKEN" // #nosec G101 -- test fixture, not a credential.

	// Distinctive so the leak scan cannot produce a false negative.
	testORValue   = "sk-or-v1-OPENROUTER-SECRET-VALUE-DO-NOT-LOG"
	testAnthValue = "sk-ant-ANTHROPIC-SECRET-VALUE-DO-NOT-LOG"
)

// RSA keygen is the slowest thing in this file, so generate once per package.
var (
	keysOnce     sync.Once
	sharedWrap   *rsa.PrivateKey // stands in for the Key Vault RSA-HSM key
	sharedSA     *rsa.PrivateKey // the service-account signing key
	sharedForeig *rsa.PrivateKey // an unrelated key, for the negative control
)

func testKeys(t *testing.T) (wrap, sa, foreign *rsa.PrivateKey) {
	t.Helper()
	keysOnce.Do(func() {
		var err error
		if sharedWrap, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if sharedSA, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if sharedForeig, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
	return sharedWrap, sharedSA, sharedForeig
}

// ---------------------------------------------------------------------------
// fixture
// ---------------------------------------------------------------------------

// azureFixture stands up the three endpoints Fetch talks to — the skr sidecar,
// IMDS, and Key Vault — and wires the environment at them. Tests steer a
// failure by overriding one handler, or by mutating the bundle, before calling
// Fetch.
type azureFixture struct {
	t *testing.T

	wrapKey   *rsa.PrivateKey
	saKey     *rsa.PrivateKey
	foreign   *rsa.PrivateKey
	saKeyJSON []byte

	// bundle is sealed fresh on every Key Vault request, so a test can mutate
	// it right up to the call.
	bundle  map[string]string
	sealPub *rsa.PublicKey

	// rawVaultValue, when non-empty, is returned as the secret's value verbatim
	// instead of a freshly sealed bundle. This is the seam every
	// envelope-tampering test uses.
	rawVaultValue string

	// Handler overrides; nil means "behave correctly".
	skrHandler   http.HandlerFunc
	imdsHandler  http.HandlerFunc
	vaultHandler http.HandlerFunc

	mu           sync.Mutex
	seenSKR      []skrRequest
	seenVaultReq []*http.Request
	seenIMDSReq  []*http.Request

	skrSrv, imdsSrv, vaultSrv *httptest.Server
}

func newAzureFixture(t *testing.T) *azureFixture {
	t.Helper()
	wrap, sa, foreign := testKeys(t)
	f := &azureFixture{
		t:       t,
		wrapKey: wrap,
		saKey:   sa,
		foreign: foreign,
		sealPub: wrap.Public().(*rsa.PublicKey),
	}
	f.saKeyJSON = makeSAKeyJSON(t, f.saKey)
	f.bundle = map[string]string{
		testDevicesSecret: `[{"key_hash":"c0ffee","owner":"joseph","device_id":"dev-1"}]`,
		testORSecret:      testORValue,
		testAnthSecret:    testAnthValue,
		testSAKeyEntry:    string(f.saKeyJSON),
	}

	f.skrSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Record every release attempt, including its parameters. This is the
		// evidence that the attestation-gated step actually ran — see
		// TestSKRReleaseStepIsActuallyExercised.
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		var decoded skrRequest
		_ = json.Unmarshal(body, &decoded)
		f.mu.Lock()
		f.seenSKR = append(f.seenSKR, decoded)
		f.mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(body))

		if f.skrHandler != nil {
			f.skrHandler(w, r)
			return
		}
		f.serveSKR(w, r)
	}))
	t.Cleanup(f.skrSrv.Close)

	f.imdsSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.seenIMDSReq = append(f.seenIMDSReq, r.Clone(r.Context()))
		f.mu.Unlock()
		if f.imdsHandler != nil {
			f.imdsHandler(w, r)
			return
		}
		f.serveIMDS(w, r)
	}))
	t.Cleanup(f.imdsSrv.Close)

	f.vaultSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.seenVaultReq = append(f.seenVaultReq, r.Clone(r.Context()))
		f.mu.Unlock()
		if f.vaultHandler != nil {
			f.vaultHandler(w, r)
			return
		}
		f.serveVault(w, r)
	}))
	t.Cleanup(f.vaultSrv.Close)

	prevIMDS := imdsBaseURL
	imdsBaseURL = f.imdsSrv.URL
	t.Cleanup(func() { imdsBaseURL = prevIMDS })

	prevVault := keyVaultBaseURLOverride
	keyVaultBaseURLOverride = f.vaultSrv.URL
	t.Cleanup(func() { keyVaultBaseURLOverride = prevVault })

	t.Setenv("QUILL_AZURE_MAA_ENDPOINT", testMAAEndpoint)
	t.Setenv("QUILL_AZURE_AKV_ENDPOINT", testAKVEndpoint)
	t.Setenv("QUILL_AZURE_SKR_KEY_ID", testSKRKeyID)
	t.Setenv("QUILL_AZURE_SKR_URL", f.skrSrv.URL+"/key/release")
	t.Setenv("QUILL_AZURE_BUNDLE_SECRET", testBundleSecret)
	t.Setenv("QUILL_AZURE_SA_KEY_ENTRY", testSAKeyEntry)
	t.Setenv("QUILL_AZURE_MI_CLIENT_ID", "")
	t.Setenv("QUILL_AZURE_REGION", "uaenorth")

	t.Setenv("QUILL_GCP_PROJECT_ID", testProject)
	t.Setenv("QUILL_DEVICE_KEYS_SECRET", testDevicesSecret)
	t.Setenv("QUILL_OPENROUTER_SECRET", testORSecret)
	t.Setenv("QUILL_ANTHROPIC_SECRET", testAnthSecret)

	return f
}

func (f *azureFixture) serveSKR(w http.ResponseWriter, r *http.Request) {
	var req skrRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// The sidecar contract: all three are required and are what the vault's
	// release policy is evaluated against.
	if req.MAAEndpoint == "" || req.AKVEndpoint == "" || req.KID == "" {
		http.Error(w, "missing maa_endpoint/akv_endpoint/kid", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"key": jwkFromRSAPrivate(f.wrapKey)})
}

func (f *azureFixture) serveIMDS(w http.ResponseWriter, r *http.Request) {
	// IMDS refuses anything without this header.
	if r.Header.Get("Metadata") != "true" {
		http.Error(w, `{"error":"invalid_request","error_description":"Required metadata header not specified"}`, http.StatusBadRequest)
		return
	}
	if got := r.URL.Query().Get("resource"); got != "https://vault.azure.net" {
		http.Error(w, fmt.Sprintf(`{"error":"invalid_resource","got":%q}`, got), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": testVaultToken,
		"resource":     "https://vault.azure.net",
		"token_type":   "Bearer",
		"expires_in":   "86399",
	})
}

func (f *azureFixture) serveVault(w http.ResponseWriter, r *http.Request) {
	// The vault authenticates the managed-identity token, not the workload.
	if r.Header.Get("Authorization") != "Bearer "+testVaultToken {
		http.Error(w, `{"error":{"code":"Unauthorized","message":"AKV10000: bad token"}}`, http.StatusUnauthorized)
		return
	}
	value := f.rawVaultValue
	if value == "" {
		value = base64.StdEncoding.EncodeToString(f.sealBundle())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":    "https://" + testAKVEndpoint + "/secrets/" + testBundleSecret + "/abc123",
		"value": value,
	})
}

// sealBundle marshals the current bundle and seals it to sealPub.
func (f *azureFixture) sealBundle() []byte {
	f.t.Helper()
	plaintext, err := json.Marshal(f.bundle)
	if err != nil {
		f.t.Fatalf("marshal bundle: %v", err)
	}
	return sealEnvelope(f.t, f.sealPub, plaintext)
}

func (f *azureFixture) skrRequests() []skrRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]skrRequest(nil), f.seenSKR...)
}

func (f *azureFixture) vaultRequests() []*http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*http.Request(nil), f.seenVaultReq...)
}

func (f *azureFixture) imdsRequests() []*http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*http.Request(nil), f.seenIMDSReq...)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func jwkFromRSAPrivate(key *rsa.PrivateKey) string {
	b64 := base64.RawURLEncoding.EncodeToString
	raw, err := json.Marshal(map[string]string{
		// Key Vault spells an HSM-backed key "RSA-HSM"; that is what the real
		// sidecar returns for an exportable RSA-HSM key.
		"kty": "RSA-HSM",
		"n":   b64(key.N.Bytes()),
		"e":   b64(big.NewInt(int64(key.E)).Bytes()),
		"d":   b64(key.D.Bytes()),
		"p":   b64(key.Primes[0].Bytes()),
		"q":   b64(key.Primes[1].Bytes()),
	})
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// sealEnvelope builds a genuine RSA-OAEP-256 + AES-256-GCM envelope, matching
// the recipe documented on secretEnvelope.
func sealEnvelope(t *testing.T, pub *rsa.PublicKey, plaintext []byte) []byte {
	t.Helper()
	return sealEnvelopeWithContentKeySize(t, pub, plaintext, 32)
}

// sealEnvelopeWithContentKeySize seals with a chosen content-key size while
// still labelling the envelope A256GCM, which is how the AES-128 downgrade
// tests are built.
func sealEnvelopeWithContentKeySize(t *testing.T, pub *rsa.PublicKey, plaintext []byte, size int) []byte {
	t.Helper()
	contentKey := make([]byte, size)
	if _, err := rand.Read(contentKey); err != nil {
		t.Fatalf("content key: %v", err)
	}
	block, err := aes.NewCipher(contentKey)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, contentKey, nil)
	if err != nil {
		t.Fatalf("oaep wrap: %v", err)
	}
	// Literals, not the package constants: this is a WIRE format shared with
	// the offline tool that produces the bundle, so the test must pin the bytes
	// rather than agree with whatever the code currently says.
	raw, err := json.Marshal(secretEnvelope{
		V:          1,
		Alg:        "RSA-OAEP-256+A256GCM",
		EncKey:     base64.StdEncoding.EncodeToString(encKey),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return raw
}

func makeSAKeyJSON(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	raw, err := json.Marshal(map[string]string{
		"type":         "service_account",
		"project_id":   testProject,
		"client_email": testSAEmail,
		"private_key":  string(pemBytes),
		"token_uri":    "https://oauth2.googleapis.com/token",
	})
	if err != nil {
		t.Fatalf("marshal sa key: %v", err)
	}
	return raw
}

func requireErrContains(t *testing.T, err error, wants ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want error containing %q, got nil", wants)
	}
	for _, want := range wants {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %q\n  got: %v", want, err)
		}
	}
}

// captureOutput redirects stdout, stderr and the log package for the duration
// of fn. Bootstrap is supposed to be silent — it returns errors rather than
// printing — and this is what proves it stays that way.
func captureOutput(t *testing.T, fn func()) string {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	oldLog := log.Writer()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout, os.Stderr = w, w
	log.SetOutput(w)

	collected := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		collected <- buf.String()
	}()

	func() {
		defer func() {
			os.Stdout, os.Stderr = oldOut, oldErr
			log.SetOutput(oldLog)
			_ = w.Close()
		}()
		fn()
	}()

	out := <-collected
	_ = r.Close()
	return out
}

// tamperEnvelope seals the current bundle, lets fn mutate the envelope, and
// installs the result as the Key Vault secret's raw value.
func (f *azureFixture) tamperEnvelope(fn func(env *secretEnvelope)) {
	f.t.Helper()
	var env secretEnvelope
	if err := json.Unmarshal(f.sealBundle(), &env); err != nil {
		f.t.Fatalf("unmarshal envelope: %v", err)
	}
	fn(&env)
	raw, err := json.Marshal(env)
	if err != nil {
		f.t.Fatalf("marshal envelope: %v", err)
	}
	f.rawVaultValue = base64.StdEncoding.EncodeToString(raw)
}

// ---------------------------------------------------------------------------
// happy path
// ---------------------------------------------------------------------------

func TestFetchHappyPath(t *testing.T) {
	f := newAzureFixture(t)

	data, err := Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if len(data.Devices) != 1 || data.Devices[0].DeviceID != "dev-1" {
		t.Errorf("devices not assembled from the bundle: %+v", data.Devices)
	}
	if data.OpenRouterAPIKey != testORValue {
		t.Errorf("openrouter key = %q", data.OpenRouterAPIKey)
	}
	if data.AnthropicAPIKey != testAnthValue {
		t.Errorf("anthropic key = %q", data.AnthropicAPIKey)
	}
	if data.Region != "uaenorth" {
		t.Errorf("region = %q, want QUILL_AZURE_REGION to win", data.Region)
	}
	// gcscache and byokcache authenticate to Google at RUNTIME, so main.go
	// still needs this to write to tmpfs. It rides in the bundle, which is what
	// keeps BOOT free of Google calls.
	if data.GCPServiceAccountKeyJSON != string(f.saKeyJSON) {
		t.Errorf("SA key JSON not populated from the bundle (len %d, want %d)",
			len(data.GCPServiceAccountKeyJSON), len(f.saKeyJSON))
	}

	// Exactly one Key Vault round trip: the bundle exists so that ~40 fetches
	// become one.
	if got := len(f.vaultRequests()); got != 1 {
		t.Errorf("Key Vault was called %d times, want exactly 1", got)
	}
}

// Secret payloads routinely carry a trailing newline (anything created with
// `printf ... | gcloud secrets create --data-file=-` does, and a bundle built by
// dumping them inherits it). An API key with "\n" on the end produces an
// unparseable Authorization header and a 401 that looks like a bad key.
func TestFetchTrimsWhitespaceFromBundleValues(t *testing.T) {
	f := newAzureFixture(t)
	f.bundle[testORSecret] = "  " + testORValue + "\n"
	f.bundle[testAnthSecret] = testAnthValue + "\r\n"

	data, err := Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if data.OpenRouterAPIKey != testORValue {
		t.Errorf("openrouter key not trimmed: %q", data.OpenRouterAPIKey)
	}
	if data.AnthropicAPIKey != testAnthValue {
		t.Errorf("anthropic key not trimmed: %q", data.AnthropicAPIKey)
	}
}

// The Key Vault secret is a string, and an operator may store the envelope JSON
// directly rather than base64 of it. Both must work: the alternative is a
// boot-fatal error over one layer of base64, which sends an incident down the
// wrong path.
func TestFetchAcceptsRawAndBase64EnvelopeFromTheVault(t *testing.T) {
	for _, form := range []struct {
		name   string
		encode func([]byte) string
	}{
		{"raw envelope JSON", func(b []byte) string { return string(b) }},
		{"base64 of the envelope", base64.StdEncoding.EncodeToString},
		{"base64url of the envelope", base64.RawURLEncoding.EncodeToString},
		{"base64, line-wrapped at 76 columns", func(b []byte) string {
			return wrapLines(base64.StdEncoding.EncodeToString(b), 76)
		}},
		{"raw envelope JSON with surrounding whitespace", func(b []byte) string { return "\n  " + string(b) + "\n" }},
	} {
		t.Run(form.name, func(t *testing.T) {
			f := newAzureFixture(t)
			f.rawVaultValue = form.encode(f.sealBundle())

			data, err := Fetch(context.Background())
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if data.OpenRouterAPIKey != testORValue {
				t.Errorf("openrouter key = %q", data.OpenRouterAPIKey)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// independence from Google — the point of the whole exercise
// ---------------------------------------------------------------------------

// hostRecorder records every host Fetch dials and fails outright on any Google
// endpoint, so this is a drive rather than an assertion about prose.
type hostRecorder struct {
	base  http.RoundTripper
	mu    sync.Mutex
	hosts []string
	googl []string
}

func (h *hostRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()
	h.mu.Lock()
	h.hosts = append(h.hosts, host)
	isGoogle := false
	for _, banned := range []string{"googleapis.com", "google.internal", "google.com", "googleusercontent.com"} {
		if host == banned || strings.HasSuffix(host, "."+banned) {
			isGoogle = true
			h.googl = append(h.googl, req.URL.String())
		}
	}
	h.mu.Unlock()
	if isGoogle {
		return nil, fmt.Errorf("hostRecorder: refused a request to Google endpoint %s", req.URL)
	}
	return h.base.RoundTrip(req)
}

// TestFetchMakesNoCallToGoogle is the BEHAVIOURAL half of the regression test
// for the architecture.
//
// The Azure adapter used to unwrap a GCP service-account key, mint a Google
// OAuth token, and pull ~39 secrets from secretmanager.googleapis.com — so a
// Google outage took down the cloud whose entire job is to survive one. This
// installs a transport that makes any Google dial fail, and requires a COMPLETE,
// SUCCESSFUL boot through it.
//
// KNOWN LIMIT, established by mutation rather than assumed: this catches a
// reintroduced Google call only if it goes through http.DefaultTransport.
// Mutation A — http.DefaultClient.Get("https://secretmanager.googleapis.com/...")
// on the boot path — turns this red. Mutation B — the same call through a client
// carrying its OWN &http.Transport{} — SURVIVES it, because the seam this test
// swaps is never consulted. A transport-level assertion cannot close that on its
// own, so the structural half below does, and neither test is sufficient alone.
func TestFetchMakesNoCallToGoogle(t *testing.T) {
	f := newAzureFixture(t)

	recorder := &hostRecorder{base: http.DefaultTransport}
	prev := http.DefaultTransport
	http.DefaultTransport = recorder
	t.Cleanup(func() { http.DefaultTransport = prev })

	data, err := Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if data.OpenRouterAPIKey != testORValue {
		t.Fatalf("boot did not actually complete: openrouter key = %q", data.OpenRouterAPIKey)
	}

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if len(recorder.googl) > 0 {
		t.Fatalf("boot dialled Google: %v", recorder.googl)
	}
	// Stronger than a deny-list: enumerate what WAS dialled and require it to be
	// only the three Azure-side endpoints. A new dependency on any fourth host
	// — Google or otherwise — has to be justified here first.
	allowed := map[string]bool{
		mustHost(t, f.skrSrv.URL):   true,
		mustHost(t, f.imdsSrv.URL):  true,
		mustHost(t, f.vaultSrv.URL): true,
	}
	for _, host := range recorder.hosts {
		if !allowed[host] {
			t.Errorf("boot dialled unexpected host %q (want only the skr sidecar, IMDS and Key Vault)", host)
		}
	}
	if len(recorder.hosts) == 0 {
		t.Error("no requests recorded — the transport seam did not take effect, so this test proved nothing")
	}
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return parsed.Hostname()
}

// ---------------------------------------------------------------------------
// the trust gate itself
// ---------------------------------------------------------------------------

// TestSKRReleaseStepIsActuallyExercised is the regression test for the gate.
//
// Everything else in this file would still pass if the SKR round trip were
// replaced by something that produces a key locally, as long as that key could
// open the bundle. This test fails on any such mutation: it requires that the
// sidecar was contacted, exactly once, with the exact MAA authority, vault and
// key id the environment names — the three values the vault's release policy is
// evaluated against. Skip the release, default one of them, or send them from
// anywhere other than the validated config, and this goes red.
func TestSKRReleaseStepIsActuallyExercised(t *testing.T) {
	f := newAzureFixture(t)

	if _, err := Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	requests := f.skrRequests()
	if len(requests) != 1 {
		t.Fatalf("skr sidecar was contacted %d times, want exactly 1 — the attestation-gated release is not on the boot path", len(requests))
	}
	// Literals, not the config struct: comparing the code's own values against
	// themselves would pass no matter what got sent.
	if requests[0].MAAEndpoint != "trquilluaen.uaen.attest.azure.net" {
		t.Errorf("maa_endpoint = %q — the release would be evaluated against the wrong attestation authority", requests[0].MAAEndpoint)
	}
	if requests[0].AKVEndpoint != "trquillkv.vault.azure.net" {
		t.Errorf("akv_endpoint = %q", requests[0].AKVEndpoint)
	}
	if requests[0].KID != "tr-bootstrap-wrap" {
		t.Errorf("kid = %q", requests[0].KID)
	}
}

// TestManagedIdentityAloneCannotReadTheSecrets is the reason the bundle is
// encrypted at all.
//
// The obvious design — let the managed identity read plaintext secrets from Key
// Vault — would make the SEV-SNP measurement irrelevant, because an identity is
// attached to a container group and not to a measurement: any operator with the
// RBAC role, any future container in the group, any compromised deploy pipeline
// could read them. This asserts the property directly: what the identity is
// served contains none of the secrets, and only the SKR-released key turns it
// into something.
func TestManagedIdentityAloneCannotReadTheSecrets(t *testing.T) {
	f := newAzureFixture(t)

	if _, err := Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	// Exactly what the vault serves to a holder of the managed-identity token.
	served := base64.StdEncoding.EncodeToString(f.sealBundle())
	for label, secret := range map[string]string{
		"openrouter key":                  testORValue,
		"anthropic key":                   testAnthValue,
		"service-account private key PEM": pemBody(t, f.saKeyJSON),
	} {
		if strings.Contains(served, secret) {
			t.Errorf("%s is readable by anything holding the managed identity — the vault secret is not actually encrypted", label)
		}
	}

	// And the ciphertext is worthless to a key that is not the released one.
	if _, err := decryptEnvelope(f.foreign, f.sealBundle()); err == nil {
		t.Error("a foreign RSA key opened the bundle")
	}
}

// The released key is not decoration: it is the ONLY thing that opens the
// bundle. A locally invented key, however well-formed, must not boot the
// enclave.
func TestOnlyTheReleasedKeyOpensTheBundle(t *testing.T) {
	f := newAzureFixture(t)
	substitute, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	f.skrHandler = func(w http.ResponseWriter, r *http.Request) {
		// A perfectly valid RSA private JWK — just not the one the vault holds.
		writeJSON(w, http.StatusOK, map[string]string{"key": jwkFromRSAPrivate(substitute)})
	}

	_, err = Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "bundle decrypt", "RSA-OAEP-SHA256")
}

// QUILL_AZURE_SKR_URL decides whether attestation happens at all. Left
// unconstrained it was a complete bypass: an off-box endpoint returning any RSA
// JWK, plus a bundle sealed to it, boots the enclave on an attacker's secrets
// with no MAA exchange, no Key Vault call and no hostdata check — while
// /attestation keeps serving a genuine token for the real measurement.
func TestFetchRefusesNonLoopbackSKRURL(t *testing.T) {
	f := newAzureFixture(t)
	t.Setenv("QUILL_AZURE_SKR_URL", "http://skr.attacker.example/key/release")

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "azure config", "QUILL_AZURE_SKR_URL", "not loopback")
	if got := len(f.skrRequests()); got != 0 {
		t.Errorf("the real sidecar was contacted %d times; the URL must be rejected before any I/O", got)
	}
}

func TestValidateSKRURLAcceptsOnlyLoopback(t *testing.T) {
	ok := []string{
		"http://localhost:8080/key/release",
		"http://127.0.0.1:8080/key/release",
		"http://[::1]:8080/key/release",
		"https://localhost:8080/key/release", // a locally terminated TLS sidecar
		"http://127.0.0.5:8284/key/release",  // the port is what sidecar versions change
	}
	for _, raw := range ok {
		if err := validateSKRURL(raw); err != nil {
			t.Errorf("validateSKRURL(%q) = %v, want nil", raw, err)
		}
	}
	bad := []string{
		"http://skr.attacker.example/key/release",
		"http://10.0.0.7:8080/key/release",
		"http://169.254.169.254/key/release", // the cloud metadata address
		"http://skr:8080/key/release",        // a sibling container by DNS name
		"file:///tmp/key.json",
		"://nonsense",
	}
	for _, raw := range bad {
		if err := validateSKRURL(raw); err == nil {
			t.Errorf("validateSKRURL(%q) = nil, want an error", raw)
		}
	}
}

// ---------------------------------------------------------------------------
// skr sidecar failures
// ---------------------------------------------------------------------------

func TestFetchSidecarUnreachable(t *testing.T) {
	newAzureFixture(t)
	// A server that has been closed leaves a port nothing is listening on.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	t.Setenv("QUILL_AZURE_SKR_URL", deadURL+"/key/release")

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "skr release", "unreachable", "skr sidecar")
}

// A 403 here is the attestation gate doing its job — the measured negative
// control on real hardware produced exactly this. The error must point at the
// measurement, not just say "403".
func TestFetchSidecarForbiddenNamesTheMeasurement(t *testing.T) {
	f := newAzureFixture(t)
	f.skrHandler = func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Forbidden: release policy not satisfied", http.StatusForbidden)
	}

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "skr release", "403", "hostdata", "tr-bootstrap-wrap")
}

func TestFetchSidecarReturnsNonJSON(t *testing.T) {
	f := newAzureFixture(t)
	const junk = "<html><body>proxy error</body></html>"
	f.skrHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, junk)
	}

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "skr release", "not JSON", "text/html")
	// A 200 body is where the private key lives. Even when it turns out to be
	// junk, echoing it is not allowed — the code cannot know that in advance.
	if strings.Contains(err.Error(), junk) {
		t.Errorf("error echoed the 200 body, which may carry key material: %v", err)
	}
}

func TestFetchReleasedKeyNotParseable(t *testing.T) {
	f := newAzureFixture(t)
	f.skrHandler = func(w http.ResponseWriter, r *http.Request) {
		// Public-only JWK: no d/p/q, so it cannot decrypt anything.
		pubOnly := `{"kty":"RSA","n":"sXchDaQ","e":"AQAB"}`
		writeJSON(w, http.StatusOK, map[string]string{"key": pubOnly})
	}

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "skr release", "missing field", `"d"`)
}

func TestFetchReleasedKeyIsInconsistent(t *testing.T) {
	f := newAzureFixture(t)
	f.skrHandler = func(w http.ResponseWriter, r *http.Request) {
		// Structurally complete but mathematically nonsense.
		b64 := base64.RawURLEncoding.EncodeToString
		bogus, _ := json.Marshal(map[string]string{
			"kty": "RSA", "n": b64([]byte{0xff, 0xff}), "e": b64([]byte{0x01, 0x00, 0x01}),
			"d": b64([]byte{0x07}), "p": b64([]byte{0x03}), "q": b64([]byte{0x05}),
		})
		writeJSON(w, http.StatusOK, map[string]string{"key": string(bogus)})
	}

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "skr release", "not a consistent RSA private key")
}

func TestFetchRejectsNonRSAReleasedKey(t *testing.T) {
	f := newAzureFixture(t)
	f.skrHandler = func(w http.ResponseWriter, r *http.Request) {
		// Every RSA field present, but the vault handed back an EC key. Reject
		// on kty rather than letting it fail later as an unreadable bignum.
		swapped := strings.Replace(jwkFromRSAPrivate(f.wrapKey), `"kty":"RSA-HSM"`, `"kty":"EC-HSM"`, 1)
		writeJSON(w, http.StatusOK, map[string]string{"key": swapped})
	}

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "skr release", "kty=", "want RSA or RSA-HSM")
}

// The body echo is gated on 2xx, not on 200. A sidecar answering 201 or 202
// with the released key used to print the whole private JWK into the bootstrap
// error, which main.go writes to stderr and ACI ships to Log Analytics.
func TestFetchWithholdsTheBodyOnAny2xx(t *testing.T) {
	f := newAzureFixture(t)
	jwk := jwkFromRSAPrivate(f.wrapKey)
	for _, status := range []int{http.StatusCreated, http.StatusAccepted, http.StatusNoContent} {
		t.Run(fmt.Sprintf("http %d", status), func(t *testing.T) {
			f.skrHandler = func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, status, map[string]string{"key": jwk})
			}
			_, err := Fetch(context.Background())
			requireErrContains(t, err, "bootstrap/azure", "skr release", "body withheld")

			var fields map[string]string
			if e := json.Unmarshal([]byte(jwk), &fields); e != nil {
				t.Fatalf("jwk: %v", e)
			}
			for _, name := range []string{"d", "p", "q"} {
				if strings.Contains(err.Error(), fields[name]) {
					t.Errorf("private JWK field %q leaked into the error on http %d", name, status)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// IMDS — the managed-identity token
// ---------------------------------------------------------------------------

// The request shape is a contract with a live Azure service. Getting the header
// or the resource wrong is a boot failure in production that no unit test would
// otherwise catch.
func TestIMDSRequestShape(t *testing.T) {
	f := newAzureFixture(t)
	if _, err := Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	requests := f.imdsRequests()
	if len(requests) != 1 {
		t.Fatalf("IMDS called %d times, want 1", len(requests))
	}
	req := requests[0]
	if req.URL.Path != "/metadata/identity/oauth2/token" {
		t.Errorf("IMDS path = %q", req.URL.Path)
	}
	// Literals, not the package constants: comparing the code's own values
	// against themselves passes no matter what they are changed to.
	if got := req.Header.Get("Metadata"); got != "true" {
		t.Errorf("Metadata header = %q, want \"true\" — IMDS refuses the request without it", got)
	}
	if got := req.URL.Query().Get("resource"); got != "https://vault.azure.net" {
		t.Errorf("resource = %q — a token for any other audience is rejected by Key Vault with 401", got)
	}
	if got := req.URL.Query().Get("api-version"); got != "2018-02-01" {
		t.Errorf("api-version = %q", got)
	}
	if got := req.URL.Query().Get("client_id"); got != "" {
		t.Errorf("client_id = %q, want it omitted when QUILL_AZURE_MI_CLIENT_ID is unset", got)
	}
}

// A container group with several user-assigned identities makes IMDS refuse to
// guess, so the client id has to be forwarded when the deploy names one.
func TestIMDSForwardsTheManagedIdentityClientID(t *testing.T) {
	f := newAzureFixture(t)
	t.Setenv("QUILL_AZURE_MI_CLIENT_ID", "6f4a1e00-0000-4000-8000-abcdefabcdef")

	if _, err := Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	requests := f.imdsRequests()
	if len(requests) != 1 {
		t.Fatalf("IMDS called %d times, want 1", len(requests))
	}
	if got := requests[0].URL.Query().Get("client_id"); got != "6f4a1e00-0000-4000-8000-abcdefabcdef" {
		t.Errorf("client_id = %q", got)
	}
}

func TestFetchIMDSUnreachable(t *testing.T) {
	f := newAzureFixture(t)
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	imdsBaseURL = deadURL

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "imds token", "unreachable", "managed identity")
	// The gate ran first, so a failure here is not an attestation failure and
	// the error must not look like one.
	if got := len(f.skrRequests()); got != 1 {
		t.Errorf("skr requests = %d, want the release to have happened before IMDS", got)
	}
	if strings.Contains(err.Error(), "hostdata") {
		t.Errorf("an IMDS failure blamed the attestation gate: %v", err)
	}
}

// A container group with no identity attached is the single most likely deploy
// mistake here, and IMDS reports it as a 400 whose body does not say so.
func TestFetchIMDSNoManagedIdentityAssigned(t *testing.T) {
	f := newAzureFixture(t)
	f.imdsHandler = func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_request","error_description":"Identity not found"}`, http.StatusBadRequest)
	}

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "imds token", "400", "no managed identity is assigned", "QUILL_AZURE_MI_CLIENT_ID", "Identity not found")
}

func TestFetchIMDSEmptyToken(t *testing.T) {
	f := newAzureFixture(t)
	f.imdsHandler = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"resource": "https://vault.azure.net"})
	}

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "imds token", "empty access_token")
}

// The 200 body of IMDS IS a bearer token for the vault. Withholding it from the
// parse error is deliberate, so it is asserted rather than left to the accident
// of encoding/json not echoing its input.
func TestFetchIMDSNonJSONWithholdsBody(t *testing.T) {
	f := newAzureFixture(t)
	f.imdsHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"access_token":"`+testVaultToken+`" TRUNCATED`)
	}

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "imds token", "not JSON", "body withheld")
	if strings.Contains(err.Error(), testVaultToken) {
		t.Errorf("managed-identity token leaked into the parse error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Key Vault
// ---------------------------------------------------------------------------

func TestKeyVaultRequestShape(t *testing.T) {
	f := newAzureFixture(t)
	if _, err := Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	requests := f.vaultRequests()
	if len(requests) != 1 {
		t.Fatalf("Key Vault called %d times, want 1", len(requests))
	}
	req := requests[0]
	if req.URL.Path != "/secrets/"+testBundleSecret {
		t.Errorf("path = %q, want /secrets/%s", req.URL.Path, testBundleSecret)
	}
	if got := req.URL.Query().Get("api-version"); got != "7.4" {
		t.Errorf("api-version = %q", got)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer "+testVaultToken {
		t.Errorf("Authorization = %q, want the IMDS-minted token", got)
	}
}

// The 403 an operator will actually hit. RBAC vaults and access-policy vaults
// need different knobs in different blades, and the response body does not say
// which model the vault is in.
func TestFetchKeyVaultForbidden(t *testing.T) {
	f := newAzureFixture(t)
	f.vaultHandler = func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"code":"Forbidden","message":"Caller is not authorized to perform action on resource."}}`, http.StatusForbidden)
	}

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "key vault", "403",
		"managed identity cannot read this secret", "Key Vault Secrets User",
		testBundleSecret, testAKVEndpoint, "not authorized")
}

func TestFetchKeyVaultUnauthorizedNamesTheAudience(t *testing.T) {
	f := newAzureFixture(t)
	f.vaultHandler = func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"code":"Unauthorized","message":"AKV10000"}}`, http.StatusUnauthorized)
	}

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "key vault", "401", "https://vault.azure.net")
}

func TestFetchKeyVaultNotFoundNamesTheEnvVar(t *testing.T) {
	f := newAzureFixture(t)
	f.vaultHandler = func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"code":"SecretNotFound","message":"A secret with (name/id) was not found"}}`, http.StatusNotFound)
	}

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "key vault", "404", "QUILL_AZURE_BUNDLE_SECRET")
}

func TestFetchKeyVaultEmptyValue(t *testing.T) {
	f := newAzureFixture(t)
	f.vaultHandler = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"value": "  "})
	}

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "key vault", "empty value", testBundleSecret)
}

func TestFetchKeyVaultValueIsNotAnEnvelope(t *testing.T) {
	f := newAzureFixture(t)
	f.vaultHandler = func(w http.ResponseWriter, r *http.Request) {
		// Not JSON, and not base64 either (contains '!').
		writeJSON(w, http.StatusOK, map[string]any{"value": "this is not a bundle!"})
	}

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "key vault", "neither a", "RSA-OAEP-256+A256GCM")
}

// In production the base is derived from the vault hostname over https. The
// test seam must not be what makes that work.
func TestKeyVaultSecretURLDerivesHTTPSFromTheEndpoint(t *testing.T) {
	prev := keyVaultBaseURLOverride
	keyVaultBaseURLOverride = ""
	t.Cleanup(func() { keyVaultBaseURLOverride = prev })

	got := keyVaultSecretURL(azureConfig{akvEndpoint: testAKVEndpoint, bundleSecret: testBundleSecret})
	want := "https://" + testAKVEndpoint + "/secrets/" + testBundleSecret + "?api-version=7.4"
	if got != want {
		t.Errorf("keyVaultSecretURL = %q, want %q", got, want)
	}
}

// The endpoint is the https authority a Key Vault bearer token is sent to.
// Accepting a scheme would let a deploy write "http://..." and ship that token
// in cleartext; accepting a path would let it point somewhere that is not the
// vault's data plane.
func TestValidateAKVEndpointRejectsSchemeAndPath(t *testing.T) {
	for _, bad := range []string{
		"https://trquillkv.vault.azure.net",
		"http://trquillkv.vault.azure.net",
		"trquillkv.vault.azure.net/secrets",
		"trquillkv.vault.azure.net?x=1",
		"trquillkv.vault.azure.net#f",
	} {
		if err := validateAKVEndpoint(bad); err == nil {
			t.Errorf("validateAKVEndpoint(%q) = nil, want an error", bad)
		}
	}
	if err := validateAKVEndpoint(testAKVEndpoint); err != nil {
		t.Errorf("validateAKVEndpoint(%q) = %v, want nil", testAKVEndpoint, err)
	}
}

func TestFetchRefusesAKVEndpointWithAScheme(t *testing.T) {
	f := newAzureFixture(t)
	t.Setenv("QUILL_AZURE_AKV_ENDPOINT", "https://"+testAKVEndpoint)

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "azure config", "QUILL_AZURE_AKV_ENDPOINT", "bare vault hostname")
	if got := len(f.skrRequests()); got != 0 {
		t.Errorf("sidecar contacted %d times; config is validated before any I/O", got)
	}
}

// ---------------------------------------------------------------------------
// the envelope, and the bundle inside it
// ---------------------------------------------------------------------------

// The envelope is not a convenience: a bare RSA-OAEP ciphertext physically
// cannot hold the bundle. This pins the arithmetic so nobody "simplifies" the
// hybrid format away.
func TestBareOAEPCannotHoldTheBundle(t *testing.T) {
	f := newAzureFixture(t)
	bundleJSON, err := json.Marshal(f.bundle)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	maxDirect := f.wrapKey.Size() - 2*sha256.Size - 2
	if len(bundleJSON) <= maxDirect {
		t.Fatalf("test premise broken: bundle is %d bytes, OAEP limit is %d", len(bundleJSON), maxDirect)
	}
	if _, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &f.wrapKey.PublicKey, bundleJSON, nil); err == nil {
		t.Fatal("expected direct OAEP of the bundle to fail on message size")
	}
}

func TestFetchBundleUndecryptable(t *testing.T) {
	f := newAzureFixture(t)
	// Sealed to a key the sidecar will never release: the exact shape of a
	// stale bundle left behind after a vault key rotation.
	f.sealPub = f.foreign.Public().(*rsa.PublicKey)

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "bundle decrypt", "RSA-OAEP-SHA256", "CURRENT vault key")
}

func TestFetchBundleEnvelopeCorrupt(t *testing.T) {
	f := newAzureFixture(t)
	f.tamperEnvelope(func(env *secretEnvelope) {
		// Flip a byte of the GCM ciphertext: OAEP still unwraps, the AEAD tag fails.
		ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		ct[0] ^= 0xff
		env.Ciphertext = base64.StdEncoding.EncodeToString(ct)
	})

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "bundle decrypt", "AES-GCM open failed")
}

// crypto/cipher's gcm.Open PANICS on a wrong-length nonce rather than returning
// an error. Without the explicit length check the enclave would not report a
// malformed envelope, it would crash at boot — the exact "hung with no
// explanation" failure mode this file is written to avoid.
func TestFetchEnvelopeBadNonceLengthIsAnErrorNotAPanic(t *testing.T) {
	f := newAzureFixture(t)
	f.tamperEnvelope(func(env *secretEnvelope) {
		env.Nonce = base64.StdEncoding.EncodeToString(make([]byte, 13)) // GCM wants 12
	})

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Fetch panicked instead of returning an error: %v", r)
		}
	}()
	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "bundle decrypt", "nonce is 13 bytes", "want 12")
}

// aes.NewCipher accepts 16 and 24 bytes as well, so without an explicit size
// check an envelope declaring A256GCM opened fine under AES-128 and the label
// was decorative.
func TestFetchRejectsContentKeyThatIsNotAES256(t *testing.T) {
	for _, size := range []int{16, 24} {
		t.Run(fmt.Sprintf("%d-byte content key", size), func(t *testing.T) {
			f := newAzureFixture(t)
			plaintext, err := json.Marshal(f.bundle)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			f.rawVaultValue = base64.StdEncoding.EncodeToString(
				sealEnvelopeWithContentKeySize(t, f.sealPub, plaintext, size))

			_, err = Fetch(context.Background())
			requireErrContains(t, err, "bootstrap/azure", "bundle decrypt",
				fmt.Sprintf("content key is %d bytes", size), "RSA-OAEP-256+A256GCM")
		})
	}
}

// The version and alg fields exist so a future format change is a loud failure
// rather than a silent misparse. Without these checks they are decoration.
func TestFetchRejectsUnknownEnvelopeVersionAndAlg(t *testing.T) {
	t.Run("version", func(t *testing.T) {
		f := newAzureFixture(t)
		f.tamperEnvelope(func(env *secretEnvelope) { env.V = 2 })
		_, err := Fetch(context.Background())
		requireErrContains(t, err, "bootstrap/azure", "bundle decrypt", "envelope version 2")
	})
	t.Run("alg", func(t *testing.T) {
		f := newAzureFixture(t)
		f.tamperEnvelope(func(env *secretEnvelope) { env.Alg = "RSA-OAEP+A128GCM" })
		_, err := Fetch(context.Background())
		requireErrContains(t, err, "bootstrap/azure", "bundle decrypt", "envelope alg", "RSA-OAEP+A128GCM")
	})
}

func TestFetchBundleIsNotAJSONObject(t *testing.T) {
	f := newAzureFixture(t)
	f.rawVaultValue = base64.StdEncoding.EncodeToString(
		sealEnvelope(t, f.sealPub, []byte("not-json-at-all")))

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "bundle parse", "secret name -> value", "content withheld")
}

func TestFetchBundleIsEmpty(t *testing.T) {
	f := newAzureFixture(t)
	f.rawVaultValue = base64.StdEncoding.EncodeToString(sealEnvelope(t, f.sealPub, []byte(`{}`)))

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "bundle parse", "carries no secrets")
}

// The bundle is replicated by hand from another store, so "the deploy names a
// secret the bundle does not carry" is the most likely steady-state failure.
// The error has to name both the binding and the missing entry, or an operator
// is left diffing ~40 names by eye.
func TestFetchBundleMissingARequiredSecret(t *testing.T) {
	f := newAzureFixture(t)
	delete(f.bundle, testORSecret)

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "openrouter key", "no entry", testORSecret)
}

func TestFetchBundleMissingTheDeviceKeys(t *testing.T) {
	f := newAzureFixture(t)
	delete(f.bundle, testDevicesSecret)

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "device-keys", "no entry", testDevicesSecret)
}

func TestFetchBundleDeviceKeysNotJSON(t *testing.T) {
	f := newAzureFixture(t)
	f.bundle[testDevicesSecret] = "not-json-at-all"

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "parse device-keys JSON")
}

// The SA key is optional only in the independent, self-signed posture.
func TestFetchBundleWithoutTheSAKeyEntryStillBoots(t *testing.T) {
	f := newAzureFixture(t)
	delete(f.bundle, testSAKeyEntry)

	data, err := Fetch(context.Background())
	if err != nil {
		t.Fatalf("a bundle with no SA key must still boot: %v", err)
	}
	if data.GCPServiceAccountKeyJSON != "" {
		t.Errorf("no SA key was supplied, so none must be carried; got %d bytes",
			len(data.GCPServiceAccountKeyJSON))
	}
}

func TestFetchBundleWithoutTheSAKeyRejectsSharedACMECache(t *testing.T) {
	f := newAzureFixture(t)
	delete(f.bundle, testSAKeyEntry)
	t.Setenv("QUILL_ACME_CACHE_GCS_BUCKET", "quill-acme-cache")

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", testSAKeyEntry, "QUILL_ACME_CACHE_GCS_BUCKET")
}

func TestFetchBundleBlankSAKeyEntryIsTreatedAsAbsent(t *testing.T) {
	// Whitespace must not become a "present" credential that main.go writes to
	// tmpfs and points GOOGLE_APPLICATION_CREDENTIALS at - that would fail at
	// first use rather than being cleanly disabled here.
	f := newAzureFixture(t)
	f.bundle[testSAKeyEntry] = "   "

	data, err := Fetch(context.Background())
	if err != nil {
		t.Fatalf("a blank SA key must be treated as absent, not fatal: %v", err)
	}
	if data.GCPServiceAccountKeyJSON != "" {
		t.Errorf("blank SA key must not be carried; got %q", data.GCPServiceAccountKeyJSON)
	}
}

func TestFetchBundleCarriesTheSAKeyWhenPresent(t *testing.T) {
	// Optional must not mean ignored.
	f := newAzureFixture(t)
	f.bundle[testSAKeyEntry] = `{"type":"service_account"}`

	data, err := Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if data.GCPServiceAccountKeyJSON != `{"type":"service_account"}` {
		t.Errorf("a supplied SA key must be carried, got %q", data.GCPServiceAccountKeyJSON)
	}
}

// A "which entry is missing?" error has to be actionable, which means listing
// the bundle's KEYS. Listing its VALUES would print every secret this system
// has into a log line that ACI ships to Log Analytics.
func TestBundleErrorListsKeysNeverValues(t *testing.T) {
	f := newAzureFixture(t)
	delete(f.bundle, testORSecret)

	_, err := Fetch(context.Background())
	if err == nil {
		t.Fatal("want an error")
	}
	// Actionable: the names that ARE present.
	if !strings.Contains(err.Error(), testAnthSecret) {
		t.Errorf("error does not list the bundle's entry names: %v", err)
	}
	for label, secret := range map[string]string{
		"anthropic key":                   testAnthValue,
		"service-account private key PEM": pemBody(t, f.saKeyJSON),
	} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s leaked into the missing-entry error", label)
		}
	}
}

// ---------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------

func TestFetchFailsLoudlyOnMissingAzureConfig(t *testing.T) {
	for _, tc := range []struct {
		env   string
		wants []string
	}{
		// Defaulting the MAA instance would attest against an authority nobody
		// chose — the forgery hole the verifier work closed.
		{"QUILL_AZURE_MAA_ENDPOINT", []string{"refusing to default the attestation authority"}},
		{"QUILL_AZURE_AKV_ENDPOINT", nil},
		{"QUILL_AZURE_SKR_KEY_ID", nil},
		{"QUILL_AZURE_BUNDLE_SECRET", []string{"encrypted bundle"}},
		{"QUILL_AZURE_SA_KEY_ENTRY", []string{"gcscache/byokcache"}},
	} {
		t.Run(tc.env, func(t *testing.T) {
			f := newAzureFixture(t)
			t.Setenv(tc.env, "")

			_, err := Fetch(context.Background())
			requireErrContains(t, err, append([]string{"bootstrap/azure", "azure config", tc.env}, tc.wants...)...)
			if got := len(f.skrRequests()); got != 0 {
				t.Errorf("sidecar contacted %d times; config is validated before any I/O", got)
			}
		})
	}
}

func TestFetchRequiresProjectID(t *testing.T) {
	newAzureFixture(t)
	t.Setenv("QUILL_GCP_PROJECT_ID", "")

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "QUILL_GCP_PROJECT_ID not set")
}

func TestFetchRequiresDeviceKeysSecret(t *testing.T) {
	newAzureFixture(t)
	t.Setenv("QUILL_DEVICE_KEYS_SECRET", "")

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "QUILL_DEVICE_KEYS_SECRET not set")
}

func TestFetchRequiresProviderSecret(t *testing.T) {
	newAzureFixture(t)
	t.Setenv("QUILL_OPENROUTER_SECRET", "")
	t.Setenv("QUILL_ANTHROPIC_SECRET", "")

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "at least one provider secret")
}

// Config is validated before any I/O so a misconfigured deploy blames itself
// rather than the first network call that happens to be in the way.
func TestFetchValidatesEnvBeforeTouchingTheSidecar(t *testing.T) {
	f := newAzureFixture(t)
	called := false
	f.skrHandler = func(w http.ResponseWriter, r *http.Request) {
		called = true
		f.serveSKR(w, r)
	}
	t.Setenv("QUILL_GCP_PROJECT_ID", "")

	if _, err := Fetch(context.Background()); err == nil {
		t.Fatal("want error")
	}
	if called {
		t.Error("skr sidecar was contacted despite invalid configuration")
	}
}

// ---------------------------------------------------------------------------
// the shared name -> field mapping, driven through the Azure adapter
// ---------------------------------------------------------------------------

// A secret NAME that is present but blank is a broken deploy, and it must fail
// at boot. An earlier draft skipped it: QUILL_ANTHROPIC_SECRET="   " booted a
// gateway whose Anthropic key was "" and 401ed every Anthropic request at
// runtime. secrets.go is shared, so this covers the live GCP path too.
func TestFetchRejectsWhitespaceOnlySecretName(t *testing.T) {
	f := newAzureFixture(t)
	t.Setenv("QUILL_ANTHROPIC_SECRET", "   ")

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "anthropic key", "QUILL_ANTHROPIC_SECRET", "whitespace only")
	if got := len(f.skrRequests()); got != 0 {
		t.Errorf("sidecar contacted %d times; env is validated before any I/O", got)
	}
}

func TestFetchRejectsWhitespaceOnlyProjectAndDeviceSecret(t *testing.T) {
	for _, env := range []string{"QUILL_GCP_PROJECT_ID", "QUILL_DEVICE_KEYS_SECRET"} {
		t.Run(env, func(t *testing.T) {
			f := newAzureFixture(t)
			t.Setenv(env, "  \t ")

			_, err := Fetch(context.Background())
			requireErrContains(t, err, "bootstrap/azure", env, "whitespace only")
			if got := len(f.skrRequests()); got != 0 {
				t.Errorf("sidecar contacted %d times", got)
			}
		})
	}
}

// An empty value still means "not configured" — that is how a container spec
// says "off", and both the pre- and post-refactor code agree on it.
func TestEmptySecretNameIsStillTreatedAsUnset(t *testing.T) {
	newAzureFixture(t)
	t.Setenv("QUILL_ANTHROPIC_SECRET", "")

	data, err := Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if data.AnthropicAPIKey != "" {
		t.Errorf("anthropic key = %q, want empty", data.AnthropicAPIKey)
	}
	if data.OpenRouterAPIKey != testORValue {
		t.Errorf("openrouter key = %q", data.OpenRouterAPIKey)
	}
}

// The advisor bindings accept a pre-rename spelling, and an empty first
// variable must still fall through to it.
func TestSecretNameFallsThroughToTheLegacySpelling(t *testing.T) {
	f := newAzureFixture(t)
	f.bundle["tr-advisor-prompt"] = "you are an advisor"
	t.Setenv("QUILL_ADVISOR_PROMPT_SECRET", "")
	t.Setenv("QUILL_SOCRATES_ADVISOR_PROMPT_SECRET", "tr-advisor-prompt")

	data, err := Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if data.AdvisorPrompt != "you are an advisor" {
		t.Errorf("advisor prompt = %q, want the value of the legacy-named entry", data.AdvisorPrompt)
	}
}

// ---------------------------------------------------------------------------
// boot-path resilience
// ---------------------------------------------------------------------------

// main.go turns any bootstrap error into os.Exit(1), so a single transient 5xx
// on IMDS or Key Vault is a container-group crash-loop that re-runs the SNP
// report and MAA exchange on every restart.
func TestFetchRetriesTransientAzureFailures(t *testing.T) {
	f := newAzureFixture(t)

	var imdsAttempts, vaultAttempts int32
	f.imdsHandler = func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&imdsAttempts, 1) == 1 {
			http.Error(w, "throttled", http.StatusTooManyRequests)
			return
		}
		f.serveIMDS(w, r)
	}
	f.vaultHandler = func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&vaultAttempts, 1) == 1 {
			http.Error(w, "backend error", http.StatusInternalServerError)
			return
		}
		f.serveVault(w, r)
	}

	data, err := Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch did not survive one transient failure per call: %v", err)
	}
	if data.OpenRouterAPIKey != testORValue {
		t.Errorf("openrouter key = %q", data.OpenRouterAPIKey)
	}
	if got := atomic.LoadInt32(&imdsAttempts); got < 2 {
		t.Errorf("IMDS attempted %d times, want a retry", got)
	}
	if got := atomic.LoadInt32(&vaultAttempts); got < 2 {
		t.Errorf("Key Vault attempted %d times, want a retry", got)
	}
}

// The sidecar is a container in the same group and ACI starts containers
// concurrently, so it may still be coming up on the first request.
func TestFetchRetriesSidecarStartupRace(t *testing.T) {
	f := newAzureFixture(t)
	var attempts int32
	f.skrHandler = func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) < 3 {
			http.Error(w, "starting up", http.StatusServiceUnavailable)
			return
		}
		f.serveSKR(w, r)
	}

	if _, err := Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch did not survive a sidecar still starting: %v", err)
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Errorf("skr attempts = %d, want 3", got)
	}
}

// A 4xx is a verdict, not a blip. Retrying a 403 from the release policy — or
// from Key Vault RBAC — only delays a boot that is already doomed, and on the
// SKR path it re-runs the hardware attestation each time.
func TestFetchDoesNotRetryVerdicts(t *testing.T) {
	t.Run("skr 403", func(t *testing.T) {
		f := newAzureFixture(t)
		var attempts int32
		f.skrHandler = func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&attempts, 1)
			http.Error(w, "Forbidden: release policy not satisfied", http.StatusForbidden)
		}
		_, err := Fetch(context.Background())
		requireErrContains(t, err, "403", "hostdata")
		if got := atomic.LoadInt32(&attempts); got != 1 {
			t.Errorf("skr attempted %d times on a 403, want 1", got)
		}
	})
	t.Run("key vault 403", func(t *testing.T) {
		f := newAzureFixture(t)
		var attempts int32
		f.vaultHandler = func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&attempts, 1)
			http.Error(w, `{"error":{"code":"Forbidden"}}`, http.StatusForbidden)
		}
		_, err := Fetch(context.Background())
		requireErrContains(t, err, "key vault", "403")
		if got := atomic.LoadInt32(&attempts); got != 1 {
			t.Errorf("key vault attempted %d times on a 403, want 1", got)
		}
	})
}

// ---------------------------------------------------------------------------
// error hygiene
// ---------------------------------------------------------------------------

// TestNoSecretMaterialIsEverLogged runs every path — success and each failure —
// and scans both the returned error and everything written to stdout/stderr/log
// for material that must never escape the boundary.
func TestNoSecretMaterialIsEverLogged(t *testing.T) {
	scenarios := []struct {
		name  string
		setup func(t *testing.T, f *azureFixture)
	}{
		{"happy path", func(*testing.T, *azureFixture) {}},
		{"sidecar non-JSON", func(_ *testing.T, f *azureFixture) {
			f.skrHandler = func(w http.ResponseWriter, r *http.Request) {
				// Worst case: the sidecar returns the raw JWK with no wrapper,
				// so the failing parse is holding real key material.
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, jwkFromRSAPrivate(f.wrapKey)+"trailing-garbage")
			}
		}},
		{"released key unusable", func(_ *testing.T, f *azureFixture) {
			f.skrHandler = func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, http.StatusOK, map[string]string{"key": `{"kty":"RSA","n":"sXchDaQ","e":"AQAB"}`})
			}
		}},
		{"imds 200 non-JSON", func(_ *testing.T, f *azureFixture) {
			f.imdsHandler = func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"access_token":"`+testVaultToken+`" TRUNCATED`)
			}
		}},
		{"key vault 403", func(_ *testing.T, f *azureFixture) {
			f.vaultHandler = func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, `{"error":{"code":"Forbidden"}}`, http.StatusForbidden)
			}
		}},
		{"key vault 200 non-JSON", func(_ *testing.T, f *azureFixture) {
			f.vaultHandler = func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"value":"`+base64.StdEncoding.EncodeToString(f.sealBundle())+`" TRUNCATED`)
			}
		}},
		{"bundle undecryptable", func(_ *testing.T, f *azureFixture) {
			f.sealPub = f.foreign.Public().(*rsa.PublicKey)
		}},
		{"bundle not JSON", func(t *testing.T, f *azureFixture) {
			// The decrypted plaintext is every secret this system has, mangled
			// just enough not to parse.
			plaintext, err := json.Marshal(f.bundle)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			f.rawVaultValue = base64.StdEncoding.EncodeToString(
				sealEnvelope(t, f.sealPub, append(plaintext, " TRUNCATED"...)))
		}},
		{"bundle missing an entry", func(_ *testing.T, f *azureFixture) {
			delete(f.bundle, testORSecret)
		}},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			f := newAzureFixture(t)
			scenario.setup(t, f)

			// Everything that must never appear in an error or on a stream.
			wrapJWK := jwkFromRSAPrivate(f.wrapKey)
			var jwkFields map[string]string
			if err := json.Unmarshal([]byte(wrapJWK), &jwkFields); err != nil {
				t.Fatalf("jwk: %v", err)
			}
			forbidden := map[string]string{
				"wrapping key private exponent (d)": jwkFields["d"],
				"wrapping key prime p":              jwkFields["p"],
				"service-account private key PEM":   pemBody(t, f.saKeyJSON),
				"managed-identity access token":     testVaultToken,
				"anthropic API key":                 testAnthValue,
			}
			// The openrouter key is deleted from the bundle in one scenario, so
			// only assert on it where it exists.
			if _, ok := f.bundle[testORSecret]; ok {
				forbidden["openrouter API key"] = testORValue
			}

			var fetchErr error
			output := captureOutput(t, func() {
				_, fetchErr = Fetch(context.Background())
			})

			haystacks := map[string]string{"stdout/stderr/log": output}
			if fetchErr != nil {
				haystacks["returned error"] = fetchErr.Error()
			}
			for where, haystack := range haystacks {
				for label, secret := range forbidden {
					if secret == "" {
						t.Fatalf("test bug: empty marker for %s", label)
					}
					if strings.Contains(haystack, secret) {
						t.Errorf("%s leaked into %s", label, where)
					}
				}
			}
			// Bootstrap returns errors; it does not print.
			if strings.TrimSpace(output) != "" {
				t.Errorf("bootstrap wrote to stdout/stderr/log: %q", output)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// test seams
// ---------------------------------------------------------------------------

// imdsBaseURL and keyVaultBaseURLOverride are package vars so this file can
// redirect them. That is only acceptable while production still resolves to the
// real endpoints.
func TestAzureEndpointSeamsDefaultToProduction(t *testing.T) {
	if imdsHost != "http://169.254.169.254" {
		t.Errorf("imdsHost = %q", imdsHost)
	}
	// A fixture redirects these and restores them on cleanup; outside one they
	// must be the production values.
	if imdsBaseURL != imdsHost {
		t.Errorf("imdsBaseURL = %q, want %q — the test seam leaked", imdsBaseURL, imdsHost)
	}
	if keyVaultBaseURLOverride != "" {
		t.Errorf("keyVaultBaseURLOverride = %q, want empty so the base is derived from QUILL_AZURE_AKV_ENDPOINT over https", keyVaultBaseURLOverride)
	}
	if keyVaultResource != "https://vault.azure.net" {
		t.Errorf("keyVaultResource = %q", keyVaultResource)
	}
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

// wrapLines reproduces what `base64` does to its output by default.
func wrapLines(text string, width int) string {
	var out strings.Builder
	for len(text) > width {
		out.WriteString(text[:width])
		out.WriteByte('\n')
		text = text[width:]
	}
	out.WriteString(text)
	out.WriteByte('\n')
	return out.String()
}

// pemBody returns the base64 body of the SA key's PEM, which is the substring
// that would actually identify a leak (the BEGIN/END armour is not secret).
func pemBody(t *testing.T, saKeyJSON []byte) string {
	t.Helper()
	var sa struct {
		PrivateKey string `json:"private_key"`
	}
	if err := json.Unmarshal(saKeyJSON, &sa); err != nil {
		t.Fatalf("sa key json: %v", err)
	}
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		t.Fatal("no PEM block in test SA key")
		// Unreachable: t.Fatal does not return. staticcheck cannot know that,
		// so without this the next line reads as a nil dereference (SA5011).
		return ""
	}
	return base64.StdEncoding.EncodeToString(block.Bytes)[:64]
}

// ---------------------------------------------------------------------------
// endpoint substitution — the second trust anchor
// ---------------------------------------------------------------------------

// QUILL_AZURE_AKV_ENDPOINT is as load-bearing as QUILL_AZURE_SKR_URL and was far
// weaker. It decides BOTH the vault the skr sidecar releases the wrapping key
// from AND the https authority a Key Vault bearer token is sent to, and the old
// check ("no scheme, no path") let through any hostname at all — including the
// userinfo form, which reads like the real vault in an ARM template or a
// CCE-policy diff:
//
//	trquillkv.vault.azure.net@attacker.example   -> authority attacker.example
//
// Driven before the fix: Fetch completed a boot with the managed-identity token
// delivered to 127.0.0.1 wearing the vault's name, and told the sidecar to
// release from the same string. The real vault is never contacted on that path,
// so hostdata is never evaluated and the CCE-policy mitigation never fires.
func TestValidateAKVEndpointRejectsUserinfoAndForeignHosts(t *testing.T) {
	bad := []struct{ endpoint, why string }{
		{"trquillkv.vault.azure.net@attacker.example", "userinfo confusion: the authority is attacker.example"},
		{"trquillkv.vault.azure.net@127.0.0.1:61444", "userinfo confusion with a port"},
		{"attacker.example.com", "not a Key Vault hostname"},
		{"trquillkv.vault.azure.net.attacker.example", "suffix is a prefix of the attacker's domain"},
		{"trquillkv.vault.azure.net:8443", "explicit port"},
		{"vault.azure.net", "the bare suffix is not a vault"},
		{"10.0.0.7", "an IP address is not a vault hostname"},
		{"trquillkv.vault.azure.net/secrets", "path"},
		{"https://trquillkv.vault.azure.net", "scheme"},
		{"", "empty"},
	}
	for _, tc := range bad {
		if err := validateAKVEndpoint(tc.endpoint); err == nil {
			t.Errorf("validateAKVEndpoint(%q) = nil, want an error (%s)", tc.endpoint, tc.why)
		}
	}
	good := []string{
		"trquillkv.vault.azure.net",
		"TRQUILLKV.VAULT.AZURE.NET",
		"tr-quill-kv.vault.azure.cn",
		"trquillkv.vault.usgovcloudapi.net",
		"trquillhsm.managedhsm.azure.net",
	}
	for _, endpoint := range good {
		if err := validateAKVEndpoint(endpoint); err != nil {
			t.Errorf("validateAKVEndpoint(%q) = %v, want nil", endpoint, err)
		}
	}
}

// End to end: the substitution is refused before ANY I/O, so neither the
// sidecar nor the vault is contacted and no token is ever minted.
func TestFetchRefusesAKVEndpointWithUserinfo(t *testing.T) {
	f := newAzureFixture(t)
	t.Setenv("QUILL_AZURE_AKV_ENDPOINT", testAKVEndpoint+"@attacker.example")

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "azure config", "QUILL_AZURE_AKV_ENDPOINT", "userinfo")
	if got := len(f.skrRequests()); got != 0 {
		t.Errorf("the sidecar was contacted %d times; the endpoint must be rejected before any I/O", got)
	}
	if got := len(f.imdsRequests()); got != 0 {
		t.Errorf("IMDS was contacted %d times; no managed-identity token may be minted for an unvalidated authority", got)
	}
}

// What validateAKVEndpoint accepts must be what keyVaultSecretURL dials. A
// syntax check that disagrees with the URL builder is exactly how the userinfo
// bypass got in, so this pins the two together rather than testing either alone.
func TestValidatedAKVEndpointIsTheAuthorityThatGetsDialled(t *testing.T) {
	prev := keyVaultBaseURLOverride
	keyVaultBaseURLOverride = ""
	t.Cleanup(func() { keyVaultBaseURLOverride = prev })

	for _, endpoint := range []string{testAKVEndpoint, "tr-quill-kv.vault.azure.cn"} {
		if err := validateAKVEndpoint(endpoint); err != nil {
			t.Fatalf("validateAKVEndpoint(%q): %v", endpoint, err)
		}
		raw := keyVaultSecretURL(azureConfig{akvEndpoint: endpoint, bundleSecret: testBundleSecret})
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		if parsed.Host != endpoint {
			t.Errorf("endpoint %q dials authority %q", endpoint, parsed.Host)
		}
		if parsed.User != nil {
			t.Errorf("endpoint %q produced userinfo %v", endpoint, parsed.User)
		}
		if parsed.Scheme != "https" {
			t.Errorf("endpoint %q dials scheme %q, want https — a Key Vault token must not go out in cleartext", endpoint, parsed.Scheme)
		}
	}
}

// ---------------------------------------------------------------------------
// redirects — validating a URL is worthless if the client walks away from it
// ---------------------------------------------------------------------------

// validateSKRURL pins the sidecar to loopback, but http.Client follows up to 10
// redirects and replays the POST body, and nothing re-validated a hop. Driven
// before the fix: a 307 from the loopback port carried the release request to
// "skr.attacker.example" — the exact host validateSKRURL refuses — and Fetch
// booted on an attacker-supplied key with no MAA exchange and no hostdata
// comparison, while /attestation kept serving a genuine token.
func TestSKRReleaseWillNotFollowARedirect(t *testing.T) {
	f := newAzureFixture(t)

	var offboxHits int32
	offbox := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&offboxHits, 1)
		writeJSON(w, http.StatusOK, map[string]string{"key": jwkFromRSAPrivate(f.wrapKey)})
	}))
	t.Cleanup(offbox.Close)

	f.skrHandler = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, offbox.URL+"/key/release", http.StatusTemporaryRedirect)
	}

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "refusing redirect")
	if got := atomic.LoadInt32(&offboxHits); got != 0 {
		t.Errorf("the redirect target was contacted %d times — the loopback pin is bypassable", got)
	}
}

// Same property on the Key Vault leg. A cross-host redirect does not leak the
// bearer token (net/http strips Authorization when the host changes), but the
// bundle must still come from the authority that was validated rather than one a
// response body picked — and a same-host, different-PORT hop DOES carry the
// token.
func TestKeyVaultFetchWillNotFollowARedirect(t *testing.T) {
	f := newAzureFixture(t)

	var elsewhereHits int32
	var sawToken string
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&elsewhereHits, 1)
		sawToken = r.Header.Get("Authorization")
		writeJSON(w, http.StatusOK, map[string]any{"value": "not-the-real-bundle"})
	}))
	t.Cleanup(elsewhere.Close)

	f.vaultHandler = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/secrets/"+testBundleSecret, http.StatusTemporaryRedirect)
	}

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "refusing redirect")
	if got := atomic.LoadInt32(&elsewhereHits); got != 0 {
		t.Errorf("the redirect target was contacted %d times (Authorization=%q) — the vault authority is not pinned", got, sawToken)
	}
}

// ---------------------------------------------------------------------------
// IMDS: audience, propagation, proxying
// ---------------------------------------------------------------------------

// The token's audience was parsed into a struct field that nothing read, which
// made the struct imply a check that did not exist. A token minted for another
// resource was accepted here and only rejected later by the vault's 401 — an
// authorization decision deferred to a remote party.
func TestFetchRejectsIMDSTokenForTheWrongAudience(t *testing.T) {
	f := newAzureFixture(t)
	f.imdsHandler = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": testVaultToken,
			"resource":     "https://management.azure.com",
			"token_type":   "Bearer",
		})
	}

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "imds token", "management.azure.com", "https://vault.azure.net")
	if got := len(f.vaultRequests()); got != 0 {
		t.Errorf("the vault was contacted %d times with a wrong-audience token", got)
	}
}

// A trailing slash is the same audience, and an IMDS version that stops echoing
// the field must not become a boot failure.
func TestFetchToleratesAudienceSpellingAndOmission(t *testing.T) {
	for _, resource := range []string{"https://vault.azure.net/", ""} {
		t.Run("resource="+resource, func(t *testing.T) {
			f := newAzureFixture(t)
			f.imdsHandler = func(w http.ResponseWriter, r *http.Request) {
				body := map[string]any{"access_token": testVaultToken, "token_type": "Bearer"}
				if resource != "" {
					body["resource"] = resource
				}
				writeJSON(w, http.StatusOK, body)
			}
			if _, err := Fetch(context.Background()); err != nil {
				t.Fatalf("Fetch: %v", err)
			}
		})
	}
}

// The retries were justified by IMDS being slow at container-group start, but
// the retryable set was 429/5xx — and IMDS answers 400 in that window, which the
// code itself documents. So the retries covered none of the cold-start race they
// were added for: an identity that had not finished propagating produced a hard
// boot failure, os.Exit(1), and an ACI restart that re-ran the SNP report and MAA
// exchange on every attempt.
func TestIMDSRetriesWhileTheManagedIdentityIsStillPropagating(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusNotFound, http.StatusGone} {
		t.Run(fmt.Sprintf("%d", status), func(t *testing.T) {
			f := newAzureFixture(t)
			var attempts int32
			f.imdsHandler = func(w http.ResponseWriter, r *http.Request) {
				if atomic.AddInt32(&attempts, 1) < 3 {
					http.Error(w, `{"error":"invalid_request","error_description":"Identity not found"}`, status)
					return
				}
				f.serveIMDS(w, r)
			}

			data, err := Fetch(context.Background())
			if err != nil {
				t.Fatalf("Fetch after %d transient IMDS %d(s): %v", atomic.LoadInt32(&attempts), status, err)
			}
			if data.AnthropicAPIKey != testAnthValue {
				t.Errorf("boot did not complete: anthropic key = %q", data.AnthropicAPIKey)
			}
			if got := atomic.LoadInt32(&attempts); got != 3 {
				t.Errorf("IMDS attempted %d times, want 3", got)
			}
		})
	}
}

// The widened set is IMDS-ONLY. At the vault a 403 (RBAC) and a 404 (no such
// secret) are verdicts about the deploy, and repeating them only delays a boot
// that is already doomed.
func TestKeyVaultStillDoesNotRetryVerdicts(t *testing.T) {
	for name, status := range map[string]int{"404": http.StatusNotFound, "400": http.StatusBadRequest} {
		t.Run(name, func(t *testing.T) {
			f := newAzureFixture(t)
			var attempts int32
			f.vaultHandler = func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&attempts, 1)
				http.Error(w, `{"error":{"code":"SecretNotFound"}}`, status)
			}
			if _, err := Fetch(context.Background()); err == nil {
				t.Fatal("want an error")
			}
			if got := atomic.LoadInt32(&attempts); got != 1 {
				t.Errorf("key vault attempted %d times on a %s, want 1", got, name)
			}
		})
	}
}

// http.DefaultTransport proxies from the environment, and Go's bypass exempts
// loopback but NOT link-local — measured: with HTTP_PROXY set, 169.254.169.254
// resolves to the proxy while 127.0.0.1 and localhost do not. The IMDS call is
// plain HTTP and its RESPONSE BODY IS THE TOKEN, so a proxy in the container
// environment would be handed that token.
func TestBootPathTransportsDoNotProxy(t *testing.T) {
	transport, ok := bootTransport().(*http.Transport)
	if !ok {
		t.Fatalf("bootTransport() is %T, want *http.Transport", bootTransport())
	}
	if transport.Proxy != nil {
		req, _ := http.NewRequest("GET", "http://169.254.169.254/metadata/identity/oauth2/token", nil)
		proxy, _ := transport.Proxy(req)
		t.Fatalf("boot-path transport honours a proxy (IMDS would go to %v)", proxy)
	}
	// The http.DefaultTransport test seam must still work, or every drive in
	// this file silently stops observing anything.
	recorder := &hostRecorder{base: http.DefaultTransport}
	prev := http.DefaultTransport
	http.DefaultTransport = recorder
	t.Cleanup(func() { http.DefaultTransport = prev })
	if got := bootTransport(); got != http.RoundTripper(recorder) {
		t.Errorf("bootTransport() = %T, want the substituted seam to be honoured verbatim", got)
	}
}

// ---------------------------------------------------------------------------
// envelope base64 tolerance, and the version pin
// ---------------------------------------------------------------------------

// decodeCiphertextBlob accepts four base64 flavours one layer out, with the
// stated reason that a boot-fatal error over one layer of base64 "sends an
// incident down the wrong path — the operator is told to rotate a vault key that
// was fine". The envelope's own three fields then accepted only padded
// StdEncoding, so a producer using Python's urlsafe_b64encode hit exactly that
// misdirection. The integrity of the envelope comes from GCM and OAEP, not from
// which alphabet carried the bytes.
func TestEnvelopeAcceptsAlternateBase64Alphabets(t *testing.T) {
	for _, enc := range []struct {
		name string
		enc  *base64.Encoding
	}{
		{"std", base64.StdEncoding},
		{"raw-std", base64.RawStdEncoding},
		{"url", base64.URLEncoding},
		{"raw-url", base64.RawURLEncoding},
	} {
		t.Run(enc.name, func(t *testing.T) {
			f := newAzureFixture(t)
			f.tamperEnvelope(func(env *secretEnvelope) {
				reencode := func(field string) string {
					raw, err := base64.StdEncoding.DecodeString(field)
					if err != nil {
						t.Fatalf("decode: %v", err)
					}
					return enc.enc.EncodeToString(raw)
				}
				env.EncKey = reencode(env.EncKey)
				env.Nonce = reencode(env.Nonce)
				env.Ciphertext = reencode(env.Ciphertext)
			})

			data, err := Fetch(context.Background())
			if err != nil {
				t.Fatalf("Fetch with %s envelope fields: %v", enc.name, err)
			}
			if data.AnthropicAPIKey != testAnthValue {
				t.Errorf("anthropic key = %q", data.AnthropicAPIKey)
			}
		})
	}
}

// Unset, the fetch follows "current", which is what makes silent substitution
// and silent rollback of the bundle take effect on the next cold start. Set, it
// pins one immutable version — and because the value lives in the CCE-measured
// env-var set, changing it changes hostdata and the release fails.
func TestBundleVersionPinIsRequested(t *testing.T) {
	prev := keyVaultBaseURLOverride
	keyVaultBaseURLOverride = ""
	t.Cleanup(func() { keyVaultBaseURLOverride = prev })

	unpinned := keyVaultSecretURL(azureConfig{akvEndpoint: testAKVEndpoint, bundleSecret: testBundleSecret})
	if want := "https://" + testAKVEndpoint + "/secrets/" + testBundleSecret + "?api-version=7.4"; unpinned != want {
		t.Errorf("unpinned URL = %q, want %q", unpinned, want)
	}
	pinned := keyVaultSecretURL(azureConfig{akvEndpoint: testAKVEndpoint, bundleSecret: testBundleSecret, bundleVersion: "abc123"})
	if want := "https://" + testAKVEndpoint + "/secrets/" + testBundleSecret + "/abc123?api-version=7.4"; pinned != want {
		t.Errorf("pinned URL = %q, want %q", pinned, want)
	}
}

// And the pin reaches the wire, not just the URL builder.
func TestFetchRequestsThePinnedBundleVersion(t *testing.T) {
	f := newAzureFixture(t)
	t.Setenv("QUILL_AZURE_BUNDLE_VERSION", "0e5c1f9b")

	if _, err := Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	requests := f.vaultRequests()
	if len(requests) != 1 {
		t.Fatalf("vault contacted %d times, want 1", len(requests))
	}
	if got, want := requests[0].URL.Path, "/secrets/"+testBundleSecret+"/0e5c1f9b"; got != want {
		t.Errorf("vault path = %q, want %q", got, want)
	}
}

// The bundle is a mechanical dump, so one provider whose export returns empty
// yields `"name": ""`. The shared assembly refuses it (see
// TestAssembleBootstrapDataRejectsAPresentButEmptySecret); this is the Azure end
// of that property, driven through the real envelope.
func TestFetchRejectsAnEmptyBundleValue(t *testing.T) {
	f := newAzureFixture(t)
	f.bundle[testAnthSecret] = "   "

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "anthropic key", testAnthSecret, "empty value")
}

// TestNoGoogleEndpointIsCompiledIntoTheAzureBootPath is the STRUCTURAL half,
// and it exists because the behavioural half above was proved decorative against
// the shape that matters most.
//
// Mutation B — a Google fetch on the boot path using a client with its own
// &http.Transport{} — passes TestFetchMakesNoCallToGoogle, because that test can
// only observe requests routed through the http.DefaultTransport seam it swaps.
// Any reintroduction that brings its own transport is invisible to it. That is
// not a hypothetical: "give this one call its own client" is an ordinary-looking
// edit, and the property it silently breaks is the entire reason this cloud
// exists.
//
// So this asserts on the SOURCE instead of on the traffic: it asks go/build
// which files the cloud_azure build actually compiles, parses each one, and
// fails on any Google host appearing in a STRING LITERAL. Comments are excluded
// by construction (the parser hands back literals, not prose), which is what
// lets secrets.go keep the paragraph explaining why the Google path was removed.
// No transport trick evades this, because the endpoint has to be written down
// somewhere.
func TestNoGoogleEndpointIsCompiledIntoTheAzureBootPath(t *testing.T) {
	buildCtx := build.Default
	buildCtx.BuildTags = []string{"cloud_azure", "llm_multi"}
	pkg, err := buildCtx.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("ImportDir: %v", err)
	}

	// The OAuth/JWT-bearer machinery must not merely be unused under cloud_azure
	// — it must not be compiled. If this file ever reappears here, the build tag
	// on secrets_google.go has been widened back to `cloud_gcp || cloud_azure`.
	for _, name := range pkg.GoFiles {
		if name == "secrets_google.go" {
			t.Errorf("secrets_google.go is compiled under cloud_azure — the Google Secret Manager transport and its OAuth machinery are reachable again")
		}
	}
	if len(pkg.GoFiles) == 0 {
		t.Fatal("no files reported for cloud_azure — this test proved nothing")
	}
	t.Logf("cloud_azure compiles: %v", pkg.GoFiles)

	banned := []string{
		"googleapis.com", "google.internal", "googleusercontent.com",
		"accounts.google.com", "oauth2.googleapis", "secretmanager",
	}
	var scanned int
	for _, name := range pkg.GoFiles {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		scanned++
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value := strings.ToLower(lit.Value)
			for _, host := range banned {
				if strings.Contains(value, host) {
					t.Errorf("%s:%d: a Google endpoint is compiled into the Azure boot path: %s",
						name, fset.Position(lit.Pos()).Line, lit.Value)
				}
			}
			return true
		})
	}
	if scanned == 0 {
		t.Fatal("scanned no files — this test proved nothing")
	}
}
