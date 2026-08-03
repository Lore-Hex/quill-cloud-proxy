//go:build cloud_azure

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
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// These tests exercise the REAL crypto: a genuine RSA keypair is generated,
// a genuine hybrid envelope is sealed to it, and Fetch's OAEP unwrap has to
// open it. Stubbing the decrypt would leave the OAEP parameters (SHA-256
// digest, MGF1-SHA256, nil label) unverified, and getting those wrong is
// exactly the class of mistake that only shows up against real hardware —
// the same way the first draft of attestation_azure.go used SHA-512 and would
// never have verified a single token.

const (
	testSAEmail       = "tr-azure@quill-cloud-proxy.iam.gserviceaccount.com"
	testAccessToken   = "ya29.TEST-MINTED-ACCESS-TOKEN"
	testProject       = "quill-cloud-proxy"
	testDevicesSecret = "tr-device-keys"
	testORSecret      = "tr-openrouter-key"
	testAnthSecret    = "tr-anthropic-key"

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
// Google's token endpoint, and Secret Manager — and wires the environment at
// them. Tests steer a failure by overriding one handler before calling Fetch.
type azureFixture struct {
	t *testing.T

	wrapKey   *rsa.PrivateKey
	saKey     *rsa.PrivateKey
	foreign   *rsa.PrivateKey
	saKeyJSON []byte

	// Handler overrides; nil means "behave correctly".
	skrHandler    http.HandlerFunc
	tokenHandler  http.HandlerFunc
	secretHandler http.HandlerFunc

	secretValues map[string]string

	mu        sync.Mutex
	seenAuthz []string
	seenSKR   []skrRequest

	skrSrv, tokenSrv, secretSrv *httptest.Server
}

func newAzureFixture(t *testing.T) *azureFixture {
	t.Helper()
	wrap, sa, foreign := testKeys(t)
	f := &azureFixture{
		t:       t,
		wrapKey: wrap,
		saKey:   sa,
		foreign: foreign,
		secretValues: map[string]string{
			testDevicesSecret: `[{"key_hash":"c0ffee","owner":"joseph","device_id":"dev-1"}]`,
			testORSecret:      testORValue,
			testAnthSecret:    testAnthValue,
		},
	}

	f.tokenSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.tokenHandler != nil {
			f.tokenHandler(w, r)
			return
		}
		f.serveToken(w, r)
	}))
	t.Cleanup(f.tokenSrv.Close)

	f.secretSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.seenAuthz = append(f.seenAuthz, r.Header.Get("Authorization"))
		f.mu.Unlock()
		if f.secretHandler != nil {
			f.secretHandler(w, r)
			return
		}
		f.serveSecret(w, r)
	}))
	t.Cleanup(f.secretSrv.Close)

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

	// The SA key must point its token_uri at our fake exchange — that is the
	// production seam too (bootstrap honours the key's own token_uri), so no
	// test-only hook is needed.
	f.saKeyJSON = makeSAKeyJSON(t, f.saKey, f.tokenSrv.URL)

	// Point the shared Secret Manager fetch at the fake.
	prevBase := secretManagerBaseURL
	secretManagerBaseURL = f.secretSrv.URL
	t.Cleanup(func() { secretManagerBaseURL = prevBase })

	t.Setenv("QUILL_AZURE_MAA_ENDPOINT", "trquilluaen.uaen.attest.azure.net")
	t.Setenv("QUILL_AZURE_AKV_ENDPOINT", "trquillkv.vault.azure.net")
	t.Setenv("QUILL_AZURE_SKR_KEY_ID", "tr-bootstrap-wrap")
	t.Setenv("QUILL_AZURE_SKR_URL", f.skrSrv.URL+"/key/release")
	t.Setenv("QUILL_AZURE_SA_KEY_CIPHERTEXT_PATH", "")
	t.Setenv("QUILL_AZURE_REGION", "uaenorth")

	t.Setenv("QUILL_GCP_PROJECT_ID", testProject)
	t.Setenv("QUILL_DEVICE_KEYS_SECRET", testDevicesSecret)
	t.Setenv("QUILL_OPENROUTER_SECRET", testORSecret)
	t.Setenv("QUILL_ANTHROPIC_SECRET", testAnthSecret)

	f.sealTo(f.wrapKey.Public().(*rsa.PublicKey))
	return f
}

// sealTo (re)builds the wrapped SA-key blob against a chosen public key and
// installs it in the environment.
func (f *azureFixture) sealTo(pub *rsa.PublicKey) {
	f.t.Helper()
	envelope := sealEnvelope(f.t, pub, f.saKeyJSON)
	f.t.Setenv("QUILL_AZURE_SA_KEY_CIPHERTEXT", base64.StdEncoding.EncodeToString(envelope))
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

func (f *azureFixture) serveToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	if got := r.PostForm.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		http.Error(w, fmt.Sprintf(`{"error":"unsupported_grant_type","got":%q}`, got), http.StatusBadRequest)
		return
	}
	// Verify the assertion for real. If bootstrap signed it wrong, the happy
	// path must fail rather than quietly passing against a stub.
	if err := verifyAssertion(r.PostForm.Get("assertion"), &f.saKey.PublicKey, f.tokenSrv.URL); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid_grant","detail":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": testAccessToken,
		"expires_in":   3600,
		"token_type":   "Bearer",
	})
}

func (f *azureFixture) serveSecret(w http.ResponseWriter, r *http.Request) {
	name := secretNameFromPath(r.URL.Path)
	value, ok := f.secretValues[name]
	if !ok {
		// Tolerate secrets the ambient environment happens to configure so the
		// suite does not depend on the developer's shell.
		value = "unused-" + name
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":    fmt.Sprintf("projects/%s/secrets/%s/versions/1", testProject, name),
		"payload": map[string]string{"data": base64.StdEncoding.EncodeToString([]byte(value))},
	})
}

func (f *azureFixture) authzHeaders() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.seenAuthz...)
}

func (f *azureFixture) skrRequests() []skrRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]skrRequest(nil), f.seenSKR...)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// secretNameFromPath pulls "<name>" out of
// /v1/projects/<p>/secrets/<name>/versions/latest:access
func secretNameFromPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i, part := range parts {
		if part == "secrets" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
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
// the recipe documented on saKeyEnvelope.
func sealEnvelope(t *testing.T, pub *rsa.PublicKey, plaintext []byte) []byte {
	t.Helper()
	contentKey := make([]byte, 32)
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
	// the offline tool that produces the blob, so the test must pin the bytes
	// rather than agree with whatever the code currently says.
	raw, err := json.Marshal(saKeyEnvelope{
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

func makeSAKeyJSON(t *testing.T, key *rsa.PrivateKey, tokenURI string) []byte {
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
		"token_uri":    tokenURI,
	})
	if err != nil {
		t.Fatalf("marshal sa key: %v", err)
	}
	return raw
}

// verifyAssertion checks the RS256 signature and the claims Google would check.
func verifyAssertion(assertion string, pub *rsa.PublicKey, audience string) error {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return fmt.Errorf("assertion has %d segments, want 3", len(parts))
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("signature not base64url: %w", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature); err != nil {
		return fmt.Errorf("bad RS256 signature: %w", err)
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("claims not base64url: %w", err)
	}
	var claims struct {
		Iss   string `json:"iss"`
		Scope string `json:"scope"`
		Aud   string `json:"aud"`
		Exp   int64  `json:"exp"`
		Iat   int64  `json:"iat"`
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return fmt.Errorf("claims not JSON: %w", err)
	}
	if claims.Iss != testSAEmail {
		return fmt.Errorf("iss=%q", claims.Iss)
	}
	// Literal, NOT the googleCloudPlatformScope constant. Comparing the code's
	// own constant against itself is a tautology that passes no matter what the
	// scope is changed to; mutation testing caught exactly that. Secret Manager
	// plus the Spanner/Bigtable/GCS access the enclave needs later all require
	// cloud-platform, so this string is the contract.
	if claims.Scope != "https://www.googleapis.com/auth/cloud-platform" {
		return fmt.Errorf("scope=%q", claims.Scope)
	}
	if claims.Aud != audience {
		return fmt.Errorf("aud=%q want %q", claims.Aud, audience)
	}
	if claims.Exp <= claims.Iat {
		return fmt.Errorf("exp %d not after iat %d", claims.Exp, claims.Iat)
	}
	return nil
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

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

func TestFetchHappyPath(t *testing.T) {
	f := newAzureFixture(t)

	data, err := Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if len(data.Devices) != 1 || data.Devices[0].DeviceID != "dev-1" {
		t.Errorf("devices not assembled from Secret Manager: %+v", data.Devices)
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
	// The whole point of the SKR round trip: main.go writes this to tmpfs and
	// points GOOGLE_APPLICATION_CREDENTIALS at it.
	if data.GCPServiceAccountKeyJSON != string(f.saKeyJSON) {
		t.Errorf("SA key JSON not populated (len %d, want %d)",
			len(data.GCPServiceAccountKeyJSON), len(f.saKeyJSON))
	}

	// Secret Manager must have been called with the token we minted, not with
	// some other credential.
	authz := f.authzHeaders()
	if len(authz) == 0 {
		t.Fatal("Secret Manager was never called")
	}
	for _, header := range authz {
		if header != "Bearer "+testAccessToken {
			t.Fatalf("Secret Manager Authorization = %q, want the minted token", header)
		}
	}
}

// The envelope is not a convenience: a bare RSA-OAEP ciphertext physically
// cannot hold a service-account key. This pins the arithmetic so nobody
// "simplifies" the hybrid format away.
func TestBareOAEPCannotHoldAServiceAccountKey(t *testing.T) {
	wrap, sa, _ := testKeys(t)
	saKeyJSON := makeSAKeyJSON(t, sa, "https://oauth2.googleapis.com/token")

	maxDirect := wrap.Size() - 2*sha256.Size - 2
	if len(saKeyJSON) <= maxDirect {
		t.Fatalf("test premise broken: SA key is %d bytes, OAEP limit is %d", len(saKeyJSON), maxDirect)
	}
	if _, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &wrap.PublicKey, saKeyJSON, nil); err == nil {
		t.Fatal("expected direct OAEP of an SA key to fail on message size")
	}
}

func TestFetchFailsLoudlyWhenMAAEndpointUnset(t *testing.T) {
	f := newAzureFixture(t)
	t.Setenv("QUILL_AZURE_MAA_ENDPOINT", "")

	_, err := Fetch(context.Background())
	// Defaulting the MAA instance would attest against an authority nobody
	// chose — the forgery hole the verifier work closed.
	requireErrContains(t, err, "bootstrap/azure", "skr config", "QUILL_AZURE_MAA_ENDPOINT")
	_ = f
}

func TestFetchSidecarUnreachable(t *testing.T) {
	f := newAzureFixture(t)
	// A server that has been closed leaves a port nothing is listening on.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	t.Setenv("QUILL_AZURE_SKR_URL", deadURL+"/key/release")

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "skr release", "unreachable", "skr sidecar")
	_ = f
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

func TestFetchCiphertextUndecryptable(t *testing.T) {
	f := newAzureFixture(t)
	// Sealed to a key the sidecar will never release: the exact shape of a
	// stale blob left behind after a vault key rotation.
	f.sealTo(f.foreign.Public().(*rsa.PublicKey))

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "sa-key decrypt", "RSA-OAEP-SHA256", "CURRENT vault key")
}

func TestFetchCiphertextEnvelopeCorrupt(t *testing.T) {
	f := newAzureFixture(t)
	envelope := sealEnvelope(t, f.wrapKey.Public().(*rsa.PublicKey), f.saKeyJSON)
	var env saKeyEnvelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Flip a byte of the GCM ciphertext: OAEP still unwraps, the AEAD tag fails.
	ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	ct[0] ^= 0xff
	env.Ciphertext = base64.StdEncoding.EncodeToString(ct)
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	t.Setenv("QUILL_AZURE_SA_KEY_CIPHERTEXT", base64.StdEncoding.EncodeToString(tampered))

	_, err = Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "sa-key decrypt", "AES-GCM open failed")
}

// crypto/cipher's gcm.Open PANICS on a wrong-length nonce rather than
// returning an error. Without the explicit length check the enclave would not
// report a malformed envelope, it would crash at boot — the exact "hung with no
// explanation" failure mode this file is written to avoid.
func TestFetchEnvelopeBadNonceLengthIsAnErrorNotAPanic(t *testing.T) {
	f := newAzureFixture(t)
	envelope := sealEnvelope(t, f.wrapKey.Public().(*rsa.PublicKey), f.saKeyJSON)
	var env saKeyEnvelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	env.Nonce = base64.StdEncoding.EncodeToString(make([]byte, 13)) // GCM wants 12
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	t.Setenv("QUILL_AZURE_SA_KEY_CIPHERTEXT", base64.StdEncoding.EncodeToString(tampered))

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Fetch panicked instead of returning an error: %v", r)
		}
	}()
	_, err = Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "sa-key decrypt", "nonce is 13 bytes", "want 12")
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

// Both forms set is a deploy that cannot be reasoned about during an incident:
// "which blob was actually used?" has no answer. Refuse instead of picking one.
func TestFetchRejectsBothCiphertextFormsAtOnce(t *testing.T) {
	f := newAzureFixture(t)
	path := t.TempDir() + "/sa-key.bin"
	if err := os.WriteFile(path, sealEnvelope(t, f.wrapKey.Public().(*rsa.PublicKey), f.saKeyJSON), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("QUILL_AZURE_SA_KEY_CIPHERTEXT_PATH", path)

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "sa-key ciphertext", "both set", "set exactly one")
}

// The path form is the mounted-secret-volume deploy shape, and it has to work
// as well as the inline env form.
func TestFetchAcceptsCiphertextFromPath(t *testing.T) {
	f := newAzureFixture(t)
	path := t.TempDir() + "/sa-key.bin"
	if err := os.WriteFile(path, sealEnvelope(t, f.wrapKey.Public().(*rsa.PublicKey), f.saKeyJSON), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("QUILL_AZURE_SA_KEY_CIPHERTEXT", "")
	t.Setenv("QUILL_AZURE_SA_KEY_CIPHERTEXT_PATH", path)

	data, err := Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if data.GCPServiceAccountKeyJSON != string(f.saKeyJSON) {
		t.Error("SA key from the path form did not round-trip")
	}
}

func TestFetchCiphertextMissing(t *testing.T) {
	f := newAzureFixture(t)
	t.Setenv("QUILL_AZURE_SA_KEY_CIPHERTEXT", "")

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "sa-key ciphertext", "QUILL_AZURE_SA_KEY_CIPHERTEXT")
	_ = f
}

func TestFetchTokenEndpoint4xx(t *testing.T) {
	f := newAzureFixture(t)
	f.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`, http.StatusBadRequest)
	}

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "google token", "jwt-bearer exchange", "400", "invalid_grant", testSAEmail)
}

func TestFetchTokenEndpointEmptyToken(t *testing.T) {
	f := newAzureFixture(t)
	f.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"expires_in": 3600})
	}

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "google token", "empty access_token")
}

// The 200 body of the token endpoint IS an access token. Withholding it from
// the parse error is deliberate, so it is asserted rather than left to the
// accident of encoding/json not echoing input.
func TestFetchTokenEndpointNonJSONWithholdsBody(t *testing.T) {
	f := newAzureFixture(t)
	f.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"access_token":"`+testAccessToken+`" TRUNCATED`)
	}

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "google token", "not JSON", "body withheld")
	if strings.Contains(err.Error(), testAccessToken) {
		t.Errorf("access token leaked into the parse error: %v", err)
	}
}

func TestFetchSecretFetchFailingNamesTheSecret(t *testing.T) {
	f := newAzureFixture(t)
	f.secretHandler = func(w http.ResponseWriter, r *http.Request) {
		if secretNameFromPath(r.URL.Path) == testORSecret {
			http.Error(w, `{"error":{"code":403,"message":"Permission denied on secret"}}`, http.StatusForbidden)
			return
		}
		f.serveSecret(w, r)
	}

	_, err := Fetch(context.Background())
	// The label must identify WHICH secret, otherwise an operator is left
	// guessing which of ~40 entries is misconfigured.
	requireErrContains(t, err, "bootstrap/azure", "openrouter key", "secret fetch http 403", "Permission denied")
}

func TestFetchDeviceKeysFetchFailingIsNamedSeparately(t *testing.T) {
	f := newAzureFixture(t)
	f.secretHandler = func(w http.ResponseWriter, r *http.Request) {
		if secretNameFromPath(r.URL.Path) == testDevicesSecret {
			http.Error(w, `{"error":{"code":404,"message":"Secret not found"}}`, http.StatusNotFound)
			return
		}
		f.serveSecret(w, r)
	}

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "device-keys", "404")
}

func TestFetchDeviceKeysNotJSON(t *testing.T) {
	f := newAzureFixture(t)
	f.secretValues[testDevicesSecret] = "not-json-at-all"

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "parse device-keys JSON")
}

// Secret Manager payloads routinely carry a trailing newline (anything created
// with `printf ... | gcloud secrets create --data-file=-` does). An API key
// with "\n" on the end produces an unparseable Authorization header and a 401
// from the provider that looks like a bad key rather than a bad payload.
func TestFetchTrimsWhitespaceFromSecretValues(t *testing.T) {
	f := newAzureFixture(t)
	f.secretValues[testORSecret] = "  " + testORValue + "\n"
	f.secretValues[testAnthSecret] = testAnthValue + "\r\n"

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

func TestFetchRequiresProjectID(t *testing.T) {
	f := newAzureFixture(t)
	t.Setenv("QUILL_GCP_PROJECT_ID", "")

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "QUILL_GCP_PROJECT_ID not set")
	_ = f
}

func TestFetchRequiresDeviceKeysSecret(t *testing.T) {
	f := newAzureFixture(t)
	t.Setenv("QUILL_DEVICE_KEYS_SECRET", "")

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "QUILL_DEVICE_KEYS_SECRET not set")
	_ = f
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

func TestFetchRequiresProviderSecret(t *testing.T) {
	f := newAzureFixture(t)
	t.Setenv("QUILL_OPENROUTER_SECRET", "")
	t.Setenv("QUILL_ANTHROPIC_SECRET", "")

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "at least one provider secret")
	_ = f
}

// TestNoSecretMaterialIsEverLogged runs every path — success and each failure
// — and scans both the returned error and everything written to
// stdout/stderr/log for material that must never escape the boundary.
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
		{"ciphertext undecryptable", func(_ *testing.T, f *azureFixture) {
			f.sealTo(f.foreign.Public().(*rsa.PublicKey))
		}},
		{"token endpoint 4xx", func(_ *testing.T, f *azureFixture) {
			f.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			}
		}},
		{"token 200 non-JSON", func(_ *testing.T, f *azureFixture) {
			f.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"access_token":"`+testAccessToken+`" TRUNCATED`)
			}
		}},
		{"secret fetch 403", func(_ *testing.T, f *azureFixture) {
			f.secretHandler = func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, `{"error":{"code":403}}`, http.StatusForbidden)
			}
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
				"minted Google access token":        testAccessToken,
				"openrouter API key":                testORValue,
				"anthropic API key":                 testAnthValue,
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
// the trust gate itself
// ---------------------------------------------------------------------------

// TestSKRReleaseStepIsActuallyExercised is the regression test for the gate.
//
// Everything else in this file would still pass if the SKR round trip were
// replaced by something that produces a key locally, as long as that key could
// open the envelope. This test fails on any such mutation: it requires that the
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

// The released key is not decoration: it is the ONLY thing that opens the
// envelope. A locally invented key, however well-formed, must not boot the
// enclave.
func TestOnlyTheReleasedKeyOpensTheCiphertext(t *testing.T) {
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
	requireErrContains(t, err, "bootstrap/azure", "sa-key decrypt")
}

// QUILL_AZURE_SKR_URL decides whether attestation happens at all. Left
// unconstrained it was a complete bypass: an off-box endpoint returning any RSA
// JWK, plus a ciphertext sealed to it, boots the enclave on an attacker's
// Google identity with no MAA exchange, no Key Vault call and no hostdata
// check — while /attestation keeps serving a genuine token for the real
// measurement.
func TestFetchRefusesNonLoopbackSKRURL(t *testing.T) {
	f := newAzureFixture(t)
	t.Setenv("QUILL_AZURE_SKR_URL", "http://skr.attacker.example/key/release")

	_, err := Fetch(context.Background())
	requireErrContains(t, err, "bootstrap/azure", "skr config", "QUILL_AZURE_SKR_URL", "not loopback")
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
// error hygiene
// ---------------------------------------------------------------------------

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
// ciphertext loading
// ---------------------------------------------------------------------------

// Both ciphertext forms accept the same bytes. They did not always: inline was
// base64-decoded and the path form was not, so writing the exact string you
// would have put in the env var into a file produced a boot-fatal error that
// blamed the vault key over one layer of base64.
func TestFetchAcceptsBase64EnvelopeFromPath(t *testing.T) {
	f := newAzureFixture(t)
	envelope := sealEnvelope(t, f.wrapKey.Public().(*rsa.PublicKey), f.saKeyJSON)
	for _, form := range []struct {
		name  string
		bytes []byte
	}{
		{"raw envelope JSON", envelope},
		{"base64 of the envelope", []byte(base64.StdEncoding.EncodeToString(envelope))},
		{"base64, line-wrapped at 76 columns", []byte(wrapLines(base64.StdEncoding.EncodeToString(envelope), 76))},
		{"raw envelope JSON with a trailing newline", append(append([]byte{}, envelope...), '\n')},
	} {
		t.Run(form.name, func(t *testing.T) {
			path := t.TempDir() + "/sa-key.bin"
			if err := os.WriteFile(path, form.bytes, 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			t.Setenv("QUILL_AZURE_SA_KEY_CIPHERTEXT", "")
			t.Setenv("QUILL_AZURE_SA_KEY_CIPHERTEXT_PATH", path)

			data, err := Fetch(context.Background())
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if data.GCPServiceAccountKeyJSON != string(f.saKeyJSON) {
				t.Error("SA key did not round-trip")
			}
		})
	}
}

// The inline form accepts the envelope JSON directly too, so an operator who
// skips the base64 step is not sent chasing the vault key.
func TestFetchAcceptsRawEnvelopeInline(t *testing.T) {
	f := newAzureFixture(t)
	envelope := sealEnvelope(t, f.wrapKey.Public().(*rsa.PublicKey), f.saKeyJSON)
	t.Setenv("QUILL_AZURE_SA_KEY_CIPHERTEXT_PATH", "")
	t.Setenv("QUILL_AZURE_SA_KEY_CIPHERTEXT", string(envelope))

	data, err := Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if data.GCPServiceAccountKeyJSON != string(f.saKeyJSON) {
		t.Error("SA key did not round-trip")
	}
}

// RSA-OAEP output is uniform binary, so ~4.6% of ciphertexts begin or end with
// a byte that happens to be ASCII whitespace. Trimming those shortened the blob
// and produced a decrypt error telling the operator to rotate a vault key that
// was fine.
func TestLoadSAKeyCiphertextDoesNotTruncateBinaryBlobs(t *testing.T) {
	for _, edge := range []byte{0x20, 0x09, 0x0a, 0x0b, 0x0c, 0x0d} {
		// A blob that is deliberately NOT valid base64 (it contains 0xff) and
		// not JSON, i.e. the bare-OAEP shape, with a whitespace byte at each end.
		blob := make([]byte, 256)
		for i := range blob {
			blob[i] = 0xff
		}
		blob[0] = edge
		blob[len(blob)-1] = edge

		path := t.TempDir() + "/blob.bin"
		if err := os.WriteFile(path, blob, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		t.Setenv("QUILL_AZURE_SA_KEY_CIPHERTEXT", "")
		t.Setenv("QUILL_AZURE_SA_KEY_CIPHERTEXT_PATH", path)

		loaded, err := loadSAKeyCiphertext()
		if err != nil {
			t.Fatalf("loadSAKeyCiphertext: %v", err)
		}
		if !bytes.Equal(loaded, blob) {
			t.Errorf("0x%02x-delimited %d-byte blob loaded as %d bytes", edge, len(blob), len(loaded))
		}
	}
}

// ---------------------------------------------------------------------------
// envelope conformance
// ---------------------------------------------------------------------------

// aes.NewCipher accepts 16 and 24 bytes as well, so without an explicit size
// check an envelope declaring A256GCM opened fine under AES-128 and the label
// was decorative.
func TestFetchRejectsContentKeyThatIsNotAES256(t *testing.T) {
	f := newAzureFixture(t)
	for _, size := range []int{16, 24} {
		t.Run(fmt.Sprintf("%d-byte content key", size), func(t *testing.T) {
			t.Setenv("QUILL_AZURE_SA_KEY_CIPHERTEXT", base64.StdEncoding.EncodeToString(
				sealEnvelopeWithContentKeySize(t, f.wrapKey.Public().(*rsa.PublicKey), f.saKeyJSON, size)))

			_, err := Fetch(context.Background())
			requireErrContains(t, err, "bootstrap/azure", "sa-key decrypt",
				fmt.Sprintf("content key is %d bytes", size), "RSA-OAEP-256+A256GCM")
		})
	}
}

// ---------------------------------------------------------------------------
// the shared Google path (this file is the only coverage it has)
// ---------------------------------------------------------------------------

// A secret NAME that is present but blank is a broken deploy, and it must fail
// at boot. An earlier draft skipped it: QUILL_ANTHROPIC_SECRET="   " booted a
// gateway whose Anthropic key was "" and 401ed every Anthropic request at
// runtime. The pre-refactor GCP code fetched a secret literally named "   " and
// died 404; this fails earlier and names the variable. secrets_google.go is
// shared, so this covers the live GCP path too.
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
	_ = f
	t.Setenv("QUILL_ADVISOR_PROMPT_SECRET", "")
	t.Setenv("QUILL_SOCRATES_ADVISOR_PROMPT_SECRET", "tr-advisor-prompt")

	data, err := Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if data.AdvisorPrompt != "unused-tr-advisor-prompt" {
		t.Errorf("advisor prompt = %q, want the value of the legacy-named secret", data.AdvisorPrompt)
	}
}

// secretManagerBaseURL is a package var so this file can redirect it. That is
// only acceptable while production still resolves to the real host.
func TestSecretManagerBaseURLDefaultsToProduction(t *testing.T) {
	if secretManagerHost != "https://secretmanager.googleapis.com" {
		t.Errorf("secretManagerHost = %q", secretManagerHost)
	}
	// newAzureFixture redirects it and restores it on cleanup; outside a
	// fixture it must be the production host.
	if secretManagerBaseURL != secretManagerHost {
		t.Errorf("secretManagerBaseURL = %q, want %q — the test seam leaked", secretManagerBaseURL, secretManagerHost)
	}
}

// ---------------------------------------------------------------------------
// boot-path resilience
// ---------------------------------------------------------------------------

// Every Google call here is a cross-cloud WAN round trip from UAE North, and
// main.go turns any bootstrap error into os.Exit(1). Without retries a single
// transient 503 anywhere in ~41 calls is a container-group crash-loop that
// re-runs the SNP report and MAA exchange on every restart.
func TestFetchRetriesTransientGoogleFailures(t *testing.T) {
	f := newAzureFixture(t)

	var tokenAttempts, secretAttempts int32
	f.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&tokenAttempts, 1) == 1 {
			http.Error(w, "upstream connect error", http.StatusServiceUnavailable)
			return
		}
		f.serveToken(w, r)
	}
	f.secretHandler = func(w http.ResponseWriter, r *http.Request) {
		if secretNameFromPath(r.URL.Path) == testORSecret && atomic.AddInt32(&secretAttempts, 1) == 1 {
			http.Error(w, "backend error", http.StatusInternalServerError)
			return
		}
		f.serveSecret(w, r)
	}

	data, err := Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch did not survive one transient 5xx per call: %v", err)
	}
	if data.OpenRouterAPIKey != testORValue {
		t.Errorf("openrouter key = %q", data.OpenRouterAPIKey)
	}
	if got := atomic.LoadInt32(&tokenAttempts); got < 2 {
		t.Errorf("token endpoint attempted %d times, want a retry", got)
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
// from Secret Manager — only delays a boot that is already doomed, and on the
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
	t.Run("secret 403", func(t *testing.T) {
		f := newAzureFixture(t)
		var attempts int32
		f.secretHandler = func(w http.ResponseWriter, r *http.Request) {
			if secretNameFromPath(r.URL.Path) == testORSecret {
				atomic.AddInt32(&attempts, 1)
				http.Error(w, `{"error":{"code":403}}`, http.StatusForbidden)
				return
			}
			f.serveSecret(w, r)
		}
		_, err := Fetch(context.Background())
		requireErrContains(t, err, "openrouter key", "403")
		if got := atomic.LoadInt32(&attempts); got != 1 {
			t.Errorf("secret fetch attempted %d times on a 403, want 1", got)
		}
	})
}

// sealEnvelopeWithContentKeySize seals with a deliberately wrong content-key
// size while still labelling the envelope A256GCM.
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
	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, contentKey, nil)
	if err != nil {
		t.Fatalf("oaep wrap: %v", err)
	}
	raw, err := json.Marshal(saKeyEnvelope{
		V:          1,
		Alg:        "RSA-OAEP-256+A256GCM",
		EncKey:     base64.StdEncoding.EncodeToString(encKey),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, plaintext, nil)),
	})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return raw
}

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
	}
	return base64.StdEncoding.EncodeToString(block.Bytes)[:64]
}
