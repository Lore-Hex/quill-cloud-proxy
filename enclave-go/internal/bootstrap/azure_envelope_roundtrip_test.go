//go:build cloud_azure

package bootstrap

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- used ONLY to prove the decryptor rejects a non-SHA-256 OAEP digest
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// This file is the CONTRACT TEST between tools/azure-seal-bundle.py and
// decryptEnvelope() in bootstrap_azure.go.
//
// Why it exists, stated plainly: until it did, NOTHING had ever produced a
// ciphertext this Go code accepted. The OAEP parameters, the envelope field
// names, the base64 dialect and the GCM tag layout were a shared *guess*,
// written twice from the same paragraph of documentation. That is precisely the
// shape of mistake that only surfaces against the real thing — the first draft
// of attestation_azure.go hashed SHA-512 into REPORT_DATA and would never have
// verified a single token, and the first Azure bootstrap called Google on the
// boot path. A guess that both sides share looks like agreement and is not.
//
// So these tests do not stub the crypto and do not re-implement the sealer.
// They EXECUTE the Python producer as a subprocess, feed its bytes through the
// unmodified enclave boot path (skr release -> IMDS -> Key Vault ->
// decodeCiphertextBlob -> decryptEnvelope -> parseBundle ->
// assembleBootstrapData), and assert the secrets come back byte for byte.
//
// If the sealer is unavailable these tests FAIL rather than skip. A skip would
// convert "the contract is unverified" into a green run, which is the exact
// state this file was written to end.

// sealerScript is the producer under test, relative to this package directory.
const sealerScript = "../../../tools/azure-seal-bundle.py"

// sealerPython resolves the interpreter that runs the sealer.
//
// QUILL_AZURE_SEALER_PYTHON lets CI point at a venv that has `cryptography`
// installed (see .github/workflows/ci.yml); otherwise plain python3. Either
// way the interpreter must be able to import cryptography, and if it cannot
// this is a hard failure with the exact remedy in the message — not a skip.
func sealerPython(t *testing.T) string {
	t.Helper()
	python := os.Getenv("QUILL_AZURE_SEALER_PYTHON")
	if strings.TrimSpace(python) == "" {
		python = "python3"
	}
	if _, err := os.Stat(sealerScript); err != nil {
		t.Fatalf("sealer %s not found: %v", sealerScript, err)
	}
	// Import what the sealer actually imports, not just the top-level package.
	// A bare `import cryptography` succeeds against a half-installed wheel whose
	// _cffi_backend is missing, and then the failure surfaces as an unreadable
	// traceback inside a subprocess three tests later.
	probe := "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; " +
		"from cryptography.hazmat.primitives.asymmetric import rsa, padding"
	out, err := exec.Command(python, "-c", probe).CombinedOutput() // #nosec G204 -- operator/CI-supplied interpreter path
	if err != nil {
		t.Fatalf("the envelope round-trip needs a python with `cryptography`.\n"+
			"  interpreter: %s\n"+
			"  error:       %v\n"+
			"  output:      %s\n"+
			"  fix:         python3 -m pip install cryptography\n"+
			"               (or set QUILL_AZURE_SEALER_PYTHON=/path/to/venv/bin/python)\n"+
			"  NOT skipped on purpose: an unverified seal/open contract is how a deploy\n"+
			"  reaches an enclave that attests correctly and then cannot decrypt its secrets.",
			python, err, out)
	}
	return python
}

// runSealer executes the producer and returns its combined output.
func runSealer(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(sealerPython(t), append([]string{sealerScript}, args...)...) // #nosec G204 -- fixed script, test-controlled args
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ---------------------------------------------------------------------------
// the deploy env under test — EVERY binding, so the round trip doubles as the
// coverage proof
// ---------------------------------------------------------------------------

// fullDeployEnv builds a container-group environment that configures every
// entry in secretBindings, plus the two entries that are not in the table (the
// device blob and the service-account key).
//
// Using the whole table rather than a representative two is deliberate: it
// makes "a newly added provider secret is missing from the sealer" a failing
// test rather than a code review someone has to remember to do. A new binding
// with no sealer support fails here before it can fail in UAE North.
func fullDeployEnv() (env map[string]string, secretNameFor []string) {
	env = map[string]string{
		"QUILL_GCP_PROJECT_ID":      testProject,
		"QUILL_GCP_REGION":          "uaenorth",
		"QUILL_DEVICE_KEYS_SECRET":  testDevicesSecret,
		"TR_CONTROL_PLANE_BASE_URL": "https://trustedrouter.com",

		// The Azure-side coordinates. resolveAzureConfig() requires all of
		// these, and the sealer requires them too so that a bundle can never be
		// built for a deploy that could not boot.
		"QUILL_AZURE_MAA_ENDPOINT":  testMAAEndpoint,
		"QUILL_AZURE_AKV_ENDPOINT":  testAKVEndpoint,
		"QUILL_AZURE_SKR_KEY_ID":    testSKRKeyID,
		"QUILL_AZURE_BUNDLE_SECRET": testBundleSecret,
		"QUILL_AZURE_SA_KEY_ENTRY":  testSAKeyEntry,
		"QUILL_AZURE_REGION":        "uaenorth",
	}
	secretNameFor = make([]string, len(secretBindings))
	for i, binding := range secretBindings {
		// One distinct, derived secret name per binding: "tr-secret-07-..." is
		// unique per entry, so a mapping that assigns the wrong field cannot
		// accidentally compare equal.
		name := fmt.Sprintf("tr-secret-%02d-%s", i, strings.ReplaceAll(binding.label, " ", "-"))
		secretNameFor[i] = name
		// The FIRST env name, which is the one firstSetEnv() prefers. The
		// legacy SOCRATES_* spellings are covered by secrets_test.go.
		env[binding.envs[0]] = name
	}
	return env, secretNameFor
}

// applyEnv mirrors the deploy env into the process, so the Go side reads
// exactly what the Python side was told. One map, two consumers — a test that
// built the two independently could pass while the real pair disagreed.
func applyEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for key, value := range env {
		t.Setenv(key, value)
	}
}

func writeJSONFile(t *testing.T, dir, name string, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %s: %v", name, err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// publicKeyPEM writes the wrapping key's PUBLIC half, which is all the sealer
// ever needs — the same asymmetry that makes this envelope confidential but not
// authentic, spelled out in the package comment.
func publicKeyPEM(t *testing.T, dir string, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	path := filepath.Join(dir, "wrap.pub.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	return path
}

// ---------------------------------------------------------------------------
// THE round trip
// ---------------------------------------------------------------------------

// TestPythonSealedBundleBootsTheEnclave is the test this whole file is for.
//
// Python seals; the real Fetch() opens. Nothing between them is stubbed: the
// bytes the sealer wrote are served as the Key Vault secret value verbatim, so
// decodeCiphertextBlob, decryptEnvelope, parseBundle and assembleBootstrapData
// all run on producer output. The assertion is byte-identity on every secret,
// against an expectation built by applying the binding table's own assign
// functions — so a mapping that lands a value in the wrong field fails here.
func TestPythonSealedBundleBootsTheEnclave(t *testing.T) {
	clearSecretEnv(t)
	f := newAzureFixture(t)
	env, secretNames := fullDeployEnv()
	applyEnv(t, env)

	dir := t.TempDir()

	// Values: one distinctive payload per secret. Distinctive because a
	// round-trip test whose values are all "x" cannot tell a correct mapping
	// from a scrambled one.
	devicesJSON := `[{"key_hash":"c0ffee","owner":"joseph","device_id":"dev-1"}]`
	values := map[string]string{testDevicesSecret: devicesJSON}
	want := &types.BootstrapData{
		Region:               env["QUILL_GCP_REGION"],
		TrustedRouterBaseURL: env["TR_CONTROL_PLANE_BASE_URL"],
	}
	if err := json.Unmarshal([]byte(devicesJSON), &want.Devices); err != nil {
		t.Fatalf("unmarshal devices: %v", err)
	}
	for i, binding := range secretBindings {
		value := fmt.Sprintf("VALUE-%02d-%s-DO-NOT-LOG", i, strings.ToUpper(strings.ReplaceAll(binding.label, " ", "_")))
		values[secretNames[i]] = value
		binding.assign(want, value)
	}
	// One value carries surrounding whitespace, because real secrets do:
	// anything created with `printf ... | gcloud secrets create --data-file=-`
	// ends in a newline, and a bundle built by dumping them inherits it. The
	// enclave trims; the expectation is therefore the trimmed value, which
	// pins that behaviour across the seam rather than leaving it to chance.
	values[secretNames[0]] = "\n  " + values[secretNames[0]] + "  \n"

	saKeyJSON := makeSAKeyJSON(t, f.saKey)
	saKeyPath := filepath.Join(dir, "sa-key.json")
	if err := os.WriteFile(saKeyPath, saKeyJSON, 0o600); err != nil {
		t.Fatalf("write sa key: %v", err)
	}

	envPath := writeJSONFile(t, dir, "deploy-env.json", env)
	valuesPath := writeJSONFile(t, dir, "values.json", values)
	envelopePath := filepath.Join(dir, "bundle.enc.json")

	out, err := runSealer(t,
		"--deploy-env", envPath,
		"--values", valuesPath,
		// Exercises the file-valued path the operator uses for the SA key,
		// which is far too large and too quote-heavy to paste into JSON.
		"--value-file", testSAKeyEntry+"="+saKeyPath,
		"--public-key-pem", publicKeyPEM(t, dir, f.wrapKey),
		"--out", envelopePath,
	)
	if err != nil {
		t.Fatalf("sealer failed: %v\n%s", err, out)
	}

	envelope, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatalf("read sealed envelope: %v", err)
	}
	assertEnvelopeShape(t, envelope, f.wrapKey)

	// Serve the sealer's bytes VERBATIM as the Key Vault secret value. Not
	// re-encoded, not re-marshalled: whatever the producer wrote is what the
	// enclave gets.
	f.rawVaultValue = string(envelope)

	got, err := Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch on a python-sealed bundle: %v", err)
	}

	// The SA key is not part of the binding table; Fetch fills it from the
	// entry QUILL_AZURE_SA_KEY_ENTRY names.
	want.GCPServiceAccountKeyJSON = string(saKeyJSON)

	if !reflect.DeepEqual(got, want) {
		// Field-by-field, because a whole-struct dump of ~40 secrets is
		// unreadable and would print every one of them.
		wantValue, gotValue := reflect.ValueOf(*want), reflect.ValueOf(*got)
		for i := 0; i < wantValue.NumField(); i++ {
			name := wantValue.Type().Field(i).Name
			if !reflect.DeepEqual(wantValue.Field(i).Interface(), gotValue.Field(i).Interface()) {
				t.Errorf("BootstrapData.%s did not survive the round trip:\n  sealed by python: %v\n  opened by go:     %v",
					name, wantValue.Field(i).Interface(), gotValue.Field(i).Interface())
			}
		}
		t.FailNow()
	}

	// Exactly one Key Vault round trip, and the SKR release actually happened:
	// a "round trip" that skipped the attestation-gated key would prove nothing
	// about the envelope that matters.
	if n := len(f.skrRequests()); n != 1 {
		t.Errorf("skr release called %d times, want exactly 1", n)
	}
	if n := len(f.vaultRequests()); n != 1 {
		t.Errorf("key vault called %d times, want exactly 1", n)
	}
}

// TestPythonSealedBundleSurvivesBase64Wrapping covers the other storage form.
//
// decodeCiphertextBlob accepts the envelope JSON or base64 OF that JSON,
// because `az keyvault secret set` stores whatever string it is handed and an
// operator pipeline that base64s on the way in is a boot-fatal error over one
// layer of encoding otherwise. Both forms have to work on producer output, not
// just on a Go-built fixture.
func TestPythonSealedBundleSurvivesBase64Wrapping(t *testing.T) {
	clearSecretEnv(t)
	f := newAzureFixture(t)
	env, secretNames := fullDeployEnv()
	applyEnv(t, env)

	dir := t.TempDir()
	values := map[string]string{
		testDevicesSecret: `[{"key_hash":"c0ffee","owner":"joseph","device_id":"dev-1"}]`,
	}
	for i := range secretBindings {
		values[secretNames[i]] = fmt.Sprintf("value-%02d", i)
	}
	saKeyPath := filepath.Join(dir, "sa-key.json")
	if err := os.WriteFile(saKeyPath, makeSAKeyJSON(t, f.saKey), 0o600); err != nil {
		t.Fatalf("write sa key: %v", err)
	}

	envelopePath := filepath.Join(dir, "bundle.enc.json")
	if out, err := runSealer(t,
		"--deploy-env", writeJSONFile(t, dir, "deploy-env.json", env),
		"--values", writeJSONFile(t, dir, "values.json", values),
		"--value-file", testSAKeyEntry+"="+saKeyPath,
		"--public-key-pem", publicKeyPEM(t, dir, f.wrapKey),
		"--out", envelopePath,
	); err != nil {
		t.Fatalf("sealer failed: %v\n%s", err, out)
	}
	envelope, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatalf("read sealed envelope: %v", err)
	}

	f.rawVaultValue = base64.StdEncoding.EncodeToString(envelope)
	got, err := Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch on a base64-wrapped python envelope: %v", err)
	}
	if got.OpenRouterAPIKey != "value-00" {
		t.Errorf("openrouter key = %q, want %q", got.OpenRouterAPIKey, "value-00")
	}
}

// assertEnvelopeShape pins the wire format itself, independently of whether it
// happens to decrypt.
//
// decryptEnvelope is deliberately tolerant on read (four base64 dialects), so a
// producer that switched to url-safe base64 would still work and this test
// would be the only place the change is visible. That tolerance is right for
// robustness and wrong for drift detection, so the two jobs are split: the
// round trip proves interoperability, this proves the format did not move.
func assertEnvelopeShape(t *testing.T, envelope []byte, key *rsa.PrivateKey) {
	t.Helper()

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(envelope, &fields); err != nil {
		t.Fatalf("envelope is not a JSON object: %v", err)
	}
	gotKeys := make([]string, 0, len(fields))
	for name := range fields {
		gotKeys = append(gotKeys, name)
	}
	sort.Strings(gotKeys)
	wantKeys := []string{"alg", "ciphertext", "enc_key", "nonce", "v"}
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Fatalf("envelope fields = %v, want exactly %v (secretEnvelope's json tags)", gotKeys, wantKeys)
	}

	var env secretEnvelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatalf("envelope does not unmarshal into secretEnvelope: %v", err)
	}
	if env.V != envelopeVersion {
		t.Errorf("envelope v = %d, want %d", env.V, envelopeVersion)
	}
	if env.Alg != envelopeAlg {
		t.Errorf("envelope alg = %q, want %q", env.Alg, envelopeAlg)
	}

	// Standard base64 WITH padding, strictly. Go would accept three other
	// dialects; this is the canary that says the producer changed.
	decoded := map[string][]byte{}
	for _, field := range []struct{ name, value string }{
		{"enc_key", env.EncKey}, {"nonce", env.Nonce}, {"ciphertext", env.Ciphertext},
	} {
		raw, err := base64.StdEncoding.DecodeString(field.value)
		if err != nil {
			t.Errorf("envelope %s is not standard padded base64 (decryptEnvelope tolerates other dialects, "+
				"so this is a producer-drift canary, not an interop failure): %v", field.name, err)
			continue
		}
		decoded[field.name] = raw
	}
	// Length checks only on fields that decoded: a partial decode reports a
	// nonsense byte count and buries the real diagnosis under it.
	if nonce, ok := decoded["nonce"]; ok && len(nonce) != 12 {
		t.Errorf("nonce is %d bytes, want 12 (crypto/cipher's gcm.Open PANICS on a wrong-length nonce, "+
			"which on the boot path is the 'hung with no explanation' failure this package exists to avoid)", len(nonce))
	}
	if encKey, ok := decoded["enc_key"]; ok && len(encKey) != key.Size() {
		t.Errorf("enc_key is %d bytes, want %d (one RSA block for a %d-bit key)", len(encKey), key.Size(), key.N.BitLen())
	}
}

// ---------------------------------------------------------------------------
// the assertions above must have teeth
// ---------------------------------------------------------------------------

// TestDecryptEnvelopeRejectsADriftedOAEPDigest proves the round trip would
// actually catch a digest disagreement.
//
// The OAEP digest was a guess on both sides, and a guess is only closed by a
// test that fails when the guess is wrong. This builds a structurally perfect
// envelope whose ONLY defect is SHA-1 instead of SHA-256 in OAEP, and requires
// decryptEnvelope to refuse it. If this passed, TestPythonSealedBundleBoots...
// would be green against a sealer using any digest at all, and the contract it
// claims to verify would be vacuous.
func TestDecryptEnvelopeRejectsADriftedOAEPDigest(t *testing.T) {
	wrap, _, _ := testKeys(t)
	payload := []byte(`{"tr-device-keys":"[]"}`)

	contentKey := make([]byte, envelopeContentKeyBytes)
	nonce := make([]byte, 12)
	if _, err := rand.Read(contentKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand: %v", err)
	}
	block, err := aes.NewCipher(contentKey)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	ciphertext := gcm.Seal(nil, nonce, payload, nil)

	for _, tc := range []struct {
		name   string
		digest func() (encKey []byte, err error)
	}{
		{"sha256 (the contract)", func() ([]byte, error) {
			return rsa.EncryptOAEP(sha256.New(), rand.Reader, &wrap.PublicKey, contentKey, nil)
		}},
		{"sha1 (drift)", func() ([]byte, error) {
			return rsa.EncryptOAEP(sha1.New(), rand.Reader, &wrap.PublicKey, contentKey, nil) // #nosec G401 -- negative control
		}},
		{"sha256 with a label (drift)", func() ([]byte, error) {
			return rsa.EncryptOAEP(sha256.New(), rand.Reader, &wrap.PublicKey, contentKey, []byte("quill"))
		}},
	} {
		encKey, err := tc.digest()
		if err != nil {
			t.Fatalf("%s: wrap content key: %v", tc.name, err)
		}
		raw, err := json.Marshal(secretEnvelope{
			V:          envelopeVersion,
			Alg:        envelopeAlg,
			EncKey:     base64.StdEncoding.EncodeToString(encKey),
			Nonce:      base64.StdEncoding.EncodeToString(nonce),
			Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		})
		if err != nil {
			t.Fatalf("%s: marshal: %v", tc.name, err)
		}
		plaintext, err := decryptEnvelope(wrap, raw)
		if strings.HasPrefix(tc.name, "sha256 (") {
			if err != nil {
				t.Fatalf("the contract digest must open: %v", err)
			}
			if string(plaintext) != string(payload) {
				t.Fatalf("contract digest opened to %q, want %q", plaintext, payload)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: decryptEnvelope ACCEPTED a mis-wrapped content key — the round-trip "+
				"test cannot detect OAEP drift and proves nothing", tc.name)
		}
	}
}

// ---------------------------------------------------------------------------
// the sealer's binding table cannot drift from secrets.go
// ---------------------------------------------------------------------------

// TestSealerBindingTableMatchesSecretBindings compares the Python mirror of the
// binding table with the Go original, entry for entry, in order.
//
// The sealer needs the table to know WHICH bundle keys a given container-group
// env demands. It cannot import secrets.go, so it carries a copy — and an
// unchecked copy of an order-sensitive table in another language is a
// guaranteed future drift. Adding a provider to one side and not the other
// otherwise produces a bundle that is missing exactly one secret, discovered by
// an enclave in UAE North after a full attestation round trip.
func TestSealerBindingTableMatchesSecretBindings(t *testing.T) {
	out, err := runSealer(t, "--print-bindings")
	if err != nil {
		t.Fatalf("sealer --print-bindings failed: %v\n%s", err, out)
	}
	var mirror []struct {
		Envs     []string `json:"envs"`
		Label    string   `json:"label"`
		Provider bool     `json:"provider"`
	}
	if err := json.Unmarshal([]byte(out), &mirror); err != nil {
		t.Fatalf("--print-bindings output is not JSON: %v\n%s", err, out)
	}

	if len(mirror) != len(secretBindings) {
		t.Fatalf("binding tables have drifted: secrets.go has %d entries, "+
			"tools/azure-seal-bundle.py has %d.\n"+
			"  A secret in one and not the other is a bundle that is missing exactly one key.",
			len(secretBindings), len(mirror))
	}
	for i, binding := range secretBindings {
		if !reflect.DeepEqual(mirror[i].Envs, binding.envs) {
			t.Errorf("binding %d envs: secrets.go %v, sealer %v", i, binding.envs, mirror[i].Envs)
		}
		if mirror[i].Label != binding.label {
			t.Errorf("binding %d label: secrets.go %q, sealer %q (the labels must match so a "+
				"seal-time error and a boot-time error name the same secret)", i, binding.label, mirror[i].Label)
		}
		if mirror[i].Provider != binding.provider {
			t.Errorf("binding %d (%s) provider flag: secrets.go %v, sealer %v (this decides whether "+
				"a deploy with only prompts configured is rejected)", i, binding.label, binding.provider, mirror[i].Provider)
		}
	}
}

// TestSealerRefusesToSealAnUnbootableBundle drives the seal-time guards that
// exist so the enclave never has to discover them.
//
// Every case here is a bundle the enclave would reject at boot — after a
// hardware SNP report, an MAA exchange, an IMDS token and a Key Vault fetch,
// with os.Exit(1) and an ACI restart as the diagnostic. Catching them at the
// operator's desk is the difference between a typo and an outage.
func TestSealerRefusesToSealAnUnbootableBundle(t *testing.T) {
	wrap, saKey, _ := testKeys(t)
	baseEnv, secretNames := fullDeployEnv()
	devicesJSON := `[{"key_hash":"c0ffee","owner":"joseph","device_id":"dev-1"}]`

	baseValues := func() map[string]string {
		values := map[string]string{testDevicesSecret: devicesJSON}
		for i := range secretBindings {
			values[secretNames[i]] = fmt.Sprintf("value-%02d", i)
		}
		return values
	}
	copyEnv := func() map[string]string {
		out := make(map[string]string, len(baseEnv))
		for k, v := range baseEnv {
			out[k] = v
		}
		return out
	}

	for _, tc := range []struct {
		name   string
		env    func(map[string]string)
		values func(map[string]string)
		// wants are substrings the failure must name, because an error that
		// does not say WHICH secret is missing costs the same as no error.
		wants []string
	}{
		{
			name:   "a configured provider secret has no value",
			values: func(v map[string]string) { delete(v, secretNames[1]) },
			wants:  []string{secretNames[1], "anthropic key", "does not provide"},
		},
		{
			name:   "a configured secret's value is blank",
			values: func(v map[string]string) { v[secretNames[2]] = "   \n" },
			wants:  []string{secretNames[2], "whitespace-only"},
		},
		{
			name:   "the device blob is missing",
			values: func(v map[string]string) { delete(v, testDevicesSecret) },
			wants:  []string{testDevicesSecret, "device keys"},
		},
		{
			name:   "the device blob is not a JSON array",
			values: func(v map[string]string) { v[testDevicesSecret] = `{"key_hash":"c0ffee"}` },
			wants:  []string{testDevicesSecret, "JSON array"},
		},
		{
			name: "no provider secret is configured at all",
			env: func(e map[string]string) {
				for _, binding := range secretBindings {
					if binding.provider {
						e[binding.envs[0]] = ""
					}
				}
			},
			wants: []string{"at least one provider secret"},
		},
		{
			name:  "a required azure coordinate is unset",
			env:   func(e map[string]string) { e["QUILL_AZURE_BUNDLE_SECRET"] = "" },
			wants: []string{"QUILL_AZURE_BUNDLE_SECRET", "is not set"},
		},
		{
			name:  "a secret name is whitespace only",
			env:   func(e map[string]string) { e["QUILL_OPENAI_SECRET"] = "  " },
			wants: []string{"QUILL_OPENAI_SECRET", "whitespace only"},
		},
		{
			name:   "a value is present that no env names",
			values: func(v map[string]string) { v["tr-secret-nobody-asked-for"] = "orphan" },
			wants:  []string{"tr-secret-nobody-asked-for", "never names"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			env, values := copyEnv(), baseValues()
			if tc.env != nil {
				tc.env(env)
			}
			if tc.values != nil {
				tc.values(values)
			}
			saKeyPath := filepath.Join(dir, "sa-key.json")
			if err := os.WriteFile(saKeyPath, makeSAKeyJSON(t, saKey), 0o600); err != nil {
				t.Fatalf("write sa key: %v", err)
			}
			out, err := runSealer(t,
				"--deploy-env", writeJSONFile(t, dir, "deploy-env.json", env),
				"--values", writeJSONFile(t, dir, "values.json", values),
				"--value-file", testSAKeyEntry+"="+saKeyPath,
				"--public-key-pem", publicKeyPEM(t, dir, wrap),
				"--out", filepath.Join(dir, "bundle.enc.json"),
			)
			if err == nil {
				t.Fatalf("sealer sealed a bundle the enclave would reject at boot\n%s", out)
			}
			if _, statErr := os.Stat(filepath.Join(dir, "bundle.enc.json")); statErr == nil {
				t.Errorf("sealer wrote an envelope despite failing; a half-written bundle is worse "+
					"than none, because an operator uploads it\n%s", out)
			}
			for _, want := range tc.wants {
				if !strings.Contains(out, want) {
					t.Errorf("failure does not name %q\n%s", want, out)
				}
			}
		})
	}
}
