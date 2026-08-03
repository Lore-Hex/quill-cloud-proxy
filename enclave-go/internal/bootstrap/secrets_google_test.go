//go:build cloud_gcp

package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Coverage for the Google Secret Manager TRANSPORT, which is now GCP-only.
//
// It used to be exercised only from bootstrap_azure_test.go, because Azure ran
// through this same code. Azure now reads Azure Key Vault, so without this file
// the live GCP fetch path would have no test at all — a coverage cliff opened
// by a change that never touched it.

const (
	gcpTestProject       = "quill-cloud-proxy"
	gcpTestDevicesSecret = "tr-device-keys"
	gcpTestORSecret      = "tr-openrouter-key"
	gcpTestToken         = "ya29.TEST-ACCESS-TOKEN"

	// Distinctive so a leak assertion cannot produce a false negative.
	gcpTestORValue = "sk-or-v1-OPENROUTER-SECRET-VALUE-DO-NOT-LOG"
)

// secretManagerFixture stands up a fake Secret Manager and points the package
// var at it.
type secretManagerFixture struct {
	t       *testing.T
	values  map[string]string
	handler http.HandlerFunc
	srv     *httptest.Server
	authz   []string
}

func newSecretManagerFixture(t *testing.T) *secretManagerFixture {
	t.Helper()
	f := &secretManagerFixture{
		t: t,
		values: map[string]string{
			gcpTestDevicesSecret: `[{"key_hash":"c0ffee","owner":"joseph","device_id":"dev-1"}]`,
			gcpTestORSecret:      gcpTestORValue,
		},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.authz = append(f.authz, r.Header.Get("Authorization"))
		if f.handler != nil {
			f.handler(w, r)
			return
		}
		f.serve(w, r)
	}))
	t.Cleanup(f.srv.Close)

	prev := secretManagerBaseURL
	secretManagerBaseURL = f.srv.URL
	t.Cleanup(func() { secretManagerBaseURL = prev })
	return f
}

func (f *secretManagerFixture) serve(w http.ResponseWriter, r *http.Request) {
	name := gcpSecretNameFromPath(r.URL.Path)
	value, ok := f.values[name]
	if !ok {
		http.Error(w, `{"error":{"code":404,"message":"Secret not found"}}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"name":    fmt.Sprintf("projects/%s/secrets/%s/versions/1", gcpTestProject, name),
		"payload": map[string]string{"data": base64.StdEncoding.EncodeToString([]byte(value))},
	})
}

// gcpSecretNameFromPath pulls "<name>" out of
// /v1/projects/<p>/secrets/<name>/versions/latest:access
func gcpSecretNameFromPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i, part := range parts {
		if part == "secrets" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func gcpTestConfig(t *testing.T) secretConfig {
	t.Helper()
	clearSecretEnv(t)
	t.Setenv("QUILL_GCP_PROJECT_ID", gcpTestProject)
	t.Setenv("QUILL_DEVICE_KEYS_SECRET", gcpTestDevicesSecret)
	t.Setenv("QUILL_OPENROUTER_SECRET", gcpTestORSecret)
	t.Setenv("QUILL_GCP_REGION", "europe-west4")
	cfg, err := resolveSecretConfig("bootstrap/gcp")
	if err != nil {
		t.Fatalf("resolveSecretConfig: %v", err)
	}
	return cfg
}

func TestFetchBootstrapSecretsHappyPath(t *testing.T) {
	f := newSecretManagerFixture(t)
	cfg := gcpTestConfig(t)

	data, err := fetchBootstrapSecrets(context.Background(), f.srv.Client(), gcpTestToken, cfg, "bootstrap/gcp")
	if err != nil {
		t.Fatalf("fetchBootstrapSecrets: %v", err)
	}
	if len(data.Devices) != 1 || data.Devices[0].DeviceID != "dev-1" {
		t.Errorf("devices = %+v", data.Devices)
	}
	if data.OpenRouterAPIKey != gcpTestORValue {
		t.Errorf("openrouter key = %q", data.OpenRouterAPIKey)
	}
	if data.Region != "europe-west4" {
		t.Errorf("region = %q", data.Region)
	}
	if len(f.authz) == 0 {
		t.Fatal("Secret Manager was never called")
	}
	for _, header := range f.authz {
		if header != "Bearer "+gcpTestToken {
			t.Fatalf("Authorization = %q, want the supplied token", header)
		}
	}
}

// The URL is a contract with a live Google API. Building it wrong is a 404 at
// boot on the production cloud, so pin the shape rather than trusting the fake
// to be forgiving.
func TestFetchSecretBuildsTheAccessURL(t *testing.T) {
	f := newSecretManagerFixture(t)
	var seen string
	f.handler = func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.Path
		f.serve(w, r)
	}
	if _, err := fetchSecret(context.Background(), f.srv.Client(), gcpTestToken, gcpTestProject, gcpTestORSecret); err != nil {
		t.Fatalf("fetchSecret: %v", err)
	}
	want := "/v1/projects/" + gcpTestProject + "/secrets/" + gcpTestORSecret + "/versions/latest:access"
	if seen != want {
		t.Errorf("path = %q, want %q", seen, want)
	}
}

// Every error must name WHICH secret failed, otherwise an operator is left
// guessing which of ~40 entries is misconfigured.
func TestFetchBootstrapSecretsNamesTheFailingSecret(t *testing.T) {
	f := newSecretManagerFixture(t)
	cfg := gcpTestConfig(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) {
		if gcpSecretNameFromPath(r.URL.Path) == gcpTestORSecret {
			http.Error(w, `{"error":{"code":403,"message":"Permission denied on secret"}}`, http.StatusForbidden)
			return
		}
		f.serve(w, r)
	}

	_, err := fetchBootstrapSecrets(context.Background(), f.srv.Client(), gcpTestToken, cfg, "bootstrap/gcp")
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{"bootstrap/gcp", "openrouter key", "secret fetch http 403", "Permission denied"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %q\n  got: %v", want, err)
		}
	}
}

func TestFetchBootstrapSecretsNamesDeviceKeysSeparately(t *testing.T) {
	f := newSecretManagerFixture(t)
	cfg := gcpTestConfig(t)
	delete(f.values, gcpTestDevicesSecret)

	_, err := fetchBootstrapSecrets(context.Background(), f.srv.Client(), gcpTestToken, cfg, "bootstrap/gcp")
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{"bootstrap/gcp", "device-keys", "404"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %q\n  got: %v", want, err)
		}
	}
}

func TestFetchBootstrapSecretsDeviceKeysNotJSON(t *testing.T) {
	f := newSecretManagerFixture(t)
	cfg := gcpTestConfig(t)
	f.values[gcpTestDevicesSecret] = "not-json-at-all"

	_, err := fetchBootstrapSecrets(context.Background(), f.srv.Client(), gcpTestToken, cfg, "bootstrap/gcp")
	if err == nil || !strings.Contains(err.Error(), "parse device-keys JSON") {
		t.Fatalf("err = %v, want a device-keys parse failure", err)
	}
}

// Secret Manager payloads routinely carry a trailing newline (anything created
// with `printf ... | gcloud secrets create --data-file=-` does). An API key with
// "\n" on the end produces an unparseable Authorization header and a 401 from
// the provider that looks like a bad key rather than a bad payload.
func TestFetchBootstrapSecretsTrimsValues(t *testing.T) {
	f := newSecretManagerFixture(t)
	cfg := gcpTestConfig(t)
	f.values[gcpTestORSecret] = "  " + gcpTestORValue + "\n"

	data, err := fetchBootstrapSecrets(context.Background(), f.srv.Client(), gcpTestToken, cfg, "bootstrap/gcp")
	if err != nil {
		t.Fatalf("fetchBootstrapSecrets: %v", err)
	}
	if data.OpenRouterAPIKey != gcpTestORValue {
		t.Errorf("openrouter key not trimmed: %q", data.OpenRouterAPIKey)
	}
}

// The 200 body IS the secret. A decode failure must not echo it.
func TestFetchSecretWithholdsTheSuccessBody(t *testing.T) {
	f := newSecretManagerFixture(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"payload":{"data":"` + base64.StdEncoding.EncodeToString([]byte(gcpTestORValue)) + `" TRUNCATED`))
	}
	_, err := fetchSecret(context.Background(), f.srv.Client(), gcpTestToken, gcpTestProject, gcpTestORSecret)
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), gcpTestORValue) {
		t.Errorf("the secret value leaked into the decode error: %v", err)
	}
	if strings.Contains(err.Error(), base64.StdEncoding.EncodeToString([]byte(gcpTestORValue))) {
		t.Errorf("the base64 secret payload leaked into the decode error: %v", err)
	}
}

// secretManagerBaseURL is a package var so tests can redirect it. That is only
// acceptable while production still resolves to the real host.
func TestSecretManagerBaseURLDefaultsToProduction(t *testing.T) {
	if secretManagerHost != "https://secretmanager.googleapis.com" {
		t.Errorf("secretManagerHost = %q", secretManagerHost)
	}
	// A fixture redirects it and restores it on cleanup; outside one it must be
	// the production host.
	if secretManagerBaseURL != secretManagerHost {
		t.Errorf("secretManagerBaseURL = %q, want %q — the test seam leaked", secretManagerBaseURL, secretManagerHost)
	}
}
