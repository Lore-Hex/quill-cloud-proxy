package llm

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Built at runtime so no literal here looks like a real AWS credential.
var (
	fakeAccessKeyID     = "AKIA" + "TESTONLY" + strings.Repeat("0", 8)
	fakeSecretAccessKey = "test-only-" + strings.Repeat("x", 30)
	fakeAzureKey        = "test-only-azure-" + strings.Repeat("0", 8)
)

func testServiceAccountJSON(t *testing.T, extra map[string]any) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	account := map[string]any{
		"type":           "service_account",
		"project_id":     "customer-project-1",
		"private_key_id": "kid-1",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email":   "router@customer-project-1.iam.gserviceaccount.com",
		"token_uri":      "https://attacker.example/token",
	}
	for k, v := range extra {
		account[k] = v
	}
	encoded, err := json.Marshal(account)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded), key
}

func TestParseAWSBYOKCredentialShapes(t *testing.T) {
	bare, err := parseAWSBYOKCredential("ABSKbedrockapikeyvalue")
	if err != nil || bare.BedrockAPIKey == "" || bare.Region != "us-east-1" {
		t.Fatalf("bare key: %+v %v", bare, err)
	}
	iam, err := parseAWSBYOKCredential(`{"access_key_id":"` + fakeAccessKeyID + `","secret_access_key":"` + fakeSecretAccessKey + `","region":"eu-west-1"}`)
	if err != nil || iam.AccessKeyID == "" || iam.Region != "eu-west-1" {
		t.Fatalf("iam: %+v %v", iam, err)
	}
	for name, secret := range map[string]string{
		"both":         `{"bedrock_api_key":"k","access_key_id":"` + fakeAccessKeyID + `","secret_access_key":"` + fakeSecretAccessKey + `"}`,
		"neither":      `{"region":"us-east-1"}`,
		"bad region":   `{"bedrock_api_key":"k","region":"evil.example.com/x"}`,
		"bad key id":   `{"access_key_id":"notakey","secret_access_key":"` + fakeSecretAccessKey + `"}`,
		"short secret": `{"access_key_id":"` + fakeAccessKeyID + `","secret_access_key":"short"}`,
		"empty":        ``,
		"spaces":       `two words`,
	} {
		if _, err := parseAWSBYOKCredential(secret); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestParseAzureBYOKCredentialPinsAzureHosts(t *testing.T) {
	good := []string{
		"https://customer.openai.azure.com",
		"https://customer.openai.azure.com/",
		"https://customer.openai.azure.com/openai/v1",
		"https://customer-foundry.services.ai.azure.com",
		"https://customer.cognitiveservices.azure.com",
	}
	for _, endpoint := range good {
		credential, err := parseAzureBYOKCredential(`{"endpoint":"` + endpoint + `","api_key":"` + fakeAzureKey + `"}`)
		if err != nil {
			t.Fatalf("%s: %v", endpoint, err)
		}
		if strings.Contains(strings.TrimPrefix(credential.Endpoint, "https://"), "/") {
			t.Fatalf("%s: endpoint not reduced to the resource root: %s", endpoint, credential.Endpoint)
		}
	}
	bad := []string{
		"http://customer.openai.azure.com",
		"https://evil.example.com",
		"https://customer.openai.azure.com.evil.example.com",
		"https://user@customer.openai.azure.com",
		"https://customer.openai.azure.com:8443",
		"https://customer.openai.azure.com/other/path",
		"https://customer.openai.azure.com?x=1",
		"https://a.b.openai.azure.com",
		"https://169.254.169.254",
	}
	for _, endpoint := range bad {
		if _, err := parseAzureBYOKCredential(`{"endpoint":"` + endpoint + `","api_key":"` + fakeAzureKey + `"}`); err == nil {
			t.Fatalf("%s: accepted", endpoint)
		}
	}
	credential, err := parseAzureBYOKCredential(`{"endpoint":"https://c.openai.azure.com","api_key":"` + fakeAzureKey + `","deployments":{"gpt-5-mini":"prod-mini"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if credential.deployment("gpt-5-mini") != "prod-mini" || credential.deployment("grok-4") != "grok-4" {
		t.Fatal("deployment mapping is wrong")
	}
	if _, err := parseAzureBYOKCredential(`{"endpoint":"https://c.openai.azure.com","api_key":"` + fakeAzureKey + `","deployments":{"m":"../x"}}`); err == nil {
		t.Fatal("path-like deployment name accepted")
	}
}

func TestParseGCPBYOKCredential(t *testing.T) {
	account, _ := testServiceAccountJSON(t, nil)
	credential, err := parseGCPBYOKCredential(account)
	if err != nil {
		t.Fatal(err)
	}
	if credential.ProjectID != "customer-project-1" || credential.Location != "global" || credential.KeyID != "kid-1" {
		t.Fatalf("credential = %+v", credential)
	}
	wrapped := `{"service_account":` + account + `,"location":"us-east5","project_id":"other-project-2"}`
	credential, err = parseGCPBYOKCredential(wrapped)
	if err != nil || credential.Location != "us-east5" || credential.ProjectID != "other-project-2" {
		t.Fatalf("wrapped: %+v %v", credential, err)
	}
	for name, extra := range map[string]map[string]any{
		"user credential": {"type": "authorized_user"},
		"bad project":     {"project_id": "UPPER/../x"},
		"bad email":       {"client_email": "not an email"},
		"bad key":         {"private_key": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"},
	} {
		account, _ := testServiceAccountJSON(t, extra)
		if _, err := parseGCPBYOKCredential(account); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	account, _ = testServiceAccountJSON(t, nil)
	if _, err := parseGCPBYOKCredential(`{"service_account":` + account + `,"location":"evil.example.com"}`); err == nil {
		t.Fatal("host-like location accepted")
	}
}

func TestServiceAccountTokenExchangeSignsAndCaches(t *testing.T) {
	account, key := testServiceAccountJSON(t, nil)
	credential, err := parseGCPBYOKCredential(account)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Errorf("grant_type = %q", form.Get("grant_type"))
		}
		parts := strings.Split(form.Get("assertion"), ".")
		if len(parts) != 3 {
			t.Fatalf("assertion = %q", form.Get("assertion"))
		}
		signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(&key.PublicKey, 5, digest[:], signature); err != nil {
			t.Errorf("assertion signature: %v", err)
		}
		claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
		if !strings.Contains(string(claims), `"aud":"https://oauth2.googleapis.com/token"`) || strings.Contains(string(claims), "attacker") {
			t.Errorf("claims = %s", claims)
		}
		_, _ = io.WriteString(w, `{"access_token":"ya29.test","expires_in":3600}`)
	}))
	defer server.Close()
	tokens := &serviceAccountTokens{entries: map[[32]byte]serviceAccountToken{}, now: time.Now, url: server.URL, httpc: server.Client()}
	for i := 0; i < 3; i++ {
		token, err := tokens.token(context.Background(), credential)
		if err != nil || token != "ya29.test" {
			t.Fatalf("token = %q %v", token, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("token exchanged %d times; want one cached exchange", calls.Load())
	}
}

func TestServiceAccountTokenRefusalIsTheCustomersCredential(t *testing.T) {
	account, _ := testServiceAccountJSON(t, nil)
	credential, _ := parseGCPBYOKCredential(account)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(400)
		_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"secret detail"}`)
	}))
	defer server.Close()
	tokens := &serviceAccountTokens{entries: map[[32]byte]serviceAccountToken{}, now: time.Now, url: server.URL, httpc: server.Client()}
	_, err := tokens.token(context.Background(), credential)
	var upstream *upstreamHTTPError
	if err == nil || !asUpstreamHTTPError(err, &upstream) || upstream.status != 401 || strings.Contains(upstream.body, "secret detail") {
		t.Fatalf("err = %v", err)
	}
}

func asUpstreamHTTPError(err error, target **upstreamHTTPError) bool {
	value, ok := err.(*upstreamHTTPError)
	if ok {
		*target = value
	}
	return ok
}

func TestServiceAccountTokenOutageKeepsItsStatus(t *testing.T) {
	account, _ := testServiceAccountJSON(t, nil)
	credential, _ := parseGCPBYOKCredential(account)
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
		tokens := &serviceAccountTokens{entries: map[[32]byte]serviceAccountToken{}, now: time.Now, url: server.URL, httpc: server.Client()}
		_, err := tokens.token(context.Background(), credential)
		server.Close()
		var upstream *upstreamHTTPError
		if !asUpstreamHTTPError(err, &upstream) || upstream.status != status {
			t.Fatalf("status %d became %v", status, err)
		}
	}
}

func TestAzureDeploymentAliasKeepsTheModelsRequestShape(t *testing.T) {
	maxTokens := 64
	req := &qtypes.OpenAIChatRequest{Model: "openai/gpt-5-mini", MaxTokens: &maxTokens}
	plain, err := PrepareChatRequest("azure", "gpt-5-mini", req, nil, nil, ChatPreparationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	aliased, err := PrepareChatRequest("azure", "gpt-5-mini", req, nil, nil, ChatPreparationOptions{wireModel: "prod-mini"})
	if err != nil {
		t.Fatal(err)
	}
	var plainBody, aliasedBody map[string]any
	_ = json.Unmarshal(plain.Bytes, &plainBody)
	_ = json.Unmarshal(aliased.Bytes, &aliasedBody)
	if aliasedBody["model"] != "prod-mini" {
		t.Fatalf("wire model = %v", aliasedBody["model"])
	}
	delete(plainBody, "model")
	delete(aliasedBody, "model")
	if fmt.Sprint(plainBody) != fmt.Sprint(aliasedBody) {
		t.Fatalf("the alias changed the request beyond its model name:\n%v\n%v", plainBody, aliasedBody)
	}
}

func TestMultiPrimeServiceAccountKeysAreRefused(t *testing.T) {
	key, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048) //nolint:staticcheck // the refused shape itself
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	account, _ := testServiceAccountJSON(t, map[string]any{
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
	})
	if _, err := parseGCPBYOKCredential(account); err == nil {
		t.Fatal("a multi-prime key was accepted")
	}
}

func TestTokenCacheIsBoundToPrivateKeyMaterial(t *testing.T) {
	victimJSON, victimKey := testServiceAccountJSON(t, nil)
	victim, _ := parseGCPBYOKCredential(victimJSON)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	// Same account, key id and modulus, different private exponent: what a
	// forged key around a known modulus would present.
	forged := &gcpBYOKCredential{
		ClientEmail: victim.ClientEmail, KeyID: victim.KeyID, ProjectID: victim.ProjectID, Location: victim.Location,
		PrivateKey: &rsa.PrivateKey{PublicKey: victimKey.PublicKey, D: other.D, Primes: other.Primes},
	}
	if serviceAccountCacheKey(victim) == serviceAccountCacheKey(forged) {
		t.Fatal("public key material alone selects the cached token")
	}
}
