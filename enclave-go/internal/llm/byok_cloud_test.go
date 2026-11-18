//go:build llm_multi

package llm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

func TestBedrockBYOKProfileFollowsTheCredentialRegion(t *testing.T) {
	for _, tc := range []struct{ upstream, region, want string }{
		{"us.anthropic.claude-sonnet-5-5", "us-west-2", "us.anthropic.claude-sonnet-5-5"},
		{"us.anthropic.claude-sonnet-5-5", "eu-central-1", "eu.anthropic.claude-sonnet-5-5"},
		{"us.anthropic.claude-sonnet-5-5", "ap-northeast-1", "apac.anthropic.claude-sonnet-5-5"},
		{"deepseek.v3.2", "eu-west-1", "deepseek.v3.2"},
	} {
		if got := bedrockBYOKProfile(tc.upstream, tc.region); got != tc.want {
			t.Fatalf("%s in %s = %s", tc.upstream, tc.region, got)
		}
	}
	if got := bedrockClaudeModelName("eu.anthropic.claude-opus-4-8"); got != "claude-opus-4-8" {
		t.Fatalf("model name = %s", got)
	}
}

func TestSigV4TransportReplacesThePlaceholderBearer(t *testing.T) {
	var seen *http.Request
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r
		seenBody, _ = io.ReadAll(r.Body)
	}))
	defer server.Close()
	transport := &sigV4Transport{
		base: server.Client().Transport, region: "us-west-2", service: "bedrock-mantle",
		credentials: aws.Credentials{AccessKeyID: fakeAccessKeyID, SecretAccessKey: "secret"},
	}
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/chat/completions", bytes.NewReader([]byte(`{"model":"m"}`)))
	req.Header.Set("Authorization", "Bearer sigv4")
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	auth := seen.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential="+fakeAccessKeyID+"/") || !strings.Contains(auth, "/us-west-2/bedrock-mantle/aws4_request") {
		t.Fatalf("authorization = %q", auth)
	}
	if string(seenBody) != `{"model":"m"}` {
		t.Fatalf("body = %s", seenBody)
	}
}

func TestMalformedCloudCredentialIsAClientError(t *testing.T) {
	for _, provider := range []string{"amazon-bedrock", "google-vertex", "azure"} {
		handled, err := invokeCloudBYOKStreaming(context.Background(), provider, nil, nil, io.Discard, InvokeOptions{ProviderAPIKey: `{"nope":true}`, Provider: provider})
		if !handled {
			t.Fatalf("%s: not handled", provider)
		}
		assertCloudBYOKRefusal(t, provider, err)
	}
	if handled, _ := invokeCloudBYOKStreaming(context.Background(), "openai", nil, nil, io.Discard, InvokeOptions{}); handled {
		t.Fatal("a non-cloud provider was handled")
	}
}

func TestCloudBYOKNeverReachesManagedClients(t *testing.T) {
	// A Bedrock Claude BYOK route must not reach the managed Bedrock Runtime
	// client, which refuses customer keys, nor any TrustedRouter credential.
	m := &multiClient{}
	err := m.InvokeStreaming(context.Background(), nil, nil, io.Discard, InvokeOptions{
		Provider: "amazon-bedrock", UpstreamModel: "us.anthropic.claude-sonnet-5-5", ProviderAPIKey: `{"region":"us-east-1"}`,
	})
	assertCloudBYOKRefusal(t, "amazon-bedrock", err)
}

// assertCloudBYOKRefusal: where the gateway can reach customer cloud hosts a
// malformed credential is the customer's 401; on a Nitro gateway the route is
// refused first, as the gateway's own limit.
func assertCloudBYOKRefusal(t *testing.T, provider string, err error) {
	t.Helper()
	if !cloudBYOKReachable {
		var local *upstreamerror.Local
		if !errors.As(err, &local) {
			t.Fatalf("%s: err = %v", provider, err)
		}
		return
	}
	var upstream *upstreamHTTPError
	if !asUpstreamHTTPError(err, &upstream) || upstream.status != http.StatusUnauthorized {
		t.Fatalf("%s: err = %v", provider, err)
	}
}

func TestSignedBedrockCredentialsAreRedactedFromUpstreamErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	transport := &sigV4Transport{
		base: server.Client().Transport, region: "us-west-2", service: "bedrock-mantle",
		credentials: aws.Credentials{AccessKeyID: fakeAccessKeyID, SecretAccessKey: fakeSecretAccessKey, SessionToken: "session-token-value-0123456789"},
	}
	ctx, redact := upstreamerror.WithCredentialRedaction(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, server.URL, bytes.NewReader([]byte(`{}`)))
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	echoed := redact(&upstreamHTTPError{status: 403, body: "signature mismatch for X-Amz-Security-Token: session-token-value-0123456789"})
	if strings.Contains(echoed.Error(), "session-token-value-0123456789") {
		t.Fatalf("session token reached the client: %v", echoed)
	}
}

func TestBedrockBYOKIgnoresTheProcessBearerToken(t *testing.T) {
	t.Setenv("AWS_BEARER_TOKEN_BEDROCK", "process-level-token")
	iam := newBedrockBYOKRuntime(&awsBYOKCredential{
		AccessKeyID: fakeAccessKeyID, SecretAccessKey: fakeSecretAccessKey, Region: "eu-west-1",
	}, pinnedBYOKHTTPClient()).Options()
	if iam.BearerAuthTokenProvider != nil || iam.Credentials == nil || fmt.Sprint(iam.AuthSchemePreference) != "[sigv4]" {
		t.Fatalf("IAM credential not pinned: bearer=%v creds=%v pref=%v", iam.BearerAuthTokenProvider, iam.Credentials, iam.AuthSchemePreference)
	}
	creds, err := iam.Credentials.Retrieve(context.Background())
	if err != nil || creds.AccessKeyID != fakeAccessKeyID {
		t.Fatalf("credentials = %+v %v", creds, err)
	}

	keyed := newBedrockBYOKRuntime(&awsBYOKCredential{BedrockAPIKey: "customer-bedrock-key", Region: "us-east-1"}, pinnedBYOKHTTPClient()).Options()
	token, err := keyed.BearerAuthTokenProvider.RetrieveBearerToken(context.Background())
	if err != nil || token.Value != "customer-bedrock-key" {
		t.Fatalf("bearer = %q %v", token.Value, err)
	}
}
