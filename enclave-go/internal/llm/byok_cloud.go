//go:build llm_multi

package llm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awscredentials "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/smithy-go/auth/bearer"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/streamhttp"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

func init() {
	cloudBYOKInvoker = invokeCloudBYOKStreaming
}

// invokeCloudBYOKStreaming serves a BYOK route on a cloud provider with the
// workspace's native credential. Each request builds its own client from the
// credential; nothing about one workspace's credential outlives the request
// except a cached short-lived Vertex access token.
func invokeCloudBYOKStreaming(
	ctx context.Context,
	provider string,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	options InvokeOptions,
) (bool, error) {
	switch provider {
	case "amazon-bedrock", "google-vertex", "azure":
		if !cloudBYOKReachable {
			// This gateway's transport cannot reach customer cloud hosts
			// (Nitro tunnels are an exact list). Refuse at once, marked as
			// the gateway's own limit, so the request fails over to its next
			// route and no provider circuit opens.
			return true, &upstreamerror.Local{Err: fmt.Errorf("llm/byok: %s BYOK is not served from this gateway", provider)}
		}
	}
	switch provider {
	case "amazon-bedrock":
		return true, invokeBedrockBYOK(ctx, req, body, out, options)
	case "google-vertex":
		return true, invokeVertexBYOK(ctx, req, body, out, options)
	case "azure":
		return true, invokeAzureBYOK(ctx, req, body, out, options)
	}
	return false, nil
}

// withoutBYOKKey returns options a provider client must not route back into
// the BYOK dispatcher: the credential has already been resolved.
func withoutBYOKKey(options InvokeOptions) InvokeOptions {
	options.ProviderAPIKey = ""
	return options
}

// --- Amazon Bedrock ----------------------------------------------------------

// bedrockBYOKProfile adapts a US cross-region Claude inference profile to the
// credential's region, so a workspace in the EU or APAC is not refused for
// calling a US profile from its own region.
func bedrockBYOKProfile(upstream, region string) string {
	if !strings.HasPrefix(upstream, "us.") {
		return upstream
	}
	switch {
	case strings.HasPrefix(region, "eu-"):
		return "eu." + strings.TrimPrefix(upstream, "us.")
	case strings.HasPrefix(region, "ap-"):
		return "apac." + strings.TrimPrefix(upstream, "us.")
	}
	return upstream
}

func invokeBedrockBYOK(ctx context.Context, req *qtypes.OpenAIChatRequest, body *qtypes.AnthropicMessagesRequest, out io.Writer, options InvokeOptions) error {
	credential, err := parseAWSBYOKCredential(options.ProviderAPIKey)
	if err != nil {
		return byokCredentialError(err)
	}
	httpc := pinnedBYOKHTTPClient()
	if strings.Contains(options.UpstreamModel, "anthropic.") {
		client := &bedrockRuntimeClient{httpc: httpc, br: newBedrockBYOKRuntime(credential, httpc)}
		profile := bedrockBYOKProfile(options.UpstreamModel, credential.Region)
		return client.invokeProfile(ctx, req, body, out, profile)
	}
	// Every other Bedrock model is served by the OpenAI-compatible Mantle
	// endpoint, with the Bedrock API key as a bearer or SigV4 for access keys.
	baseURL := "https://bedrock-mantle." + credential.Region + ".api.aws/v1"
	apiKey := credential.BedrockAPIKey
	if apiKey == "" {
		signed := *httpc
		signed.Transport = &sigV4Transport{
			base:    httpc.Transport,
			region:  credential.Region,
			service: "bedrock-mantle",
			credentials: aws.Credentials{
				AccessKeyID: credential.AccessKeyID, SecretAccessKey: credential.SecretAccessKey, SessionToken: credential.SessionToken,
			},
		}
		httpc = &signed
		apiKey = "sigv4"
	}
	return invokeOpenAICompatibleStreamingWithClientOptions(
		ctx, httpc, "amazon-bedrock", baseURL, apiKey, req, body, out, options.UpstreamModel,
		openAICompatibleInvocationOptions{providerCacheScope: options.ProviderCacheScope},
	)
}

// newBedrockBYOKRuntime builds a Bedrock Runtime client that authenticates
// only with the customer's credential. Authentication is pinned in the
// constructor's options, which the SDK applies AFTER it reads
// AWS_BEARER_TOKEN_BEDROCK from the environment, so a process-level token can
// never replace the customer's and bill another account.
func newBedrockBYOKRuntime(credential *awsBYOKCredential, httpc *http.Client) *bedrockruntime.Client {
	config := aws.Config{
		Region:           credential.Region,
		HTTPClient:       streamhttp.Client{Base: httpc},
		RetryMaxAttempts: 1,
	}
	return bedrockruntime.NewFromConfig(config, func(o *bedrockruntime.Options) {
		if credential.BedrockAPIKey != "" {
			o.Credentials = nil
			o.BearerAuthTokenProvider = bearer.StaticTokenProvider{Token: bearer.Token{Value: credential.BedrockAPIKey}}
			o.AuthSchemePreference = []string{"httpBearerAuth"}
			return
		}
		o.BearerAuthTokenProvider = nil
		o.Credentials = awscredentials.NewStaticCredentialsProvider(
			credential.AccessKeyID, credential.SecretAccessKey, credential.SessionToken,
		)
		o.AuthSchemePreference = []string{"sigv4"}
	})
}

// sigV4Transport replaces the placeholder bearer with an AWS Signature V4 for
// the request it carries.
type sigV4Transport struct {
	base        http.RoundTripper
	region      string
	service     string
	credentials aws.Credentials
}

func (t *sigV4Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	var payload []byte
	if req.Body != nil {
		read, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		payload = read
	}
	signed := req.Clone(req.Context())
	signed.Body = io.NopCloser(bytes.NewReader(payload))
	signed.ContentLength = int64(len(payload))
	signed.Header.Del("Authorization")
	digest := sha256.Sum256(payload)
	if err := v4.NewSigner().SignHTTP(req.Context(), t.credentials, signed, hex.EncodeToString(digest[:]), t.service, t.region, time.Now()); err != nil {
		return nil, fmt.Errorf("llm/byok: Bedrock request signing failed")
	}
	// The request was recorded for error redaction before it was signed, so
	// the signed values are registered here, or an upstream error echoing its
	// headers could carry them to the client.
	for _, value := range []string{
		signed.Header.Get("Authorization"), signed.Header.Get("X-Amz-Security-Token"),
		t.credentials.AccessKeyID, t.credentials.SecretAccessKey, t.credentials.SessionToken,
	} {
		upstreamerror.RecordCredential(req.Context(), value)
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(signed)
}

// --- Google Vertex -----------------------------------------------------------

func invokeVertexBYOK(ctx context.Context, req *qtypes.OpenAIChatRequest, body *qtypes.AnthropicMessagesRequest, out io.Writer, options InvokeOptions) error {
	credential, err := parseGCPBYOKCredential(options.ProviderAPIKey)
	if err != nil {
		return byokCredentialError(err)
	}
	auth := &gcpClient{
		projectID: credential.ProjectID,
		region:    credential.Location,
		httpc:     pinnedBYOKHTTPClient(),
		tokens: func(ctx context.Context) (string, error) {
			return byokServiceAccountTokens.token(ctx, credential)
		},
	}
	plain := withoutBYOKKey(options)
	if strings.HasPrefix(directModelID("google-vertex", req.Model, options.UpstreamModel), "claude-") {
		if err := validateVertexClaudeCacheTTL(body); err != nil {
			return err
		}
		return auth.InvokeStreaming(ctx, req, body, out, plain)
	}
	return (&vertexGeminiClient{auth: auth}).InvokeStreaming(ctx, req, body, out, plain)
}

// --- Azure ---------------------------------------------------------------------

func invokeAzureBYOK(ctx context.Context, req *qtypes.OpenAIChatRequest, body *qtypes.AnthropicMessagesRequest, out io.Writer, options InvokeOptions) error {
	credential, err := parseAzureBYOKCredential(options.ProviderAPIKey)
	if err != nil {
		return byokCredentialError(err)
	}
	deployment := credential.deployment(options.UpstreamModel)
	plain := withoutBYOKKey(options)
	requestedModel := ""
	if req != nil {
		requestedModel = req.Model
	}
	if azureUsesAnthropicWire(options.UpstreamModel, requestedModel) {
		// The Claude model name drives reasoning normalization, so the
		// request is built for the authorized model; only the wire name is the
		// workspace's deployment.
		anthropic := newAnthropicAt("azure", credential.Endpoint+"/anthropic/v1/messages", credential.APIKey, true)
		anthropic.httpc = azurePinnedHTTPClient(anthropic.httpc)
		anthropic.wireModel = deployment
		return anthropic.InvokeStreaming(ctx, req, body, out, plain)
	}
	return invokeOpenAICompatibleStreamingWithClientOptions(
		ctx, azurePinnedHTTPClient(nil), "azure", credential.Endpoint+"/openai/v1", credential.APIKey,
		req, body, out, options.UpstreamModel,
		openAICompatibleInvocationOptions{providerCacheScope: options.ProviderCacheScope, wireModel: deployment},
	)
}

// --- Shared ----------------------------------------------------------------------

// pinnedBYOKHTTPClient never follows a redirect: a redirect could carry the
// customer's credential or prompt to another authority.
func pinnedBYOKHTTPClient() *http.Client {
	client := *defaultHTTPClient()
	client.Timeout = defaultStreamingHTTPTimeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client
}

// byokCredentialError makes a malformed stored credential a 401 the client can
// act on (fix the key), never a provider outage that trips a circuit.
func byokCredentialError(err error) error {
	var upstream *upstreamHTTPError
	if errors.As(err, &upstream) {
		return err
	}
	return &upstreamHTTPError{status: http.StatusUnauthorized, body: err.Error()}
}
