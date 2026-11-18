package llm

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Native BYOK credentials for the cloud providers. The control plane seals a
// JSON document under the workspace's BYOK envelope; it is opened only here,
// inside the enclave, and every field is validated before any of it is used.
// No field may choose where a request or token exchange is sent beyond the
// documented provider hosts, so a credential can never redirect traffic.

type awsBYOKCredential struct {
	// Either a Bedrock API key (bearer) or IAM access keys (SigV4).
	BedrockAPIKey   string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
}

type gcpBYOKCredential struct {
	ClientEmail string
	PrivateKey  *rsa.PrivateKey
	KeyID       string
	ProjectID   string
	Location    string
}

type azureBYOKCredential struct {
	// Endpoint is the resource root, https://<name>.openai.azure.com or a
	// services.ai.azure.com / cognitiveservices.azure.com resource.
	Endpoint    string
	APIKey      string
	Deployments map[string]string
}

var (
	awsRegionPattern      = regexp.MustCompile(`^[a-z]{2}(-gov)?-[a-z]+-[0-9]$`)
	awsAccessKeyPattern   = regexp.MustCompile(`^(AKIA|ASIA)[A-Z0-9]{12,124}$`)
	gcpProjectPattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	gcpLocationPattern    = regexp.MustCompile(`^([a-z]+-[a-z]+[0-9]+|global|us|eu)$`)
	gcpClientEmailPattern = regexp.MustCompile(`^[a-zA-Z0-9._%+-]{1,128}@[a-z0-9.-]{1,253}$`)
	azureHostPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}\.(openai\.azure\.com|services\.ai\.azure\.com|cognitiveservices\.azure\.com)$`)
	azureDeploymentName   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

const maxCloudCredentialBytes = 16 << 10

func decodeCloudCredential(secret string, into any) error {
	if len(secret) > maxCloudCredentialBytes {
		return fmt.Errorf("credential is too large")
	}
	decoder := json.NewDecoder(strings.NewReader(secret))
	if err := decoder.Decode(into); err != nil {
		return fmt.Errorf("credential is not a JSON object")
	}
	return nil
}

// parseAWSBYOKCredential accepts a bare Bedrock API key (region us-east-1),
// or {"bedrock_api_key", "region"}, or {"access_key_id",
// "secret_access_key", "session_token"?, "region"}.
func parseAWSBYOKCredential(secret string) (*awsBYOKCredential, error) {
	secret = strings.TrimSpace(secret)
	if !strings.HasPrefix(secret, "{") {
		if secret == "" || strings.ContainsAny(secret, " \r\n\t") {
			return nil, fmt.Errorf("llm/byok: Bedrock credential is empty or malformed")
		}
		return &awsBYOKCredential{BedrockAPIKey: secret, Region: "us-east-1"}, nil
	}
	var raw struct {
		BedrockAPIKey   string `json:"bedrock_api_key"`
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
		SessionToken    string `json:"session_token"`
		Region          string `json:"region"`
	}
	if err := decodeCloudCredential(secret, &raw); err != nil {
		return nil, fmt.Errorf("llm/byok: Bedrock %w", err)
	}
	credential := &awsBYOKCredential{
		BedrockAPIKey:   strings.TrimSpace(raw.BedrockAPIKey),
		AccessKeyID:     strings.TrimSpace(raw.AccessKeyID),
		SecretAccessKey: strings.TrimSpace(raw.SecretAccessKey),
		SessionToken:    strings.TrimSpace(raw.SessionToken),
		Region:          strings.TrimSpace(raw.Region),
	}
	if credential.Region == "" {
		credential.Region = "us-east-1"
	}
	if !awsRegionPattern.MatchString(credential.Region) {
		return nil, fmt.Errorf("llm/byok: Bedrock region is invalid")
	}
	hasKey := credential.BedrockAPIKey != ""
	hasIAM := credential.AccessKeyID != "" || credential.SecretAccessKey != ""
	switch {
	case hasKey == hasIAM:
		return nil, fmt.Errorf("llm/byok: Bedrock credential needs exactly one of bedrock_api_key or access keys")
	case hasIAM && (!awsAccessKeyPattern.MatchString(credential.AccessKeyID) || len(credential.SecretAccessKey) < 16 || strings.ContainsAny(credential.SecretAccessKey, " \r\n\t")):
		return nil, fmt.Errorf("llm/byok: Bedrock access keys are malformed")
	case hasKey && strings.ContainsAny(credential.BedrockAPIKey, " \r\n\t"):
		return nil, fmt.Errorf("llm/byok: Bedrock API key is malformed")
	}
	return credential, nil
}

// parseGCPBYOKCredential accepts a service-account key file, optionally
// wrapped as {"service_account": {...}, "location": "..."}. The key file's
// own token_uri is ignored: tokens are exchanged only at Google's endpoint.
func parseGCPBYOKCredential(secret string) (*gcpBYOKCredential, error) {
	var outer map[string]json.RawMessage
	if err := decodeCloudCredential(secret, &outer); err != nil {
		return nil, fmt.Errorf("llm/byok: Vertex %w", err)
	}
	location := "global"
	if raw, ok := outer["location"]; ok {
		if err := json.Unmarshal(raw, &location); err != nil {
			return nil, fmt.Errorf("llm/byok: Vertex location is invalid")
		}
	}
	accountJSON := []byte(secret)
	if wrapped, ok := outer["service_account"]; ok {
		accountJSON = wrapped
	}
	var account struct {
		Type         string `json:"type"`
		ProjectID    string `json:"project_id"`
		PrivateKeyID string `json:"private_key_id"`
		PrivateKey   string `json:"private_key"`
		ClientEmail  string `json:"client_email"`
	}
	if err := json.Unmarshal(accountJSON, &account); err != nil {
		return nil, fmt.Errorf("llm/byok: Vertex service account is not a JSON object")
	}
	if raw, ok := outer["project_id"]; ok && len(outer["service_account"]) > 0 {
		var project string
		if err := json.Unmarshal(raw, &project); err == nil && project != "" {
			account.ProjectID = project
		}
	}
	location = strings.TrimSpace(location)
	switch {
	case account.Type != "service_account":
		return nil, fmt.Errorf("llm/byok: Vertex credential must be a service account key")
	case !gcpProjectPattern.MatchString(account.ProjectID):
		return nil, fmt.Errorf("llm/byok: Vertex project_id is invalid")
	case !gcpLocationPattern.MatchString(location):
		return nil, fmt.Errorf("llm/byok: Vertex location is invalid")
	case !gcpClientEmailPattern.MatchString(account.ClientEmail):
		return nil, fmt.Errorf("llm/byok: Vertex client_email is invalid")
	}
	key, err := parseRSAPrivateKey(account.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &gcpBYOKCredential{
		ClientEmail: account.ClientEmail,
		PrivateKey:  key,
		KeyID:       strings.TrimSpace(account.PrivateKeyID),
		ProjectID:   account.ProjectID,
		Location:    location,
	}, nil
}

func parseRSAPrivateKey(encoded string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(encoded))
	if block == nil {
		return nil, fmt.Errorf("llm/byok: Vertex private_key is not PEM")
	}
	var key *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("llm/byok: Vertex private_key must be RSA of at least 2048 bits")
		}
		key = rsaKey
	} else if parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = parsed
	} else {
		return nil, fmt.Errorf("llm/byok: Vertex private_key is not an RSA key")
	}
	// Google issues two-prime keys. A multi-prime or inconsistent key is not
	// one, and is refused before it can sign or touch the token cache.
	if key.N.BitLen() < 2048 || len(key.Primes) != 2 || key.Validate() != nil {
		return nil, fmt.Errorf("llm/byok: Vertex private_key must be a valid two-prime RSA key of at least 2048 bits")
	}
	return key, nil
}

// parseAzureBYOKCredential accepts {"endpoint", "api_key", "deployments"?}.
// deployments maps an upstream model id to the customer's deployment name;
// without an entry the upstream model id is the deployment name.
func parseAzureBYOKCredential(secret string) (*azureBYOKCredential, error) {
	var raw struct {
		Endpoint    string            `json:"endpoint"`
		APIKey      string            `json:"api_key"`
		Deployments map[string]string `json:"deployments"`
	}
	if err := decodeCloudCredential(secret, &raw); err != nil {
		return nil, fmt.Errorf("llm/byok: Azure %w", err)
	}
	endpoint, err := azureResourceRoot(raw.Endpoint)
	if err != nil {
		return nil, err
	}
	apiKey := strings.TrimSpace(raw.APIKey)
	if len(apiKey) < 16 || strings.ContainsAny(apiKey, " \r\n\t") {
		return nil, fmt.Errorf("llm/byok: Azure api_key is malformed")
	}
	if len(raw.Deployments) > 200 {
		return nil, fmt.Errorf("llm/byok: Azure deployments holds at most 200 entries")
	}
	deployments := make(map[string]string, len(raw.Deployments))
	for model, deployment := range raw.Deployments {
		deployment = strings.TrimSpace(deployment)
		if !azureDeploymentName.MatchString(deployment) {
			return nil, fmt.Errorf("llm/byok: Azure deployment name is invalid")
		}
		deployments[strings.TrimSpace(model)] = deployment
	}
	return &azureBYOKCredential{Endpoint: endpoint, APIKey: apiKey, Deployments: deployments}, nil
}

// azureResourceRoot reduces an Azure endpoint to https://<host>, accepting
// only Azure OpenAI / AI Foundry resource hosts, so a credential cannot point
// the gateway at any other server.
func azureResourceRoot(endpoint string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Port() != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("llm/byok: Azure endpoint must be an https Azure resource URL")
	}
	host := strings.ToLower(parsed.Hostname())
	if !azureHostPattern.MatchString(host) {
		return "", fmt.Errorf("llm/byok: Azure endpoint must be an Azure OpenAI or AI Foundry resource")
	}
	switch strings.TrimRight(parsed.Path, "/") {
	case "", "/openai", "/openai/v1":
	default:
		return "", fmt.Errorf("llm/byok: Azure endpoint must be the resource root")
	}
	return "https://" + host, nil
}

func (c *azureBYOKCredential) deployment(upstreamModel string) string {
	if deployment, ok := c.Deployments[upstreamModel]; ok {
		return deployment
	}
	return upstreamModel
}
