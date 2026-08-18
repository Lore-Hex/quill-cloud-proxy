//go:build cloud_azure

package enclavetls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

const (
	azureBlobAPIVersion       = "2023-11-03"
	azureStorageResource      = "https://storage.azure.com/"
	azureIMDSTokenEndpoint    = "http://169.254.169.254/metadata/identity/oauth2/token" // #nosec G101 -- fixed link-local metadata endpoint.
	azureIMDSAPIVersion       = "2018-02-01"
	azureCacheEnvelopeVersion = byte(1)
	azureCacheKeyBytes        = 32
	azureCacheMaxPlaintext    = 1 << 20
)

// AzureBlobCacheOptions describes the Azure-local shared ACME cache. Account
// and container are public coordinates. EncryptionKey is released inside the
// measured workload as part of the sealed Key Vault bundle.
type AzureBlobCacheOptions struct {
	Account       string
	Container     string
	EncryptionKey string
	MIClientID    string
}

// NewAzureBlobCache returns an autocert cache backed by Azure Blob Storage.
// The managed identity only transports ciphertext: every value is protected
// with AES-256-GCM inside the enclave before it reaches Blob Storage.
func NewAzureBlobCache(opts AzureBlobCacheOptions) (autocert.Cache, error) {
	key, err := decodeAzureCacheKey(opts.EncryptionKey)
	if err != nil {
		return nil, err
	}
	account := strings.TrimSpace(opts.Account)
	container := strings.TrimSpace(opts.Container)
	if err := validateAzureStorageAccount(account); err != nil {
		return nil, err
	}
	if err := validateAzureContainer(container); err != nil {
		return nil, err
	}
	return newAzureBlobCache(azureBlobCacheConfig{
		account:   account,
		container: container,
		key:       key,
		endpoint:  "https://" + account + ".blob.core.windows.net",
		blobHTTP:  &http.Client{Timeout: 15 * time.Second},
		tokens: newAzureManagedIdentityTokenSource(
			&http.Client{Timeout: 10 * time.Second},
			strings.TrimSpace(opts.MIClientID),
		),
	})
}

type azureBearerTokenSource interface {
	Token(context.Context) (string, error)
}

type azureBlobCacheConfig struct {
	account   string
	container string
	key       []byte
	endpoint  string
	blobHTTP  *http.Client
	tokens    azureBearerTokenSource
}

type azureBlobCache struct {
	account   string
	container string
	key       []byte
	endpoint  string
	blobHTTP  *http.Client
	tokens    azureBearerTokenSource
}

func newAzureBlobCache(cfg azureBlobCacheConfig) (*azureBlobCache, error) {
	if len(cfg.key) != azureCacheKeyBytes {
		return nil, fmt.Errorf("azureblobcache: encryption key is %d bytes, want %d", len(cfg.key), azureCacheKeyBytes)
	}
	if cfg.blobHTTP == nil {
		return nil, errors.New("azureblobcache: nil blob HTTP client")
	}
	if cfg.tokens == nil {
		return nil, errors.New("azureblobcache: nil token source")
	}
	if strings.TrimSpace(cfg.endpoint) == "" {
		return nil, errors.New("azureblobcache: empty endpoint")
	}
	return &azureBlobCache{
		account:   cfg.account,
		container: cfg.container,
		key:       append([]byte(nil), cfg.key...),
		endpoint:  strings.TrimRight(cfg.endpoint, "/"),
		blobHTTP:  cfg.blobHTTP,
		tokens:    cfg.tokens,
	}, nil
}

func (c *azureBlobCache) Get(ctx context.Context, key string) ([]byte, error) {
	resp, err := c.do(ctx, http.MethodGet, key, nil)
	if err != nil {
		return nil, fmt.Errorf("azureblobcache: get: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, autocert.ErrCacheMiss
	}
	if resp.StatusCode != http.StatusOK {
		return nil, azureBlobStatusError("get", resp)
	}
	sealed, err := io.ReadAll(io.LimitReader(resp.Body, azureCacheMaxPlaintext+64))
	if err != nil {
		return nil, fmt.Errorf("azureblobcache: get body: %w", err)
	}
	if len(sealed) > azureCacheMaxPlaintext+32 {
		return nil, fmt.Errorf("azureblobcache: encrypted object too large: %d bytes", len(sealed))
	}
	plaintext, err := c.open(key, sealed)
	if err != nil {
		return nil, fmt.Errorf("azureblobcache: decrypt %q: %w", key, err)
	}
	return plaintext, nil
}

func (c *azureBlobCache) Put(ctx context.Context, key string, data []byte) error {
	if len(data) > azureCacheMaxPlaintext {
		return fmt.Errorf("azureblobcache: plaintext too large: %d bytes", len(data))
	}
	sealed, err := c.seal(key, data)
	if err != nil {
		return fmt.Errorf("azureblobcache: encrypt %q: %w", key, err)
	}
	resp, err := c.do(ctx, http.MethodPut, key, sealed)
	if err != nil {
		return fmt.Errorf("azureblobcache: put: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return azureBlobStatusError("put", resp)
	}
	return nil
}

func (c *azureBlobCache) Delete(ctx context.Context, key string) error {
	resp, err := c.do(ctx, http.MethodDelete, key, nil)
	if err != nil {
		return fmt.Errorf("azureblobcache: delete: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusAccepted, http.StatusNoContent, http.StatusNotFound:
		return nil
	default:
		return azureBlobStatusError("delete", resp)
	}
}

func (c *azureBlobCache) do(ctx context.Context, method, key string, body []byte) (*http.Response, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.blobURL(key), reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("x-ms-version", azureBlobAPIVersion)
	req.Header.Set("x-ms-date", time.Now().UTC().Format(http.TimeFormat))
	if method == http.MethodPut {
		req.Header.Set("x-ms-blob-type", "BlockBlob")
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	return c.blobHTTP.Do(req)
}

func (c *azureBlobCache) blobURL(key string) string {
	// Cache keys are public host/account identifiers, but encoding them avoids
	// path traversal and makes every possible autocert key one Blob name.
	name := base64.RawURLEncoding.EncodeToString([]byte(key))
	return c.endpoint + "/" + url.PathEscape(c.container) + "/autocert-v1/" + name
}

func (c *azureBlobCache) seal(cacheKey string, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 1+len(nonce))
	out[0] = azureCacheEnvelopeVersion
	copy(out[1:], nonce)
	return gcm.Seal(out, nonce, plaintext, c.aad(cacheKey)), nil
}

func (c *azureBlobCache) open(cacheKey string, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	header := 1 + gcm.NonceSize()
	if len(sealed) < header+gcm.Overhead() {
		return nil, errors.New("truncated envelope")
	}
	if sealed[0] != azureCacheEnvelopeVersion {
		return nil, fmt.Errorf("unsupported envelope version %d", sealed[0])
	}
	nonce := sealed[1:header]
	return gcm.Open(nil, nonce, sealed[header:], c.aad(cacheKey))
}

func (c *azureBlobCache) aad(cacheKey string) []byte {
	return []byte("trustedrouter/azure-acme-cache/v1\x00" + c.account + "\x00" + c.container + "\x00" + cacheKey)
}

func decodeAzureCacheKey(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, errors.New("azureblobcache: encryption key is empty")
	}
	var key []byte
	var err error
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		key, err = encoding.DecodeString(encoded)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("azureblobcache: encryption key is not base64: %w", err)
	}
	if len(key) != azureCacheKeyBytes {
		return nil, fmt.Errorf("azureblobcache: encryption key is %d bytes, want %d", len(key), azureCacheKeyBytes)
	}
	return key, nil
}

func validateAzureStorageAccount(value string) error {
	if len(value) < 3 || len(value) > 24 {
		return fmt.Errorf("azureblobcache: storage account length is %d, want 3..24", len(value))
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return fmt.Errorf("azureblobcache: storage account %q must contain only lowercase letters and digits", value)
		}
	}
	return nil
}

func validateAzureContainer(value string) error {
	if len(value) < 3 || len(value) > 63 {
		return fmt.Errorf("azureblobcache: container length is %d, want 3..63", len(value))
	}
	if value[0] == '-' || value[len(value)-1] == '-' || strings.Contains(value, "--") {
		return fmt.Errorf("azureblobcache: invalid container name %q", value)
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return fmt.Errorf("azureblobcache: invalid container name %q", value)
		}
	}
	return nil
}

func azureBlobStatusError(operation string, resp *http.Response) error {
	if code := strings.TrimSpace(resp.Header.Get("x-ms-error-code")); code != "" {
		return fmt.Errorf("azureblobcache: %s status %d code=%s", operation, resp.StatusCode, code)
	}
	return fmt.Errorf("azureblobcache: %s status %d", operation, resp.StatusCode)
}

type azureManagedIdentityTokenSource struct {
	httpClient *http.Client
	clientID   string
	endpoint   string
	now        func() time.Time

	mu     sync.Mutex
	token  string
	expiry time.Time
}

func newAzureManagedIdentityTokenSource(httpClient *http.Client, clientID string) *azureManagedIdentityTokenSource {
	return &azureManagedIdentityTokenSource{
		httpClient: httpClient,
		clientID:   clientID,
		endpoint:   azureIMDSTokenEndpoint,
		now:        time.Now,
	}
}

func (s *azureManagedIdentityTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.token != "" && now.Before(s.expiry.Add(-30*time.Second)) {
		return s.token, nil
	}
	u, err := url.Parse(s.endpoint)
	if err != nil {
		return "", err
	}
	query := u.Query()
	query.Set("api-version", azureIMDSAPIVersion)
	query.Set("resource", azureStorageResource)
	if s.clientID != "" {
		query.Set("client_id", s.clientID)
	}
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata", "true")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("azure managed identity token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("azure managed identity token status %d", resp.StatusCode)
	}
	var payload struct {
		AccessToken string          `json:"access_token"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
		ExpiresOn   json.RawMessage `json:"expires_on"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&payload); err != nil {
		return "", fmt.Errorf("azure managed identity token decode: %w", err)
	}
	if strings.TrimSpace(payload.AccessToken) == "" {
		return "", errors.New("azure managed identity token is empty")
	}
	expiry := now.Add(5 * time.Minute)
	if seconds, ok := parseAzureTokenNumber(payload.ExpiresIn); ok && seconds > 0 {
		expiry = now.Add(time.Duration(seconds) * time.Second)
	} else if epoch, ok := parseAzureTokenNumber(payload.ExpiresOn); ok && epoch > now.Unix() {
		expiry = time.Unix(epoch, 0)
	}
	s.token = payload.AccessToken
	s.expiry = expiry
	return s.token, nil
}

func parseAzureTokenNumber(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, false
	}
	value := strings.Trim(string(raw), "\"")
	parsed, err := strconv.ParseInt(value, 10, 64)
	return parsed, err == nil
}
