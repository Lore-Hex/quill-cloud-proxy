package llm

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// googleTokenURL is the only place a customer service-account assertion is
// exchanged; a key file's own token_uri is never followed.
const googleTokenURL = "https://oauth2.googleapis.com/token" // #nosec G101 -- token endpoint URL, not a secret.

const googleCloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

type serviceAccountToken struct {
	value   string
	expires time.Time
}

// serviceAccountTokens caches access tokens per service-account key, keyed by
// a digest of the key material, until shortly before they expire. Entries
// hold only short-lived access tokens, never the key.
type serviceAccountTokens struct {
	mu      sync.Mutex
	entries map[[32]byte]serviceAccountToken
	httpc   *http.Client
	now     func() time.Time
	url     string
}

var byokServiceAccountTokens = &serviceAccountTokens{
	entries: map[[32]byte]serviceAccountToken{},
	now:     time.Now,
	url:     googleTokenURL,
}

const maxServiceAccountTokenEntries = 1024

func (s *serviceAccountTokens) client() *http.Client {
	if s.httpc != nil {
		return s.httpc
	}
	client := *defaultHTTPClient()
	client.Timeout = 15 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client
}

// serviceAccountCacheKey binds a cached token to PRIVATE key material: the
// private exponent and primes, besides the account. Public fields (email, key
// id, modulus) are knowable by anyone, so a key built around another account's
// modulus must never find that account's token here; it misses, signs its own
// assertion, and Google refuses it.
func serviceAccountCacheKey(credential *gcpBYOKCredential) [32]byte {
	hash := sha256.New()
	_, _ = io.WriteString(hash, "trustedrouter/byok-vertex-token/v1\x00"+credential.ClientEmail+"\x00"+credential.KeyID+"\x00")
	key := credential.PrivateKey
	for _, part := range append([]*big.Int{key.N, key.D}, key.Primes...) {
		bytes := part.Bytes()
		_, _ = hash.Write([]byte{byte(len(bytes) >> 8), byte(len(bytes))})
		_, _ = hash.Write(bytes)
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func (s *serviceAccountTokens) token(ctx context.Context, credential *gcpBYOKCredential) (string, error) {
	key := serviceAccountCacheKey(credential)
	now := s.now()
	s.mu.Lock()
	if entry, ok := s.entries[key]; ok && now.Before(entry.expires.Add(-time.Minute)) {
		s.mu.Unlock()
		return entry.value, nil
	}
	s.mu.Unlock()

	assertion, err := serviceAccountAssertion(credential, now)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("llm/byok: Vertex token exchange unavailable")
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", fmt.Errorf("llm/byok: Vertex token exchange unreadable")
	}
	if resp.StatusCode != http.StatusOK {
		// The body is never echoed: it may describe the key.
		switch resp.StatusCode {
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
			// Google refused the assertion: the customer's credential, not the
			// provider, is the problem.
			return "", &upstreamHTTPError{status: http.StatusUnauthorized, body: "Vertex refused the BYOK service account credential"}
		}
		// Rate limits and outages keep their status, so they read as the
		// provider being unavailable rather than as a bad key.
		return "", &upstreamHTTPError{status: resp.StatusCode, body: "Vertex token exchange is unavailable"}
	}
	var decoded struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(payload, &decoded); err != nil || decoded.AccessToken == "" || decoded.ExpiresIn <= 0 {
		return "", fmt.Errorf("llm/byok: Vertex token exchange returned no token")
	}
	entry := serviceAccountToken{value: decoded.AccessToken, expires: now.Add(time.Duration(decoded.ExpiresIn) * time.Second)}
	s.mu.Lock()
	if len(s.entries) >= maxServiceAccountTokenEntries {
		s.entries = map[[32]byte]serviceAccountToken{}
	}
	s.entries[key] = entry
	s.mu.Unlock()
	return entry.value, nil
}

// serviceAccountAssertion builds the RS256 JWT a service account signs to
// ask Google for an access token (RFC 7523).
func serviceAccountAssertion(credential *gcpBYOKCredential, now time.Time) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	if credential.KeyID != "" {
		header["kid"] = credential.KeyID
	}
	claims := map[string]any{
		"iss":   credential.ClientEmail,
		"scope": googleCloudPlatformScope,
		"aud":   googleTokenURL,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, credential.PrivateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("llm/byok: Vertex assertion signing failed")
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
