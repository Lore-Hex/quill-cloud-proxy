package llm

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const (
	nearAIAttestationMaxBytes = 8 << 20
	nearAIAttestationTimeout  = 3 * time.Minute
	nearAIAttestationAttempts = 3
)

var nearAIDirectDomains = map[string]string{
	"deepseek-ai/DeepSeek-V4-Flash":  "dsv4-flash.completions.near.ai",
	"google/gemma-4-31B-it":          "gemma-4-31b.completions.near.ai",
	"zai-org/GLM-5.1-FP8":            "glm-5-1.completions.near.ai",
	"z-ai/glm-5.2":                   "glm-5-2.completions.near.ai",
	"z-ai/glm-5.3-flash":             "glm-5-3-flash.completions.near.ai",
	"openai/gpt-oss-120b":            "gpt-oss-120b.completions.near.ai",
	"Qwen/Qwen3.6-27B-FP8":           "qwen3-6-27b.completions.near.ai",
	"Qwen/Qwen3.6-35B-A3B-FP8":       "qwen3-6-35b.completions.near.ai",
	"Qwen/Qwen3.8-27B":               "qwen3-8-27b.completions.near.ai",
	"Qwen/Qwen3-VL-30B-A3B-Instruct": "qwen3-vl-30b.completions.near.ai",
	"Qwen/Qwen3.5-122B-A10B":         "qwen35-122b.completions.near.ai",
}

var nearAIModelMap = map[string]string{
	"deepseek/deepseek-v4-flash":     "deepseek-ai/DeepSeek-V4-Flash",
	"google/gemma-4-31b-it":          "google/gemma-4-31B-it",
	"z-ai/glm-5.1":                   "zai-org/GLM-5.1-FP8",
	"z-ai/glm-5.2":                   "z-ai/glm-5.2",
	"z-ai/glm-5.3-flash":             "z-ai/glm-5.3-flash",
	"openai/gpt-oss-120b":            "openai/gpt-oss-120b",
	"qwen/qwen3.6-27b":               "Qwen/Qwen3.6-27B-FP8",
	"qwen/qwen3.6-35b-a3b":           "Qwen/Qwen3.6-35B-A3B-FP8",
	"qwen/qwen3.8-27b":               "Qwen/Qwen3.8-27B",
	"qwen/qwen3-vl-30b-a3b-instruct": "Qwen/Qwen3-VL-30B-A3B-Instruct",
	"qwen/qwen3.5-122b-a10b":         "Qwen/Qwen3.5-122B-A10B",
}

type nearAIClient struct {
	apiKey         string
	verifyEvidence func(context.Context, *nearAIEvidenceEnvelope) (*nearAIVerificationResult, error)
	openConnection func(string, int) (nearAIConnection, *http.Client, error)
	newNonce       func() (string, error)
}

type nearAIConnection interface {
	Fingerprint() (string, error)
	Dials() int32
	CloseIdleConnections()
}

func newNearAI(apiKey string) *nearAIClient {
	return &nearAIClient{
		apiKey:         strings.TrimSpace(apiKey),
		verifyEvidence: verifyNearAIEvidenceWithSidecar,
		openConnection: func(domain string, attempt int) (nearAIConnection, *http.Client, error) {
			connection, client, err := newNearAISingleConnection(domain)
			if err == nil {
				connection.attempt = attempt
			}
			return connection, client, err
		},
		newNonce: nearAINonce,
	}
}

func (c *nearAIClient) InvokeStreaming(
	ctx context.Context,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	options ...InvokeOptions,
) error {
	if strings.TrimSpace(c.apiKey) == "" {
		return errors.New("llm/near-ai: missing api key")
	}
	if req == nil {
		return errors.New("llm/near-ai: missing request")
	}
	option := firstOptions(options)
	upstreamModel := directModelID("near-ai", req.Model, option.UpstreamModel)
	domain := nearAIDirectDomains[upstreamModel]
	if domain == "" {
		return errors.New("llm/near-ai: authorized model has no pinned direct attested endpoint")
	}

	transport, httpc, err := c.openVerifiedConnection(ctx, upstreamModel, domain)
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	// Once inference starts, never retry: the upstream may have consumed the
	// prompt or emitted output even if its response subsequently fails.
	return invokeOpenAICompatibleStreamingWithClient(
		ctx,
		httpc,
		"near-ai",
		"https://"+domain+"/v1",
		c.apiKey,
		req,
		body,
		out,
		upstreamModel,
		option.ProviderCacheScope,
	)
}

func (c *nearAIClient) openVerifiedConnection(ctx context.Context, upstreamModel, domain string) (nearAIConnection, *http.Client, error) {
	attestCtx, cancel := context.WithTimeout(ctx, nearAIAttestationTimeout)
	defer cancel()
	var lastErr error
	for attempt := 0; attempt < nearAIAttestationAttempts; attempt++ {
		if err := attestCtx.Err(); err != nil {
			return nil, nil, err
		}
		nonce, err := c.newNonce()
		if err != nil {
			return nil, nil, err
		}
		transport, httpc, err := c.openConnection(domain, attempt)
		if err != nil {
			return nil, nil, err
		}
		evidence, err := fetchNearAIAttestation(attestCtx, httpc, c.apiKey, domain, nonce)
		if err != nil {
			transport.CloseIdleConnections()
			var transportError net.Error
			if errors.As(err, &transportError) && attestCtx.Err() == nil {
				lastErr = err
				continue
			}
			return nil, nil, err
		}
		fingerprint, err := transport.Fingerprint()
		if err != nil {
			transport.CloseIdleConnections()
			return nil, nil, err
		}
		if _, err := c.verifyEvidence(attestCtx, &nearAIEvidenceEnvelope{
			Model: upstreamModel, Domain: domain, Nonce: nonce,
			TLSFingerprint: fingerprint, Evidence: evidence,
		}); err != nil {
			// Mixed deployment pools can contain an unreviewed member.
			// Discard its connection; the next one needs a fresh nonce and
			// complete verification before it can receive any prompt.
			transport.CloseIdleConnections()
			lastErr = err
			continue
		}
		if transport.Dials() != 1 {
			transport.CloseIdleConnections()
			return nil, nil, errors.New("llm/near-ai: attested TLS connection changed before inference")
		}
		if err := attestCtx.Err(); err != nil {
			transport.CloseIdleConnections()
			return nil, nil, err
		}
		return transport, httpc, nil
	}
	return nil, nil, fmt.Errorf("llm/near-ai: no verified connection after %d attempts: %w", nearAIAttestationAttempts, lastErr)
}

func nearAINonce() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("llm/near-ai: generate attestation nonce: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func fetchNearAIAttestation(
	ctx context.Context,
	httpc *http.Client,
	apiKey, domain, nonce string,
) (json.RawMessage, error) {
	query := url.Values{
		"include_tls_fingerprint": []string{"true"},
		"nonce":                   []string{nonce},
		"signing_algo":            []string{"ed25519"},
	}
	endpoint := "https://" + domain + "/v1/attestation/report?" + query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "TrustedRouter-Attestation/1.0")
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("llm/near-ai: fetch direct attestation: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("llm/near-ai: direct attestation returned HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, nearAIAttestationMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("llm/near-ai: read direct attestation: %w", err)
	}
	if len(raw) > nearAIAttestationMaxBytes {
		return nil, errors.New("llm/near-ai: direct attestation exceeded size limit")
	}
	if !json.Valid(raw) {
		return nil, errors.New("llm/near-ai: direct attestation was not JSON")
	}
	return raw, nil
}

type nearAISingleConnection struct {
	transport   *http.Transport
	expected    string
	attempt     int
	dials       atomic.Int32
	fingerprint chan string
	once        sync.Once
}

func newNearAISingleConnection(domain string) (*nearAISingleConnection, *http.Client, error) {
	if domain != strings.ToLower(domain) || !strings.HasSuffix(domain, ".completions.near.ai") ||
		strings.ContainsAny(domain, "/:@") {
		return nil, nil, errors.New("llm/near-ai: invalid pinned direct endpoint")
	}
	connection := &nearAISingleConnection{
		expected:    net.JoinHostPort(domain, "443"),
		fingerprint: make(chan string, 1),
	}
	connection.transport = &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     false,
		MaxConnsPerHost:       1,
		MaxIdleConns:          1,
		MaxIdleConnsPerHost:   1,
		IdleConnTimeout:       3 * time.Minute,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 3 * time.Minute,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	connection.transport.DialTLSContext = connection.dialTLS
	httpc := &http.Client{
		Transport: connection.transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("llm/near-ai: redirects are forbidden on attested direct endpoints")
		},
	}
	return connection, httpc, nil
}

func (c *nearAISingleConnection) dialTLS(ctx context.Context, network, address string) (net.Conn, error) {
	if address != c.expected {
		return nil, fmt.Errorf("llm/near-ai: refused unexpected TLS endpoint %q", address)
	}
	if c.dials.Add(1) != 1 {
		return nil, errors.New("llm/near-ai: attested connection closed; refusing unverified redial")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	addresses, err := net.DefaultResolver.LookupHost(lookupCtx, host)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("llm/near-ai: resolve direct endpoint: %w", err)
	}
	selected, err := nearAIAddressForAttempt(addresses, c.attempt)
	if err != nil {
		return nil, err
	}
	// Rotate only DNS-advertised IPs. TLS still authenticates the pinned
	// domain, and every new connection requires its own bound attestation.
	raw, err := dialer.DialContext(ctx, network, net.JoinHostPort(selected, port))
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: strings.TrimSuffix(c.expected, ":443"),
		NextProtos: []string{"http/1.1"},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		_ = tlsConn.Close()
		return nil, errors.New("llm/near-ai: direct endpoint returned no TLS certificate")
	}
	digest := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
	c.once.Do(func() { c.fingerprint <- hex.EncodeToString(digest[:]) })
	return tlsConn, nil
}

func nearAIAddressForAttempt(addresses []string, attempt int) (string, error) {
	unique := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		if ip := net.ParseIP(address); ip != nil {
			unique[ip.String()] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(unique))
	for address := range unique {
		ordered = append(ordered, address)
	}
	sort.Strings(ordered)
	if len(ordered) == 0 || attempt < 0 {
		return "", errors.New("llm/near-ai: no valid direct endpoint address")
	}
	return ordered[attempt%len(ordered)], nil
}

func (c *nearAISingleConnection) Fingerprint() (string, error) {
	select {
	case fingerprint := <-c.fingerprint:
		c.fingerprint <- fingerprint
		return fingerprint, nil
	default:
		return "", errors.New("llm/near-ai: TLS certificate was not captured")
	}
}

func (c *nearAISingleConnection) Dials() int32 {
	return c.dials.Load()
}

func (c *nearAISingleConnection) CloseIdleConnections() {
	c.transport.CloseIdleConnections()
}
