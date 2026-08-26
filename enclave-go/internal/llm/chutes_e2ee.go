package llm

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"golang.org/x/sync/singleflight"
)

const (
	defaultChutesAPIBase    = "https://api.chutes.ai"
	defaultChutesModelsBase = "https://llm.chutes.ai"
	chutesModelMapTTL       = 5 * time.Minute
	chutesDiscoveryMaxBytes = 4 << 20
	chutesMaxInstanceTries  = 5
)

var chutesUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

type chutesInstance struct {
	InstanceID string   `json:"instance_id"`
	E2EPubkey  string   `json:"e2e_pubkey"`
	Nonces     []string `json:"nonces"`
}

type chutesDiscoveryResponse struct {
	Instances      []chutesInstance `json:"instances"`
	NonceExpiresIn int64            `json:"nonce_expires_in"`
}

type chutesNoncePool struct {
	instances []chutesInstance
	expiresAt time.Time
}

type chutesInvocation struct {
	instanceID string
	e2ePubkey  string
	nonce      string
}

type chutesModelEntry struct {
	ID                  string `json:"id"`
	ChuteID             string `json:"chute_id"`
	ConfidentialCompute bool   `json:"confidential_compute"`
}

type chutesModelList struct {
	Data []chutesModelEntry `json:"data"`
}

type chutesE2EEClient struct {
	apiKey     string
	apiBase    string
	modelsBase string
	httpc      *http.Client
	now        func() time.Time

	modelMu      sync.RWMutex
	modelMap     map[string]string
	modelExpires time.Time
	modelGroup   singleflight.Group

	nonceMu    sync.Mutex
	noncePools map[string]*chutesNoncePool
	nonceGroup singleflight.Group

	proofMu    sync.RWMutex
	proofCache map[string]chutesVerificationResult
	proofGroup singleflight.Group

	verifyEvidence func(context.Context, *chutesEvidenceEnvelope) (*chutesVerificationResult, error)
}

func newChutesE2EE(apiKey string) *chutesE2EEClient {
	return &chutesE2EEClient{
		apiKey:         strings.TrimSpace(apiKey),
		apiBase:        defaultChutesAPIBase,
		modelsBase:     defaultChutesModelsBase,
		httpc:          defaultHTTPClient(),
		now:            time.Now,
		modelMap:       make(map[string]string),
		noncePools:     make(map[string]*chutesNoncePool),
		proofCache:     make(map[string]chutesVerificationResult),
		verifyEvidence: verifyChutesEvidenceWithSidecar,
	}
}

func (c *chutesE2EEClient) InvokeStreaming(
	ctx context.Context,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	options ...InvokeOptions,
) error {
	option := firstOptions(options)
	apiKey := strings.TrimSpace(option.ProviderAPIKey)
	if apiKey == "" {
		apiKey = c.apiKey
	}
	if apiKey == "" {
		return errors.New("llm/chutes: missing api key")
	}
	if req == nil {
		return errors.New("llm/chutes: missing request")
	}

	messages, err := openAICompatibleMessagesWithFetchedImages(ctx, body)
	if err != nil {
		return err
	}
	upstreamID := directModelID("chutes", req.Model, option.UpstreamModel)
	if strings.TrimSpace(upstreamID) == "" {
		return errors.New("llm/chutes: missing upstream model")
	}
	requestBody := buildOpenAICompatibleRequest("chutes", upstreamID, req, body, messages)
	requestBody.Stream = true
	chuteID, err := c.resolveChuteID(ctx, apiKey, upstreamID)
	if err != nil {
		return err
	}

	poolKey := chutesPoolKey(apiKey, chuteID)
	excluded := make(map[string]struct{})
	var failures []string
	var lastErr error
	var lastInvokeErr error
	refreshed := false
	for len(excluded) < chutesMaxInstanceTries {
		invocation, takeErr := c.takeInvocation(ctx, apiKey, chuteID, poolKey, excluded, refreshed)
		if takeErr != nil {
			lastErr = takeErr
			if !refreshed {
				c.dropNoncePool(poolKey)
				refreshed = true
				continue
			}
			failures = append(failures, "discovery")
			break
		}
		excluded[invocation.instanceID] = struct{}{}

		verification, err := c.verifyInvocation(ctx, apiKey, chuteID, invocation)
		if err != nil {
			lastErr = err
			failures = append(failures, "attestation")
			continue
		}
		_ = WithUpstreamVerification(ctx, verification.Policy, verification.VerifiedAt, verification.ExpiresAt)
		counted := &byteCountingWriter{writer: out}
		err = c.invokeEncryptedStream(ctx, apiKey, chuteID, invocation, requestBody, counted)
		if err == nil {
			return nil
		}
		if counted.bytes > 0 || !chutesRetryableError(err) {
			return err
		}
		lastErr = err
		lastInvokeErr = err
		failures = append(failures, "invoke")
	}
	if len(failures) == 0 {
		failures = append(failures, "no_instances")
	}
	terminalErr := lastInvokeErr
	if terminalErr == nil {
		terminalErr = lastErr
	}
	if terminalErr != nil {
		return fmt.Errorf(
			"llm/chutes: no attested E2E instance succeeded (%s): %w",
			strings.Join(failures, ","),
			terminalErr,
		)
	}
	return fmt.Errorf("llm/chutes: no attested E2E instance succeeded (%s)", strings.Join(failures, ","))
}

type byteCountingWriter struct {
	writer io.Writer
	bytes  int64
}

func (w *byteCountingWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	w.bytes += int64(n)
	return n, err
}

func chutesPoolKey(apiKey, chuteID string) string {
	digest := sha256.Sum256([]byte(apiKey))
	return chuteID + ":" + hex.EncodeToString(digest[:8])
}

func chutesProofKey(instanceID, pubkey string) string {
	digest := sha256.Sum256([]byte(pubkey))
	return instanceID + ":" + hex.EncodeToString(digest[:])
}

func (c *chutesE2EEClient) resolveChuteID(ctx context.Context, apiKey, model string) (string, error) {
	if chutesUUIDPattern.MatchString(model) {
		return model, nil
	}
	lookup := func() string {
		c.modelMu.RLock()
		defer c.modelMu.RUnlock()
		if c.now().After(c.modelExpires) {
			return ""
		}
		if chuteID := c.modelMap[model]; chuteID != "" {
			return chuteID
		}
		return c.modelMap[strings.ToLower(model)]
	}
	if chuteID := lookup(); chuteID != "" {
		return chuteID, nil
	}
	if err := c.refreshModelMap(ctx, apiKey); err != nil {
		return "", err
	}
	if chuteID := lookup(); chuteID != "" {
		return chuteID, nil
	}
	// A cache can still be fresh while a newly published model is absent.
	c.modelMu.Lock()
	c.modelExpires = time.Time{}
	c.modelMu.Unlock()
	if err := c.refreshModelMap(ctx, apiKey); err != nil {
		return "", err
	}
	if chuteID := lookup(); chuteID != "" {
		return chuteID, nil
	}
	return "", fmt.Errorf("llm/chutes: model %q is not an active confidential chute", model)
}

func (c *chutesE2EEClient) refreshModelMap(ctx context.Context, apiKey string) error {
	_, err, _ := c.modelGroup.Do("models", func() (any, error) {
		c.modelMu.RLock()
		fresh := c.now().Before(c.modelExpires)
		c.modelMu.RUnlock()
		if fresh {
			return nil, nil
		}
		var listing chutesModelList
		if err := c.getJSON(ctx, c.modelsBase+"/v1/models", apiKey, &listing); err != nil {
			return nil, fmt.Errorf("llm/chutes: refresh model map: %w", err)
		}
		mapped := make(map[string]string, len(listing.Data)*2)
		for _, entry := range listing.Data {
			if !entry.ConfidentialCompute || strings.TrimSpace(entry.ID) == "" ||
				!chutesUUIDPattern.MatchString(strings.TrimSpace(entry.ChuteID)) {
				continue
			}
			mapped[entry.ID] = entry.ChuteID
			mapped[strings.ToLower(entry.ID)] = entry.ChuteID
		}
		if len(mapped) == 0 {
			return nil, errors.New("llm/chutes: confidential model map is empty")
		}
		c.modelMu.Lock()
		c.modelMap = mapped
		c.modelExpires = c.now().Add(chutesModelMapTTL)
		c.modelMu.Unlock()
		return nil, nil
	})
	return err
}

func (c *chutesE2EEClient) takeInvocation(
	ctx context.Context,
	apiKey, chuteID, poolKey string,
	excluded map[string]struct{},
	forceRefresh bool,
) (*chutesInvocation, error) {
	if !forceRefresh {
		if invocation := c.takeCachedInvocation(poolKey, excluded); invocation != nil {
			return invocation, nil
		}
	}
	if err := c.refreshNoncePool(ctx, apiKey, chuteID, poolKey); err != nil {
		return nil, err
	}
	if invocation := c.takeCachedInvocation(poolKey, excluded); invocation != nil {
		return invocation, nil
	}
	return nil, errors.New("llm/chutes: no unused E2E invocation nonce")
}

func (c *chutesE2EEClient) takeCachedInvocation(poolKey string, excluded map[string]struct{}) *chutesInvocation {
	c.nonceMu.Lock()
	defer c.nonceMu.Unlock()
	pool := c.noncePools[poolKey]
	if pool == nil || !c.now().Before(pool.expiresAt) {
		delete(c.noncePools, poolKey)
		return nil
	}
	for index := range pool.instances {
		instance := &pool.instances[index]
		if _, skip := excluded[instance.InstanceID]; skip || len(instance.Nonces) == 0 {
			continue
		}
		nonce := instance.Nonces[0]
		instance.Nonces = instance.Nonces[1:]
		return &chutesInvocation{
			instanceID: instance.InstanceID,
			e2ePubkey:  instance.E2EPubkey,
			nonce:      nonce,
		}
	}
	return nil
}

func (c *chutesE2EEClient) refreshNoncePool(ctx context.Context, apiKey, chuteID, poolKey string) error {
	_, err, _ := c.nonceGroup.Do(poolKey, func() (any, error) {
		var discovered chutesDiscoveryResponse
		endpoint := c.apiBase + "/e2e/instances/" + url.PathEscape(chuteID)
		if err := c.getJSON(ctx, endpoint, apiKey, &discovered); err != nil {
			return nil, fmt.Errorf("llm/chutes: discover E2E instances: %w", err)
		}
		if len(discovered.Instances) == 0 {
			return nil, errors.New("llm/chutes: no E2E-capable instances")
		}
		valid := make([]chutesInstance, 0, len(discovered.Instances))
		for _, instance := range discovered.Instances {
			pubkey, decodeErr := base64.StdEncoding.DecodeString(instance.E2EPubkey)
			if strings.TrimSpace(instance.InstanceID) == "" || decodeErr != nil || len(pubkey) != 1184 || len(instance.Nonces) == 0 {
				continue
			}
			validNonces := instance.Nonces[:0]
			for _, nonce := range instance.Nonces {
				if strings.TrimSpace(nonce) != "" {
					validNonces = append(validNonces, nonce)
				}
			}
			instance.Nonces = validNonces
			if len(instance.Nonces) > 0 {
				valid = append(valid, instance)
			}
		}
		if len(valid) == 0 {
			return nil, errors.New("llm/chutes: discovery returned no valid E2E instances")
		}
		ttl := time.Duration(discovered.NonceExpiresIn) * time.Second
		if ttl <= 0 || ttl > 60*time.Second {
			ttl = 55 * time.Second
		}
		// Leave time for attestation and invocation; never hand out a nonce at
		// the provider's exact expiry boundary.
		ttl -= 5 * time.Second
		if ttl <= 0 {
			return nil, errors.New("llm/chutes: discovery nonce lifetime is too short")
		}
		c.nonceMu.Lock()
		c.noncePools[poolKey] = &chutesNoncePool{instances: valid, expiresAt: c.now().Add(ttl)}
		c.nonceMu.Unlock()
		return nil, nil
	})
	return err
}

func (c *chutesE2EEClient) dropNoncePool(poolKey string) {
	c.nonceMu.Lock()
	delete(c.noncePools, poolKey)
	c.nonceMu.Unlock()
}

func (c *chutesE2EEClient) verifyInvocation(
	ctx context.Context,
	apiKey, chuteID string,
	invocation *chutesInvocation,
) (*chutesVerificationResult, error) {
	proofKey := chutesProofKey(invocation.instanceID, invocation.e2ePubkey)
	c.proofMu.RLock()
	cached := c.proofCache[proofKey]
	c.proofMu.RUnlock()
	if c.now().Before(cached.ExpiresAt) {
		return &cached, nil
	}
	verified, err, _ := c.proofGroup.Do(proofKey, func() (any, error) {
		c.proofMu.RLock()
		cachedResult := c.proofCache[proofKey]
		c.proofMu.RUnlock()
		if c.now().Before(cachedResult.ExpiresAt) {
			return &cachedResult, nil
		}
		nonceBytes := make([]byte, 32)
		if _, err := rand.Read(nonceBytes); err != nil {
			return nil, fmt.Errorf("llm/chutes: generate attestation nonce: %w", err)
		}
		attestationNonce := hex.EncodeToString(nonceBytes)
		endpoint := c.apiBase + "/instances/" + url.PathEscape(invocation.instanceID) +
			"/evidence?nonce=" + url.QueryEscape(attestationNonce)
		evidence, err := c.getRawJSON(ctx, endpoint, apiKey, chutesEvidenceMaxBytes)
		if err != nil {
			return nil, fmt.Errorf("llm/chutes: fetch instance evidence: %w", err)
		}
		result, err := c.verifyEvidence(ctx, &chutesEvidenceEnvelope{
			ChuteID:   chuteID,
			Instance:  invocation.instanceID,
			Nonce:     attestationNonce,
			E2EPubkey: invocation.e2ePubkey,
			Evidence:  evidence,
		})
		if err != nil {
			return nil, err
		}
		c.proofMu.Lock()
		c.proofCache[proofKey] = *result
		c.proofMu.Unlock()
		return result, nil
	})
	if err != nil {
		return nil, err
	}
	result, ok := verified.(*chutesVerificationResult)
	if !ok || result == nil {
		return nil, errors.New("llm/chutes: attestation verification returned no result")
	}
	return result, nil
}

func (c *chutesE2EEClient) invokeEncryptedStream(
	ctx context.Context,
	apiKey, chuteID string,
	invocation *chutesInvocation,
	payload openAICompatibleRequest,
	out io.Writer,
) error {
	encrypted, err := buildChutesEncryptedRequest(invocation.e2ePubkey, payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.apiBase+"/e2e/invoke",
		bytes.NewReader(encrypted.blob),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", "TrustedRouter/1.0")
	req.Header.Set("X-Chute-Id", chuteID)
	req.Header.Set("X-Instance-Id", invocation.instanceID)
	req.Header.Set("X-E2E-Nonce", invocation.nonce)
	req.Header.Set("X-E2E-Stream", "true")
	req.Header.Set("X-E2E-Path", "/v1/chat/completions")
	req.Header.Set("X-E2EE-Usage-Passthrough", "true")
	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("llm/chutes: encrypted invoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return &upstreamHTTPError{status: resp.StatusCode, body: "chutes encrypted invoke failed"}
	}
	return translateChutesEncryptedStream(resp.Body, out, encrypted.responseSK)
}

func chutesRetryableError(err error) bool {
	status, ok := HTTPStatusFromError(err)
	if !ok {
		return true
	}
	return status == http.StatusForbidden || status == http.StatusNotFound || status == http.StatusGone ||
		status == http.StatusUpgradeRequired || status == http.StatusTooManyRequests || status >= 500
}

func (c *chutesE2EEClient) getJSON(ctx context.Context, endpoint, apiKey string, target any) error {
	body, err := c.getRawJSON(ctx, endpoint, apiKey, chutesDiscoveryMaxBytes)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	return nil
}

func (c *chutesE2EEClient) getRawJSON(
	ctx context.Context,
	endpoint, apiKey string,
	maxBytes int64,
) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "TrustedRouter/1.0")
	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, &upstreamHTTPError{status: resp.StatusCode, body: "chutes metadata request failed"}
	}
	limited := io.LimitReader(resp.Body, maxBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", maxBytes)
	}
	if !json.Valid(body) {
		return nil, errors.New("response is not valid JSON")
	}
	return json.RawMessage(body), nil
}
