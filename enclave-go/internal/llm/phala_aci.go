package llm

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/phalaaci"
)

// RedPill's ACI endpoint was verified directly; this hostname also has an
// existing Nitro opaque-TLS vsock route. There is no cross-host fallback.
const phalaACIDomain = "api.redpill.ai"

// Verify-before-release bounds memory across simultaneous large generations.
// This initial implementation buffers real SSE; it never synthesizes chunks.
var phalaACISlots = make(chan struct{}, 2)

type phalaClient struct {
	apiKey string
	open   func() (*http.Client, func() string, func(), error)
	verify func(context.Context, phalaaci.VerificationRequest) (*phalaaci.Proof, error)
	now    func() time.Time
}

func newPhala(apiKey string) *phalaClient {
	return &phalaClient{apiKey: strings.TrimSpace(apiKey), open: newPhalaConnection, verify: verifyPhalaWithSidecar, now: time.Now}
}

func (c *phalaClient) InvokeStreaming(ctx context.Context, req *qtypes.OpenAIChatRequest, body *qtypes.AnthropicMessagesRequest, out io.Writer, options ...InvokeOptions) error {
	if req == nil || body == nil {
		return errors.New("llm/phala: request missing")
	}
	option := firstOptions(options)
	apiKey := c.apiKey
	if option.ProviderAPIKey != "" {
		apiKey = strings.TrimSpace(option.ProviderAPIKey)
	}
	if apiKey == "" {
		return errors.New("llm/phala: missing API key")
	}
	// ACI model and AAD identifiers are byte-exact. The old phala/<bare>
	// aliases must not overwrite the signed authorization's current model ID.
	model := option.UpstreamModel
	if model == "" {
		model = req.Model
	}
	if model == "" || len(model) > 256 || model != strings.TrimSpace(model) {
		return errors.New("llm/phala: missing authorized model")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	select {
	case phalaACISlots <- struct{}{}:
		defer func() { <-phalaACISlots }()
	case <-ctx.Done():
		return ctx.Err()
	default:
		return &upstreamHTTPError{status: http.StatusServiceUnavailable, body: "Phala verified-response capacity is busy"}
	}
	httpc, fingerprint, closeConnection, err := c.open()
	if err != nil {
		return err
	}
	defer closeConnection()
	nonce, err := phalaNonce()
	if err != nil {
		return err
	}
	report, err := phalaArtifact(ctx, httpc, "attestation?nonce="+nonce, "")
	if err != nil {
		return err
	}
	proof, err := c.verify(ctx, phalaaci.VerificationRequest{Domain: phalaACIDomain, Model: model, Nonce: nonce, Fingerprint: fingerprint(), Report: report})
	if err != nil {
		return fmt.Errorf("llm/phala: attestation refused: %w", err)
	}
	if err := validatePhalaProof(proof, model, fingerprint(), c.now()); err != nil {
		return err
	}
	sessionID, session, err := selectPhalaSession(ctx, httpc, proof, c.now())
	if err != nil {
		return err
	}
	msgs, err := openAICompatibleMessagesWithFetchedImages(ctx, body)
	if err != nil {
		return err
	}
	request := buildOpenAICompatibleRequest("phala", model, req, body, msgs)
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	e2eeNonce, err := phalaNonce()
	if err != nil {
		return err
	}
	started := c.now()
	if err := validatePhalaProof(proof, model, fingerprint(), started); err != nil {
		return err
	}
	if session.Expires <= started.Unix() {
		return errors.New("llm/phala: upstream session expired before request")
	}
	encryption, err := phalaaci.NewEncryption(proof, e2eeNonce, started.Unix())
	if err != nil {
		return err
	}
	encrypted, requestHash, err := encryption.EncryptChat(raw, sessionID)
	clear(raw)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+phalaACIDomain+"/v1/chat/completions", bytes.NewReader(encrypted))
	if err != nil {
		return err
	}
	// Forbid HTTP client's transparent replay of this paid POST.
	httpReq.GetBody = nil
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	httpReq.Header.Set("X-E2EE-Version", "2")
	httpReq.Header.Set("X-Client-Pub-Key", hex.EncodeToString(encryption.Private.PublicKey().Bytes()))
	httpReq.Header.Set("X-Model-Pub-Key", hex.EncodeToString(encryption.Server.Bytes()))
	httpReq.Header.Set("X-E2EE-Nonce", e2eeNonce)
	httpReq.Header.Set("X-E2EE-Timestamp", strconv.FormatInt(started.Unix(), 10))
	resp, err := httpc.Do(httpReq)
	if err != nil {
		return errors.New("llm/phala: attested request transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &upstreamHTTPError{status: resp.StatusCode, body: "Phala confidential inference rejected the request"}
	}
	if resp.Header.Get("X-E2EE-Applied") != "true" || resp.Header.Get("X-E2EE-Version") != "2" ||
		resp.Header.Get("X-E2EE-Algo") != phalaaci.Suite || resp.Header.Get("X-ACI-Keyset-Digest") != proof.Digest {
		return errors.New("llm/phala: encrypted response headers/keyset missing or changed")
	}
	id := resp.Header.Get("X-Receipt-ID")
	if !validPhalaReceiptID(id) {
		return errors.New("llm/phala: receipt ID absent or malformed")
	}
	wire, err := readPhalaBounded(resp.Body)
	if err != nil {
		return err
	}
	defer clear(wire)
	responseHash := phalaaci.Hash(wire)
	decrypted, chatID, err := encryption.DecryptStream(wire)
	if err != nil {
		return err
	}
	defer clear(decrypted)
	receipt, err := phalaArtifact(ctx, httpc, "receipts/"+id, apiKey)
	if err != nil {
		return err
	}
	if err := phalaaci.VerifyReceipt(receipt, proof, phalaaci.Exchange{ReceiptID: id, ChatID: chatID,
		RequestHash: requestHash, ResponseHash: responseHash, StartedAt: started, SessionID: sessionID, Session: session}, c.now()); err != nil {
		return err
	}
	// No caller bytes, usage terminal, or settlement can precede this point.
	if err := ctx.Err(); err != nil {
		return err
	}
	return translateOpenAIStreamToAnthropic(bytes.NewReader(decrypted), out)
}

func phalaNonce() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func readPhalaBounded(reader io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, phalaaci.MaxArtifactBytes+1))
	if err != nil || len(raw) > phalaaci.MaxArtifactBytes {
		return nil, errors.New("llm/phala: artifact incomplete or oversized")
	}
	return raw, nil
}

func phalaArtifact(ctx context.Context, httpc *http.Client, path, apiKey string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+phalaACIDomain+"/v1/aci/"+path, nil)
	if err != nil {
		return nil, err
	}
	if apiKey != "" {
		request.Header.Set("Authorization", "Bearer "+apiKey)
	}
	response, err := httpc.Do(request)
	if err != nil {
		return nil, errors.New("llm/phala: attestation artifact fetch failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("llm/phala: artifact returned HTTP %d", response.StatusCode)
	}
	return readPhalaBounded(response.Body)
}

func selectPhalaSession(ctx context.Context, httpc *http.Client, proof *phalaaci.Proof, now time.Time) (string, *phalaaci.Session, error) {
	raw, err := phalaArtifact(ctx, httpc, "sessions?model="+url.QueryEscape(proof.Model), "")
	if err != nil {
		return "", nil, err
	}
	var list struct {
		Version  string `json:"api_version"`
		Sessions []struct {
			ID string `json:"session_id"`
		} `json:"sessions"`
	}
	if phalaaci.Decode(raw, &list) != nil || list.Version != "aci/1" {
		return "", nil, errors.New("llm/phala: invalid session list")
	}
	// Bound fan-out even when a provider publishes thousands of instances.
	for index, entry := range list.Sessions {
		if index >= 8 {
			break
		}
		if !phalaaci.IsHex(entry.ID, 32) {
			continue
		}
		raw, err := phalaArtifact(ctx, httpc, "sessions/"+entry.ID, "")
		if err != nil {
			continue
		}
		session, err := phalaaci.VerifySession(raw, entry.ID, proof, now)
		if err == nil {
			return entry.ID, session, nil
		}
	}
	return "", nil, errors.New("llm/phala: no unexpired reviewed upstream session with complete evidence")
}

func validPhalaReceiptID(id string) bool {
	if !strings.HasPrefix(id, "rcpt-") || len(id) > 85 {
		return false
	}
	return phalaaci.IsHex(strings.TrimPrefix(id, "rcpt-"), 12)
}

func validatePhalaProof(proof *phalaaci.Proof, model, fingerprint string, now time.Time) error {
	if proof == nil || proof.Policy != phalaaci.PolicyName || proof.Domain != phalaACIDomain || proof.Model != model ||
		proof.Fingerprint != fingerprint || !phalaaci.IsHex(fingerprint, 32) || len(proof.UpstreamVerifiers) == 0 ||
		!proof.ExpiresAt.After(now) || proof.VerifiedAt.IsZero() || proof.VerifiedAt.After(now.Add(5*time.Second)) ||
		proof.ExpiresAt.After(proof.VerifiedAt.Add(2*time.Minute)) || proof.ExpiresAt.Unix() > proof.Keyset.NotAfter ||
		!strings.HasPrefix(proof.Digest, "sha256:") || !phalaaci.IsHex(strings.TrimPrefix(proof.Digest, "sha256:"), 32) {
		return errors.New("llm/phala: invalid or expired attestation proof")
	}
	return nil
}

func verifyPhalaWithSidecar(ctx context.Context, request phalaaci.VerificationRequest) (*phalaaci.Proof, error) {
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://attest-sidecar/verify-phala", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := chutesSidecarHTTPClient().Do(req)
	if err != nil {
		return nil, errors.New("Phala attestation sidecar unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, errors.New("Phala attestation/release policy rejected")
	}
	raw, err = readPhalaBounded(response.Body)
	if err != nil {
		return nil, err
	}
	var proof phalaaci.Proof
	if err := phalaaci.Decode(raw, &proof); err != nil {
		return nil, err
	}
	return &proof, nil
}
