package llm

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/phalaaci"
)

type phalaRoundTrip func(*http.Request) (*http.Response, error)

func (f phalaRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func phalaTestJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := phalaaci.CanonicalValue(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPhalaACIExchangeFailsClosed(t *testing.T) {
	for _, test := range []string{"success", "byok", "attestation", "missing-evidence", "receipt-signature", "receipt-model", "receipt-request-hash", "receipt-session", "receipt-unavailable", "plaintext", "truncated", "missing-headers", "keyset-rotation", "provider-401", "provider-412", "disconnect", "tools"} {
		t.Run(test, func(t *testing.T) {
			now := time.Unix(1750000000, 0)
			server, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			model := "openai/gpt-oss-20b"
			fingerprint := strings.Repeat("a", 64)
			proof := &phalaaci.Proof{Policy: phalaaci.PolicyName, Domain: phalaACIDomain, Model: model, Fingerprint: fingerprint, VerifiedAt: now, ExpiresAt: now.Add(time.Minute), Digest: phalaaci.Hash([]byte("test-keyset")), UpstreamVerifiers: []string{"reviewed"}, Keyset: phalaaci.Keyset{NotAfter: now.Unix() + 300, ReceiptKeys: []phalaaci.Key{{ID: "key", Algo: "ed25519", PublicKey: hex.EncodeToString(public)}}, EncryptionKeys: []phalaaci.Key{{ID: "enc", Algo: phalaaci.Suite, PublicKey: hex.EncodeToString(server.PublicKey().Bytes())}}}}
			evidence := []byte(`{"quote":"local-test"}`)
			session := map[string]any{"api_version": "aci/1", "upstream_name": "test", "endpoint": "https://test.phala.com", "verifier_id": "reviewed", "established_at": now.Unix() - 10, "expires_at": now.Unix() + 120, "channel_binding": []any{map[string]any{"type": "tls_spki_sha256", "origin": "https://test.phala.com", "spki_sha256": fingerprint}}, "evidence": map[string]any{"digest": phalaaci.Hash(evidence), "data": "data:application/json;base64," + base64.StdEncoding.EncodeToString(evidence)}}
			if test == "missing-evidence" {
				session["evidence"] = map[string]any{}
			}
			sessionRaw := phalaTestJSON(t, session)
			sessionID := phalaaci.Hex(sessionRaw)
			receiptID := "rcpt-" + strings.Repeat("b", 24)
			var receipt []byte
			posts := 0
			closed := false
			httpc := &http.Client{Transport: phalaRoundTrip(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host != phalaACIDomain {
					t.Fatal("unexpected host")
				}
				var raw []byte
				status := 200
				headers := http.Header{}
				switch r.URL.Path {
				case "/v1/aci/attestation":
					if !phalaaci.IsHex(r.URL.Query().Get("nonce"), 32) || r.Header.Get("Authorization") != "" {
						t.Fatal("bad attestation request")
					}
					raw = []byte(`{}`)
				case "/v1/aci/sessions":
					raw = phalaTestJSON(t, map[string]any{"api_version": "aci/1", "sessions": []any{map[string]any{"session_id": sessionID}}})
				case "/v1/aci/sessions/" + sessionID:
					raw = sessionRaw
				case "/v1/chat/completions":
					posts++
					if r.GetBody != nil {
						t.Fatal("paid POST is replayable")
					}
					want := "Bearer prepaid-test-key"
					if test == "byok" {
						want = "Bearer workspace-test-key"
					}
					if r.Header.Get("Authorization") != want {
						t.Fatal("wrong credential used")
					}
					if test == "provider-401" || test == "provider-412" {
						status = 401
						if test == "provider-412" {
							status = 412
						}
						raw = []byte(`{"error":"private response must not be logged"}`)
						break
					}
					if test == "disconnect" {
						return nil, errors.New("synthetic disconnect")
					}
					wire, _ := io.ReadAll(r.Body)
					if bytes.Contains(wire, []byte("private prompt")) {
						t.Fatal("plaintext prompt sent")
					}
					if r.Header.Get("X-E2EE-Version") != "2" || r.Header.Get("X-Signing-Algo") != "" {
						t.Fatal("missing E2EE v2 headers")
					}
					var payload map[string]any
					json.Unmarshal(wire, &payload)
					provider := payload["provider"].(map[string]any)
					if provider["aci_verified"] != true || provider["allow_fallbacks"] != false || provider["aci_session_ids"].([]any)[0] != sessionID {
						t.Fatal("missing strict route/session constraints")
					}
					ts, _ := strconv.ParseInt(r.Header.Get("X-E2EE-Timestamp"), 10, 64)
					crypto := &phalaaci.Encryption{Model: model, Nonce: r.Header.Get("X-E2EE-Nonce"), Timestamp: ts}
					msgs := payload["messages"].([]any)
					message := msgs[0].(map[string]any)
					aad, _ := crypto.AAD("messages.0.content", "", false)
					plain, err := phalaaci.DecryptField(server, message["content"].(string), aad)
					if err != nil || string(plain) != "private prompt" {
						t.Fatalf("cannot decrypt request: %v", err)
					}
					message["content"] = string(plain)
					requestHash := phalaaci.Hash(phalaTestJSON(t, payload))
					clientRaw, _ := hex.DecodeString(r.Header.Get("X-Client-Pub-Key"))
					clientKey, err := ecdh.X25519().NewPublicKey(clientRaw)
					if err != nil {
						t.Fatal(err)
					}
					aad, _ = crypto.AAD("choices.0.delta.content", "chat-1", true)
					ciphertext, err := phalaaci.EncryptField(clientKey, []byte("PONG"), aad)
					if err != nil {
						t.Fatal(err)
					}
					if test == "plaintext" {
						ciphertext = "PONG"
					}
					chunk := phalaTestJSON(t, map[string]any{"id": "chat-1", "choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": ciphertext}, "finish_reason": nil}}})
					raw = append([]byte("data: "), chunk...)
					raw = append(raw, []byte("\n\ndata: {\"id\":\"chat-1\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":2,\"total_tokens\":7}}\n\ndata: [DONE]\n\n")...)
					if test == "truncated" {
						raw = bytes.Replace(raw, []byte("data: [DONE]"), nil, 1)
					}
					upstreamSession := sessionID
					if test == "receipt-session" {
						upstreamSession = strings.Repeat("c", 64)
					}
					if test == "receipt-request-hash" {
						requestHash = phalaaci.Hash([]byte("other"))
					}
					document := map[string]any{"api_version": "aci/1", "receipt_id": receiptID, "chat_id": "chat-1", "key_id": "key", "workload_keyset_digest": proof.Digest, "model": model, "method": "POST", "endpoint": "/v1/chat/completions", "served_at": now.Unix(), "event_log": []any{map[string]any{"type": "request.received", "body_hash": requestHash}, map[string]any{"type": "route.selected", "target_route_id": "test:" + model}, map[string]any{"type": "upstream.verified", "model_id": model, "required": true, "result": "verified", "session_id": upstreamSession}, map[string]any{"type": "response.returned", "body_hash": phalaaci.Hash(raw)}}}
					if test == "receipt-model" {
						document["model"] = "wrong-model"
					}
					sig := ed25519.Sign(private, phalaTestJSON(t, document))
					if test == "receipt-signature" {
						sig[0] ^= 1
					}
					document["signature"] = hex.EncodeToString(sig)
					receipt = phalaTestJSON(t, document)
					headers.Set("X-E2EE-Applied", "true")
					headers.Set("X-E2EE-Version", "2")
					headers.Set("X-E2EE-Algo", phalaaci.Suite)
					headers.Set("X-ACI-Keyset-Digest", proof.Digest)
					headers.Set("X-Receipt-ID", receiptID)
					if test == "missing-headers" {
						headers.Del("X-E2EE-Applied")
					}
					if test == "keyset-rotation" {
						headers.Set("X-ACI-Keyset-Digest", phalaaci.Hash([]byte("rotated")))
					}
				case "/v1/aci/receipts/" + receiptID:
					if test == "receipt-unavailable" {
						status = 404
					}
					raw = receipt
				default:
					t.Fatalf("unexpected request %s", r.URL.Path)
				}
				return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(bytes.NewReader(raw)), Request: r}, nil
			})}
			client := &phalaClient{apiKey: "prepaid-test-key", now: func() time.Time { return now }, open: func() (*http.Client, func() string, func(), error) {
				return httpc, func() string { return fingerprint }, func() { closed = true }, nil
			}, verify: func(_ context.Context, r phalaaci.VerificationRequest) (*phalaaci.Proof, error) {
				if test == "attestation" {
					return nil, errors.New("quote rejected")
				}
				return proof, nil
			}}
			request := &qtypes.OpenAIChatRequest{Model: model}
			body := &qtypes.AnthropicMessagesRequest{}
			if err := json.Unmarshal([]byte(`{"messages":[{"role":"user","content":"private prompt"}],"max_tokens":16}`), body); err != nil {
				t.Fatal(err)
			}
			if test == "tools" {
				if err := json.Unmarshal([]byte(`{"model":"openai/gpt-oss-20b","tools":[{"type":"function","function":{"name":"private_tool"}}]}`), request); err != nil {
					t.Fatal(err)
				}
			}
			option := InvokeOptions{Provider: "phala", UpstreamModel: model}
			if test == "byok" {
				option.ProviderAPIKey = "workspace-test-key"
			}
			var output bytes.Buffer
			err = client.InvokeStreaming(context.Background(), request, body, &output, option)
			good := test == "success" || test == "byok"
			if good && (err != nil || !strings.Contains(output.String(), "PONG")) {
				t.Fatalf("valid exchange failed: %v output=%s", err, output.String())
			}
			if !good && (err == nil || output.Len() != 0) {
				t.Fatalf("unsafe exchange succeeded: %v bytes=%d", err, output.Len())
			}
			if !closed {
				t.Fatal("connection not closed")
			}
			if test == "attestation" || test == "missing-evidence" || test == "tools" {
				if posts != 0 {
					t.Fatal("prompt sent before preflight passed")
				}
			} else if posts != 1 {
				t.Fatalf("paid POST count=%d", posts)
			}
		})
	}
}

func TestPhalaGenericTransportCannotBypassACI(t *testing.T) {
	err := invokeOpenAICompatibleStreamingWithClientOptions(context.Background(), nil, "phala", "https://untrusted.test", "test-key", nil, nil, io.Discard, "model", openAICompatibleInvocationOptions{})
	if err == nil || !strings.Contains(err.Error(), "generic HTTPS transport forbidden") {
		t.Fatalf("bypassed ACI: %v", err)
	}
}

func TestPhalaCapacityRejectsBeforeNetwork(t *testing.T) {
	for index := 0; index < cap(phalaACISlots); index++ {
		phalaACISlots <- struct{}{}
	}
	defer func() {
		for index := 0; index < cap(phalaACISlots); index++ {
			<-phalaACISlots
		}
	}()
	client := newPhala("test-key")
	client.open = func() (*http.Client, func() string, func(), error) {
		t.Fatal("busy request opened network connection")
		return nil, nil, nil, nil
	}
	err := client.InvokeStreaming(context.Background(), &qtypes.OpenAIChatRequest{Model: "openai/gpt-oss-20b"}, &qtypes.AnthropicMessagesRequest{}, io.Discard)
	var upstream *upstreamHTTPError
	if !errors.As(err, &upstream) || upstream.status != 503 {
		t.Fatalf("expected immediate busy response, got %v", err)
	}
}
