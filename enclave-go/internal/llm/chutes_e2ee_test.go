package llm

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"golang.org/x/crypto/chacha20poly1305"
)

func decryptChutesTestRequest(t *testing.T, blob []byte, instanceSK *mlkem.DecapsulationKey768) map[string]any {
	t.Helper()
	if len(blob) < chutesMLKEMCiphertextSize+chutesNonceSize+chutesTagSize {
		t.Fatalf("encrypted request is too short: %d", len(blob))
	}
	mlkemCiphertext := blob[:chutesMLKEMCiphertextSize]
	sharedSecret, err := instanceSK.Decapsulate(mlkemCiphertext)
	if err != nil {
		t.Fatalf("decapsulate request: %v", err)
	}
	key, err := deriveChutesKey(sharedSecret, mlkemCiphertext, chutesRequestKDFInfo)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := aead.Open(
		nil,
		blob[chutesMLKEMCiphertextSize:chutesMLKEMCiphertextSize+chutesNonceSize],
		blob[chutesMLKEMCiphertextSize+chutesNonceSize:],
		nil,
	)
	if err != nil {
		t.Fatalf("decrypt request: %v", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if err := zr.Close(); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	return payload
}

func chutesTestEncryptedStream(t *testing.T, responsePK string, plaintextEvents ...string) string {
	return chutesTestEncryptedStreamWithTerminal(t, responsePK, true, plaintextEvents...)
}

func chutesTestEncryptedStreamWithTerminal(
	t *testing.T,
	responsePK string,
	includeInnerTerminal bool,
	plaintextEvents ...string,
) string {
	t.Helper()
	pubkeyBytes, err := base64.StdEncoding.DecodeString(responsePK)
	if err != nil {
		t.Fatal(err)
	}
	pubkey, err := mlkem.NewEncapsulationKey768(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	sharedSecret, ciphertext := pubkey.Encapsulate()
	key, err := deriveChutesKey(sharedSecret, ciphertext, chutesStreamKDFInfo)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}
	var stream strings.Builder
	initPayload, _ := json.Marshal(map[string]string{"e2e_init": base64.StdEncoding.EncodeToString(ciphertext)})
	fmt.Fprintf(&stream, "data: %s\n\n", initPayload)
	for _, plaintext := range plaintextEvents {
		writeEncryptedChutesTestEvent(t, &stream, aead, plaintext)
	}
	if includeInnerTerminal {
		writeEncryptedChutesTestEvent(t, &stream, aead, "data: [DONE]")
	}
	stream.WriteString("data: [DONE]\n\n")
	return stream.String()
}

func writeEncryptedChutesTestEvent(t *testing.T, stream *strings.Builder, aead cipher.AEAD, plaintext string) {
	t.Helper()
	nonce := make([]byte, chutesNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	sealed := aead.Seal(nil, nonce, []byte(plaintext), nil)
	raw := append(append([]byte(nil), nonce...), sealed...)
	payload, _ := json.Marshal(map[string]string{"e2e": base64.StdEncoding.EncodeToString(raw)})
	fmt.Fprintf(stream, "data: %s\n\n", payload)
}

func TestChutesEncryptedRequestRoundTrip(t *testing.T) {
	instanceSK, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	prompt := "PRIVATE-PROMPT-MUST-BE-ENCRYPTED"
	encrypted, err := buildChutesEncryptedRequest(
		base64.StdEncoding.EncodeToString(instanceSK.EncapsulationKey().Bytes()),
		map[string]any{"model": "test/model-TEE", "prompt": prompt, "stream": true},
	)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted.blob, []byte(prompt)) {
		t.Fatal("encrypted request contains prompt plaintext")
	}
	payload := decryptChutesTestRequest(t, encrypted.blob, instanceSK)
	if payload["prompt"] != prompt {
		t.Fatalf("prompt = %#v", payload["prompt"])
	}
	encodedResponsePK, ok := payload["e2e_response_pk"].(string)
	if !ok {
		t.Fatal("request did not carry a response public key")
	}
	decodedResponsePK, err := base64.StdEncoding.DecodeString(encodedResponsePK)
	if err != nil || len(decodedResponsePK) != 1184 {
		t.Fatalf("invalid response public key: len=%d err=%v", len(decodedResponsePK), err)
	}
}

func TestDecryptChutesStreamRejectsOutOfOrderAndTruncatedEvents(t *testing.T) {
	responseSK, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	chunk := base64.StdEncoding.EncodeToString(make([]byte, chutesNonceSize+chutesTagSize))
	for name, stream := range map[string]string{
		"chunk before init": fmt.Sprintf("data: {\"e2e\":%q}\n\ndata: [DONE]\n\n", chunk),
		"done before chunk": "data: {\"e2e_init\":\"bad\"}\n\ndata: [DONE]\n\n",
		"no done":           "data: {\"e2e_error\":{\"message\":\"failed\"}}\n\n",
		"unknown event":     "data: {\"other\":true}\n\n",
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if err := decryptChutesStream(strings.NewReader(stream), &out, responseSK); err == nil {
				t.Fatal("expected encrypted stream to fail closed")
			}
		})
	}
}

func TestDecryptChutesStreamRejectsEmptyAndTamperedStreams(t *testing.T) {
	responseSK, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	responsePK := base64.StdEncoding.EncodeToString(responseSK.EncapsulationKey().Bytes())

	t.Run("empty", func(t *testing.T) {
		stream := chutesTestEncryptedStream(t, responsePK)
		if err := decryptChutesStream(strings.NewReader(stream), io.Discard, responseSK); err == nil ||
			!strings.Contains(err.Error(), "before authenticated terminal marker") {
			t.Fatalf("empty stream error = %v", err)
		}
	})

	t.Run("tampered", func(t *testing.T) {
		stream := chutesTestEncryptedStream(t, responsePK, `data: {"choices":[{"delta":{"content":"PONG"}}]}`)
		marker := `"e2e":"`
		start := strings.Index(stream, marker)
		if start < 0 {
			t.Fatal("test stream has no encrypted chunk")
		}
		start += len(marker)
		mutated := []byte(stream)
		if mutated[start] == 'A' {
			mutated[start] = 'B'
		} else {
			mutated[start] = 'A'
		}
		if err := decryptChutesStream(bytes.NewReader(mutated), io.Discard, responseSK); err == nil ||
			!strings.Contains(err.Error(), "authenticate") {
			t.Fatalf("tampered stream error = %v", err)
		}
	})
}

func TestDecryptChutesStreamFramesRawOpenAIJSONAndAcceptsPreframedSSE(t *testing.T) {
	responseSK, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	responsePK := base64.StdEncoding.EncodeToString(responseSK.EncapsulationKey().Bytes())
	for name, plaintext := range map[string]string{
		"raw JSON":      `{"choices":[{"delta":{"content":"PONG"}}]}`,
		"preframed SSE": `data: {"choices":[{"delta":{"content":"PONG"}}]}`,
		"raw text":      `PONG`,
	} {
		t.Run(name, func(t *testing.T) {
			stream := chutesTestEncryptedStream(t, responsePK, plaintext)
			var output bytes.Buffer
			if err := decryptChutesStream(strings.NewReader(stream), &output, responseSK); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), `data: {"choices"`) ||
				!strings.HasSuffix(output.String(), "data: [DONE]\n\n") {
				t.Fatalf("unexpected framed stream: %q", output.String())
			}
		})
	}

	stream := chutesTestEncryptedStream(t, responsePK, `PONG`, `data: [DONE]`, ``)
	stream = strings.TrimSuffix(stream, "data: [DONE]\n\n")
	var terminalOutput bytes.Buffer
	if err := decryptChutesStream(strings.NewReader(stream), &terminalOutput, responseSK); err != nil {
		t.Fatal(err)
	}
	if strings.Count(terminalOutput.String(), "data: [DONE]") != 1 {
		t.Fatalf("terminal marker count in %q", terminalOutput.String())
	}

	truncated := chutesTestEncryptedStreamWithTerminal(t, responsePK, false, `PONG`)
	if err := decryptChutesStream(strings.NewReader(truncated), io.Discard, responseSK); err == nil ||
		!strings.Contains(err.Error(), "authenticated terminal marker") {
		t.Fatalf("truncated stream error = %v", err)
	}

	stream = chutesTestEncryptedStream(t, responsePK, string([]byte{0xff, 0xfe}))
	if err := decryptChutesStream(strings.NewReader(stream), io.Discard, responseSK); err == nil ||
		!strings.Contains(err.Error(), "invalid text framing") {
		t.Fatalf("invalid plaintext error = %v", err)
	}
}

func TestChutesClientSkipsUnverifiedInstanceAndNeverSendsPlaintext(t *testing.T) {
	firstSK, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	secondSK, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	const chuteID = "aac09863-35b4-5d9b-9b67-6e6a9d54273a"
	const model = "moonshotai/Kimi-K2.6-TEE"
	const prompt = "PRIVATE-CHUTES-E2E-PROMPT"
	var invokeCalls atomic.Int64
	var firstInvoked atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/models":
			_, _ = fmt.Fprintf(w, `{"data":[{"id":%q,"chute_id":%q,"confidential_compute":true}]}`, model, chuteID)
		case r.URL.Path == "/e2e/instances/"+chuteID:
			_ = json.NewEncoder(w).Encode(chutesDiscoveryResponse{
				NonceExpiresIn: 60,
				Instances: []chutesInstance{
					{InstanceID: "bad-instance", E2EPubkey: base64.StdEncoding.EncodeToString(firstSK.EncapsulationKey().Bytes()), Nonces: []string{"bad-nonce"}},
					{InstanceID: "good-instance", E2EPubkey: base64.StdEncoding.EncodeToString(secondSK.EncapsulationKey().Bytes()), Nonces: []string{"good-nonce"}},
				},
			})
		case strings.HasPrefix(r.URL.Path, "/instances/"):
			_, _ = io.WriteString(w, `{}`)
		case r.URL.Path == "/e2e/invoke":
			invokeCalls.Add(1)
			instanceID := r.Header.Get("X-Instance-Id")
			if instanceID == "bad-instance" {
				firstInvoked.Store(true)
			}
			blob, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				t.Errorf("read encrypted body: %v", readErr)
				return
			}
			if bytes.Contains(blob, []byte(prompt)) {
				t.Error("Chutes relay received prompt plaintext")
			}
			payload := decryptChutesTestRequest(t, blob, secondSK)
			messages, _ := json.Marshal(payload["messages"])
			if !bytes.Contains(messages, []byte(prompt)) {
				t.Errorf("attested instance did not recover prompt: %s", messages)
			}
			responsePK, _ := payload["e2e_response_pk"].(string)
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, chutesTestEncryptedStream(
				t,
				responsePK,
				`data: {"choices":[{"delta":{"content":"PONG"},"finish_reason":"stop"}]}`,
			))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newChutesE2EE("operator-key")
	client.apiBase = server.URL
	client.modelsBase = server.URL
	client.httpc = server.Client()
	client.verifyEvidence = func(_ context.Context, envelope *chutesEvidenceEnvelope) (*chutesVerificationResult, error) {
		if envelope.Instance == "bad-instance" {
			return nil, errors.New("outdated TDX instance")
		}
		now := time.Now()
		return &chutesVerificationResult{
			VerifiedAt: now,
			ExpiresAt:  now.Add(time.Minute),
			Policy:     "chutes-tdx-nvidia-e2e-v1",
		}, nil
	}
	var out bytes.Buffer
	err = client.InvokeStreaming(
		context.Background(),
		&qtypes.OpenAIChatRequest{Model: model},
		&qtypes.AnthropicMessagesRequest{
			Messages: []qtypes.AnthropicMessage{{Role: "user", Content: prompt}},
		},
		&out,
		InvokeOptions{Provider: "chutes", UpstreamModel: model},
	)
	if err != nil {
		t.Fatal(err)
	}
	if firstInvoked.Load() {
		t.Fatal("client sent ciphertext to an instance whose attestation failed")
	}
	if invokeCalls.Load() != 1 {
		t.Fatalf("invoke calls = %d, want 1", invokeCalls.Load())
	}
	if !strings.Contains(out.String(), "PONG") {
		t.Fatalf("translated stream did not contain response: %s", out.String())
	}
}
