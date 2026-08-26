// Command receipt-fixtures emits frozen parity fixtures for inference-receipt
// verifiers (docs/design/signed-receipts-wire-format.md). SDK test suites and
// the reference verifier consume these byte-identical files so every
// implementation proves itself against the same enclave-authored artifacts.
//
// The attestation document in these fixtures is a placeholder: fixture keys
// are NOT enclave keys and must never chain to hardware. Verifiers are
// expected to pass signature, claims, and hash checks on these fixtures and
// then fail closed at attestation-chain verification.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
)

const (
	// A fixed seed keeps regenerated fixtures byte-identical. This key signs
	// test vectors only; treat any receipt chaining to it as untrusted.
	fixtureSeedHex = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
	fixtureIAT     = 1_756_224_000 // 2026-08-26T16:00:00Z
	fixtureIssuer  = "https://api.trustedrouter.com"
)

func b64(digest [32]byte) string {
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func writeFile(dir, name string, data []byte) {
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", name, err)
		os.Exit(1)
	}
}

func main() {
	out := flag.String("out", "receipt-fixtures", "output directory")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}
	seed, err := hex.DecodeString(fixtureSeedHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seed: %v\n", err)
		os.Exit(1)
	}
	signer, err := receipt.NewSignerFromSeed(seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signer: %v\n", err)
		os.Exit(1)
	}

	attestation := []byte("parity-fixture-attestation-document-not-real-evidence")
	attDigest := sha256.Sum256(attestation)
	requestBody := []byte(`{"model":"trustedrouter/auto","messages":[{"role":"user","content":"parity fixture prompt"}]}`)
	responseBody := []byte(`{"id":"chatcmpl-fixture1","object":"chat.completion","model":"openai/gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"parity fixture completion"},"finish_reason":"stop"}]}`)

	// --- compact receipt over exact body bytes -----------------------------
	compactClaims := receipt.Claims{
		RV:         1,
		Issuer:     fixtureIssuer,
		IssuedAt:   fixtureIAT,
		JTI:        "chatcmpl-fixture1",
		Generation: "gen_fixture1",
		Nonce:      "fixture_nonce_1",
		Route:      "chat.completions",
		Request:    receipt.HashRecord{Algorithm: "sha256", Hash: b64(sha256.Sum256(requestBody)), Of: "body"},
		Response:   receipt.ResponseRecord{Algorithm: "sha256", Hash: b64(sha256.Sum256(responseBody)), Of: "body"},
		Model: receipt.Model{
			Requested: "trustedrouter/auto",
			Selected:  "openai/gpt-4o-mini",
			Provider:  "openai",
			Endpoint:  "openai/gpt-4o-mini@openai/prepaid",
		},
		Upstream:  receipt.Upstream{Tier: "tls-webpki"},
		AttSHA256: b64(attDigest),
	}
	compact, err := signer.SignCompact(compactClaims)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign compact: %v\n", err)
		os.Exit(1)
	}

	// --- chat streaming receipt (sse-data-v1) ------------------------------
	// The digest construction here is written straight from the spec, on
	// purpose: SHA-256(D_1 || 0x0A || ... || D_n || 0x0A) over data payloads
	// in wire order, excluding the receipt event and [DONE]. It deliberately
	// does not share code with the enclave's receiptHashWriter so a fixture
	// mismatch would expose a divergence between either side and the spec.
	chatPayloads := [][]byte{
		[]byte(`{"id":"chatcmpl-fixture2","object":"chat.completion.chunk","created":1756224000,"model":"openai/gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":"Hello"},"finish_reason":null}]}`),
		[]byte(`{"id":"chatcmpl-fixture2","object":"chat.completion.chunk","created":1756224000,"model":"openai/gpt-4o-mini","choices":[{"index":0,"delta":{"content":" fixture"},"finish_reason":null}]}`),
		[]byte(`{"id":"chatcmpl-fixture2","object":"chat.completion.chunk","created":1756224000,"model":"openai/gpt-4o-mini","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`),
	}
	streamHash := sha256.New()
	for _, payload := range chatPayloads {
		streamHash.Write(payload)
		streamHash.Write([]byte{'\n'})
	}
	var chatDigest [32]byte
	copy(chatDigest[:], streamHash.Sum(nil))
	events := len(chatPayloads)
	chatStreamClaims := receipt.Claims{
		RV:       1,
		Issuer:   fixtureIssuer,
		IssuedAt: fixtureIAT,
		JTI:      "chatcmpl-fixture2",
		Nonce:    "fixture_nonce_2",
		Route:    "chat.completions",
		Request:  receipt.HashRecord{Algorithm: "sha256", Hash: b64(sha256.Sum256(requestBody)), Of: "body"},
		Response: receipt.ResponseRecord{Algorithm: "sha256", Hash: b64(chatDigest), Of: "sse-data-v1", Events: &events},
		Model: receipt.Model{
			Requested: "trustedrouter/auto",
			Selected:  "openai/gpt-4o-mini",
			Provider:  "openai",
			Endpoint:  "openai/gpt-4o-mini@openai/prepaid",
		},
		Upstream: receipt.Upstream{
			Tier:                  "tee-verified",
			Policy:                "chutes-tdx-nvidia-e2e-v1",
			VerifiedAt:            fixtureIAT - 120,
			VerificationExpiresAt: fixtureIAT + 480,
		},
	}
	chatFlattened, err := signer.SignFlattened(chatStreamClaims, attestation, "gcp-cs-jwt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign flattened: %v\n", err)
		os.Exit(1)
	}
	receiptChunk := map[string]any{
		"id":                "chatcmpl-fixture2",
		"object":            "chat.completion.chunk",
		"created":           int64(fixtureIAT),
		"model":             "openai/gpt-4o-mini",
		"choices":           []any{},
		"inference_receipt": json.RawMessage(chatFlattened),
	}
	receiptChunkJSON, err := json.Marshal(receiptChunk)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal receipt chunk: %v\n", err)
		os.Exit(1)
	}
	var chatStream []byte
	for _, payload := range chatPayloads {
		chatStream = append(chatStream, []byte("data: ")...)
		chatStream = append(chatStream, payload...)
		chatStream = append(chatStream, []byte("\n\n")...)
	}
	chatStream = append(chatStream, []byte("data: ")...)
	chatStream = append(chatStream, receiptChunkJSON...)
	chatStream = append(chatStream, []byte("\n\ndata: [DONE]\n\n")...)

	// --- responses streaming receipt (sse-events-v1) -----------------------
	type namedEvent struct{ name, payload string }
	responsesEvents := []namedEvent{
		{"response.created", `{"type":"response.created","response":{"id":"resp_fixture3","status":"in_progress"}}`},
		{"response.output_text.delta", `{"type":"response.output_text.delta","delta":"parity"}`},
		{"response.completed", `{"type":"response.completed","response":{"id":"resp_fixture3","status":"completed"}}`},
	}
	eventsHash := sha256.New()
	for _, event := range responsesEvents {
		eventsHash.Write([]byte(event.name))
		eventsHash.Write([]byte{'\n'})
		eventsHash.Write([]byte(event.payload))
		eventsHash.Write([]byte{'\n'})
	}
	var responsesDigest [32]byte
	copy(responsesDigest[:], eventsHash.Sum(nil))
	responsesCount := len(responsesEvents)
	responsesClaims := chatStreamClaims
	responsesClaims.JTI = "resp_fixture3"
	responsesClaims.Nonce = "fixture_nonce_3"
	responsesClaims.Route = "responses"
	responsesClaims.Response = receipt.ResponseRecord{Algorithm: "sha256", Hash: b64(responsesDigest), Of: "sse-events-v1", Events: &responsesCount}
	responsesClaims.Upstream = receipt.Upstream{Tier: "tls-webpki"}
	responsesFlattened, err := signer.SignFlattened(responsesClaims, attestation, "gcp-cs-jwt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign responses flattened: %v\n", err)
		os.Exit(1)
	}
	var responsesStream []byte
	for _, event := range responsesEvents {
		responsesStream = append(responsesStream, []byte("event: "+event.name+"\ndata: "+event.payload+"\n\n")...)
	}
	responsesStream = append(responsesStream, []byte("data: ")...)
	responsesStream = append(responsesStream, mustCompactChunk("resp_fixture3", responsesFlattened)...)
	responsesStream = append(responsesStream, []byte("\n\ndata: [DONE]\n\n")...)

	writeFile(*out, "request.json", requestBody)
	writeFile(*out, "response.json", responseBody)
	writeFile(*out, "attestation.bin", attestation)
	writeFile(*out, "receipt-compact.jws", []byte(compact))
	writeFile(*out, "receipt-chat-stream.jws.json", chatFlattened)
	writeFile(*out, "chat-stream.sse", chatStream)
	writeFile(*out, "receipt-responses-stream.jws.json", responsesFlattened)
	writeFile(*out, "responses-stream.sse", responsesStream)
	manifest := map[string]any{
		"spec":            "inference-receipt/1",
		"seed_sha256":     fmt.Sprintf("%x", sha256.Sum256(seed)),
		"kid":             signer.Kid(),
		"iat":             fixtureIAT,
		"attestation":     "placeholder — chain verification MUST fail closed on these fixtures",
		"expected_nonces": map[string]string{"compact": "fixture_nonce_1", "chat_stream": "fixture_nonce_2", "responses_stream": "fixture_nonce_3"},
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal manifest: %v\n", err)
		os.Exit(1)
	}
	writeFile(*out, "manifest.json", append(manifestJSON, '\n'))
	fmt.Printf("wrote parity fixtures to %s (kid %s)\n", *out, signer.Kid())
}

func mustCompactChunk(id string, flattened []byte) []byte {
	chunk, err := json.Marshal(map[string]any{
		"id":                id,
		"object":            "chat.completion.chunk",
		"created":           int64(fixtureIAT),
		"model":             "openai/gpt-4o-mini",
		"choices":           []any{},
		"inference_receipt": json.RawMessage(flattened),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal chunk: %v\n", err)
		os.Exit(1)
	}
	return chunk
}
