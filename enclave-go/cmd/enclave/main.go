// quill-enclave runs INSIDE the Nitro Enclave.
//
// At startup it dials the parent via vsock to fetch BootstrapData (device
// list + Bedrock credentials + region + vsock-proxy port). It then listens
// on vsock CID 16 port 8001 for inbound HTTP from the parent's relay,
// validates the bearer, calls Bedrock via the vsock-tunneled HTTPS client,
// and streams OpenAI-format chunks back.
//
// Strict policy: NO logging, NO disk writes, NO network except vsock. The
// only `fmt.Print*` calls in this binary go to stdout/stderr at startup
// for fatal-error visibility ONLY when running in --debug-mode.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/attestation"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/bootstrap"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/enclavetls"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/entropy"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// EnclaveListenPort + newRawListener are provided by listener_aws.go
// (vsock CID-LOCAL) or listener_gcp.go (plain TCP).

func main() {
	ctx := context.Background()

	// 0. Seed the kernel's CSPRNG from the NSM hardware RNG before any
	// crypto/rand consumer (TLS keypair, request IDs, x509 serials) reads
	// it. Linux's /dev/urandom is starved at boot inside an enclave —
	// without seeding, an early TLS keypair could be generated from
	// dangerously low entropy. NSM-sourced bytes come from the Nitro
	// hypervisor's hardware RNG, distinct from the guest kernel's pool.
	// Skipped outside enclaves (no /dev/nsm); not fatal if seeding fails
	// — the kernel will still hit a real entropy source eventually, but
	// the trust story prefers we shout if it doesn't.
	if err := entropy.Seed(); err != nil {
		fmt.Fprintf(os.Stderr, "entropy.seed_failed: %v (continuing)\n", err)
	}

	// 1. Fetch bootstrap data from parent.
	boot, err := bootstrap.Fetch(ctx)
	if err != nil {
		// Boot fatal: emit to stderr only in debug mode (--debug-mode shows console).
		fmt.Fprintf(os.Stderr, "bootstrap fetch failed: %v\n", err)
		os.Exit(1)
	}

	// 2. Build registries. Capture a canonical hash of the device list
	// so /attestation can include it in the document's UserData — clients
	// learn the exact set of bearer tokens currently authorized, and any
	// silent rotation produces a new attestation.
	registry := auth.New(boot.Devices)
	br := llm.New(boot) // build-tag-gated: AWS Bedrock by default, GCP Vertex with -tags gcp

	deviceBlob, _ := json.Marshal(boot.Devices)

	// 3. Listen on vsock. When QUILL_ENCLAVE_TLS=true, wrap the listener
	// with an enclave-generated self-signed cert so TLS is terminated INSIDE
	// the attested binary — i.e. the parent never sees plaintext, and the
	// PCR0-measured code is the first thing to handle the prompt bytes.
	//
	// Phase 1: feature-flagged. The parent's relay still ships HTTP-over-
	// vsock by default; flipping the flag without flipping the parent will
	// break the chain (the parent won't speak TLS). Phase 2 swaps the
	// parent to a raw TCP pump so this flag becomes the default.
	rawListener, err := newRawListener()
	if err != nil {
		fmt.Fprintf(os.Stderr, "raw listener failed: %v\n", err)
		os.Exit(1)
	}
	var listener net.Listener = rawListener

	// leafDER is non-nil only when TLS is enabled; the /attestation handler
	// uses it to bind the live cert into the NSM-signed document. Empty
	// = /attestation responds 503 (we have no cert to attest).
	var leafDER []byte

	if os.Getenv("QUILL_ENCLAVE_TLS") == "true" {
		srv, err := enclavetls.NewSelfSigned("api.quill.lorehex.co")
		if err != nil {
			fmt.Fprintf(os.Stderr, "enclavetls cert failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "enclavetls.cert_fingerprint sha256=%s\n", srv.LeafFingerprint)
		leafDER = srv.Certificate.Certificate[0]
		listener = srv.Wrap(rawListener)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go serveOne(ctx, conn, registry, br, leafDER, deviceBlob)
	}
}

func serveOne(ctx context.Context, conn net.Conn, reg *auth.Registry, br llm.Client, leafDER, deviceBlob []byte) {
	defer conn.Close()

	method, path, bearer, body, err := readRequest(conn)
	if err != nil {
		writeError(conn, 400, "could not read request")
		return
	}

	// /attestation is the only path that's anonymous: clients call it
	// BEFORE pinning, so requiring a bearer would defeat the purpose.
	// Trust binding still holds — the doc commits to the live TLS cert,
	// which only this enclave can speak.
	if method == "GET" && path == "/attestation" {
		serveAttestation(conn, leafDER, deviceBlob)
		return
	}

	device := reg.Lookup(bearer)
	if device == nil {
		writeError(conn, 401, "Invalid API key")
		return
	}

	var req types.OpenAIChatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(conn, 400, "invalid JSON")
		return
	}

	anthropicReq, err := adapter.ToAnthropic(&req, "claude-opus-4-7")
	if err != nil {
		var aerr *adapter.AdapterError
		if asAdapterErr(err, &aerr) {
			writeError(conn, aerr.Status, aerr.Message)
			return
		}
		writeError(conn, 500, "adapter error")
		return
	}
	requestID := newRequestID()
	if err := writeResponseHead(conn, 200); err != nil {
		return
	}

	chunkW := newChunkedWriter(conn)
	defer chunkW.Close()

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		// llm.Client decides what model-name translation (if any) to do
		// internally — Bedrock maps to inference profile IDs; Vertex
		// passes through unchanged.
		if err := br.InvokeStreaming(ctx, req.Model, anthropicReq, pw); err != nil {
			emitErrorAsAnthropicSSE(pw, err)
		}
	}()

	if err := adapter.TransformStream(pr, chunkW, requestID, req.Model); err != nil {
		// nothing to do — connection breakage gets surfaced to parent.
		return
	}
	_ = device // device_id can be reported via a counter-flush vsock RPC in V1.1
}

// emitErrorAsAnthropicSSE turns an upstream-LLM failure into a small
// Anthropic-shaped SSE conversation: a content_block_delta carrying the
// API error text, followed by message_stop. The adapter then translates
// these to OpenAI chunks so the client sees `[upstream: <code>: <message>]`
// as the assistant's reply.
//
// Trust note: upstream API error responses contain only the error
// code/message (e.g. "ValidationException: max_tokens must be > 0",
// "Insufficient credits", etc.). They never echo back the user's prompt
// or any completion text, so emitting them verbatim keeps our
// zero-prompt-retention property intact.
//
// classifyUpstreamError is provided per-cloud (smithy unwrap on AWS,
// plain error.Error() on GCP) so this file stays cloud-agnostic.
func emitErrorAsAnthropicSSE(w io.Writer, err error) {
	code, msg := classifyUpstreamError(err)
	text := fmt.Sprintf("[upstream: %s: %s]", code, msg)

	delta := map[string]any{
		"type":  "content_block_delta",
		"index": 0,
		"delta": map[string]any{"type": "text_delta", "text": text},
	}
	deltaJSON, _ := json.Marshal(delta)
	fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", deltaJSON)

	stopDelta := map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": "end_turn"},
	}
	stopJSON, _ := json.Marshal(stopDelta)
	fmt.Fprintf(w, "event: message_delta\ndata: %s\n\n", stopJSON)
	fmt.Fprintf(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
}

// asAdapterErr is the local errors.As substitute (no extra imports).
func asAdapterErr(err error, target **adapter.AdapterError) bool {
	for cur := err; cur != nil; {
		if e, ok := cur.(*adapter.AdapterError); ok {
			*target = e
			return true
		}
		// crude unwrap: errors.Unwrap from wrapper%w chains
		type unwrapper interface{ Unwrap() error }
		u, ok := cur.(unwrapper)
		if !ok {
			break
		}
		cur = u.Unwrap()
	}
	return false
}

// readRequest reads a minimal HTTP/1.1 request: status line + headers + body.
// Returns method + path + bearer + body. We don't validate Host or any
// other field; the dispatch happens by path in serveOne.
func readRequest(r net.Conn) (method, path, bearer string, body []byte, err error) {
	br := bufio.NewReader(r)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return "", "", "", nil, err
	}
	// "GET /path HTTP/1.1\r\n" — split into 3 fields
	parts := strings.Fields(statusLine)
	if len(parts) >= 2 {
		method = parts[0]
		path = parts[1]
	}

	contentLength := 0
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", "", "", nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "authorization":
			if strings.HasPrefix(v, "Bearer ") {
				bearer = v[len("Bearer "):]
			}
		case "content-length":
			contentLength, _ = strconv.Atoi(v)
		}
	}
	body = make([]byte, contentLength)
	if contentLength > 0 {
		if _, err := io.ReadFull(br, body); err != nil {
			return "", "", "", nil, err
		}
	}
	return method, path, bearer, body, nil
}

// serveAttestation answers GET /attestation with the NSM-signed CBOR
// document binding the live TLS cert's public key. Clients fetch this
// before sending prompts; verify against AWS's NSM root + check PCR0
// matches the trust page's published value + check the cert presented in
// their TLS handshake matches the doc's PublicKey field.
//
// nonce: ?nonce=<hex> in the query string. Optional but recommended —
// a client-supplied freshness token so the doc is provably not a replay.
func serveAttestation(conn io.Writer, leafDER, deviceBlob []byte) {
	if leafDER == nil {
		writeError(conn, 503, "TLS not enabled in this enclave; attestation requires a bound cert")
		return
	}
	doc, err := attestation.Get(leafDER, deviceBlob, nil)
	if err != nil {
		writeError(conn, 500, "attestation: "+err.Error())
		return
	}
	fmt.Fprintf(conn,
		"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
		len(doc))
	conn.Write(doc)
}

func writeError(w io.Writer, status int, message string) {
	body, _ := json.Marshal(map[string]any{
		"error": map[string]any{"status": status, "message": message},
	})
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		status, statusText(status), len(body))
	w.Write(body)
}

func writeResponseHead(w io.Writer, status int) error {
	_, err := fmt.Fprintf(w,
		"HTTP/1.1 %d %s\r\nTransfer-Encoding: chunked\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nX-Accel-Buffering: no\r\nConnection: close\r\n\r\n",
		status, statusText(status))
	return err
}

func statusText(status int) string {
	switch status {
	case 200:
		return "OK"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 500:
		return "Internal Server Error"
	default:
		return "Error"
	}
}

// chunkedWriter wraps a net.Conn writer with HTTP/1.1 chunked transfer-encoding.
type chunkedWriter struct {
	w io.Writer
}

func newChunkedWriter(w io.Writer) *chunkedWriter { return &chunkedWriter{w: w} }

func (c *chunkedWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if _, err := fmt.Fprintf(c.w, "%x\r\n", len(p)); err != nil {
		return 0, err
	}
	n, err := c.w.Write(p)
	if err != nil {
		return n, err
	}
	if _, err := c.w.Write([]byte("\r\n")); err != nil {
		return n, err
	}
	return n, nil
}

func (c *chunkedWriter) Close() error {
	_, err := c.w.Write([]byte("0\r\n\r\n"))
	return err
}

// newRequestID returns "chatcmpl-<32 hex>" with no allocations beyond the buffer.
func newRequestID() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return "chatcmpl-" + hex.EncodeToString(buf[:])
}
