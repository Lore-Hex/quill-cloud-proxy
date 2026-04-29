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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/bedrock"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/bootstrap"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/mdlayher/vsock"
	"crypto/rand"
)

// EnclaveListenPort is the vsock port the parent's relay forwards to.
const EnclaveListenPort uint32 = 8001

func main() {
	ctx := context.Background()

	// 1. Fetch bootstrap data from parent.
	boot, err := bootstrap.Fetch(ctx)
	if err != nil {
		// Boot fatal: emit to stderr only in debug mode (--debug-mode shows console).
		fmt.Fprintf(os.Stderr, "bootstrap fetch failed: %v\n", err)
		os.Exit(1)
	}

	// 2. Build registries.
	registry := auth.New(boot.Devices)
	br := bedrock.New(boot)

	// 3. Listen on vsock for inbound HTTP from the parent's relay.
	listener, err := vsock.Listen(EnclaveListenPort, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vsock listen failed: %v\n", err)
		os.Exit(1)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go serveOne(ctx, conn, registry, br)
	}
}

func serveOne(ctx context.Context, conn net.Conn, reg *auth.Registry, br *bedrock.Client) {
	defer conn.Close()

	bearer, body, err := readRequest(conn)
	if err != nil {
		writeError(conn, 400, "could not read request")
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
	bedrockModelID, ok := bedrock.MapModel(req.Model)
	if !ok {
		writeError(conn, 400, "unknown model: "+req.Model)
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
		if err := br.InvokeStreaming(ctx, bedrockModelID, anthropicReq, pw); err != nil {
			// Last-ditch: write an SSE-shaped error and end. We deliberately
			// don't include the prompt or completion in this message.
			fmt.Fprintf(pw, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		}
	}()

	if err := adapter.TransformStream(pr, chunkW, requestID, req.Model); err != nil {
		// nothing to do — connection breakage gets surfaced to parent.
		return
	}
	_ = device // device_id can be reported via a counter-flush vsock RPC in V1.1
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
// Looks only for Authorization (Bearer) and Content-Length. Everything else
// is ignored.
func readRequest(r net.Conn) (bearer string, body []byte, err error) {
	br := bufio.NewReader(r)
	// Status line
	if _, err := br.ReadString('\n'); err != nil {
		return "", nil, err
	}
	contentLength := 0
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", nil, err
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
	if _, err := io.ReadFull(br, body); err != nil {
		return "", nil, err
	}
	return bearer, body, nil
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
