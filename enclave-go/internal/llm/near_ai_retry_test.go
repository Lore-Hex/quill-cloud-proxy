package llm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestNearAIPreInferenceRetriesKeepConnectionsBound(t *testing.T) {
	for _, test := range []struct {
		name                                string
		rejected, wantConnections, wantPost int
		cancel, badFetch, badDials, badPost bool
		badDialFirst, partialStream         bool
		wantError                           bool
	}{
		{name: "first verified", wantConnections: 1, wantPost: 1},
		{name: "second verified", rejected: 1, wantConnections: 2, wantPost: 1},
		{name: "third verified", rejected: 2, wantConnections: 3, wantPost: 1},
		{name: "all unreviewed", rejected: 9, wantConnections: 3, wantError: true},
		{name: "cancelled verification", cancel: true, rejected: 1, wantConnections: 1, wantError: true},
		{name: "authentication failure", badFetch: true, wantConnections: 1, wantError: true},
		{name: "connection changed", badDials: true, wantConnections: 1, wantError: true},
		{name: "never retry inference", badPost: true, wantConnections: 1, wantPost: 1, wantError: true},
		{name: "unreachable first address", badDialFirst: true, wantConnections: 2, wantPost: 1},
		{name: "never retry partial stream", partialStream: true, wantConnections: 1, wantPost: 1, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client := newNearAI("test-key")
			var connections []*nearAITestConnection
			var nonces []string
			var sharedDeadline time.Time
			posts, verified := 0, 0
			client.openConnection = func(domain string, attempt int) (nearAIConnection, *http.Client, error) {
				if attempt != len(connections) {
					t.Fatal("address-selection attempt did not advance")
				}
				if domain != "glm-5-3-flash.completions.near.ai" {
					t.Fatalf("unexpected domain: %s", domain)
				}
				for _, previous := range connections {
					if !previous.closed.Load() {
						t.Fatal("failed connection was retained on retry")
					}
				}
				index := len(connections) + 1
				conn := &nearAITestConnection{fingerprint: fmt.Sprintf("%064x", index), dials: 1}
				if test.badDials {
					conn.dials = 2
				}
				connections = append(connections, conn)
				httpc := &http.Client{Transport: nearAIRoundTripper(func(req *http.Request) (*http.Response, error) {
					status, payload := http.StatusOK, `{"evidence":true}`
					if req.Method == http.MethodGet {
						deadline, ok := req.Context().Deadline()
						if !ok || (!sharedDeadline.IsZero() && !deadline.Equal(sharedDeadline)) {
							t.Fatal("retry reset or removed the shared attestation deadline")
						}
						sharedDeadline = deadline
						nonce := req.URL.Query().Get("nonce")
						if len(nonce) != 64 {
							t.Fatal("invalid nonce")
						}
						for _, previous := range nonces {
							if previous == nonce {
								t.Fatal("retry reused challenge nonce")
							}
						}
						nonces = append(nonces, nonce)
						if test.badDialFirst && index == 1 {
							return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("unreachable")}
						}
						if test.badFetch {
							status = http.StatusUnauthorized
						}
					} else {
						posts++
						if req.Method != http.MethodPost || verified != index || conn.closed.Load() {
							t.Fatal("inference escaped its verified connection")
						}
						payload = "data: {\"id\":\"test\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"PONG\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"
						if test.badPost {
							status, payload = http.StatusBadGateway, `{"error":{"message":"inference failed"}}`
						}
					}
					var body io.Reader = strings.NewReader(payload)
					if test.partialStream && req.Method == http.MethodPost {
						body = io.MultiReader(strings.NewReader(strings.TrimSuffix(payload, "data: [DONE]\n\n")), nearAIErrorReader{})
					}
					return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(body), Request: req}, nil
				})}
				return conn, httpc, nil
			}
			client.verifyEvidence = func(_ context.Context, evidence *nearAIEvidenceEnvelope) (*nearAIVerificationResult, error) {
				index := len(connections)
				if posts != 0 || evidence.TLSFingerprint != connections[index-1].fingerprint ||
					evidence.Nonce != nonces[index-1] || evidence.Model != "z-ai/glm-5.3-flash" {
					t.Fatal("evidence was not bound to this attempt before inference")
				}
				if test.cancel {
					cancel()
				}
				if index <= test.rejected {
					return nil, errors.New("unreviewed deployment")
				}
				verified = index
				return &nearAIVerificationResult{VerifiedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}, nil
			}
			var out bytes.Buffer
			err := client.InvokeStreaming(ctx, &qtypes.OpenAIChatRequest{Model: "z-ai/glm-5.3-flash"},
				&qtypes.AnthropicMessagesRequest{Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "private prompt"}}}, &out)
			if (err != nil) != test.wantError || len(connections) != test.wantConnections || posts != test.wantPost {
				t.Fatalf("err=%v connections=%d posts=%d", err, len(connections), posts)
			}
			for _, conn := range connections {
				if !conn.closed.Load() {
					t.Fatal("connection not closed after completion")
				}
			}
			if test.wantPost == 0 && out.Len() != 0 {
				t.Fatal("unverified attempt emitted response bytes")
			}
		})
	}
}

type nearAIErrorReader struct{}

func (nearAIErrorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestNearAIAddressRotationOnlyUsesDNSIPs(t *testing.T) {
	for attempt, want := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.1"} {
		for _, addresses := range [][]string{
			{"192.0.2.2", "192.0.2.1", "192.0.2.2"},
			{"192.0.2.1", "192.0.2.2", "not-an-ip"},
		} {
			got, err := nearAIAddressForAttempt(addresses, attempt)
			if err != nil || got != want {
				t.Fatalf("attempt=%d got=%q err=%v want=%q", attempt, got, err, want)
			}
		}
	}
	for _, addresses := range [][]string{nil, {"attacker.invalid"}, {"127.0.0.1:443"}} {
		if _, err := nearAIAddressForAttempt(addresses, 0); err == nil {
			t.Fatal("invalid DNS addresses accepted")
		}
	}
}
