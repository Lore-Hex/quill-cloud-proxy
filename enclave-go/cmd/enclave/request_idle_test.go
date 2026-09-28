package main

import (
	"bufio"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/requesttiming"
)

type timedRequestRead struct {
	data string
	ms   int64
}

type idleTimingConn struct {
	*scriptedConn
	clock *phaseAuditClock
	reads []timedRequestRead
}

func (c *idleTimingConn) Read(p []byte) (int, error) {
	if len(c.reads) == 0 {
		return 0, io.EOF
	}
	step := &c.reads[0]
	c.clock.advance(step.ms)
	step.ms = 0
	n := copy(p, step.data)
	step.data = step.data[n:]
	if step.data == "" {
		c.reads = c.reads[1:]
	}
	return n, nil
}

func (c *idleTimingConn) Write(p []byte) (int, error) {
	c.clock.advance(11)
	return c.scriptedConn.Write(p)
}

func parseAuditEventForRequest(t *testing.T, logs, event, requestLogID string) map[string]string {
	t.Helper()
	if requestLogID == "" {
		t.Fatal("cannot select audit event with an empty request_log_id")
	}
	var selected map[string]string
	matches := 0
	for _, line := range strings.Split(logs, "\n") {
		if !strings.HasPrefix(line, event+" ") {
			continue
		}
		fields := parseAuditEvent(t, line, event)
		if fields["request_log_id"] == requestLogID {
			selected = fields
			matches++
		}
	}
	if matches != 1 {
		t.Fatalf("expected exactly one %s with request_log_id=%q; found %d in capture:\n%s", event, requestLogID, matches, logs)
	}
	return selected
}

func TestParseAuditEventForRequestIgnoresForeignLines(t *testing.T) {
	logs := captureProviderStreamStderr(t, func() *providerInvocation {
		_, err := io.WriteString(os.Stderr, "enclave.request_end request_log_id=\"foreign-request\" idle_wait_ms=0 status=500\n"+
			"enclave.request_accept request_log_id=\"own-request\"\n"+
			"enclave.request_end request_log_id=\"own-request\" idle_wait_ms=1179 status=200\n"+
			"enclave.request_end request_log_id=\"another-request\" idle_wait_ms=23 status=400\n")
		if err != nil {
			t.Fatal(err)
		}
		return nil
	})
	end := parseAuditEventForRequest(t, logs, "enclave.request_end", "own-request")
	if end["request_log_id"] != "own-request" || end["idle_wait_ms"] != "1179" || end["status"] != "200" {
		t.Fatalf("selected foreign request_end: %v", end)
	}
}

func TestRequestEndIdleSplit(t *testing.T) {
	const header = "GET /health HTTP/1.1\r\nHost: test.quill.local\r\nContent-Length: 2\r\n\r\n"
	for _, mode := range []keepAliveMode{keepAliveOn, keepAliveLegacy} {
		for _, pipelined := range []bool{false, true} {
			name := map[keepAliveMode]string{keepAliveOn: "on", keepAliveLegacy: "legacy"}[mode] + "/idle"
			if pipelined {
				name += "/pipelined"
			}
			t.Run(name, func(t *testing.T) {
				clock := &phaseAuditClock{now: time.Unix(1000, 0)}
				base := &idleTimingConn{scriptedConn: newScriptedConn("", nil), clock: clock,
					reads: []timedRequestRead{{"G", 23}, {header[1:], 7}, {"{}", 5}}}
				if pipelined {
					base.reads[2].data += header // next headers buffered during first body read
				} else {
					base.reads = append(base.reads, timedRequestRead{"G", 1179}, timedRequestRead{header[1:], 7})
				}
				base.reads = append(base.reads, timedRequestRead{"{}", 5})
				stats := &responseStatsConn{Conn: base}
				deadlines := &requestDeadlineConn{Conn: stats}
				reader := bufio.NewReaderSize(deadlines, maxHTTPHeaderLineBytes+1)
				config := keepAliveConfig{mode: mode, idleTimeout: defaultKeepAliveIdleTimeout, maxRequests: 10}
				attestations, health, requests := 0, 0, 0
				for i := 0; i < 2; i++ {
					phases := requesttiming.New(clock.Now(), clock.Now)
					ctx := requesttiming.WithTimer(context.Background(), phases)
					armRequestReadDeadline(deadlines, reader, requests, config)
					responseStart := base.writes.Len()
					logs := captureProviderStreamStderr(t, func() *providerInvocation {
						if !serveOneRequest(ctx, stats, stats, reader, deadlines, auth.New(nil), &panicStreamingLLM{t: t}, nil, nil, nil, &attestations, &health, &requests, config) {
							t.Error("health request closed reusable connection")
						}
						return nil
					})
					// Write clears stats.requestID when injecting the response headers.
					// Read this request's ID from its response, not the shared stderr capture.
					response, _ := readRawHTTPResponse(t, base.writes.Bytes()[responseStart:])
					requestLogID := response.Header.Get("x-request-id")
					if requestLogID == "" {
						t.Fatal("health response missing x-request-id")
					}
					end := parseAuditEventForRequest(t, logs, "enclave.request_end", requestLogID)
					want := map[string]string{"idle_wait_ms": "0", "accept_to_start_ms": "35", "request_ms": "57", "elapsed_ms": "57"}
					if i == 1 {
						want = map[string]string{"idle_wait_ms": "1179", "accept_to_start_ms": "12", "request_ms": "34", "elapsed_ms": "1213"}
						if pipelined {
							want = map[string]string{"idle_wait_ms": "0", "accept_to_start_ms": "5", "request_ms": "27", "elapsed_ms": "27"}
						}
					}
					for key, value := range want {
						if end[key] != value {
							t.Errorf("request %d: %s=%s want %s; %v", i+1, key, end[key], value, end)
						}
					}
					if end["status"] != "200" || requests != i+1 {
						t.Fatalf("request behavior changed: count=%d event=%v", requests, end)
					}
				}
			})
		}
	}
}
