package main

import (
	"bufio"
	"context"
	"io"
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
					logs := captureProviderStreamStderr(t, func() *providerInvocation {
						if !serveOneRequest(ctx, stats, stats, reader, deadlines, auth.New(nil), &panicStreamingLLM{t: t}, nil, nil, nil, &attestations, &health, &requests, config) {
							t.Error("health request closed reusable connection")
						}
						return nil
					})
					end := parseAuditEvent(t, logs, "enclave.request_end")
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
