package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/requesttiming"
)

// The second deadline clear occurs after readRequest returns, before Start.
// Advancing here distinguishes body completion from the later Start boundary.
type bodyTimingConn struct {
	*idleTimingConn
	clears  int
	readErr error
}

func (c *bodyTimingConn) SetReadDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		c.clears++
		if c.clears == 2 {
			c.clock.advance(37)
		}
	}
	return nil
}

func (c *bodyTimingConn) Read(p []byte) (int, error) {
	if len(c.reads) == 0 && c.readErr != nil {
		return 0, c.readErr
	}
	return c.idleTimingConn.Read(p)
}

func TestRequestEndBodyReadDelayedChunks(t *testing.T) {
	for _, reused := range []bool{false, true} {
		t.Run(fmt.Sprintf("reused=%v", reused), func(t *testing.T) {
			clock := &phaseAuditClock{now: time.Unix(1000, 0)}
			base := &bodyTimingConn{idleTimingConn: &idleTimingConn{
				scriptedConn: newScriptedConn("", nil), clock: clock,
				reads: []timedRequestRead{
					{"GET /health HTTP/1.1\r\nContent-Length: 6\r\n\r\n", 0},
					{"ab", 120}, {"cd", 230}, {"ef", 310},
				},
			}}
			requests := 0
			wantIdle := int64(0)
			if reused {
				requests = 1
				wantIdle = 1179
				base.reads[0].ms = wantIdle
			}
			stats := &responseStatsConn{Conn: base}
			deadlines := &requestDeadlineConn{Conn: stats}
			reader := bufio.NewReader(deadlines)
			phases := requesttiming.New(clock.Now(), clock.Now)
			ctx := requesttiming.WithTimer(t.Context(), phases)
			attestations, health := 0, 0
			config := keepAliveConfig{mode: keepAliveOn, idleTimeout: defaultKeepAliveIdleTimeout, maxRequests: 10}
			armRequestReadDeadline(deadlines, reader, requests, config)
			logs := captureProviderStreamStderr(t, func() *providerInvocation {
				serveOneRequest(ctx, stats, stats, reader, deadlines, auth.New(nil), &panicStreamingLLM{t: t}, nil, nil, nil, &attestations, &health, &requests, config)
				return nil
			})
			f := phases.Snapshot()
			if f.BodyReadMS != 660 || f.AcceptToStartMS != 697 || f.BodyReadMS > f.AcceptToStartMS || f.IdleWaitMS != wantIdle {
				t.Fatalf("delayed body: %+v", f)
			}
			response, _ := readRawHTTPResponse(t, base.writes.Bytes())
			end := parseAuditEventForRequest(t, logs, "enclave.request_end", response.Header.Get("x-request-id"))
			if end["body_read_ms"] != "660" || end["status"] != "200" {
				t.Fatalf("body timing log: %v", end)
			}
		})
	}
}

func TestReadRequestBodyTimingFailures(t *testing.T) {
	reset := errors.New("connection reset")
	for _, tc := range []struct {
		name, header, body string
		readErr, wantErr   error
		wantMS             int64
	}{
		{"truncated", "Content-Length: 6\r\n", "abc", nil, io.ErrUnexpectedEOF, 25},
		{"reset", "Content-Length: 6\r\n", "abc", reset, reset, 25},
		{"oversize", fmt.Sprintf("Content-Length: %d\r\n", maxRequestBodyBytes+1), "", nil, errBodyTooLarge, 0},
		{"framing", "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n", "", nil, errAmbiguousRequestFraming, 0},
		{"empty", "Content-Length: 0\r\n", "", nil, nil, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := &phaseAuditClock{now: time.Unix(1000, 0)}
			phases := requesttiming.New(clock.Now(), clock.Now)
			conn := &bodyTimingConn{idleTimingConn: &idleTimingConn{
				scriptedConn: newScriptedConn("", nil), clock: clock,
				reads: []timedRequestRead{{"POST / HTTP/1.1\r\n" + tc.header + "\r\n", 5}},
			}, readErr: tc.readErr}
			if tc.body != "" {
				conn.reads = append(conn.reads, timedRequestRead{tc.body, 20})
			}
			_, _, _, _, _, _, err := readRequestWithTiming(bufio.NewReader(conn), nil, phases)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("read error=%v, want %v", err, tc.wantErr)
			}
			// Expose the recorded mark even on errors; production rejections
			// without Start stay clamped to zero (covered by timer unit tests).
			phases.Start()
			phases.End()
			if f := phases.Snapshot(); f.BodyReadMS != tc.wantMS || f.BodyReadMS > f.AcceptToStartMS {
				t.Fatalf("read boundary: %+v, want body=%d", f, tc.wantMS)
			}
		})
	}
}
