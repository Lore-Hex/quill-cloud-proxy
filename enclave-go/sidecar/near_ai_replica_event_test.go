package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
)

// The November 12 gpu03 boot has not yet recorded a replica key. Append the
// two public replica-key events this instance recorded on November 6 so the
// post-boot rules stay exercised, and re-bind RTMR3 in both quotes.
func reviewedNearAICaseWithReplicaKeys(t *testing.T) *nearAITestCase {
	t.Helper()
	c := reviewedNearAIPoolCase(t, nearAIGPU03Compose)
	raw, err := os.ReadFile(filepath.Join("testdata", "near-ai-2026-11-06", "a0e3c6f4-events.json"))
	if err != nil {
		t.Fatal(err)
	}
	var earlier []nearAIRuntimeEvent
	if err := json.Unmarshal(raw, &earlier); err != nil {
		t.Fatal(err)
	}
	added := 0
	for _, event := range earlier {
		if event.IMR == 3 && event.Event == "nearai-replica-report-key-v1" {
			c.report.EventLog = append(c.report.EventLog, event)
			added++
		}
	}
	if added != 2 {
		t.Fatalf("want two replica-key events, got %d", added)
	}
	rtmr3, err := replayNearAIRuntimeEvents(c.report.EventLog, nearAIGPU03Compose, c.policy.OSImageHash)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []*tdxpb.TDQuoteBody{c.modelBody, c.managerBody} {
		body.Rtmrs[3] = append([]byte{}, rtmr3...)
	}
	c.encodeReport(t)
	if _, err := c.verifier.verify(context.Background(), c.request); err != nil {
		t.Fatalf("reviewed replica-key events rejected: %v", err)
	}
	return c
}

func TestNearAIReplicaEventRejectsUnreviewedChanges(t *testing.T) {
	tests := map[string]func(*nearAITestCase){
		"unknown post-boot event": func(c *nearAITestCase) { c.report.EventLog[len(c.report.EventLog)-1].Event = "unknown" },
		"post-boot identity": func(c *nearAITestCase) {
			for _, event := range c.report.EventLog {
				if event.IMR == 3 && event.Event == "compose-hash" {
					c.report.EventLog[len(c.report.EventLog)-1] = event
					return
				}
			}
			t.Fatal("fixture has no compose-hash event")
		},
		"dropped event": func(c *nearAITestCase) { c.report.EventLog = c.report.EventLog[:len(c.report.EventLog)-1] },
		"reordered keys": func(c *nearAITestCase) {
			n := len(c.report.EventLog)
			c.report.EventLog[n-1], c.report.EventLog[n-2] = c.report.EventLog[n-2], c.report.EventLog[n-1]
		},
		"replica key before ready": func(c *nearAITestCase) {
			n := len(c.report.EventLog)
			c.report.EventLog = append([]nearAIRuntimeEvent{c.report.EventLog[n-1]}, c.report.EventLog[:n-1]...)
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			c := reviewedNearAICaseWithReplicaKeys(t)
			change(c)
			c.encodeReport(t)
			if _, err := c.verifier.verify(context.Background(), c.request); err == nil {
				t.Fatal("accepted changed post-boot event sequence")
			}
		})
	}
}

func TestNearAIReplicaKeyPayloadValidation(t *testing.T) {
	c := reviewedNearAICaseWithReplicaKeys(t)
	payload, err := hex.DecodeString(c.report.EventLog[len(c.report.EventLog)-1].EventPayload)
	if err != nil {
		t.Fatal(err)
	}
	if !validNearAIReplicaKeyEvent(payload) {
		t.Fatal("reviewed public replica key event rejected")
	}
	tests := map[string]func(map[string]string){
		"missing host":       func(v map[string]string) { delete(v, "host_id") },
		"empty host":         func(v map[string]string) { v["host_id"] = "" },
		"long host":          func(v map[string]string) { v["host_id"] = strings.Repeat("h", 129) },
		"bad UUID":           func(v map[string]string) { v["boot_id"] = "not-a-uuid" },
		"wrong UUID version": func(v map[string]string) { v["boot_id"] = "00000000-0000-1000-8000-000000000000" },
		"wrong key ID":       func(v map[string]string) { v["key_id"] = strings.Repeat("f", 16) },
		"short key":          func(v map[string]string) { v["public_key_hex"] = "aabb" },
		"bad key":            func(v map[string]string) { v["public_key_hex"] = strings.Repeat("zz", 32) },
		"unknown field":      func(v map[string]string) { v["unknown"] = "value" },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			var fields map[string]string
			if err := json.Unmarshal(payload, &fields); err != nil {
				t.Fatal(err)
			}
			change(fields)
			raw, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if validNearAIReplicaKeyEvent(raw) {
				t.Fatal("accepted malformed replica-key payload")
			}
		})
	}
	for _, raw := range [][]byte{nil, []byte("null"), []byte("[]"), []byte("{"), []byte(strings.Repeat(" ", 1025))} {
		if validNearAIReplicaKeyEvent(raw) {
			t.Fatal("accepted invalid or oversized payload")
		}
	}
}
