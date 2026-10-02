package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestNearAIReplicaEventRejectsUnreviewedChanges(t *testing.T) {
	const compose = "55db164f4f8c6a837c2217c601c21bba4758f908536a6cd5b2978550205a9179"
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
			c := reviewedNearAIPoolCase(t, compose)
			change(c)
			c.encodeReport(t)
			if _, err := c.verifier.verify(context.Background(), c.request); err == nil {
				t.Fatal("accepted changed post-boot event sequence")
			}
		})
	}
}

func TestNearAIReplicaKeyPayloadValidation(t *testing.T) {
	c := reviewedNearAIPoolCase(t, "55db164f4f8c6a837c2217c601c21bba4758f908536a6cd5b2978550205a9179")
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
