package main

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestReceiptHashWriterDomainsAndFragmentation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		domain     string
		wire       string
		preimage   string
		eventCount int
	}{
		{"chat", "sse-data-v1", "data: one\n\ndata: two\n\ndata: [DONE]\n\n", "one\ntwo\n", 2},
		{"responses", "sse-events-v1", "event: response.created\ndata: one\n\ndata: two\n\ndata: [DONE]\n\n", "response.created\none\n\ntwo\n", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			writer := newReceiptHashWriter(&out, tc.domain)
			for _, fragment := range []string{tc.wire[:3], tc.wire[3:11], tc.wire[11:]} {
				if _, err := writer.Write([]byte(fragment)); err != nil {
					t.Fatal(err)
				}
			}
			digest, count := writer.Seal()
			want := sha256.Sum256([]byte(tc.preimage))
			if !writer.Valid() || digest != want || count != tc.eventCount || out.String() != tc.wire {
				t.Fatalf("valid=%v digest=%x want=%x count=%d output=%q", writer.Valid(), digest, want, count, out.String())
			}
		})
	}
}

func TestReceiptHashWriterRejectsMultilineDataDomain(t *testing.T) {
	var out bytes.Buffer
	w := newReceiptHashWriter(&out, "sse-data-v1")
	if _, err := w.Write([]byte("data: first\ndata: second\n\n")); err != nil {
		t.Fatal(err)
	}
	_, _ = w.Seal()
	if w.Valid() {
		t.Fatal("multiline data event remained receipt-valid")
	}
}
