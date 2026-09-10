package main

import (
	"testing"
)

// An identical re-mint must not spend a history slot: after A then B, re-minting B
// eight times leaves A as the only previous document.
func TestIdenticalRemintsDoNotEvictHistory(t *testing.T) {
	receiptAttestationCache.Store(nil)
	orig := getAttestation
	defer func() { getAttestation = orig }()
	docs := [][]byte{[]byte("DOC-A")}
	getAttestation = func(_, _, _, _, _ []byte) ([]byte, error) { return docs[len(docs)-1], nil }
	if err := remintReceiptAttestationBound(nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	docs = append(docs, []byte("DOC-B"))
	for i := 0; i < 9; i++ {
		if err := remintReceiptAttestationBound(nil, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	cached := receiptAttestationCache.Load()
	if string(cached.document) != "DOC-B" {
		t.Fatalf("current = %q, want DOC-B", cached.document)
	}
	if len(cached.previous) != 1 || string(cached.previous[0].document) != "DOC-A" {
		t.Fatalf("previous = %d entries (%q), want exactly DOC-A", len(cached.previous), cached.previous)
	}
	if want := receiptAttestationDigest([]byte("DOC-A")); cached.previous[0].sha256 != want {
		t.Fatalf("history hash %q, want %q", cached.previous[0].sha256, want)
	}
}
