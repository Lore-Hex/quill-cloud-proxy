package shadowcoord

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

func TestReviewWireAdditionalBounds(t *testing.T) {
	f := fixture(t)
	id := f.Items[0]
	other := id
	other.KeyID = "other"
	entry := map[string]any{"key_id": id.KeyID, "workspace_id": id.WorkspaceID, "lookup_digest": id.LookupDigest, "miss": "missing"}
	duplicate, _ := json.Marshal(map[string]any{"authority": "shadow-only", "items": []any{entry, entry}})
	if _, m := DecodeBatch(200, duplicate, []Identity{id, other}); m == nil {
		t.Fatal("duplicate identity accepted")
	}
	for _, status := range []int{404, 405} {
		if _, m := DecodeBatch(status, []byte(`{"detail":"Not Found"}`), f.Items); m == nil || m.Status != status || m.Code != "malformed-response" {
			t.Fatal(status, m)
		}
	}
	huge := []byte(`{"miss":"future-code","pad":"` + strings.Repeat("a", MaxResponseBytes) + `"}`)
	if _, m := DecodeBatch(503, huge, f.Items); m == nil || m.Code != "malformed-response" {
		t.Fatal("oversized valid JSON accepted", m)
	}
	for _, code := range []string{strings.Repeat("x", 129), "newline\ninjection", "contains space", "contains\"quote", "é"} {
		b, _ := json.Marshal(map[string]string{"miss": code})
		if _, m := DecodeBatch(503, b, f.Items); m == nil || m.Code != "malformed-response" {
			t.Fatal(m)
		}
	}
}
func TestReviewTwoConcurrentRequestsOneOrdinal(t *testing.T) {
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	start := make(chan struct{})
	out := make(chan Decision, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; out <- c.Predecision(f.Items[0].LookupDigest, req).Decision() }()
	}
	close(start)
	wg.Wait()
	close(out)
	eligible := 0
	for d := range out {
		if d.Eligible {
			eligible++
		}
	}
	if eligible != 1 {
		t.Fatal("concurrent winners", eligible)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.Run(ctx, nil)
}
