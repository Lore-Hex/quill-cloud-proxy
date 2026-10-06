package shadowcoord

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/speculation"
	"testing"
)

func TestReviewEnclaveUnresolvedCapacity(t *testing.T) {
	base, clock, req, _, f := setup(t)
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	keys := f.Keys
	keys[0].PublicKeyB64URL = base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	cfg := Config{Keys: keys}
	var results []Result
	clone := func(v any) map[string]any { b, _ := json.Marshal(v); return ParseRequest(b) }
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": keys[0].Kid, "typ": speculation.ShadowTyp})
	for i := 0; i < 33; i++ {
		id := Identity{WorkspaceID: fmt.Sprint("w", i), KeyID: fmt.Sprint("k", i), LookupDigest: fmt.Sprintf("%064x", i+1)}
		e := base.config.Evidence[0]
		e.Identity = id
		e.Local.Bindings = clone(e.Local.Bindings)
		e.Health.WorkspaceID = id.WorkspaceID
		e.Health.KeyID = id.KeyID
		claims := clone(f.Claims)
		for k, v := range map[string]string{"workspace_id": id.WorkspaceID, "key_id": id.KeyID, "lookup_digest": id.LookupDigest} {
			claims[k] = v
			e.Local.Bindings[k] = v
		}
		claims["grant_id"] = fmt.Sprint("grant", i)
		payload, _ := json.Marshal(claims)
		msg := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
		grant := msg + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(msg)))
		cfg.Evidence = append(cfg.Evidence, e)
		results = append(results, Result{Identity: id, Grant: grant})
	}
	c := New(Shadow, cfg, clock)
	for _, e := range cfg.Evidence {
		c.ObserveAuthorized(e.Identity)
	}
	c.RefreshOnce(t.Context(), func(context.Context, []Identity) ([]Result, *Miss) { return results, nil })
	eligible := 0
	for _, e := range cfg.Evidence {
		d := c.Predecision(e.Identity.LookupDigest, req).Decision()
		if d.Eligible {
			eligible++
		} else {
			t.Log(d)
		}
	}
	if eligible != 32 {
		t.Fatalf("admitted %d unresolved workspaces, simulated slot retained=%d micro; required enclave concurrency ceiling=32", eligible, c.slotRetained)
	}
}
