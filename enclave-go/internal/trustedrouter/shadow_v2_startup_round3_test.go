package trustedrouter

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Adopted from the round-2 reviewer probe. The entry observation now completes
// after retention, just as it does at both production request entries.
func TestReviewRound2AdmissionTransition(t *testing.T) {
	for _, transition := range []struct {
		name          string
		before, after bool
	}{
		{"becomes-ready", false, true},
		{"stays-waiting", false, false},
		{"stays-ready", true, true},
		{"becomes-waiting", true, false},
	} {
		t.Run(transition.name, func(t *testing.T) {
			h, _, _, _ := startupFixture(t)
			c := &Client{asyncShadow: true}
			a := v2Authorization(t, shadowV2Variants(t, "authorize_compared")[0])
			enclaveOptedAdmission.Store(&startupAdmission{ready: transition.before, harness: h})
			before := time.Now().UnixMicro()
			start := c.recordStartupAdmissionStart(a, "chat.completions")
			entered := time.Now().UnixMicro()
			// The coordinator can finish between the adjacent request-entry calls.
			done := make(chan struct{})
			go func() {
				enclaveOptedAdmission.Store(&startupAdmission{ready: transition.after, harness: h})
				close(done)
			}()
			<-done
			c.retainShadowAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
			retained := a.shadowSettlement != nil
			if retained != transition.after {
				t.Fatal("fixture did not reach expected retention decision")
			}
			start.record(retained)
			if len(h.attempts) != 1 {
				t.Fatal("attempt missing")
			}
			want := "rejected"
			if retained {
				want = "accepted"
			}
			if h.attempts[0].result != want {
				t.Fatalf("retention=%v recorded as %s", retained, h.attempts[0].result)
			}
			if h.attempts[0].atUS < before || h.attempts[0].atUS > entered {
				t.Fatal("attempt lost entry timestamp")
			}
		})
	}
}

// Capture the complete output stream and all original buffers, without choosing
// record kinds or fields. The fixture has finished its startup work before read.
func startupEntryCapture(h *ShadowV2StartupHarness, w *startupTestWriter) []byte {
	var capture bytes.Buffer
	w.mu.Lock()
	capture.Write(w.Bytes())
	w.mu.Unlock()
	capture.Write(h.manifestOriginal)
	capture.Write(h.configOriginal)
	capture.Write(h.readyOriginal)
	for _, original := range h.originals {
		capture.Write(original.raw)
	}
	return capture.Bytes()
}

// Keep the capture itself checked so removing the entry-output read is detected.
func TestStartupEntryCaptureIncludesRecordsAndOriginals(t *testing.T) {
	h, d, m, w := startupFixture(t)
	runStartupFixture(h, d, m)
	const entryValue = "incoming-entry-capture-check"
	if _, ok := h.emitter.emit(startupReady{"a3_traffic_ready", entryValue, 1}); !ok {
		t.Fatal("entry capture fixture was not emitted")
	}
	capture := startupEntryCapture(h, w)
	for _, raw := range [][]byte{[]byte(entryValue), h.manifestOriginal, h.configOriginal, h.readyOriginal} {
		if len(raw) == 0 || !bytes.Contains(capture, raw) {
			t.Fatal("entry capture omitted records or originals")
		}
	}
	for _, original := range h.originals {
		if len(original.raw) == 0 || !bytes.Contains(capture, original.raw) {
			t.Fatal("entry capture omitted a retained original")
		}
	}
}

// Adopted from the reviewer's entry and header probes, extended to both states,
// both production entry methods, both v2 variants and all retained originals.
func TestReviewRound2EntryRecords(t *testing.T) {
	for _, ready := range []bool{false, true} {
		for _, route := range []string{"chat.completions", "responses"} {
			for _, method := range []string{"chat", "embeddings"} {
				for _, variant := range []string{"authorize_compared", "authorize_excluded"} {
					name := fmt.Sprintf("%v/%s/%s/%s", ready, route, method, variant)
					t.Run(name, func(t *testing.T) {
						h, d, m, w := startupFixture(t)
						if ready {
							runStartupFixture(h, d, m)
						} else {
							enclaveOptedAdmission.Store(&startupAdmission{harness: h})
						}
						if EnclaveOptedAdmission() != ready {
							t.Fatal("readiness state not exercised")
						}
						var incoming []string
						value := func(field string) string {
							v := fmt.Sprintf("entry-%x-%s", sha256.Sum256([]byte(name)), field)
							incoming = append(incoming, v)
							return v
						}
						raw := shadowV2Variants(t, variant)[0]["object"]
						var object map[string]json.RawMessage
						if err := json.Unmarshal(raw, &object); err != nil {
							t.Fatal(err)
						}
						for _, field := range []string{"authorization_id", "workspace_id", "generation_id", "credit_reservation_id", "model", "requested_model", "endpoint_id"} {
							object[field], _ = json.Marshal(value(field))
						}
						digest := fmt.Sprintf("%x", sha256.Sum256([]byte(name+"-digest")))
						incoming = append(incoming, digest)
						object["api_key_hash"], _ = json.Marshal(digest)
						raw, err := json.Marshal(object)
						if err != nil {
							t.Fatal(err)
						}
						c := New("https://trustedrouter.com", "fixture", &http.Client{Transport: startupRoundTrip(func(*http.Request) (*http.Response, error) {
							return v2Reply(`{"data":` + string(raw) + `}`), nil
						})})
						c.asyncShadow = true
						req := &qtypes.OpenAIChatRequest{
							Model: value("request-model"), IdempotencyKey: value("idempotency-header"),
							HTTPReferer: "https://" + value("referer-header") + ".invalid/", App: value("title-header"),
							User: value("user"), SessionID: value("session"),
							Metadata: map[string]any{value("metadata-key"): value("metadata-value")},
						}
						incoming = append(incoming, req.HTTPReferer)
						if method == "chat" {
							_, err = c.AuthorizeWithRoute(t.Context(), value("bearer-header"), req, route)
						} else {
							_, err = c.AuthorizeEmbeddingsWithRoute(t.Context(), value("bearer-header"), &qtypes.EmbeddingRequest{
								Model: req.Model, IdempotencyKey: req.IdempotencyKey, HTTPReferer: req.HTTPReferer,
								App: req.App, User: req.User, SessionID: req.SessionID, Metadata: req.Metadata,
							}, 1, route)
						}
						if err != nil {
							t.Fatal(err)
						}
						if len(h.attempts) != 1 {
							t.Fatal("actual request entry recorder not exercised")
						}
						// Also exercise successful retention with the unchanged fixture
						// fields and the same distinct request headers/model/metadata.
						original := v2Authorization(t, shadowV2Variants(t, variant)[0])
						// The variant overlays the common request fixture. Recreate
						// that complete reply without changing either fixture file.
						base, _ := json.Marshal(original)
						var complete, overlay map[string]json.RawMessage
						if json.Unmarshal(base, &complete) != nil || json.Unmarshal(shadowV2Variants(t, variant)[0]["object"], &overlay) != nil {
							t.Fatal("complete request fixture")
						}
						for key, v := range overlay {
							complete[key] = v
						}
						raw, err = json.Marshal(complete)
						if err != nil {
							t.Fatal(err)
						}
						incoming = append(incoming, original.AuthorizationID, original.WorkspaceID, original.GenerationID,
							original.APIKeyHash, original.InvocationNonce, original.CreditReservationID, string(original.BillingSnapshotHash))
						var retained *Authorization
						if method == "chat" {
							retained, err = c.AuthorizeWithRoute(t.Context(), value("retained-bearer-header"), req, route)
						} else {
							retained, err = c.AuthorizeEmbeddingsWithRoute(t.Context(), value("retained-bearer-header"), &qtypes.EmbeddingRequest{
								Model: req.Model, IdempotencyKey: req.IdempotencyKey, HTTPReferer: req.HTTPReferer,
								App: req.App, User: req.User, SessionID: req.SessionID, Metadata: req.Metadata,
							}, 1, route)
						}
						if err != nil {
							t.Fatal(err)
						}
						wantRetained := ready && route == "chat.completions"
						if (retained.shadowSettlement != nil) != wantRetained || len(h.attempts) != 2 {
							t.Fatal("unchanged fixture did not reach expected retention outcome")
						}
						if (h.attempts[1].result == "accepted") != wantRetained {
							t.Fatal("actual entry result differs from retention")
						}
						// Finish startup after the waiting request too, so every retained
						// original and every output line is inspected in either state.
						if !ready {
							runStartupFixture(h, d, m)
						}
						capture := startupEntryCapture(h, w)
						for _, v := range incoming {
							if v != "" && bytes.Contains(capture, []byte(v)) {
								t.Fatalf("entry copied incoming value into records or originals: %s", v)
							}
						}
					})
				}
			}
		}
	}
}
