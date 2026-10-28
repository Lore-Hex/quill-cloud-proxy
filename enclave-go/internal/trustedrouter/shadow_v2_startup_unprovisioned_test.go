package trustedrouter

import (
	"context"
	"encoding/json"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func unsetStartupEnv(t *testing.T, name string) {
	t.Helper()
	t.Setenv(name, "")
	if err := os.Unsetenv(name); err != nil {
		t.Fatal(err)
	}
}

// Only cloud input and stdout are substituted; installation, manifest loading,
// coordinator, request entry, retention and settle use production code.
func productionStartup(t *testing.T, manifest *string, shadow bool, configure func(*ShadowV2StartupHarness)) (*ShadowV2StartupHarness, *Client, *startupTestWriter) {
	t.Helper()
	t.Setenv("TR_ASYNC_SETTLE_SHADOW", startupPin(shadow))
	t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", "off")
	unsetStartupEnv(t, "TR_SHADOW_V2_LAUNCH_FD")
	if manifest == nil {
		unsetStartupEnv(t, "TR_SHADOW_V2_STARTUP_MANIFEST")
	} else {
		t.Setenv("TR_SHADOW_V2_STARTUP_MANIFEST", *manifest)
	}
	setShadowRevision(t)
	previous, inputs := enclaveOptedAdmission.Load(), configureStartupInputs
	enclaveOptedAdmission.Store(nil)
	t.Cleanup(func() { enclaveOptedAdmission.Store(previous); configureStartupInputs = inputs })
	writer := &startupTestWriter{}
	configureStartupInputs = func(h *ShadowV2StartupHarness) {
		h.emitter.close()
		h.emitter = newStartupEmitter(writer)
		// No inherited fd in GCP. Exercise the actual metadata-derived identity
		// builder with local cloud inputs, without inventing a launcher insert ID.
		h.acquire = func(context.Context) (startupLaunchAcquisition, error) {
			return startupInstanceLaunch("test-project", "us-central1-a", "123456789", "test-vm-boot", shadowRevision(), "us-central1")
		}
		if configure != nil {
			configure(h)
		}
	}
	c := New("https://trustedrouter.com", "test", &http.Client{})
	c.region = "us-central1"
	fd, present := CaptureShadowV2LaunchDescriptor()
	if fd != nil || present {
		t.Fatal("production launcher unexpectedly declared fd3")
	}
	h := StartShadowV2Startup(t.Context(), time.Now(), fd, present, nil, c, nil)
	t.Cleanup(func() { <-h.done; h.emitter.close() })
	return h, c, writer
}
func awaitProductionStartup(t *testing.T, h *ShadowV2StartupHarness) {
	t.Helper()
	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		t.Fatal("startup did not finish")
	}
}

func TestUnprovisionedProductionBoot(t *testing.T) {
	raw, err := os.ReadFile("testdata/async_settlement/shadow_binding_production.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name          string
			Claims        asyncTicketClaims
			Authorization json.RawMessage
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"unset", "empty"} {
		t.Run(mode, func(t *testing.T) {
			var manifest *string
			if mode == "empty" {
				empty := ""
				manifest = &empty
			}
			h, c, _ := productionStartup(t, manifest, true, nil)
			awaitProductionStartup(t, h)
			for _, tc := range fixture.Cases {
				t.Run(tc.Name, func(t *testing.T) {
					// The round-3 response projection omits ordinary usage_type. Restore that
					// real response field; the shared literal binding and snapshot are untouched.
					var response map[string]json.RawMessage
					if err := json.Unmarshal(tc.Authorization, &response); err != nil {
						t.Fatal(err)
					}
					response["usage_type"] = json.RawMessage(`"Credits"`)
					reply, err := json.Marshal(map[string]any{"data": response})
					if err != nil {
						t.Fatal(err)
					}
					var headers, bodies []string
					c.httpc.Transport = liveOracleTransport(func(r *http.Request) (*http.Response, error) {
						if r.URL.Path == "/internal/gateway/authorize" {
							return v2Reply(string(reply)), nil
						}
						if r.URL.Path != "/internal/gateway/settle" {
							t.Fatalf("unexpected path %s", r.URL.Path)
						}
						body, err := io.ReadAll(r.Body)
						if err != nil {
							t.Fatal(err)
						}
						headers = append(headers, r.Header.Get(shadowSettlementHeader))
						bodies = append(bodies, string(body))
						return v2Reply(`{"data":{"settled":true,"cost_microdollars":2}}`), nil
					})
					a, err := c.AuthorizeWithRoute(t.Context(), "test-key", &qtypes.OpenAIChatRequest{Model: "probe", Stream: tc.Claims.Streamed}, tc.Claims.RouteType)
					if err != nil {
						t.Fatal(err)
					}
					u := shadowUsage()
					u.RouteType, u.Streamed, u.SelectedEndpoint = tc.Claims.RouteType, tc.Claims.Streamed, a.EndpointID
					u.InputTokens, u.OutputTokens = 1, 1
					a.RecordShadowInvocation(u.SelectedEndpoint, a.Provider)
					if _, err := c.Settle(t.Context(), a, u); err != nil {
						t.Fatal(err)
					}
					if a.shadowSettlement == nil || len(headers) != 1 || headers[0] == "" {
						t.Fatalf("production boot: retained=%t envelope_present=%t admission=%t", a.shadowSettlement != nil, len(headers) == 1 && headers[0] != "", EnclaveOptedAdmission())
					}
					envelope := decodeShadow(t, headers[0])
					if string(envelope["variant"]) != `"compared"` || string(envelope["go_error"]) != "null" || string(envelope["terminal"]) == "null" {
						t.Fatalf("not compared: %s", headers[0])
					}
					if a.async != nil {
						t.Fatal("shadow enabled money async")
					}
					c.asyncShadow = false
					if _, err := c.Settle(t.Context(), a, u); err != nil {
						t.Fatal(err)
					}
					c.asyncShadow = true
					if headers[1] != "" || bodies[0] != bodies[1] {
						t.Fatal("ordinary settle body changed")
					}
				})
			}
		})
	}
}
func TestUnprovisionedStartupRecord(t *testing.T) {
	h, _, w := productionStartup(t, nil, true, nil)
	awaitProductionStartup(t, h)
	rows := w.records(t)
	if len(rows) != 1 || rows[0]["kind"] != "a3_startup_unprovisioned" || rows[0]["boot"] != h.boot || len(rows[0]) != 3 || rows[0]["at_us"] != float64(h.start.UnixMicro()) {
		t.Fatalf("missing content-free unprovisioned record: %v", rows)
	}
	if _, err := startupRecordBytes(rows[0]); err == nil {
		t.Fatal("diagnostic entered the frozen certification schema")
	}
	if state := enclaveOptedAdmission.Load(); state == nil || state.ready {
		t.Fatal("unprovisioned admission claimed ready")
	}
	if h.readyOriginal != nil || h.acknowledgement != "" || len(h.completions) != 0 {
		t.Fatal("unprovisioned boot certified readiness")
	}
	t.Setenv("TR_SHADOW_V2_STARTUP_MANIFEST", "configured-later")
	if !EnclaveOptedAdmission() {
		t.Fatal("install decision changed after provisioning")
	}
	if len(w.records(t)) != 1 {
		t.Fatal("diagnostic repeated")
	}
}
func TestConfiguredStartupRemainsStrict(t *testing.T) {
	for _, mode := range []string{"whitespace", "missing", "unreadable", "invalid-json", "invalid-schema", "valid-pending", "no-descriptor", "unset-after-install"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.json")
			var configure func(*ShadowV2StartupHarness)
			var release chan struct{}
			switch mode {
			case "whitespace":
				path = " \t\n"
			case "unreadable":
				if err := os.WriteFile(path, []byte(`{}`), 0000); err != nil {
					t.Fatal(err)
				}
			case "invalid-json":
				if err := os.WriteFile(path, []byte(`{`), 0600); err != nil {
					t.Fatal(err)
				}
			case "invalid-schema":
				if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "valid-pending":
				_, _, m, _ := startupFixture(t)
				m.Revision = shadowFixtureRevision
				m.PublicDescriptors.SourceRevision = shadowFixtureRevision
				if !m.valid(startupLaunchDescriptor{"instance", "launch", "enclave", shadowFixtureRevision, "us-central1"}) {
					t.Fatal("pending manifest must be valid")
				}
				release = make(chan struct{})
				configure = func(h *ShadowV2StartupHarness) {
					load := h.load
					h.load = func() (startupManifest, []byte, error) { <-release; return load() }
				}
				raw, _ := canonicalShadow(m)
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "no-descriptor":
				configure = func(h *ShadowV2StartupHarness) {
					h.acquire = func(context.Context) (startupLaunchAcquisition, error) {
						return startupLaunchAcquisition{}, errStartupRecord
					}
				}
			}
			h, _, w := productionStartup(t, &path, true, configure)
			if mode == "unset-after-install" {
				unsetStartupEnv(t, "TR_SHADOW_V2_STARTUP_MANIFEST")
			}
			if EnclaveOptedAdmission() {
				t.Fatal("configured boot admitted before ready")
			}
			if release != nil {
				close(release)
			}
			awaitProductionStartup(t, h)
			if EnclaveOptedAdmission() {
				t.Fatal("configured boot admitted without prerequisites")
			}
			if recordKinds(w.records(t), "a3_startup_unprovisioned") != 0 || h.readyOriginal != nil || h.acknowledgement != "" {
				t.Fatal("configured boot bypassed strict readiness")
			}
		})
	}
}
func TestUnprovisionedShadowOff(t *testing.T) {
	h, c, w := productionStartup(t, nil, false, nil)
	awaitProductionStartup(t, h)
	if enclaveOptedAdmission.Load() != nil || len(w.records(t)) != 0 {
		t.Fatal("shadow-off boot stored admission or emitted startup records")
	}
	for _, tc := range []struct {
		shadow bool
		route  string
		policy []byte
	}{{false, "chat.completions", []byte(`"shadow-v2"`)}, {true, "embeddings", []byte(`"shadow-v2"`)}, {true, "chat.completions", nil}} {
		c.asyncShadow = tc.shadow
		a := &Authorization{BillingShadowPolicy: tc.policy}
		if n := testing.AllocsPerRun(100, func() { start := c.recordStartupAdmissionStart(a, tc.route); start.record(false) }); n != 0 {
			t.Fatalf("off-path allocations: %v", n)
		}
	}
}
func TestUnprovisionedAttemptRecorderBounded(t *testing.T) {
	h, c, _ := productionStartup(t, nil, true, nil)
	awaitProductionStartup(t, h)
	a := &Authorization{BillingShadowPolicy: json.RawMessage(`"shadow-v2"`)}
	for i := 0; i < 10000; i++ {
		start := c.recordStartupAdmissionStart(a, "chat.completions")
		start.record(true)
	}
	if len(h.attempts) != 256 || cap(h.attempts) != 256 || h.attemptOverflow.Load() != 9744 {
		t.Fatalf("recorder grew or lost overflow: %d/%d/%d", len(h.attempts), cap(h.attempts), h.attemptOverflow.Load())
	}
	for _, a := range h.attempts {
		if a.result != "accepted" {
			t.Fatal("retention result changed")
		}
	}
	h.attemptMu.Lock()
	start := c.recordStartupAdmissionStart(a, "responses")
	start.record(true)
	h.attemptMu.Unlock()
	if h.attemptOverflow.Load() != 9745 {
		t.Fatal("contention not counted")
	}
}
