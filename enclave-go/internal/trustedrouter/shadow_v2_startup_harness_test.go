package trustedrouter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type startupTestWriter struct {
	mu sync.Mutex
	bytes.Buffer
}

func (w *startupTestWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.Buffer.Write(p)
}
func (w *startupTestWriter) records(t *testing.T) []map[string]any {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(w.Bytes()), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var r map[string]any
		if json.Unmarshal(line, &r) != nil {
			t.Fatal("invalid line")
		}
		out = append(out, r)
	}
	return out
}
func startupFixture(t *testing.T) (*ShadowV2StartupHarness, startupLaunchDescriptor, startupManifest, *startupTestWriter) {
	t.Helper()
	old := ShadowBuildRevision
	ShadowBuildRevision = strings.Repeat("a", 40)
	t.Cleanup(func() { ShadowBuildRevision = old; enclaveOptedAdmission.Store(nil) })
	writer := &startupTestWriter{}
	h := newStartupHarness(time.Unix(1700000000, 0), newStartupEmitter(writer))
	t.Cleanup(h.emitter.close)
	var tick atomicTestClock
	tick.at = h.start.Add(time.Second)
	h.now = tick.now
	h.pins = map[string]string{"TR_ASYNC_SETTLE_NEGOTIATE": "off", "TR_ASYNC_SETTLE_SHADOW": "on"}
	d := startupLaunchDescriptor{"instance:one", "launch:one", "enclave", ShadowBuildRevision, "us-central1"}
	cfg := startupConfig{[]startupTarget{{"transport", "router.example", "us-central1", 10000000}, {"read", "router.example", "us-central1", 10000000}}, startupReleasedPath{"router.example", "us-central1"}, []string{"descriptor-one"}, strings.Repeat("b", 64), map[string]string{"TR_ASYNC_SETTLE_NEGOTIATE": "off", "TR_ASYNC_SETTLE_SHADOW": "on"}}
	raw, _ := canonicalShadow(cfg)
	sum := sha256.Sum256(raw)
	m := startupManifest{d.Revision, d.Region, hex.EncodeToString(sum[:]), strings.Repeat("c", 64), strings.Repeat("d", 64), cfg, startupPublicDescriptors{1, hex.EncodeToString(sum[:]), d.Revision, cfg.DescriptorIDs}, map[string]map[string]startupArtifact{}}
	for _, criterion := range startupCriteria {
		m.Artifacts[criterion] = map[string]startupArtifact{}
		for _, source := range strings.Fields(startupSources[criterion]) {
			checks := map[string]string{}
			for _, name := range strings.Fields(startupChecks[criterion]) {
				checks[name] = "pass"
			}
			m.Artifacts[criterion][source] = startupArtifact{criterion + "-" + source, criterion, source, d.Revision, d.Region, m.ConfigSHA256, h.start.Add(-time.Hour).UnixMicro(), h.start.Add(-time.Minute).UnixMicro(), checks}
		}
	}
	h.probe = func(context.Context, startupTarget) startupProbeResult {
		return startupProbeResult{true, true, true, "router-boot"}
	}
	h.image = func(context.Context) ([]byte, error) {
		return canonicalShadow(startupImage{d.Revision, cfg.EnclaveImageSHA256})
	}
	h.retainReady = func(_ context.Context, raw []byte) (string, error) {
		h.readyOriginal = bytes.Clone(raw)
		return "generation:1", nil
	}
	return h, d, m, writer
}

type atomicTestClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *atomicTestClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(time.Millisecond)
	return c.at
}
func runStartupFixture(h *ShadowV2StartupHarness, d startupLaunchDescriptor, m startupManifest) {
	h.run(context.Background(), d, func() (startupManifest, []byte, error) { raw, _ := canonicalShadow(m); return m, raw, nil })
}
func recordKinds(rows []map[string]any, kind string) int {
	n := 0
	for _, r := range rows {
		if r["kind"] == kind {
			n++
		}
	}
	return n
}

func TestStartupReadyOrdering(t *testing.T) {
	h, d, m, w := startupFixture(t)
	runStartupFixture(h, d, m)
	rows := w.records(t)
	if len(rows) != 8 || rows[0]["kind"] != "a3_startup_correlation" || rows[7]["kind"] != "a3_traffic_ready" {
		t.Fatalf("order: %v", rows)
	}
	at := rows[7]["at_us"].(float64)
	for _, r := range rows[1:7] {
		if r["completed_at_us"].(float64) >= at {
			t.Fatal("ready preceded completion")
		}
	}
	if !EnclaveOptedAdmission() {
		t.Fatal("ready was not admitted")
	}
	for _, criterion := range startupCriteria {
		t.Run(criterion, func(t *testing.T) {
			h, d, m, w := startupFixture(t)
			if criterion == "observer_freshness" {
				h.probe = func(context.Context, startupTarget) startupProbeResult {
					return startupProbeResult{true, true, false, "router-boot"}
				}
			} else {
				delete(m.Artifacts, criterion)
			}
			runStartupFixture(h, d, m)
			if recordKinds(w.records(t), "a3_traffic_ready") != 0 {
				t.Fatal("ready before six completions")
			}
		})
	}
}
func TestStartupFailedAdoption(t *testing.T) {
	for _, criterion := range startupCriteria {
		if startupSources[criterion] == "" {
			continue
		}
		t.Run(criterion, func(t *testing.T) {
			h, d, m, w := startupFixture(t)
			source := strings.Fields(startupSources[criterion])[0]
			a := m.Artifacts[criterion][source]
			a.Checks[strings.Fields(startupChecks[criterion])[0]] = "fail"
			runStartupFixture(h, d, m)
			rows := w.records(t)
			if recordKinds(rows, "a3_traffic_ready") != 0 {
				t.Fatal("failed adopted as passed")
			}
			found := false
			for _, r := range rows {
				if r["criterion"] == criterion {
					found = true
					if r["checks"].(map[string]any)[strings.Fields(startupChecks[criterion])[0]] != "fail" {
						t.Fatal("failure rewritten")
					}
				}
			}
			if !found {
				t.Fatal("failed adoption missing")
			}
		})
	}
}
func TestStartupAcknowledgement(t *testing.T) {
	for _, mode := range []string{"missing", "error", "empty", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			h, d, m, w := startupFixture(t)
			enclaveOptedAdmission.Store(&startupAdmission{harness: h})
			switch mode {
			case "missing":
				h.retainReady = nil
			case "error":
				h.retainReady = func(context.Context, []byte) (string, error) { return "", errors.New("write") }
			case "empty":
				h.retainReady = func(context.Context, []byte) (string, error) { return "", nil }
			case "canceled":
				h.retainReady = func(ctx context.Context, _ []byte) (string, error) { <-ctx.Done(); return "generation:1", nil }
			}
			runStartupFixture(h, d, m)
			if EnclaveOptedAdmission() {
				t.Fatal("admission without acknowledgement")
			}
			if recordKinds(w.records(t), "a3_traffic_ready") != 1 {
				t.Fatal("ready must be written once")
			}
		})
	}
}
func TestStartupOneAdoption(t *testing.T) {
	h, d, m, w := startupFixture(t)
	a := m.Artifacts["transport"]["ci"]
	a.Checks["actual_hops"] = "fail"
	runStartupFixture(h, d, m)
	a.Checks["actual_hops"] = "pass"
	runStartupFixture(h, d, m)
	if recordKinds(w.records(t), "a3_boot_check") != 6 || recordKinds(w.records(t), "a3_traffic_ready") != 0 {
		t.Fatal("adoption retried")
	}
}
func TestStartupDormantPins(t *testing.T) {
	h, d, m, w := startupFixture(t)
	h.pins["TR_ASYNC_SETTLE_SHADOW"] = "off"
	m.Config.EffectivePins["TR_ASYNC_SETTLE_SHADOW"] = "off"
	startupRehash(&m)
	runStartupFixture(h, d, m)
	found := false
	for _, r := range w.records(t) {
		if r["criterion"] == "marker_keys" {
			found = true
			if r["effective_pins"].(map[string]any)["TR_ASYNC_SETTLE_SHADOW"] != "off" {
				t.Fatal("dormant pin changed")
			}
		}
	}
	if !found {
		t.Fatal("missing dormant marker")
	}
	if enclaveOptedAdmission.Load() != nil {
		t.Fatal("off installed admission gate")
	}
}
func startupRehash(m *startupManifest) {
	raw, _ := canonicalShadow(m.Config)
	sum := sha256.Sum256(raw)
	m.ConfigSHA256 = hex.EncodeToString(sum[:])
	m.PublicDescriptors.ConfigSHA256 = m.ConfigSHA256
	for _, sources := range m.Artifacts {
		for k, a := range sources {
			a.ConfigSHA256 = m.ConfigSHA256
			sources[k] = a
		}
	}
}
func TestStartupAdmission(t *testing.T) {
	h, _, _, _ := startupFixture(t)
	for _, on := range []bool{false, true} {
		for _, ready := range []bool{false, true} {
			enclaveOptedAdmission.Store(&startupAdmission{ready, h})
			c := &Client{asyncShadow: on}
			a := v2Authorization(t, shadowV2Variants(t, "authorize_compared")[0])
			c.retainShadowAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
			if (a.shadowSettlement != nil) != (on && ready) {
				t.Fatalf("on=%v ready=%v retained=%v", on, ready, a.shadowSettlement != nil)
			}
		}
	}
	if len(h.attempts) != 2 || h.attempts[0].result != "rejected" || h.attempts[1].result != "accepted" || h.attempts[0].atUS >= h.attempts[1].atUS {
		t.Fatal("attempt start observations")
	}
	a := &Authorization{}
	if v2, stop := retainShadowV2(a, &qtypes.OpenAIChatRequest{}, "chat.completions"); v2 || stop {
		t.Fatal("non-cohort changed")
	}
}
func TestStartupDoesNotDelay(t *testing.T) {
	h, _, _, _ := startupFixture(t)
	release := make(chan struct{})
	finished := make(chan struct{})
	defer close(release)
	go func() { h.launch(func() { <-release }); close(finished) }()
	select {
	case <-finished:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("harness blocked startup")
	}
}
func TestStartupRace(t *testing.T) {
	h, d, m, _ := startupFixture(t)
	enclaveOptedAdmission.Store(&startupAdmission{harness: h})
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				EnclaveOptedAdmission()
				h.RecordShutdownWait(h.start.Add(time.Second), h.start.Add(2*time.Second))
			}
		}()
	}
	runStartupFixture(h, d, m)
	wg.Wait()
	if len(h.attempts) != 256 || h.attemptOverflow != 344 {
		t.Fatal("bounded attempts lost counts")
	}
}
func TestStartupMissingManifest(t *testing.T) {
	h, d, _, w := startupFixture(t)
	h.run(context.Background(), d, func() (startupManifest, []byte, error) { return startupManifest{}, nil, os.ErrNotExist })
	if len(w.records(t)) != 1 {
		t.Fatal("missing input became check")
	}
}
func TestStartupManifestTimes(t *testing.T) {
	for _, mode := range []string{"future", "reversed", "too-long", "wrong-region", "wrong-config"} {
		t.Run(mode, func(t *testing.T) {
			h, d, m, w := startupFixture(t)
			a := m.Artifacts["transport"]["regional_trial"]
			switch mode {
			case "future":
				a.CompletedAtUS = h.start.Add(time.Hour).UnixMicro()
			case "reversed":
				a.StartedAtUS = a.CompletedAtUS
			case "too-long":
				a.StartedAtUS = a.CompletedAtUS - 3600000001
			case "wrong-region":
				a.Region = "other"
			case "wrong-config":
				a.ConfigSHA256 = strings.Repeat("e", 64)
			}
			m.Artifacts["transport"]["regional_trial"] = a
			runStartupFixture(h, d, m)
			if recordKinds(w.records(t), "a3_boot_check") != 5 || recordKinds(w.records(t), "a3_traffic_ready") != 0 {
				t.Fatal("bad original adopted")
			}
		})
	}
}
func TestStartupMissingLocalFields(t *testing.T) {
	for _, mode := range []string{"marker", "router_boot", "echo", "image", "late"} {
		t.Run(mode, func(t *testing.T) {
			h, d, m, w := startupFixture(t)
			h.probe = func(ctx context.Context, _ startupTarget) startupProbeResult {
				r := startupProbeResult{true, true, true, "router-boot"}
				switch mode {
				case "marker":
					r.markerMatches = false
				case "router_boot":
					r.routerBoot = ""
				case "echo":
					r.echoReady = false
				case "late":
					return startupProbeResult{}
				}
				return r
			}
			if mode == "image" {
				h.image = nil
			}
			runStartupFixture(h, d, m)
			if recordKinds(w.records(t), "a3_traffic_ready") != 0 {
				t.Fatal("missing local fields adopted")
			}
		})
	}
}
func TestStartupPartialShutdown(t *testing.T) {
	h, _, _, w := startupFixture(t)
	h.RecordShutdownWait(h.start.Add(time.Second), h.start.Add(2*time.Second))
	if h.shutdown["export_wait"] != [2]int64{1000000, 2000000} || len(w.records(t)) != 0 {
		t.Fatal("invented shutdown span")
	}
}

type startupRoundTrip func(*http.Request) (*http.Response, error)

func (f startupRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestStartupConfiguredRouter(t *testing.T) {
	calls := 0
	c := &Client{baseURLs: []string{"https://router.example"}, httpc: &http.Client{Transport: startupRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://router.example/ready" || len(r.Header) != 0 {
			t.Fatal("unexpected target or headers")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"status":"ready","router_boot":"incoming-body"}`))}, nil
	})}}
	r := startupReadRouter(context.Background(), c, startupTarget{"read", "router.example", "us-central1", 1000000})
	if !r.ready || r.routerBoot != "" || r.markerMatches || r.echoReady || calls != 1 {
		t.Fatal("invented router fields")
	}
	startupReadRouter(context.Background(), c, startupTarget{"read", "unrelated", "us-central1", 1000000})
	if calls != 1 {
		t.Fatal("used unrelated target")
	}
}
func TestStartupManifestRoundTrip(t *testing.T) {
	_, _, m, _ := startupFixture(t)
	raw, _ := canonicalShadow(m)
	path := t.TempDir() + "/manifest.json"
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var got startupManifest
	retained, err := readStartupJSON(path, 262144, &got)
	if err != nil || !bytes.Equal(retained, raw) || !reflect.DeepEqual(m, got) {
		t.Fatal("manifest changed")
	}
}

func TestStartupCachedImage(t *testing.T) {
	revision := strings.Repeat("a", 40)
	digest := strings.Repeat("b", 64)
	for _, payload := range []string{`{"image_digest":"sha256:` + digest + `"}`, `{"submods":{"container":{"image_digest":"sha256:` + digest + `"}}}`} {
		document := []byte("header." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".tail")
		raw, err := startupCachedImageRecord("gcp-cs-jwt", document, revision)
		if err != nil {
			t.Fatal("cached image missing")
		}
		var got startupImage
		if json.Unmarshal(raw, &got) != nil || got.Revision != revision || got.ImageSHA256 != digest {
			t.Fatal("image join")
		}
		if bytes.Contains(raw, document) {
			t.Fatal("source document copied")
		}
	}
	for _, payload := range []string{`{}`, `{"image_digest":"Bearer incoming.value"}`, `{"image_digest":"sha256:` + digest + `","submods":{"container":{"image_digest":"sha256:` + strings.Repeat("c", 64) + `"}}}`} {
		document := []byte("header." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".tail")
		if _, err := startupCachedImageRecord("gcp-cs-jwt", document, revision); err == nil {
			t.Fatal("unavailable image accepted")
		}
	}
	if _, err := startupCachedImageRecord("other", nil, revision); err == nil {
		t.Fatal("unmapped image source")
	}
}

func TestStartupBoundedPorts(t *testing.T) {
	for _, port := range []string{"manifest", "probe", "image", "ack"} {
		t.Run(port, func(t *testing.T) {
			h, d, m, _ := startupFixture(t)
			release := make(chan struct{})
			defer close(release)
			load := func() (startupManifest, []byte, error) { raw, _ := canonicalShadow(m); return m, raw, nil }
			switch port {
			case "manifest":
				load = func() (startupManifest, []byte, error) { <-release; return m, nil, nil }
			case "probe":
				h.probe = func(context.Context, startupTarget) startupProbeResult { <-release; return startupProbeResult{} }
			case "image":
				h.image = func(context.Context) ([]byte, error) { <-release; return nil, nil }
			case "ack":
				h.retainReady = func(context.Context, []byte) (string, error) { <-release; return "late", nil }
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			done := make(chan struct{})
			go func() { h.run(ctx, d, load); close(done) }()
			select {
			case <-done:
			case <-time.After(300 * time.Millisecond):
				t.Fatal("port exceeded coordinator deadline")
			}
			if state := enclaveOptedAdmission.Load(); state != nil && state.ready {
				t.Fatal("late port admitted")
			}
		})
	}
}
