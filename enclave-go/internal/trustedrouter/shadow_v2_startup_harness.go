package trustedrouter

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

var startupCriteria = []string{"transport", "size", "regional_load", "boot_transport", "observer_freshness", "marker_keys"}

type startupTarget struct {
	Operation  string `json:"operation"`
	Resource   string `json:"resource"`
	Region     string `json:"region"`
	DeadlineUS int64  `json:"-"`
}
type startupReleasedPath struct {
	Resource string `json:"resource"`
	Region   string `json:"region"`
}
type startupDependencies struct {
	Router  []startupTarget `json:"router"`
	Enclave []startupTarget `json:"enclave"`
}

type startupConfig struct {
	Dependencies       startupDependencies `json:"dependencies"`
	RouterPath         startupReleasedPath `json:"router_path"`
	DescriptorIDs      []string            `json:"descriptor_ids"`
	EnclaveImageSHA256 string              `json:"enclave_image_sha256"`
	EffectivePins      map[string]string   `json:"effective_pins"`
}
type startupArtifact struct {
	ID            string            `json:"id"`
	Criterion     string            `json:"criterion"`
	Source        string            `json:"source"`
	Revision      string            `json:"revision"`
	Region        string            `json:"region"`
	ConfigSHA256  string            `json:"config_sha256"`
	StartedAtUS   int64             `json:"started_at_us"`
	CompletedAtUS int64             `json:"completed_at_us"`
	Checks        map[string]string `json:"checks"`
}
type startupPublicDescriptors struct {
	AuthorityEpoch int64    `json:"authority_epoch"`
	ConfigSHA256   string   `json:"config_sha256"`
	SourceRevision string   `json:"source_revision"`
	DescriptorIDs  []string `json:"descriptor_ids"`
}
type startupImage struct {
	Revision    string `json:"revision"`
	ImageSHA256 string `json:"image_sha256"`
}
type startupManifest struct {
	Revision          string                                `json:"revision"`
	Region            string                                `json:"region"`
	ConfigSHA256      string                                `json:"config_sha256"`
	PolicySHA256      string                                `json:"policy_sha256"`
	FixtureSHA256     string                                `json:"fixture_sha256"`
	Config            startupConfig                         `json:"-"`
	ConfigOriginal    string                                `json:"config_original"`
	PublicDescriptors startupPublicDescriptors              `json:"public_descriptors"`
	Artifacts         map[string]map[string]startupArtifact `json:"artifacts"`
}

func (m *startupManifest) valid(d startupLaunchDescriptor) bool {
	raw := []byte(m.ConfigOriginal)
	if len(raw) == 0 || len(raw) > 262144 || json.Unmarshal(raw, &m.Config) != nil {
		return false
	}
	var dependencies struct {
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	if json.Unmarshal(raw, &dependencies) != nil || dependencies.Dependencies["router"] == nil || dependencies.Dependencies["enclave"] == nil || m.Config.Dependencies.Router == nil {
		return false
	}
	sum := sha256.Sum256(raw)
	if m.Revision != d.Revision || m.Region != d.Region || m.ConfigSHA256 != hex.EncodeToString(sum[:]) || !startupDigest.MatchString(m.PolicySHA256) || !startupDigest.MatchString(m.FixtureSHA256) || !startupDigest.MatchString(m.Config.EnclaveImageSHA256) {
		return false
	}
	if !startupID.MatchString(m.Config.RouterPath.Resource) || !startupID.MatchString(m.Config.RouterPath.Region) || len(m.Config.Dependencies.Enclave) < 2 || len(m.Config.Dependencies.Enclave) > 16 || len(m.Config.DescriptorIDs) == 0 || len(m.Config.DescriptorIDs) > 16 {
		return false
	}
	descriptorIDs := map[string]bool{}
	for _, id := range m.Config.DescriptorIDs {
		if !startupID.MatchString(id) || descriptorIDs[id] {
			return false
		}
		descriptorIDs[id] = true
	}
	ops := map[string]bool{}
	seen := map[string]bool{}
	for _, d := range m.Config.Dependencies.Enclave {
		key := d.Operation + "/" + d.Resource
		if seen[key] || d.Resource != m.Config.RouterPath.Resource || d.Region != m.Config.RouterPath.Region || (d.Operation != "transport" && d.Operation != "read") {
			return false
		}
		seen[key] = true
		ops[d.Operation] = true
	}
	return ops["transport"] && ops["read"] && startupNames(m.Config.EffectivePins, "TR_ASYNC_SETTLE_NEGOTIATE TR_ASYNC_SETTLE_SHADOW", func(v string) bool { return v == "on" || v == "off" })
}

type startupProbeResult struct {
	ready, markerMatches, echoReady bool
	routerBoot                      string
}
type startupLocalAttempt struct {
	atUS   int64
	result string
}
type startupAdmission struct {
	ready   bool
	harness *ShadowV2StartupHarness
}

var enclaveOptedAdmission atomic.Pointer[startupAdmission]

// ShadowV2StartupHarness owns only boot records and the opted retention flag.
// No request object is passed to its builders or retained observations.
type ShadowV2StartupHarness struct {
	mu                   sync.Mutex
	start                time.Time
	boot                 string
	descriptor           startupLaunchDescriptor
	acquisition          startupLaunchAcquisition
	emitter              *startupEmitter
	originals            []startupOriginal
	manifestOriginal     []byte
	completions          map[string]int64
	attempts             []startupLocalAttempt
	attemptMu            sync.Mutex
	configOriginal       []byte
	load                 func() (startupManifest, []byte, error)
	acquire              func(context.Context) (startupLaunchAcquisition, error)
	attemptOverflow      atomic.Uint64
	observedDependencies []startupDependency
	observedRouterPath   startupRouterPath
	shutdown             map[string][2]int64
	readyOriginal        []byte
	acknowledgement      string
	pins                 map[string]string
	now                  func() time.Time
	probe                func(context.Context, startupTarget) startupProbeResult
	image                func(context.Context) ([]byte, error)
	// EnclaveReadyRetention returns a retained-channel acknowledgement. The
	// installed local seam retains bytes in this boot only, not across VM loss.
	retainReady func(context.Context, []byte) (string, error)
	done        chan struct{}
	runOnce     sync.Once
}

func newStartupHarness(start time.Time, emitter *startupEmitter) *ShadowV2StartupHarness {
	var id [16]byte
	_, err := rand.Read(id[:])
	boot := ""
	if err == nil {
		boot = hex.EncodeToString(id[:])
	}
	return &ShadowV2StartupHarness{start: start, boot: boot, emitter: emitter, completions: map[string]int64{}, shutdown: map[string][2]int64{}, attempts: make([]startupLocalAttempt, 0, 256), now: time.Now, done: make(chan struct{})}
}
func startupPin(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// StartShadowV2Startup returns immediately. Descriptor reads, release loading,
// local checks and stdout writes happen in its bounded background run.
func StartShadowV2Startup(ctx context.Context, start time.Time, fd *os.File, present bool, boot *qtypes.BootstrapData, c *Client, imageDocument func() (string, []byte)) *ShadowV2StartupHarness {
	h := newStartupHarness(start, newStartupEmitter(os.Stdout))
	shadowOn, negotiateOn := false, false
	if c != nil {
		shadowOn, negotiateOn = c.asyncShadow, c.asyncNegotiate
	} else {
		shadowOn, negotiateOn = shadowFlag(boot), asyncFlag(boot)
	}
	h.pins = map[string]string{"TR_ASYNC_SETTLE_SHADOW": startupPin(shadowOn), "TR_ASYNC_SETTLE_NEGOTIATE": startupPin(negotiateOn)}
	if h.pins["TR_ASYNC_SETTLE_SHADOW"] == "on" {
		enclaveOptedAdmission.Store(&startupAdmission{harness: h})
	}
	h.retainReady = func(_ context.Context, raw []byte) (string, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.readyOriginal = bytes.Clone(raw)
		return "local-completion", nil
	}
	if imageDocument != nil {
		h.image = func(context.Context) ([]byte, error) {
			kind, document := imageDocument()
			return startupCachedImageRecord(kind, document, shadowRevision())
		}
	}
	h.probe = func(ctx context.Context, target startupTarget) startupProbeResult {
		return startupReadRouter(ctx, c, target)
	}
	h.acquire = func(ctx context.Context) (startupLaunchAcquisition, error) {
		region := ""
		if c != nil {
			region = c.region
		}
		return acquireStartupLaunch(ctx, fd, present, shadowRevision(), region)
	}
	h.load = func() (startupManifest, []byte, error) {
		var m startupManifest
		raw, err := readStartupJSON(os.Getenv("TR_SHADOW_V2_STARTUP_MANIFEST"), 262144, &m)
		return m, raw, err
	}
	configureStartupInputs(h)
	h.launch(func() {
		defer close(h.done)
		runCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		descriptorCtx, stop := context.WithTimeout(runCtx, 3*time.Second)
		acquisition, measured := startupBounded(descriptorCtx, func() startupAcquired { value, err := h.acquire(descriptorCtx); return startupAcquired{value, err} })
		stop()
		if !measured || acquisition.err != nil {
			return
		}
		h.mu.Lock()
		h.acquisition = acquisition.value
		h.mu.Unlock()
		h.run(runCtx, acquisition.value.descriptor, h.load)
	})
	return h
}

// CaptureShadowV2LaunchDescriptor accepts only an explicitly inherited launch
// descriptor and must run before opening serving listeners.
func CaptureShadowV2LaunchDescriptor() (*os.File, bool) { return inheritedStartupDescriptor() }

// configureStartupInputs is a package-local input seam. Production keeps the
// installed local adapters; tests replace inputs before the coordinator starts.
var configureStartupInputs = func(*ShadowV2StartupHarness) {}

type startupAcquired struct {
	value startupLaunchAcquisition
	err   error
}

func (h *ShadowV2StartupHarness) launch(run func()) {
	go func() { defer h.recoverStartup(); run() }()
}
func (h *ShadowV2StartupHarness) recoverStartup() {
	if recover() != nil {
		if state := enclaveOptedAdmission.Load(); state != nil && state.harness == h {
			enclaveOptedAdmission.CompareAndSwap(state, &startupAdmission{harness: h})
		}
	}
}

func (h *ShadowV2StartupHarness) run(ctx context.Context, d startupLaunchDescriptor, load func() (startupManifest, []byte, error)) {
	h.runOnce.Do(func() { defer h.recoverStartup(); h.runBoot(ctx, d, load) })
}
func (h *ShadowV2StartupHarness) runBoot(ctx context.Context, d startupLaunchDescriptor, load func() (startupManifest, []byte, error)) {
	if !d.valid() || !startupID.MatchString(h.boot) || d.Revision != shadowRevision() {
		return
	}
	h.mu.Lock()
	h.descriptor = d
	h.mu.Unlock()
	if _, ok := h.emitter.emit(startupCorrelation{"a3_startup_correlation", d.Instance, d.Launch, h.boot, "enclave", d.Revision, d.Region, h.start.UnixMicro(), h.now().UnixMicro()}); !ok {
		return
	}
	clockRaw, _ := canonicalShadow(map[string]any{"clock": "utc_ns", "boot": h.boot, "boot_at_us": h.start.UnixMicro()})
	original, ok := retainStartupOriginal("boot_clock", clockRaw)
	if !ok {
		return
	}
	h.originals = append(h.originals, original)
	clock := startupClock{"utc_ns", h.boot, h.start.UnixMicro(), original.coordinate}
	loadCtx, stopLoad := context.WithTimeout(ctx, time.Second)
	loaded, loadedOK := startupBounded(loadCtx, func() startupLoadedManifest { m, raw, err := load(); return startupLoadedManifest{m, raw, err} })
	stopLoad()
	m, raw, err := loaded.manifest, loaded.raw, loaded.err
	if !loadedOK || err != nil || !m.valid(d) {
		return
	}
	h.manifestOriginal = bytes.Clone(raw)
	h.configOriginal = []byte(m.ConfigOriginal)
	for _, criterion := range startupCriteria {
		if ctx.Err() != nil {
			return
		}
		b, available := h.adoptInputs(m, criterion)
		if !available {
			continue
		}
		var record any = b
		switch criterion {
		case "boot_transport":
			if h.probe == nil {
				continue
			}
			deps := make([]startupDependency, 0, len(m.Config.Dependencies.Enclave))
			complete := true
			for _, target := range m.Config.Dependencies.Enclave {
				target.DeadlineUS = 10000000
				begin := h.now()
				stepCtx, cancel := context.WithTimeout(ctx, time.Duration(target.DeadlineUS)*time.Microsecond)
				result, measured := startupBounded(stepCtx, func() startupProbeResult { return h.probe(stepCtx, target) })
				elapsed := h.now().Sub(begin).Microseconds()
				expired := !measured || stepCtx.Err() != nil
				cancel()
				dep := startupDependency{h.boot, target.Region, m.ConfigSHA256, target.Operation, target.Resource, 1, result.markerMatches, elapsed, target.DeadlineUS, begin.UnixMicro()}
				deps = append(deps, dep)
				// A missing marker cannot be projected into the closed dependency shape.
				if !result.markerMatches || elapsed < 0 || elapsed > target.DeadlineUS || expired {
					complete = false
				}
				if !result.ready {
					for k := range b.Checks {
						b.Checks[k] = "fail"
					}
				}
			}
			h.mu.Lock()
			h.observedDependencies = append([]startupDependency(nil), deps...)
			h.mu.Unlock()
			if !complete {
				continue
			}
			b.CompletedAtUS = h.now().UnixMicro()
			record = startupTransportCheck{b, deps, clock}
		case "observer_freshness":
			if h.probe == nil {
				continue
			}
			target := startupTarget{"read", m.Config.RouterPath.Resource, m.Config.RouterPath.Region, 10000000}
			begin := h.now()
			stepCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			result, measured := startupBounded(stepCtx, func() startupProbeResult { return h.probe(stepCtx, target) })
			expired := !measured || stepCtx.Err() != nil
			cancel()
			path := startupRouterPath{result.ready, target.Resource, result.routerBoot, target.Region, begin.UnixMicro()}
			h.mu.Lock()
			h.observedRouterPath = path
			h.mu.Unlock()
			if expired || !result.ready || !result.echoReady || !startupID.MatchString(result.routerBoot) {
				continue
			}
			b.CompletedAtUS = h.now().UnixMicro()
			record = startupObserverCheck{b, path, target.Region, true, result.echoReady, clock}
		case "marker_keys":
			p := m.PublicDescriptors
			if h.image == nil || p.AuthorityEpoch <= 0 || p.ConfigSHA256 != m.ConfigSHA256 || p.SourceRevision != d.Revision || !reflect.DeepEqual(p.DescriptorIDs, m.Config.DescriptorIDs) {
				continue
			}
			stepCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			loadedImage, measured := startupBounded(stepCtx, func() startupLoadedImage { raw, err := h.image(stepCtx); return startupLoadedImage{raw, err} })
			imageRaw, err := loadedImage.raw, loadedImage.err
			expired := !measured || stepCtx.Err() != nil
			cancel()
			var image startupImage
			if err != nil || expired || !shadowExactObject(imageRaw, &image) || image.Revision != d.Revision || image.ImageSHA256 != m.Config.EnclaveImageSHA256 {
				continue
			}
			var releaseFields map[string]json.RawMessage
			if json.Unmarshal(raw, &releaseFields) != nil {
				continue
			}
			public, ok := retainStartupOriginal("public_descriptors", releaseFields["public_descriptors"])
			if !ok {
				continue
			}
			imageOriginal, ok := retainStartupOriginal("image_record", imageRaw)
			if !ok {
				continue
			}
			h.originals = append(h.originals, public, imageOriginal)
			if !reflect.DeepEqual(h.pins, m.Config.EffectivePins) {
				for k := range b.Checks {
					b.Checks[k] = "fail"
				}
			}
			b.CompletedAtUS = h.now().UnixMicro()
			record = startupMarkerCheck{b, h.pins, d.Revision, p.AuthorityEpoch, public.coordinate, m.PolicySHA256, m.FixtureSHA256, imageOriginal.coordinate, image.Revision}
		}
		if _, ok := h.emitter.emit(record); !ok {
			continue
		}
		passed := true
		for _, result := range b.Checks {
			if result != "pass" {
				passed = false
			}
		}
		if passed {
			h.completions[criterion] = b.CompletedAtUS
		}
	}
	h.finishReady(ctx)
}
func (h *ShadowV2StartupHarness) adoptInputs(m startupManifest, criterion string) (startupBootCheck, bool) {
	b := startupBootCheck{"a3_boot_check", h.boot, "enclave", m.Revision, m.Region, h.start.UnixMicro(), criterion, 0, map[string]string{}, m.ConfigSHA256, map[string]string{}}
	for _, name := range strings.Fields(startupChecks[criterion]) {
		b.Checks[name] = "pass"
	}
	adoption := h.now().UnixMicro()
	for _, source := range strings.Fields(startupSources[criterion]) {
		a, ok := m.Artifacts[criterion][source]
		if !ok || !startupID.MatchString(a.ID) || a.Criterion != criterion || a.Source != source || a.Revision != m.Revision || a.Region != m.Region || a.ConfigSHA256 != m.ConfigSHA256 || a.StartedAtUS < 0 || a.CompletedAtUS <= a.StartedAtUS || a.CompletedAtUS > adoption || (source != "ci" && a.CompletedAtUS-a.StartedAtUS > 3600000000) || !startupNames(a.Checks, startupChecks[criterion], func(v string) bool { return v == "pass" || v == "fail" }) {
			return b, false
		}
		b.Inputs[source] = a.ID
		for k, v := range a.Checks {
			if v == "fail" {
				b.Checks[k] = "fail"
			}
		}
	}
	b.CompletedAtUS = h.now().UnixMicro()
	return b, true
}
func (h *ShadowV2StartupHarness) finishReady(ctx context.Context) {
	if len(h.completions) != 6 {
		return
	}
	at := h.now().UnixMicro()
	for _, completed := range h.completions {
		if at <= completed {
			return
		}
	}
	raw, ok := h.emitter.emit(startupReady{"a3_traffic_ready", h.boot, at})
	if !ok || h.retainReady == nil {
		return
	}
	ackCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	retained, measured := startupBounded(ackCtx, func() startupReadyAck {
		ack, err := h.retainReady(ackCtx, bytes.Clone(raw))
		return startupReadyAck{ack, err}
	})
	ack, err := retained.ack, retained.err
	if !measured || err != nil || ack == "" || ackCtx.Err() != nil {
		return
	}
	h.mu.Lock()
	h.acknowledgement = ack
	h.mu.Unlock()
	if h.pins["TR_ASYNC_SETTLE_SHADOW"] == "on" {
		enclaveOptedAdmission.Store(&startupAdmission{ready: true, harness: h})
	}
}

// EnclaveOptedAdmission is called only for marked v2 cohort traffic while the
// client's existing shadow switch is on. Its decision is one atomic flag read.
func EnclaveOptedAdmission() bool {
	state := enclaveOptedAdmission.Load()
	if state == nil {
		return true
	}
	return state.ready
}

// Called by the request entry before retention, after the response identifies
// the cohort. The off, non-cohort and absent-policy paths allocate nothing.
func (c *Client) recordStartupAdmissionStart(a *Authorization, route string) startupAdmissionStart {
	if !c.asyncShadow || !asyncCohort(route) || !startupOptedPolicy(a.BillingShadowPolicy) {
		return startupAdmissionStart{}
	}
	return recordStartupAdmissionStart()
}

// Compare the one ASCII marker without allocating a decoded string. Its only
// alternate JSON spelling is a sequence of ASCII unicode escapes. The existing
// retention parser still owns the request decision.
func startupOptedPolicy(raw []byte) bool {
	raw = bytes.Trim(raw, " \t\r\n")
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return false
	}
	const digits = "0123456789abcdef"
	at, end := 1, len(raw)-1
	for i := 0; i < len(shadowPolicyV2); i++ {
		want := shadowPolicyV2[i]
		if at >= end {
			return false
		}
		if raw[at] == want {
			at++
			continue
		}
		if at+6 > end || raw[at] != '\\' || raw[at+1] != 'u' || raw[at+2] != '0' || raw[at+3] != '0' || raw[at+4]|0x20 != digits[want>>4] || raw[at+5]|0x20 != digits[want&15] {
			return false
		}
		at += 6
	}
	return at == end
}

// The entry observation carries only the clock and destination for the result.
// Readiness is observed by retention; the entry snapshot does not choose a result.
type startupAdmissionStart struct {
	harness *ShadowV2StartupHarness
	atUS    int64
}

func recordStartupAdmissionStart() startupAdmissionStart {
	state := enclaveOptedAdmission.Load()
	if state == nil {
		return startupAdmissionStart{}
	}
	return startupAdmissionStart{state.harness, time.Now().UnixMicro()}
}

// record uses the completed retention decision and preserves the entry time.
// A busy or full recorder drops and counts immediately without growing its buffer.
func (start startupAdmissionStart) record(retained bool) {
	h := start.harness
	if h == nil {
		return
	}
	result := "rejected"
	if retained {
		result = "accepted"
	}
	if !h.attemptMu.TryLock() {
		h.attemptOverflow.Add(1)
		return
	}
	defer h.attemptMu.Unlock()
	if len(h.attempts) == cap(h.attempts) {
		h.attemptOverflow.Add(1)
		return
	}
	h.attempts = append(h.attempts, startupLocalAttempt{start.atUS, result})
}

func startupReadRouter(ctx context.Context, c *Client, target startupTarget) startupProbeResult {
	if c == nil || c.httpc == nil || len(c.baseURLs) == 0 {
		return startupProbeResult{}
	}
	base, err := url.Parse(c.baseURLs[0])
	if err != nil || base.Host != target.Resource || base.Scheme != "https" {
		return startupProbeResult{}
	}
	base.Path = "/ready"
	base.RawQuery = ""
	base.Fragment = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return startupProbeResult{}
	}
	// No redirects, retries, body logging or request-derived targets.
	client := &http.Client{Transport: c.httpc.Transport, Timeout: time.Duration(target.DeadlineUS) * time.Microsecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return startupProbeResult{}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(raw) > 4096 || resp.StatusCode != 200 {
		return startupProbeResult{}
	}
	var status struct {
		Status string `json:"status"`
	}
	if json.Unmarshal(raw, &status) != nil {
		return startupProbeResult{}
	}
	// Existing /ready has status, but no boot, marker/pins or settle echo result.
	return startupProbeResult{ready: status.Status == "ready"}
}

// RecordShutdownWait retains an actual monotonic interval for this process.
// A partial set is not emitted as a final a3_shutdown_span.
func (h *ShadowV2StartupHarness) RecordShutdownWait(begin, end time.Time) {
	if h == nil {
		return
	}
	a, b := begin.Sub(h.start).Microseconds(), end.Sub(h.start).Microseconds()
	if a < 0 || b < a {
		return
	}
	h.mu.Lock()
	h.shutdown["export_wait"] = [2]int64{a, b}
	h.mu.Unlock()
}

// EnclaveImageRecord reads only the already minted local document. The image
// digest is joined to the released binary revision by the reviewed manifest.
// No part of the source document is included in a runtime record.
func startupCachedImageRecord(kind string, document []byte, revision string) ([]byte, error) {
	if kind != "gcp-cs-jwt" || len(document) > 32768 || !startupRevision.MatchString(revision) {
		return nil, errStartupRecord
	}
	parts := strings.Split(string(document), ".")
	if len(parts) != 3 {
		return nil, errStartupRecord
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return nil, errStartupRecord
	}
	var claims struct {
		ImageDigest string `json:"image_digest"`
		Submods     struct {
			Container struct {
				ImageDigest string `json:"image_digest"`
			} `json:"container"`
		} `json:"submods"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return nil, errStartupRecord
	}
	digest := claims.ImageDigest
	if digest == "" {
		digest = claims.Submods.Container.ImageDigest
	} else if claims.Submods.Container.ImageDigest != "" && claims.Submods.Container.ImageDigest != digest {
		return nil, errStartupRecord
	}
	digest = strings.TrimPrefix(digest, "sha256:")
	if !startupDigest.MatchString(digest) {
		return nil, errStartupRecord
	}
	return canonicalShadow(startupImage{revision, digest})
}

type startupLoadedManifest struct {
	manifest startupManifest
	raw      []byte
	err      error
}
type startupLoadedImage struct {
	raw []byte
	err error
}
type startupReadyAck struct {
	ack string
	err error
}

// Each port is invoked once. A stalled port can hold at most its one worker;
// the coordinator stops waiting at the declared deadline.
func startupBounded[T any](ctx context.Context, fn func() T) (T, bool) {
	done := make(chan T, 1)
	go func() {
		defer func() {
			if recover() != nil {
				close(done)
			}
		}()
		done <- fn()
	}()
	select {
	case result, ok := <-done:
		return result, ok && ctx.Err() == nil
	case <-ctx.Done():
		var zero T
		return zero, false
	}
}
