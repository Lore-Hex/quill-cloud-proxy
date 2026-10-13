package trustedrouter

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var startupID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$`)
var startupDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var startupRevision = regexp.MustCompile(`^[0-9a-f]{40}$`)
var startupLimits = map[string]int{"a3_startup_correlation": 2048, "a3_boot_check": 16384, "a3_traffic_ready": 1024, "a3_opted_attempt": 2048, "a3_shutdown_span": 4096}
var startupChecks = map[string]string{
	"transport": "actual_hops both_routes_variants compared_outcome", "size": "event_snapshot headers_fragments native_memory transactions",
	"regional_load": "cpu_reads envelope publisher_export_shutdown", "boot_transport": "local_dependencies regional_hops",
	"observer_freshness": "role_warm_path slot_freshness", "marker_keys": "deployed_pins public_epoch separation_negatives",
}
var startupSources = map[string]string{"transport": "ci regional_trial", "size": "ci sizing_trial", "regional_load": "budget_trial", "boot_transport": "regional_trial", "observer_freshness": "", "marker_keys": "ci"}
var startupFields = map[string]string{
	"a3_startup_correlation": "kind instance launch boot role revision region process_start_us recorded_at_us",
	"a3_boot_check":          "kind boot role revision region boot_at_us criterion completed_at_us checks config_sha256 inputs",
	"a3_traffic_ready":       "kind boot at_us", "a3_opted_attempt": "kind boot at_us result receipt",
	"a3_shutdown_span": "kind boot instance launch revision region day interval_end_us complete clock clock_origin spans outcome",
}
var startupRoleFields = map[string]string{
	"boot_transport":     "dependencies clock_basis",
	"observer_freshness": "router_path configured_router_region local_transport_ready echo_ready clock_basis",
	"marker_keys":        "effective_pins source_revision authority_epoch public_descriptors policy_sha256 fixture_sha256 attested_image attested_revision",
}
var startupCoordinateKinds = map[string]int{"boot_clock": 262144, "health_basis": 6144, "health_claim": 1024, "health": 4096, "public_descriptors": 16384, "image_record": 16384, "receipt_page": 65536, "closure": 4096, "close_result": 4096}

// Coordinates and originals are made together; the stored buffer is never rebuilt.
type startupCoordinate struct {
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}
type startupOriginal struct {
	coordinate startupCoordinate
	raw        []byte
}

func retainStartupOriginal(kind string, raw []byte) (startupOriginal, bool) {
	if len(raw) == 0 || len(raw) > startupCoordinateKinds[kind] {
		return startupOriginal{}, false
	}
	owned := bytes.Clone(raw)
	sum := sha256.Sum256(owned)
	return startupOriginal{startupCoordinate{kind, hex.EncodeToString(sum[:]), len(owned)}, owned}, true
}
func (c startupCoordinate) valid(kind string) bool {
	return c.Kind == kind && startupDigest.MatchString(c.SHA256) && c.Bytes > 0 && c.Bytes <= startupCoordinateKinds[kind]
}

type startupCorrelation struct {
	Kind           string `json:"kind"`
	Instance       string `json:"instance"`
	Launch         string `json:"launch"`
	Boot           string `json:"boot"`
	Role           string `json:"role"`
	Revision       string `json:"revision"`
	Region         string `json:"region"`
	ProcessStartUS int64  `json:"process_start_us"`
	RecordedAtUS   int64  `json:"recorded_at_us"`
}
type startupClock struct {
	Clock    string            `json:"clock"`
	Boot     string            `json:"boot"`
	BootAtUS int64             `json:"boot_at_us"`
	Original startupCoordinate `json:"original"`
}
type startupDependency struct {
	Boot          string `json:"boot"`
	Region        string `json:"region"`
	ConfigSHA256  string `json:"config_sha256"`
	Operation     string `json:"operation"`
	Resource      string `json:"resource"`
	Attempts      int    `json:"attempts"`
	MarkerMatches bool   `json:"marker_matches"`
	ElapsedUS     int64  `json:"elapsed_us"`
	DeadlineUS    int64  `json:"deadline_us"`
	ObservedAtUS  int64  `json:"observed_at_us"`
}
type startupRouterPath struct {
	Ready        bool   `json:"ready"`
	Resource     string `json:"resource"`
	RouterBoot   string `json:"router_boot"`
	Region       string `json:"region"`
	ObservedAtUS int64  `json:"observed_at_us"`
}
type startupBootCheck struct {
	Kind          string            `json:"kind"`
	Boot          string            `json:"boot"`
	Role          string            `json:"role"`
	Revision      string            `json:"revision"`
	Region        string            `json:"region"`
	BootAtUS      int64             `json:"boot_at_us"`
	Criterion     string            `json:"criterion"`
	CompletedAtUS int64             `json:"completed_at_us"`
	Checks        map[string]string `json:"checks"`
	ConfigSHA256  string            `json:"config_sha256"`
	Inputs        map[string]string `json:"inputs"`
}
type startupTransportCheck struct {
	startupBootCheck
	Dependencies []startupDependency `json:"dependencies"`
	ClockBasis   startupClock        `json:"clock_basis"`
}
type startupObserverCheck struct {
	startupBootCheck
	RouterPath             startupRouterPath `json:"router_path"`
	ConfiguredRouterRegion string            `json:"configured_router_region"`
	LocalTransportReady    bool              `json:"local_transport_ready"`
	EchoReady              bool              `json:"echo_ready"`
	ClockBasis             startupClock      `json:"clock_basis"`
}
type startupMarkerCheck struct {
	startupBootCheck
	EffectivePins     map[string]string `json:"effective_pins"`
	SourceRevision    string            `json:"source_revision"`
	AuthorityEpoch    int64             `json:"authority_epoch"`
	PublicDescriptors startupCoordinate `json:"public_descriptors"`
	PolicySHA256      string            `json:"policy_sha256"`
	FixtureSHA256     string            `json:"fixture_sha256"`
	AttestedImage     startupCoordinate `json:"attested_image"`
	AttestedRevision  string            `json:"attested_revision"`
}
type startupReady struct {
	Kind string `json:"kind"`
	Boot string `json:"boot"`
	AtUS int64  `json:"at_us"`
}
type startupReceipt struct {
	Day      string            `json:"day"`
	Boot     string            `json:"boot"`
	Sequence int64             `json:"sequence"`
	Original startupCoordinate `json:"original"`
}
type startupAttempt struct {
	Kind    string         `json:"kind"`
	Boot    string         `json:"boot"`
	AtUS    int64          `json:"at_us"`
	Result  string         `json:"result"`
	Receipt startupReceipt `json:"receipt"`
}
type startupClockOrigin struct {
	Boot              string `json:"boot"`
	MonotonicAtBootUS int64  `json:"monotonic_at_boot_us"`
}
type startupShutdown struct {
	Kind          string              `json:"kind"`
	Boot          string              `json:"boot"`
	Instance      string              `json:"instance"`
	Launch        string              `json:"launch"`
	Revision      string              `json:"revision"`
	Region        string              `json:"region"`
	Day           string              `json:"day"`
	IntervalEndUS int64               `json:"interval_end_us"`
	Complete      bool                `json:"complete"`
	Clock         string              `json:"clock"`
	ClockOrigin   startupClockOrigin  `json:"clock_origin"`
	Spans         map[string][2]int64 `json:"spans"`
	Outcome       string              `json:"outcome"`
}

func startupNames(values map[string]string, names string, allowed func(string) bool) bool {
	keys := strings.Fields(names)
	if len(values) != len(keys) {
		return false
	}
	for _, k := range keys {
		v, ok := values[k]
		if !ok || !allowed(v) {
			return false
		}
	}
	return true
}
func startupDay(day string) bool {
	t, e := time.Parse("2006-01-02", day)
	return e == nil && t.Format("2006-01-02") == day
}
func startupCommon(boot, role, revision, region string) bool {
	return startupID.MatchString(boot) && role == "enclave" && startupRevision.MatchString(revision) && startupID.MatchString(region)
}
func (b startupBootCheck) valid() bool {
	names, ok := startupChecks[b.Criterion]
	return ok && b.Kind == "a3_boot_check" && startupCommon(b.Boot, b.Role, b.Revision, b.Region) && b.BootAtUS >= 0 && b.CompletedAtUS >= b.BootAtUS && startupDigest.MatchString(b.ConfigSHA256) && startupNames(b.Checks, names, func(v string) bool { return v == "pass" || v == "fail" }) && startupNames(b.Inputs, startupSources[b.Criterion], startupID.MatchString)
}
func (c startupClock) valid(b startupBootCheck) bool {
	return c.Clock == "utc_ns" && c.Boot == b.Boot && c.BootAtUS == b.BootAtUS && c.Original.valid("boot_clock")
}
func startupRecordValid(record any) bool {
	switch r := record.(type) {
	case startupCorrelation:
		return r.Kind == "a3_startup_correlation" && startupCommon(r.Boot, r.Role, r.Revision, r.Region) && startupID.MatchString(r.Instance) && startupID.MatchString(r.Launch) && r.ProcessStartUS >= 0 && r.RecordedAtUS >= r.ProcessStartUS
	case startupBootCheck:
		return r.valid() && (r.Criterion == "transport" || r.Criterion == "size" || r.Criterion == "regional_load")
	case startupTransportCheck:
		if !r.valid() || r.Criterion != "boot_transport" || !r.ClockBasis.valid(r.startupBootCheck) || len(r.Dependencies) < 1 || len(r.Dependencies) > 16 {
			return false
		}
		seen := map[string]bool{}
		for _, d := range r.Dependencies {
			key := d.Operation + "/" + d.Resource + "/" + d.Region
			if seen[key] || d.Boot != r.Boot || !startupID.MatchString(d.Region) || d.ConfigSHA256 != r.ConfigSHA256 || (d.Operation != "transport" && d.Operation != "read") || !startupID.MatchString(d.Resource) || d.Attempts != 1 || !d.MarkerMatches || d.ElapsedUS < 0 || d.ElapsedUS > d.DeadlineUS || d.DeadlineUS <= 0 || d.DeadlineUS > 10000000 || d.ObservedAtUS < r.BootAtUS || d.ObservedAtUS > r.CompletedAtUS || d.ElapsedUS > r.CompletedAtUS-d.ObservedAtUS {
				return false
			}
			seen[key] = true
		}
		return true
	case startupObserverCheck:
		p := r.RouterPath
		return r.valid() && r.Criterion == "observer_freshness" && r.ClockBasis.valid(r.startupBootCheck) && p.Ready && startupID.MatchString(p.Resource) && startupID.MatchString(p.RouterBoot) && startupID.MatchString(p.Region) && p.Region == r.ConfiguredRouterRegion && r.LocalTransportReady && r.EchoReady && p.ObservedAtUS >= r.BootAtUS && p.ObservedAtUS <= r.CompletedAtUS
	case startupMarkerCheck:
		return r.valid() && r.Criterion == "marker_keys" && startupNames(r.EffectivePins, "TR_ASYNC_SETTLE_NEGOTIATE TR_ASYNC_SETTLE_SHADOW", func(v string) bool { return v == "on" || v == "off" || v == "true" || v == "false" }) && r.SourceRevision == r.Revision && r.AttestedRevision == r.Revision && r.AuthorityEpoch > 0 && r.PublicDescriptors.valid("public_descriptors") && r.AttestedImage.valid("image_record") && startupDigest.MatchString(r.PolicySHA256) && startupDigest.MatchString(r.FixtureSHA256)
	case startupReady:
		return r.Kind == "a3_traffic_ready" && startupID.MatchString(r.Boot) && r.AtUS >= 0
	case startupAttempt:
		return r.Kind == "a3_opted_attempt" && startupID.MatchString(r.Boot) && r.AtUS >= 0 && (r.Result == "accepted" || r.Result == "failed" || r.Result == "rejected" || r.Result == "timeout") && r.Receipt.Boot == r.Boot && startupDay(r.Receipt.Day) && r.Receipt.Sequence > 0 && r.Receipt.Original.valid("receipt_page")
	case startupShutdown:
		if r.Kind != "a3_shutdown_span" || !startupCommon(r.Boot, "enclave", r.Revision, r.Region) || !startupID.MatchString(r.Instance) || !startupID.MatchString(r.Launch) || !startupDay(r.Day) || r.IntervalEndUS < 0 || r.Clock != "monotonic_us" || r.ClockOrigin.Boot != r.Boot || r.ClockOrigin.MonotonicAtBootUS < 0 || (r.Outcome != "graceful" && r.Outcome != "hard_kill") || len(r.Spans) != 5 {
			return false
		}
		for _, k := range strings.Fields("preparation export_wait final_pass close result") {
			s, ok := r.Spans[k]
			if !ok || s[0] < r.ClockOrigin.MonotonicAtBootUS || s[1] < s[0] {
				return false
			}
		}
		p, w, f, c, z := r.Spans["preparation"], r.Spans["export_wait"], r.Spans["final_pass"], r.Spans["close"], r.Spans["result"]
		return p[1] == w[0] && w[1] == f[0] && c[0] >= f[0] && c[1] <= z[0] && z[1] <= f[1] && c[1]-c[0] <= 2000000 && z[1]-z[0] <= 2000000 && f[1]-f[0] <= 4000000 && f[1]-p[0] <= 9000000 && !(r.Outcome == "hard_kill" && r.Complete)
	}
	return false
}

var errStartupRecord = errors.New("startup record unavailable")

func startupRecordBytes(record any) ([]byte, error) {
	if !startupRecordValid(record) {
		return nil, errStartupRecord
	}
	raw, err := canonicalShadow(record)
	if err != nil {
		return nil, errStartupRecord
	}
	var head struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(raw, &head) != nil || !startupWithinLimit(head.Kind, len(raw)) {
		return nil, errStartupRecord
	}
	return raw, nil
}
func startupWithinLimit(kind string, n int) bool {
	limit, ok := startupLimits[kind]
	return ok && n > 0 && n <= limit
}

// The existing workload stdout channel carries one structured object per line.
// A bounded queue keeps a slow stdout reader off the startup and request paths.
type startupLine struct {
	raw  []byte
	done chan bool
}

type startupEmitter struct {
	queue   chan startupLine
	dropped atomic.Uint64
	once    sync.Once
}

func newStartupEmitter(w io.Writer) *startupEmitter {
	e := &startupEmitter{queue: make(chan startupLine, 32)}
	go func() {
		for item := range e.queue {
			line := append(bytes.Clone(item.raw), '\n')
			n, err := w.Write(line)
			if err != nil || n != len(line) {
				e.dropped.Add(1)
			}
			item.done <- err == nil && n == len(line)
		}
	}()
	return e
}
func (e *startupEmitter) emit(record any) ([]byte, bool) {
	raw, err := startupRecordBytes(record)
	if err != nil {
		e.dropped.Add(1)
		return nil, false
	}
	item := startupLine{raw, make(chan bool, 1)}
	select {
	case e.queue <- item:
		select {
		case ok := <-item.done:
			return raw, ok
		case <-time.After(250 * time.Millisecond):
			e.dropped.Add(1)
			return nil, false
		}
	default:
		e.dropped.Add(1)
		return nil, false
	}
}
func (e *startupEmitter) close() { e.once.Do(func() { close(e.queue) }) }
