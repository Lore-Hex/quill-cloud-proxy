package trustedrouter

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func startupFieldNames(value any) string {
	var fields []string
	var collect func(reflect.Type)
	collect = func(typ reflect.Type) {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if f.Anonymous {
				collect(f.Type)
			} else {
				fields = append(fields, strings.Split(f.Tag.Get("json"), ",")[0])
			}
		}
	}
	collect(reflect.TypeOf(value))
	sort.Strings(fields)
	return strings.Join(fields, " ")
}
func sortedStartupFields(s string) string {
	parts := strings.Fields(s)
	sort.Strings(parts)
	return strings.Join(parts, " ")
}
func TestStartupInventory(t *testing.T) {
	raw, err := os.ReadFile("testdata/shadow_v2_runtime_records_inventory.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != "a661658e2fa8a958292fe39e8ba82d252935254c2a17d646b6205052603428f3" {
		t.Fatal("cross-repository fixture changed; review explicit fixture and schema update")
	}
	var inv struct {
		Fields                  map[string]string            `json:"fields"`
		RoleFields              map[string]map[string]string `json:"role_fields"`
		Limits                  map[string]int               `json:"limits"`
		Checks                  map[string][]string          `json:"checks"`
		Sources                 map[string][]string          `json:"sources"`
		AttemptResults          []string                     `json:"attempt_results"`
		EmittedCoordinateFields string                       `json:"emitted_coordinate_fields"`
		EmittedCoordinates      map[string]struct {
			Kind     string `json:"kind"`
			MaxBytes int    `json:"max_bytes"`
		} `json:"emitted_coordinates"`
		LaunchDescriptorFields string `json:"launch_descriptor_fields"`
	}
	if json.Unmarshal(raw, &inv) != nil {
		t.Fatal("inventory decode")
	}
	if !reflect.DeepEqual(inv.Fields, startupFields) || !reflect.DeepEqual(inv.Limits, startupLimits) {
		t.Fatal("record inventory mismatch")
	}
	shapes := map[string]any{"a3_startup_correlation": startupCorrelation{}, "a3_boot_check": startupBootCheck{}, "a3_traffic_ready": startupReady{}, "a3_opted_attempt": startupAttempt{}, "a3_shutdown_span": startupShutdown{}}
	for kind, v := range shapes {
		if startupFieldNames(v) != sortedStartupFields(inv.Fields[kind]) {
			t.Fatalf("fields %s", kind)
		}
	}
	roles := map[string]any{"boot_transport": startupTransportCheck{}, "observer_freshness": startupObserverCheck{}, "marker_keys": startupMarkerCheck{}}
	for criterion, v := range roles {
		fields := inv.RoleFields[criterion]["enclave"]
		if fields != startupRoleFields[criterion] || startupFieldNames(v) != sortedStartupFields(inv.Fields["a3_boot_check"]+" "+fields) {
			t.Fatalf("role fields %s", criterion)
		}
	}
	if len(inv.Checks) != len(startupChecks) || len(inv.Sources) != len(startupSources) {
		t.Fatal("criterion inventory")
	}
	for k, v := range inv.Checks {
		if strings.Join(v, " ") != startupChecks[k] || strings.Join(inv.Sources[k], " ") != startupSources[k] {
			t.Fatalf("criterion %s", k)
		}
	}
	if strings.Join(inv.AttemptResults, " ") != strings.Join(startupResultNames(), " ") || startupFieldNames(startupCoordinate{}) != sortedStartupFields(inv.EmittedCoordinateFields) || startupFieldNames(startupLaunchDescriptor{}) != sortedStartupFields(inv.LaunchDescriptorFields) {
		t.Fatal("closed fields mismatch")
	}
	kinds := map[string]int{}
	for _, c := range inv.EmittedCoordinates {
		kinds[c.Kind] = c.MaxBytes
		if startupCoordinateKinds[c.Kind] != c.MaxBytes {
			t.Fatal("coordinate mismatch")
		}
	}
	if !reflect.DeepEqual(kinds, startupCoordinateKinds) {
		t.Fatal("complete coordinate kind map differs")
	}
}
func TestStartupByteLimits(t *testing.T) {
	for kind, limit := range startupLimits {
		t.Run(kind, func(t *testing.T) {
			if !startupWithinLimit(kind, len(bytes.Repeat([]byte{'x'}, limit))) {
				t.Fatal("at limit rejected")
			}
			if startupWithinLimit(kind, len(bytes.Repeat([]byte{'x'}, limit+1))) {
				t.Fatal("one over accepted")
			}
		})
	}
	if startupWithinLimit("a3_unknown", 1) || startupWithinLimit("a3_traffic_ready", 0) {
		t.Fatal("unlisted limit")
	}
}
func TestStartupOriginalBuffer(t *testing.T) {
	raw := []byte(`{"boot":"one","boot_at_us":1,"clock":"utc_ns"}`)
	o, ok := retainStartupOriginal("boot_clock", raw)
	if !ok {
		t.Fatal("original missing")
	}
	sum := sha256.Sum256(raw)
	raw[0] = 'x'
	if o.raw[0] != '{' || o.coordinate.SHA256 != hex.EncodeToString(sum[:]) || o.coordinate.Bytes != len(raw) {
		t.Fatal("coordinate did not use retained buffer")
	}
	for kind, limit := range startupCoordinateKinds {
		if _, ok = retainStartupOriginal(kind, make([]byte, limit)); !ok {
			t.Fatal("original at limit")
		}
		if _, ok = retainStartupOriginal(kind, make([]byte, limit+1)); ok {
			t.Fatal("original one over")
		}
	}
}
func startupAllRecords(t *testing.T) []any {
	h, d, m, w := startupFixture(t)
	runStartupFixture(h, d, m)
	var out []any
	for _, r := range w.records(t) {
		raw, _ := json.Marshal(r)
		var v any
		switch r["kind"] {
		case "a3_startup_correlation":
			v = &startupCorrelation{}
		case "a3_traffic_ready":
			v = &startupReady{}
		case "a3_boot_check":
			switch r["criterion"] {
			case "boot_transport":
				v = &startupTransportCheck{}
			case "observer_freshness":
				v = &startupObserverCheck{}
			case "marker_keys":
				v = &startupMarkerCheck{}
			default:
				v = &startupBootCheck{}
			}
		}
		if json.Unmarshal(raw, v) != nil {
			t.Fatal("record decode")
		}
		out = append(out, reflect.ValueOf(v).Elem().Interface())
	}
	out = append(out, startupAttempt{"a3_opted_attempt", h.boot, h.start.UnixMicro(), "rejected", startupReceipt{"2023-11-14", h.boot, 1, startupCoordinate{"receipt_page", strings.Repeat("a", 64), 10}}})
	out = append(out, startupShutdown{"a3_shutdown_span", h.boot, d.Instance, d.Launch, d.Revision, d.Region, "2023-11-14", h.start.UnixMicro(), true, "monotonic_us", startupClockOrigin{h.boot, 0}, map[string][2]int64{"preparation": {1, 2}, "export_wait": {2, 3}, "final_pass": {3, 6}, "close": {3, 4}, "result": {4, 6}}, "graceful"})
	return out
}
func TestStartupNoRequestContent(t *testing.T) {
	records := startupAllRecords(t)
	for _, record := range records {
		raw, err := startupRecordBytes(record)
		if err != nil {
			t.Fatalf("valid builder %T", record)
		}
		if bytes.Contains(raw, []byte("request-header-value")) {
			t.Fatal("request header copied into record")
		}
		for _, content := range []string{"Bearer incoming.value", `{"prompt":"hello"}`, "X-Request: value\n", "request/body?credential=value"} {
			v := reflect.New(reflect.TypeOf(record)).Elem()
			v.Set(reflect.ValueOf(record))
			v.FieldByName("Boot").SetString(content)
			if _, err = startupRecordBytes(v.Interface()); err == nil {
				t.Fatalf("request-shaped builder input accepted %T", record)
			}
		}
	}
	h, _, _, w := startupFixture(t)
	enclaveOptedAdmission.Store(&startupAdmission{harness: h})
	a := v2Authorization(t, shadowV2Variants(t, "authorize_compared")[0])
	a.AuthorizationID = "request-header-value"
	retainShadowV2(a, nil, "chat.completions")
	if len(w.records(t)) != 0 || len(h.attempts) != 0 {
		t.Fatal("request reached records")
	}
}
func TestStartupRecordValidation(t *testing.T) {
	for _, record := range startupAllRecords(t) {
		t.Run(reflect.TypeOf(record).Name(), func(t *testing.T) {
			if !startupRecordValid(record) {
				t.Fatal("valid record")
			}
			value := reflect.New(reflect.TypeOf(record)).Elem()
			value.Set(reflect.ValueOf(record))
			value.FieldByName("Kind").SetString("a3_unknown")
			if startupRecordValid(value.Interface()) {
				t.Fatal("unknown kind")
			}
		})
	}
	if startupRecordValid(map[string]any{"kind": "a3_traffic_ready"}) {
		t.Fatal("untyped record")
	}
}

type startupFailWriter struct{}

func (startupFailWriter) Write([]byte) (int, error) { return 0, errors.New("write") }
func TestStartupEmissionFailure(t *testing.T) {
	e := newStartupEmitter(startupFailWriter{})
	defer e.close()
	if _, ok := e.emit(startupReady{"a3_traffic_ready", "boot", 1}); ok {
		t.Fatal("write failure accepted")
	}
	if e.dropped.Load() != 1 {
		t.Fatal("drop not counted")
	}
	if _, ok := e.emit(startupReady{"a3_traffic_ready", "bad?", 1}); ok || e.dropped.Load() != 2 {
		t.Fatal("invalid record emitted")
	}
}

type startupPausedWriter struct{ release chan struct{} }

func (w startupPausedWriter) Write(p []byte) (int, error) { <-w.release; return len(p), nil }
func TestStartupBoundedEmitter(t *testing.T) {
	release := make(chan struct{})
	e := newStartupEmitter(startupPausedWriter{release})
	defer e.close()
	defer close(release)
	start := time.Now()
	if _, ok := e.emit(startupReady{"a3_traffic_ready", "boot", 1}); ok {
		t.Fatal("unfinished write accepted")
	}
	if time.Since(start) > time.Second {
		t.Fatal("unbounded emitter")
	}
}

func startupResultNames() []string {
	var names []string
	for name := range startupAttemptResults {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
