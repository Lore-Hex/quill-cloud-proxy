package shadowcoord

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const timingJSON = `{"data":{"timing":{"total_ms":23.5,"key_lookup_ms":1,"routing_ms":2,"store_ms":3,"post_commit_ms":4,"spanner_rpcs":5}}}`

func TestPhysicalTimingUnknown(t *testing.T) {
	for _, body := range []string{timingJSON, strings.Replace(timingJSON, `{"data"`, `{"error":{"type":"storage_error"},"data"`, 1)} {
		if r := DecodeTiming([]byte(body)); r == nil || r.TotalMS != 23.5 || r.SpannerRPCs != 5 {
			t.Fatal(r)
		}
	}
	for _, body := range []string{`{}`, timingJSON[:len(timingJSON)-1], strings.Replace(timingJSON, `23.5`, `null`, 1), strings.Replace(timingJSON, `23.5`, `-1`, 1), strings.Replace(timingJSON, `23.5`, `"bad"`, 1), strings.Replace(timingJSON, `"routing_ms":2,`, ``, 1), strings.Replace(timingJSON, `"spanner_rpcs":5`, `"spanner_rpcs":1.5`, 1)} {
		if DecodeTiming([]byte(body)) != nil {
			t.Fatal(body)
		}
	}
}
func TestSerialTimingAndDeniedEvidence(t *testing.T) {
	for _, ok := range []bool{false, true} {
		c, clock, req, r, f := setup(t)
		warm(c, f, r)
		x := c.Predecision(f.Items[0].LookupDigest, req)
		x.StartAuthorize("nonce", "denial")
		clock.add(100 * time.Millisecond)
		status := 402
		if ok {
			status = 200
		}
		x.EndAuthorize("auth", status)
		x.ProviderStart(Route{Endpoint: "ep1", Provider: "fixture-provider", Model: "fixture-text"}, true)
		clock.add(200 * time.Millisecond)
		x.Content(false)
		x.Content(true)
		x.ProviderEnd(true)
		x.Finish()
		var rec Record
		for len(c.records) > 0 {
			rec = <-c.records
		}
		if rec.ActualOverlap != 0 || rec.Applicability != "not-applicable" {
			t.Fatal(rec)
		}
		if ok {
			if rec.MeasuredP == nil || *rec.MeasuredP != 200*time.Millisecond || rec.Counterfactual == nil || *rec.Counterfactual != 100*time.Millisecond {
				t.Fatal(rec)
			}
		} else if rec.MeasuredP != nil || rec.Counterfactual != nil || rec.Provider != nil {
			t.Fatal("invented denied P", rec)
		}
		b, _ := json.Marshal(rec)
		if !ok && !strings.Contains(string(b), `"measured_p_ns":null`) {
			t.Fatal(string(b))
		}
	}
}
func TestFallbackIsNotProposedRoute(t *testing.T) {
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	x := c.Predecision(f.Items[0].LookupDigest, req)
	x.StartAuthorize("nonce", "")
	x.EndAuthorize("auth", 200)
	x.ProviderStart(Route{Endpoint: "ep1", Provider: "fixture-provider", Model: "fixture-text"}, false)
	x.Content(false)
	x.Finish()
	var rec Record
	for len(c.records) > 0 {
		rec = <-c.records
	}
	if rec.MeasuredP != nil {
		t.Fatal(rec)
	}
}
func TestFirstContentVersusSSEMetadata(t *testing.T) {
	var s ContentStream
	for _, b := range []string{"event: message_start\n", `data: {"type":"message_start"}` + "\n\n", `data: {"choices":[{"delta":{"role":"assistant"}}]}` + "\n\n"} {
		if s.Feed([]byte(b)) {
			t.Fatal("metadata counted")
		}
	}
	if s.Feed([]byte(`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hi"}}`)) {
		t.Fatal("incomplete line")
	}
	if !s.Feed([]byte("\n\n")) {
		t.Fatal("content not counted")
	}
	if s.Feed([]byte("data: {}\n")) {
		t.Fatal("duplicate content")
	}
	var chat ContentStream
	if !chat.Feed([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n")) {
		t.Fatal("chat content")
	}
}
func TestIntervalUnionIntersection(t *testing.T) {
	if Union([]Interval{{Start: 5, End: 15}, {Start: 0, End: 10}, {Start: 20, End: 25}, {Start: 30, End: 29}}) != 20 || Intersection(Interval{Start: 0, End: 10}, Interval{Start: 5, End: 15}) != 5 || Intersection(Interval{Start: 0, End: 5}, Interval{Start: 5, End: 10}) != 0 {
		t.Fatal("interval math")
	}
}

func TestUnfinishedProviderIntervalRemainsUnknown(t *testing.T) {
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	x := c.Predecision(f.Items[0].LookupDigest, req)
	x.StartAuthorize("nonce", "")
	x.EndAuthorize("auth", 200)
	x.ProviderStart(Route{Endpoint: "ep1", Provider: "fixture-provider", Model: "fixture-text"}, true)
	x.Content(false)
	x.Finish()
	var rec Record
	for len(c.records) > 0 {
		rec = <-c.records
	}
	if rec.Provider != nil || rec.MeasuredP != nil {
		t.Fatal("active provider end invented", rec)
	}
	x.ProviderEnd(true)
	if rec.Provider != nil || rec.MeasuredP != nil {
		t.Fatal("late callback rewrote observation")
	}
}
