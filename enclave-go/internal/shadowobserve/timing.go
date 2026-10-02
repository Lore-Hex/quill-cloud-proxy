package shadowobserve

import (
	"encoding/json"
	"math"
	"sort"
	"time"
)

// RouterTiming is a single physical attempt. Nil is UNKNOWN, including partial data.
// Router phase durations share a router clock; they are never subtracted from enclave timestamps.
type RouterTiming struct {
	TotalMS      float64 `json:"total_ms"`
	KeyLookupMS  float64 `json:"key_lookup_ms"`
	RoutingMS    float64 `json:"routing_ms"`
	StoreMS      float64 `json:"store_ms"`
	PostCommitMS float64 `json:"post_commit_ms"`
	SpannerRPCs  int64   `json:"spanner_rpcs"`
}

func DecodeTiming(body []byte) *RouterTiming {
	var e struct {
		Data struct {
			Timing json.RawMessage `json:"timing"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &e) != nil || len(e.Data.Timing) > 1024 {
		return nil
	}
	var values map[string]json.RawMessage
	if json.Unmarshal(e.Data.Timing, &values) != nil || len(values) != 6 {
		return nil
	}
	nums := make([]float64, 5)
	for i, k := range []string{"total_ms", "key_lookup_ms", "routing_ms", "store_ms", "post_commit_ms"} {
		raw := values[k]
		if len(raw) == 0 || string(raw) == "null" || json.Unmarshal(raw, &nums[i]) != nil || math.IsNaN(nums[i]) || math.IsInf(nums[i], 0) || nums[i] < 0 || nums[i] > 3600000 {
			return nil
		}
	}
	var rpcs int64
	raw := values["spanner_rpcs"]
	if len(raw) == 0 || string(raw) == "null" || json.Unmarshal(raw, &rpcs) != nil || rpcs < 0 || rpcs > 1000000 {
		return nil
	}
	return &RouterTiming{nums[0], nums[1], nums[2], nums[3], nums[4], rpcs}
}

type Interval struct {
	Start time.Duration `json:"start_ns"`
	End   time.Duration `json:"end_ns"`
}

func Intersection(a, b Interval) time.Duration {
	return max(0, min(a.End, b.End)-max(a.Start, b.Start))
}
func Union(intervals []Interval) time.Duration {
	sorted := append([]Interval(nil), intervals...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Start < sorted[j].Start })
	var total time.Duration
	var end time.Duration
	for _, i := range sorted {
		if i.End > i.Start {
			total += max(0, i.End-max(end, i.Start))
			end = max(end, i.End)
		}
	}
	return total
}
