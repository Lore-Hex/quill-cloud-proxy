package trustedrouter

import (
	"encoding/json"
	"math"
	"os"
	"testing"
)

func TestCandidateCostSharedPythonVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/usage_cost_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name      string         `json:"name"`
		Candidate CandidatePrice `json:"candidate"`
		Usage     struct {
			Input    int `json:"input_tokens"`
			Output   int `json:"output_tokens"`
			Cached   int `json:"cache_read_tokens"`
			Creation int `json:"cache_creation_tokens"`
			Tier     int `json:"price_tier_input_tokens"`
		} `json:"usage"`
		Expected int `json:"expected_microdollars"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != 29 {
		t.Fatalf("case count = %d", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			got, ok := tc.Candidate.CostMicrodollars(tc.Usage.Input, tc.Usage.Output, tc.Usage.Cached, tc.Usage.Creation, tc.Usage.Tier)
			if !ok || got != tc.Expected {
				t.Fatalf("cost = %d, %v; want %d", got, ok, tc.Expected)
			}
		})
	}
}

func TestCandidateCostRejectsUnknownOrUnrepresentablePrices(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*CandidatePrice, *[4]int)
	}{
		{"rounding", func(p *CandidatePrice, _ *[4]int) { p.Rounding = "bankers" }},
		{"version", func(p *CandidatePrice, _ *[4]int) { p.PriceHistoryVersion = 2 }},
		{"fee", func(p *CandidatePrice, _ *[4]int) { p.RequestFeeMicro = -1 }},
		{"rate", func(p *CandidatePrice, _ *[4]int) { p.Rates.OutputMicroPerMillion = -1 }},
		{"input", func(_ *CandidatePrice, u *[4]int) { u[0] = -1 }},
		{"output", func(_ *CandidatePrice, u *[4]int) { u[1] = -1 }},
		{"cache-read", func(_ *CandidatePrice, u *[4]int) { u[2] = -1 }},
		{"cache-write", func(_ *CandidatePrice, u *[4]int) { u[3] = -1 }},
		{"overflow", func(p *CandidatePrice, u *[4]int) { p.RequestFeeMicro = math.MaxInt64; u[0] = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := CandidatePrice{PriceHistoryVersion: 1, Rounding: "half_up_per_million", Rates: PriceRates{InputMicroPerMillion: 1_000_000}}
			u := [4]int{1, 1, 1, 1}
			tc.change(&p, &u)
			if cost, ok := p.CostMicrodollars(u[0], u[1], u[2], u[3], 0); ok || cost != 0 {
				t.Fatalf("cost = %d, %v", cost, ok)
			}
		})
	}
}

func TestSettlementCostPresence(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		known      bool
		cost       int
	}{
		{"missing", `{}`, false, 0},
		{"null", `{"cost_microdollars":null}`, false, 0},
		{"zero", `{"cost_microdollars":0}`, true, 0},
		{"paid", `{"cost_microdollars":17}`, true, 17},
		{"durable-missing", `{"disposition":"intent_durable"}`, false, 0},
		{"durable-paid", `{"disposition":"intent_durable","cost_microdollars":19}`, true, 19},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := SettleResult{CostMicrodollars: 999, CostMicrodollarsKnown: true}
			if err := json.Unmarshal([]byte(tc.body), &r); err != nil {
				t.Fatal(err)
			}
			if r.HasCost() != tc.known || r.CostMicrodollars != tc.cost {
				t.Fatalf("decoded = %+v", r)
			}
			encoded, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			value, present := fields["cost_microdollars"]
			if present != tc.known || (present && value != float64(tc.cost)) {
				t.Fatalf("encoded = %s", encoded)
			}
		})
	}
}
