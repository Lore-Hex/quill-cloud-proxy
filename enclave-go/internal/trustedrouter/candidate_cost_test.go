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
			// Present only on the one-hour cache-write vectors.
			Creation1h *int `json:"cache_creation_1h_input_tokens"`
			Tier       int  `json:"price_tier_input_tokens"`
		} `json:"usage"`
		Expected int `json:"expected_microdollars"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != 38 {
		t.Fatalf("case count = %d", len(cases))
	}
	withCreation1h, nonZeroCreation1h := 0, 0
	for _, tc := range cases {
		creation1h := 0
		if tc.Usage.Creation1h != nil {
			withCreation1h++
			creation1h = *tc.Usage.Creation1h
		}
		if creation1h > 0 {
			nonZeroCreation1h++
		}
		t.Run(tc.Name, func(t *testing.T) {
			got, ok := tc.Candidate.CostMicrodollars(tc.Usage.Input, tc.Usage.Output, tc.Usage.Cached, tc.Usage.Creation, creation1h, tc.Usage.Tier)
			if !ok || got != tc.Expected {
				t.Fatalf("cost = %d, %v; want %d", got, ok, tc.Expected)
			}
		})
	}
	// The one-hour vectors must reach the cost function with their count.
	if withCreation1h != 9 || nonZeroCreation1h != 8 {
		t.Fatalf("one-hour vectors = %d, non-zero = %d", withCreation1h, nonZeroCreation1h)
	}
}

// One request priced term by term: the one-hour subset of the cache writes at
// twice the selected tier's input rate, the rest at the cache-creation rate.
func TestCandidateCostOneHourCacheWritesTermByTerm(t *testing.T) {
	limit := int64(200_000)
	price := CandidatePrice{
		PriceHistoryVersion: 1, Rounding: "half_up_per_million", RequestFeeMicro: 3,
		Rates: PriceRates{InputMicroPerMillion: 9_000_000, OutputMicroPerMillion: 9_000_000, CachedInputMicroPerMillion: 9_000_000, CacheCreationMicroPerMillion: 9_000_000},
		Tiers: []PriceTier{
			{MaxPromptTokens: &limit, Rates: PriceRates{InputMicroPerMillion: 3_165_000, OutputMicroPerMillion: 15_825_000, CachedInputMicroPerMillion: 316_500, CacheCreationMicroPerMillion: 3_956_250}},
			{Rates: PriceRates{InputMicroPerMillion: 6_330_000, OutputMicroPerMillion: 23_737_500, CachedInputMicroPerMillion: 633_000, CacheCreationMicroPerMillion: 7_912_500}},
		},
	}
	// Prompt = 14 + 6081 + 2000 = 8095 tokens: the first tier.
	//   request fee                                   3
	//   input        14 * 3_165_000 / 1e6 =   44.31 -> 44
	//   output        6 * 15_825_000 / 1e6 =  94.95 -> 95
	//   cache read 6081 * 316_500 / 1e6 = 1924.6365 -> 1925
	//   5m writes  1200 * 3_956_250 / 1e6 = 4747.5  -> 4748
	//   1h writes   800 * 6_330_000 / 1e6 =            5064
	const want = 3 + 44 + 95 + 1925 + 4748 + 5064
	if got, ok := price.CostMicrodollars(14, 6, 6081, 2000, 800, 0); !ok || got != want {
		t.Fatalf("cost = %d, %v; want %d", got, ok, want)
	}
	// With no one-hour count every write keeps the cache-creation rate:
	//   writes     2000 * 3_956_250 / 1e6 = 7912.5 -> 7913
	const allFiveMinute = 3 + 44 + 95 + 1925 + 7913
	if got, ok := price.CostMicrodollars(14, 6, 6081, 2000, 0, 0); !ok || got != allFiveMinute {
		t.Fatalf("five-minute cost = %d, %v; want %d", got, ok, allFiveMinute)
	}
	// A count above the total, or below zero, is bounded to the writes made.
	const allOneHour = 3 + 44 + 95 + 1925 + 12_660
	if got, ok := price.CostMicrodollars(14, 6, 6081, 2000, 2001, 0); !ok || got != allOneHour {
		t.Fatalf("clamped cost = %d, %v; want %d", got, ok, allOneHour)
	}
	if got, ok := price.CostMicrodollars(14, 6, 6081, 2000, -5, 0); !ok || got != allFiveMinute {
		t.Fatalf("negative count cost = %d, %v; want %d", got, ok, allFiveMinute)
	}
	// The one-hour count is part of the writes: it never moves the tier. A
	// prompt of 200_001 tokens selects the second tier for every term.
	//   input  199_001 * 6_330_000 / 1e6 = 1_259_676.33 -> 1_259_676
	//   5m writes  400 * 7_912_500 / 1e6 =                       3165
	//   1h writes  600 * 12_660_000 / 1e6 =                      7596
	const secondTier = 3 + 1_259_676 + 3165 + 7596
	if got, ok := price.CostMicrodollars(199_001, 0, 0, 1000, 600, 0); !ok || got != secondTier {
		t.Fatalf("second-tier cost = %d, %v; want %d", got, ok, secondTier)
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
			if cost, ok := p.CostMicrodollars(u[0], u[1], u[2], u[3], 0, 0); ok || cost != 0 {
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
