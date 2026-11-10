package billingv1

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Every expected count, charge and hash in this file is a literal worked from
// the literal rates and counts beside it. None is produced by the code under test.

// candidateText is one candidate with fixed rates, in microdollars per million
// tokens: input 3000000, cached input 300000, cache creation 3750000, output
// 15000000. provider is spliced in as JSON text, so a caller can pass a string
// outside the identity alphabet or a value that is not a string.
func candidateText(endpoint, provider, model, convention string) string {
	return `{"endpoint_id":"` + endpoint + `","provider":` + provider + `,"model_id":"` + model + `",` +
		`"usage_type":"Credits","price_history_version":1,` +
		`"rates":{"input_micro_per_million":3000000,"cached_input_micro_per_million":300000,` +
		`"cache_creation_micro_per_million":3750000,"output_micro_per_million":15000000},` +
		`"tiers":[],"request_fee_micro":0,"rounding":"half_up_per_million",` +
		`"prompt_convention":"` + convention + `","output_convention":"includes_reasoning"}`
}

// snapshotText wraps candidates, given in endpoint order, as snapshot JSON.
func snapshotText(candidates ...string) []byte {
	return []byte(`{"v":1,"kind":"credits_endpoint","candidates":[` + strings.Join(candidates, ",") + `],` +
		`"minimum_charge":"one_micro_if_positive","charge_cap":null,"tier_basis":"total_prompt",` +
		`"tier_boundary":"inclusive","tier_fallback":"last_tier"}`)
}

func quoted(t *testing.T, value string) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func acceptedSnapshot(t *testing.T, raw []byte) Snapshot {
	t.Helper()
	s, err := ParseSnapshot(raw)
	if err != nil {
		t.Fatalf("refused %s: %v", raw, err)
	}
	return s
}

// refusedSnapshot returns the typed error of a snapshot that must not parse, so
// each test can also check which rule refused it.
func refusedSnapshot(t *testing.T, raw []byte) *Error {
	t.Helper()
	_, err := ParseSnapshot(raw)
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != "invalid_snapshot" {
		t.Fatalf("want invalid_snapshot, got %v for %s", err, raw)
	}
	return typed
}

// settled evaluates one endpoint, then passes the result through the envelope
// check the enclave runs before it sends an async settlement.
func settled(t *testing.T, s Snapshot, endpoint string, raw RawUsage) Evaluation {
	t.Helper()
	result, err := Evaluate(s, endpoint, raw, DefaultEligibility())
	if err != nil {
		t.Fatal(err)
	}
	hash, err := CanonicalHash(s)
	if err != nil {
		t.Fatal(err)
	}
	envelope := TerminalEnvelope{
		V: 1, AuthorizationID: "auth-v1", GenerationID: "gen-v1", WorkspaceID: "ws-v1", KeyID: "key-v1",
		InvocationNonce: "nonce-v1", BillingAuthority: "local", JournalRegion: "us-central1", Epoch: 1,
		SelectedEndpoint: endpoint, SnapshotVersion: 1, SnapshotHash: hash, Usage: result.Usage,
		ChargeMicro: result.ChargeMicro, TerminalKind: "settle", RouteType: "chat.completions",
	}
	if err = ValidateEnvelope(s, envelope); err != nil {
		t.Fatal(err)
	}
	envelope.ChargeMicro++
	var typed *Error
	if err = ValidateEnvelope(s, envelope); !errors.As(err, &typed) || typed.Code != "charge_mismatch" {
		t.Fatalf("a changed charge passed the envelope check: %v", err)
	}
	return result
}

// A provider serving another publisher's model: the model identifier does not
// begin with the provider slug.
func TestResoldModelParsesAndEvaluates(t *testing.T) {
	const endpoint = "deepseek/billing-v1@venice/prepaid"
	s := acceptedSnapshot(t, snapshotText(candidateText(endpoint, `"venice"`, "deepseek/billing-v1", "includes_cache")))
	candidates := s.Candidates()
	if len(candidates) != 1 || candidates[0].Provider != "venice" || candidates[0].ModelID != "deepseek/billing-v1" || candidates[0].PromptConvention != "includes_cache" {
		t.Fatalf("candidate changed: %+v", candidates)
	}
	// The input count includes the cache: 2001 - 2 = 1999 uncached.
	// 1999 * 3000000 = 5997000000 -> 5997
	//    2 *  300000 =     600000 ->    1 (0.6 rounds half up)
	//    7 * 15000000 = 105000000 ->  105
	got := settled(t, s, endpoint, RawUsage{InputTokens: 2001, OutputTokens: 7, CacheReadTokens: 2})
	want := Evaluation{Usage: NormalizedUsage{UncachedInputTokens: 1999, TotalPromptTokens: 2001, OutputTokens: 7, CacheReadTokens: 2}, ChargeMicro: 6103}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	// More cached tokens than the input count cannot be a count that includes them.
	_, err := Evaluate(s, endpoint, RawUsage{InputTokens: 2, OutputTokens: 7, CacheReadTokens: 3}, DefaultEligibility())
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != "malformed_usage" {
		t.Fatalf("want malformed_usage, got %v", err)
	}
}

// amazon-bedrock and google-vertex serving an anthropic/ model follow Anthropic's
// own convention: the enclave relays those streams in Anthropic's format, whose
// input count leaves out the cache (internal/llm/billing_convention_test.go ties
// the rule to that dispatch). The same providers serving any other model keep
// an input count that includes the cache.
func TestResoldAnthropicModelsExcludeCache(t *testing.T) {
	const (
		other   = "amazon/billing-v1@amazon-bedrock/prepaid"
		bedrock = "anthropic/billing-v1@amazon-bedrock/prepaid"
		direct  = "anthropic/billing-v1@anthropic/prepaid"
		vertex  = "anthropic/billing-v1@google-vertex/prepaid"
	)
	s := acceptedSnapshot(t, snapshotText(
		candidateText(other, `"amazon-bedrock"`, "amazon/billing-v1", "includes_cache"),
		candidateText(bedrock, `"amazon-bedrock"`, "anthropic/billing-v1", "excludes_cache"),
		candidateText(direct, `"anthropic"`, "anthropic/billing-v1", "excludes_cache"),
		candidateText(vertex, `"google-vertex"`, "anthropic/billing-v1", "excludes_cache"),
	))
	raw := RawUsage{InputTokens: 1000, OutputTokens: 200, CacheReadTokens: 600, CacheCreationTokens: 100, ReasoningTokens: 50}
	// Cache outside the input count: 1000 uncached of a 1000 + 600 + 100 = 1700-token prompt.
	// 1000 * 3000000 -> 3000; 600 * 300000 -> 180; 100 * 3750000 -> 375; 200 * 15000000 -> 3000.
	excluded := Evaluation{Usage: NormalizedUsage{UncachedInputTokens: 1000, TotalPromptTokens: 1700, OutputTokens: 200, CacheReadTokens: 600, CacheCreationTokens: 100, ReasoningTokens: 50}, ChargeMicro: 6555}
	for _, endpoint := range []string{bedrock, direct, vertex} {
		if got := settled(t, s, endpoint, raw); got != excluded {
			t.Fatalf("%s: got %+v, want %+v", endpoint, got, excluded)
		}
	}
	// Cache inside the input count: 1000 - 600 - 100 = 300 uncached of a 1000-token prompt.
	// 300 * 3000000 -> 900; 180; 375; 3000.
	included := Evaluation{Usage: NormalizedUsage{UncachedInputTokens: 300, TotalPromptTokens: 1000, OutputTokens: 200, CacheReadTokens: 600, CacheCreationTokens: 100, ReasoningTokens: 50}, ChargeMicro: 4455}
	if got := settled(t, s, other, raw); got != included {
		t.Fatalf("%s: got %+v, want %+v", other, got, included)
	}
	// The other convention is refused for each of them.
	for _, candidate := range []string{
		candidateText(bedrock, `"amazon-bedrock"`, "anthropic/billing-v1", "includes_cache"),
		candidateText(vertex, `"google-vertex"`, "anthropic/billing-v1", "includes_cache"),
		candidateText(other, `"amazon-bedrock"`, "amazon/billing-v1", "excludes_cache"),
	} {
		refused := refusedSnapshot(t, snapshotText(candidate))
		if refused.Field != "candidates[0]" || !strings.HasPrefix(refused.Kind, "unsupported_adapter") {
			t.Fatalf("refused by another rule: %#v", refused)
		}
	}
}

func TestProviderOutsideIdentityPatternRefused(t *testing.T) {
	const endpoint, model = "openai/billing-v1@openai/prepaid", "openai/billing-v1"
	for _, provider := range []string{
		"", " ", "a b", "openai ", " openai", "x\n", "\topenai", "\u00e9", "open\u00e4i", "a!b", `a"b`, "a<b", "a>b", "a&b",
		"a,b", "a;b", "a*b", "a?b", "a#b", "a%b", "a=b", "a~b", "a|b", "a\\b", "a'b", "a`b", "a$b", "a^b", "(a)", "[a]", "{a}",
		strings.Repeat("x", 513),
	} {
		refused := refusedSnapshot(t, snapshotText(candidateText(endpoint, quoted(t, provider), model, "includes_cache")))
		if refused.Field != "candidates[0].provider" || refused.Kind != "invalid identity" {
			t.Fatalf("%q refused by another rule: %#v", provider, refused)
		}
	}
	for _, provider := range []string{`123`, `null`, `true`, `["openai"]`, `{"slug":"openai"}`} {
		refused := refusedSnapshot(t, snapshotText(candidateText(endpoint, provider, model, "includes_cache")))
		if refused.Field != "candidates[0].provider" || refused.Kind != "string_type" {
			t.Fatalf("%s refused by another rule: %#v", provider, refused)
		}
	}
	// The same candidate parses with a provider inside the pattern, at both
	// length bounds and with every punctuation mark the alphabet allows.
	for _, provider := range []string{"a", strings.Repeat("x", 512), "AZaz09_./:@+-", "amazon-bedrock", "google-ai-studio", "z.ai"} {
		s := acceptedSnapshot(t, snapshotText(candidateText(endpoint, quoted(t, provider), model, "includes_cache")))
		if got := s.Candidates()[0].Provider; got != provider {
			t.Fatalf("provider changed: %q", got)
		}
	}
}

// excludes_cache exactly for the provider "anthropic", whatever the model, and
// for "amazon-bedrock" or "google-vertex" when the model identifier begins with
// "anthropic/". Nothing else: not another slug, spelling or publisher.
func TestPromptConventionRule(t *testing.T) {
	const endpoint = "m/billing-v1@p/prepaid"
	for _, tc := range []struct {
		provider, model string
		excludes        bool
	}{
		{"anthropic", "anthropic/billing-v1", true}, {"anthropic", "openai/billing-v1", true}, {"anthropic", "billing-v1", true},
		{"amazon-bedrock", "anthropic/billing-v1", true}, {"google-vertex", "anthropic/billing-v1", true},
		{"amazon-bedrock", "amazon/billing-v1", false}, {"amazon-bedrock", "anthropic", false}, {"amazon-bedrock", "anthropic-x/billing-v1", false},
		{"amazon-bedrock", "Anthropic/billing-v1", false}, {"amazon-bedrock", "x/anthropic/billing-v1", false},
		{"google-vertex", "google/billing-v1", false}, {"google-vertex", "anthropicx/billing-v1", false},
		{"openai", "anthropic/billing-v1", false}, {"azure", "anthropic/billing-v1", false}, {"venice", "anthropic/billing-v1", false},
		{"Anthropic", "anthropic/billing-v1", false}, {"ANTHROPIC", "anthropic/billing-v1", false}, {"anthropic-vertex", "anthropic/billing-v1", false},
		{"anthropic.", "anthropic/billing-v1", false}, {"anthropic/claude", "anthropic/billing-v1", false}, {"x-anthropic", "anthropic/billing-v1", false},
		{"anthropi", "anthropic/billing-v1", false}, {"Amazon-Bedrock", "anthropic/billing-v1", false}, {"amazon-bedrock-eu", "anthropic/billing-v1", false},
		{"Google-Vertex", "anthropic/billing-v1", false}, {"google-vertex-eu", "anthropic/billing-v1", false},
	} {
		want, wrong := "includes_cache", "excludes_cache"
		if tc.excludes {
			want, wrong = wrong, want
		}
		if got := PromptConvention(tc.provider, tc.model); got != want {
			t.Fatalf("%s %s: %s", tc.provider, tc.model, got)
		}
		acceptedSnapshot(t, snapshotText(candidateText(endpoint, quoted(t, tc.provider), tc.model, want)))
		refused := refusedSnapshot(t, snapshotText(candidateText(endpoint, quoted(t, tc.provider), tc.model, wrong)))
		if refused.Field != "candidates[0]" || !strings.HasPrefix(refused.Kind, "unsupported_adapter") {
			t.Fatalf("%s %s with %s refused by another rule: %#v", tc.provider, tc.model, wrong, refused)
		}
	}
}

// Six candidates from four providers. The same anthropic/ model is served by
// anthropic, amazon-bedrock and google-vertex at the same rates; amazon-bedrock
// also serves another publisher's model; one candidate has price tiers.
const mixedProviderSnapshot = `{
  "v": 1,
  "kind": "credits_endpoint",
  "candidates": [
    {
      "endpoint_id": "amazon/billing-v1@amazon-bedrock/prepaid",
      "provider": "amazon-bedrock",
      "model_id": "amazon/billing-v1",
      "usage_type": "Credits",
      "price_history_version": 1,
      "rates": {"input_micro_per_million": 800000, "cached_input_micro_per_million": 800000, "cache_creation_micro_per_million": 1000000, "output_micro_per_million": 3200000},
      "tiers": [],
      "request_fee_micro": 0,
      "rounding": "half_up_per_million",
      "prompt_convention": "includes_cache",
      "output_convention": "includes_reasoning"
    },
    {
      "endpoint_id": "anthropic/billing-v1@amazon-bedrock/prepaid",
      "provider": "amazon-bedrock",
      "model_id": "anthropic/billing-v1",
      "usage_type": "Credits",
      "price_history_version": 1,
      "rates": {"input_micro_per_million": 3000000, "cached_input_micro_per_million": 300000, "cache_creation_micro_per_million": 3750000, "output_micro_per_million": 15000000},
      "tiers": [],
      "request_fee_micro": 0,
      "rounding": "half_up_per_million",
      "prompt_convention": "excludes_cache",
      "output_convention": "includes_reasoning"
    },
    {
      "endpoint_id": "anthropic/billing-v1@anthropic/prepaid",
      "provider": "anthropic",
      "model_id": "anthropic/billing-v1",
      "usage_type": "Credits",
      "price_history_version": 1,
      "rates": {"input_micro_per_million": 3000000, "cached_input_micro_per_million": 300000, "cache_creation_micro_per_million": 3750000, "output_micro_per_million": 15000000},
      "tiers": [],
      "request_fee_micro": 0,
      "rounding": "half_up_per_million",
      "prompt_convention": "excludes_cache",
      "output_convention": "includes_reasoning"
    },
    {
      "endpoint_id": "anthropic/billing-v1@google-vertex/prepaid",
      "provider": "google-vertex",
      "model_id": "anthropic/billing-v1",
      "usage_type": "Credits",
      "price_history_version": 1,
      "rates": {"input_micro_per_million": 3000000, "cached_input_micro_per_million": 300000, "cache_creation_micro_per_million": 3750000, "output_micro_per_million": 15000000},
      "tiers": [],
      "request_fee_micro": 0,
      "rounding": "half_up_per_million",
      "prompt_convention": "excludes_cache",
      "output_convention": "includes_reasoning"
    },
    {
      "endpoint_id": "deepseek/billing-v1@venice/prepaid",
      "provider": "venice",
      "model_id": "deepseek/billing-v1",
      "usage_type": "Credits",
      "price_history_version": 1,
      "rates": {"input_micro_per_million": 700000, "cached_input_micro_per_million": 700000, "cache_creation_micro_per_million": 875000, "output_micro_per_million": 1100000},
      "tiers": [],
      "request_fee_micro": 0,
      "rounding": "half_up_per_million",
      "prompt_convention": "includes_cache",
      "output_convention": "includes_reasoning"
    },
    {
      "endpoint_id": "openai/billing-v1@azure/prepaid",
      "provider": "azure",
      "model_id": "openai/billing-v1",
      "usage_type": "Credits",
      "price_history_version": 1,
      "rates": {"input_micro_per_million": 2500000, "cached_input_micro_per_million": 1250000, "cache_creation_micro_per_million": 3125000, "output_micro_per_million": 10000000},
      "tiers": [
        {"max_prompt_tokens": 1000, "rates": {"input_micro_per_million": 2500000, "cached_input_micro_per_million": 1250000, "cache_creation_micro_per_million": 3125000, "output_micro_per_million": 10000000}},
        {"max_prompt_tokens": null, "rates": {"input_micro_per_million": 5000000, "cached_input_micro_per_million": 2500000, "cache_creation_micro_per_million": 6250000, "output_micro_per_million": 15000000}}
      ],
      "request_fee_micro": 0,
      "rounding": "half_up_per_million",
      "prompt_convention": "includes_cache",
      "output_convention": "includes_reasoning"
    }
  ],
  "minimum_charge": "one_micro_if_positive",
  "charge_cap": null,
  "tier_basis": "total_prompt",
  "tier_boundary": "inclusive",
  "tier_fallback": "last_tier"
}`

// SHA-256 of the snapshot above as compact ASCII JSON with sorted keys, taken
// with Python's json and hashlib modules.
const mixedProviderSnapshotHash = "2133e39ecfb5ed32599a00ce33cba5fa660ec73d6599dc97c039fcc20776836c"

func TestMixedProviderSnapshot(t *testing.T) {
	s := acceptedSnapshot(t, []byte(mixedProviderSnapshot))
	var providers []string
	for _, c := range s.Candidates() {
		providers = append(providers, c.Provider+" "+c.PromptConvention)
	}
	if got := strings.Join(providers, ", "); got != "amazon-bedrock includes_cache, amazon-bedrock excludes_cache, anthropic excludes_cache, google-vertex excludes_cache, venice includes_cache, azure includes_cache" {
		t.Fatalf("candidates changed: %s", got)
	}
	hash, err := CanonicalHash(s)
	if err != nil || hash != mixedProviderSnapshotHash {
		t.Fatalf("hash %s (%v)", hash, err)
	}
	encoded, err := CanonicalBytes(s)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := CanonicalBytes(acceptedSnapshot(t, encoded)); err != nil || string(again) != string(encoded) {
		t.Fatalf("round trip changed the snapshot (%v)", err)
	}

	raw := RawUsage{InputTokens: 1000, OutputTokens: 200, CacheReadTokens: 600, CacheCreationTokens: 100, ReasoningTokens: 50}
	included := NormalizedUsage{UncachedInputTokens: 300, TotalPromptTokens: 1000, OutputTokens: 200, CacheReadTokens: 600, CacheCreationTokens: 100, ReasoningTokens: 50}
	excluded := NormalizedUsage{UncachedInputTokens: 1000, TotalPromptTokens: 1700, OutputTokens: 200, CacheReadTokens: 600, CacheCreationTokens: 100, ReasoningTokens: 50}
	for _, tc := range []struct {
		endpoint string
		want     Evaluation
	}{
		// 300 * 800000 -> 240; 600 * 800000 -> 480; 100 * 1000000 -> 100; 200 * 3200000 -> 640.
		{"amazon/billing-v1@amazon-bedrock/prepaid", Evaluation{Usage: included, ChargeMicro: 1460}},
		// 1000 * 3000000 -> 3000; 600 * 300000 -> 180; 100 * 3750000 -> 375; 200 * 15000000 -> 3000.
		{"anthropic/billing-v1@amazon-bedrock/prepaid", Evaluation{Usage: excluded, ChargeMicro: 6555}},
		{"anthropic/billing-v1@anthropic/prepaid", Evaluation{Usage: excluded, ChargeMicro: 6555}},
		{"anthropic/billing-v1@google-vertex/prepaid", Evaluation{Usage: excluded, ChargeMicro: 6555}},
		// 300 * 700000 -> 210; 600 * 700000 -> 420; 100 * 875000 = 87500000 -> 88 (half up); 200 * 1100000 -> 220.
		{"deepseek/billing-v1@venice/prepaid", Evaluation{Usage: included, ChargeMicro: 938}},
		// A 1000-token prompt is inside the first tier (inclusive bound 1000).
		// 300 * 2500000 -> 750; 600 * 1250000 -> 750; 100 * 3125000 = 312500000 -> 313 (half up); 200 * 10000000 -> 2000.
		{"openai/billing-v1@azure/prepaid", Evaluation{Usage: included, ChargeMicro: 3813}},
	} {
		if got := settled(t, s, tc.endpoint, raw); got != tc.want {
			t.Fatalf("%s: got %+v, want %+v", tc.endpoint, got, tc.want)
		}
	}
	// One more input token passes the first tier's bound: 301 uncached of 1001.
	// 301 * 5000000 -> 1505; 600 * 2500000 -> 1500; 100 * 6250000 -> 625; 200 * 15000000 -> 3000.
	raw.InputTokens = 1001
	got := settled(t, s, "openai/billing-v1@azure/prepaid", raw)
	want := Evaluation{Usage: NormalizedUsage{UncachedInputTokens: 301, TotalPromptTokens: 1001, OutputTokens: 200, CacheReadTokens: 600, CacheCreationTokens: 100, ReasoningTokens: 50}, ChargeMicro: 6630}
	if got != want {
		t.Fatalf("second tier: got %+v, want %+v", got, want)
	}

	// One refused candidate refuses the whole snapshot, wherever it sits.
	refused := refusedSnapshot(t, snapshotText(
		candidateText("amazon/billing-v1@amazon-bedrock/prepaid", `"amazon-bedrock"`, "amazon/billing-v1", "includes_cache"),
		candidateText("anthropic/billing-v1@amazon-bedrock/prepaid", `"amazon-bedrock"`, "anthropic/billing-v1", "includes_cache"),
		candidateText("deepseek/billing-v1@venice/prepaid", `"venice"`, "deepseek/billing-v1", "includes_cache"),
	))
	if refused.Field != "candidates[1]" || !strings.HasPrefix(refused.Kind, "unsupported_adapter") {
		t.Fatalf("refused by another rule: %#v", refused)
	}
	// Candidates are ordered by endpoint whatever their providers.
	refused = refusedSnapshot(t, snapshotText(
		candidateText("b/billing-v1@amazon-bedrock/prepaid", `"amazon-bedrock"`, "b/billing-v1", "includes_cache"),
		candidateText("a/billing-v1@venice/prepaid", `"venice"`, "a/billing-v1", "includes_cache"),
	))
	if refused.Field != "" || !strings.HasPrefix(refused.Kind, "candidates must be unique and sorted") {
		t.Fatalf("refused by another rule: %#v", refused)
	}
}

// BuildSnapshot is a test-only mirror of the router's builder. It holds a cache
// price rule for the listed providers only, and must refuse any other provider
// instead of freezing its rates with a listed provider's rule.
func TestBuilderRefusesProviderWithoutCacheRule(t *testing.T) {
	endpointTextFor := func(provider, model string) []byte {
		return []byte(`{"id":"` + model + `@reseller/prepaid","provider":` + provider + `,"model_id":"` + model + `","usage_type":"Credits",` +
			`"prompt_price_microdollars_per_million_tokens":1000000,"completion_price_microdollars_per_million_tokens":2000000,"request_price_microdollars":0,` +
			`"price_tiers":[{"max_prompt_tokens":null,"prompt_price_microdollars_per_million_tokens":1000000,` +
			`"completion_price_microdollars_per_million_tokens":2000000,"prompt_cached_price_microdollars_per_million_tokens":250000}]}`)
	}
	endpointText := func(provider string) []byte { return endpointTextFor(provider, "deepseek/billing-v1") }
	requireBuilderRefusal := func(err error, provider string) {
		t.Helper()
		var typed *Error
		if !errors.As(err, &typed) || typed.Code != "invalid_builder" || typed.Field != "provider" || typed.Kind != "no cache price rule" {
			t.Fatalf("%s: want the cache price rule refusal, got %v", provider, err)
		}
	}
	explicit := int64(250000)
	for _, provider := range []string{"venice", "mistral", "azure", "Anthropic", "openai2", "vertex", "gemini", "Amazon-Bedrock"} {
		endpoint, err := ParseEndpoint(endpointText(quoted(t, provider)))
		if err != nil || endpoint.Provider != provider {
			t.Fatalf("%s: endpoint did not parse: %v", provider, err)
		}
		_, err = BuildSnapshot([]Endpoint{endpoint}, DefaultEligibility())
		requireBuilderRefusal(err, provider)
		// An explicit cached price does not stand in for the provider's rule:
		// the top-level rates and the cache-write price still need it.
		_, err = freezeRates(provider, 1000000, 2000000, &explicit)
		requireBuilderRefusal(err, provider)
		_, err = freezeRates(provider, 1000000, 2000000, nil)
		requireBuilderRefusal(err, provider)
		// A requested exclusion is still reported first, as for every provider.
		requested := DefaultEligibility()
		requested.CustomModel = true
		var typed *Error
		if _, err = BuildSnapshot([]Endpoint{endpoint}, requested); !errors.As(err, &typed) || typed.Code != "custom_model" {
			t.Fatalf("%s: want custom_model, got %v", provider, err)
		}
		// One endpoint without a rule refuses the whole build.
		listed, err := ParseEndpoint([]byte(strings.Replace(string(endpointText(`"openai"`)), "@reseller/", "@openai/", 1)))
		if err != nil {
			t.Fatal(err)
		}
		_, err = BuildSnapshot([]Endpoint{listed, endpoint}, DefaultEligibility())
		requireBuilderRefusal(err, provider)
	}
	// The same endpoint builds under each listed provider, with that provider's
	// own default cache-read price (1000000 / 2, / 10, / 4 and / 1), the
	// explicit tier price, the 5/4 cache-write price and the convention the
	// provider and model imply.
	for _, tc := range []struct {
		provider, model, convention string
		read                        int64
	}{
		{"openai", "deepseek/billing-v1", "includes_cache", 500000},
		{"anthropic", "deepseek/billing-v1", "excludes_cache", 100000},
		{"google-vertex", "deepseek/billing-v1", "includes_cache", 250000},
		{"google-vertex", "anthropic/billing-v1", "excludes_cache", 250000},
		{"amazon-bedrock", "deepseek/billing-v1", "includes_cache", 1000000},
		{"amazon-bedrock", "anthropic/billing-v1", "excludes_cache", 1000000},
	} {
		endpoint, err := ParseEndpoint(endpointTextFor(quoted(t, tc.provider), tc.model))
		if err != nil {
			t.Fatal(err)
		}
		s, err := BuildSnapshot([]Endpoint{endpoint}, DefaultEligibility())
		if err != nil {
			t.Fatalf("%s %s: %v", tc.provider, tc.model, err)
		}
		c := s.Candidates()[0]
		top := Rates{InputMicroPerMillion: 1000000, CachedInputMicroPerMillion: tc.read, CacheCreationMicroPerMillion: 1250000, OutputMicroPerMillion: 2000000}
		tier := Rates{InputMicroPerMillion: 1000000, CachedInputMicroPerMillion: 250000, CacheCreationMicroPerMillion: 1250000, OutputMicroPerMillion: 2000000}
		if c.Provider != tc.provider || c.ModelID != tc.model || c.PromptConvention != tc.convention || c.Rates != top || len(c.Tiers) != 1 || c.Tiers[0].Rates != tier {
			t.Fatalf("%s %s: built %+v", tc.provider, tc.model, c)
		}
	}
	// The builder's endpoint parser applies the same provider pattern.
	for _, provider := range []string{`""`, `"a b"`, `"a!b"`, `123`, `null`} {
		_, err := ParseEndpoint(endpointText(provider))
		var typed *Error
		if !errors.As(err, &typed) || typed.Code != "invalid_builder" || typed.Field != "provider" {
			t.Fatalf("%s: want invalid_builder at provider, got %v", provider, err)
		}
	}
}
