package billingv1

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"testing"
)

const fixtureDir = "../trustedrouter/testdata/async_settlement/"
const fixturePath = fixtureDir + "billing_v1.json"
const fixtureSHA = "4aedf13e4ba30b4d1f0767f829e790c37ce3f957a39c15d1eb6aff8c8734fd81"
const rulesPath = fixtureDir + "billing_v1.rules.json"
const rulesSHA = "ab9bac52a666efb4e268dbec210c1a598e490815bf25501ccc0759fe722ce5c4"
const baseCaseCount, baseRuleCount = 759, 374

// The router's supplement for every provider. The base files stay byte for
// byte as pinned above; the contract is the base minus the names the
// supplement supersedes, then the supplement's own cases and rules, in order.
const supplementPath = fixtureDir + "billing_v1_providers.json"
const supplementSHA = "b74f40c3c079569e63bc8d296ca2a9953e9b09b5b2a5b6eb24b1cf85a2df45f4"
const supplementSchemaPath = fixtureDir + "billing_v1_providers.schema.json"
const supplementSchemaSHA = "de35dba91ae2970afee42f3983de2351264721228ebd8e31a4436b7bf206dc15"
const supplementCaseCount, supplementRuleCount = 24, 18
const supersededCaseCount, supersededRuleCount = 4, 4

type fixtureCase struct {
	RawJSONHex                   *string          `json:"raw_json_hex"`
	ExpectedCanonicalASCII       *string          `json:"expected_canonical_ascii"`
	Name                         string           `json:"name"`
	Operation                    string           `json:"operation"`
	Model                        string           `json:"model"`
	Field                        string           `json:"field"`
	Input                        json.RawMessage  `json:"input"`
	Snapshot                     json.RawMessage  `json:"snapshot"`
	RawUsage                     json.RawMessage  `json:"raw_usage"`
	Context                      json.RawMessage  `json:"context"`
	Phase                        string           `json:"phase"`
	SelectedEndpoint             string           `json:"selected_endpoint"`
	ExpectedError                *string          `json:"expected_error"`
	ExpectedExclusion            *string          `json:"expected_exclusion"`
	ExpectedHash                 *string          `json:"expected_hash"`
	ExpectedChargeMicro          *int64           `json:"expected_charge_micro"`
	ExpectedNormalizedUsage      *NormalizedUsage `json:"expected_normalized_usage"`
	ExpectedTerminalEnvelopeHash *string          `json:"expected_terminal_envelope_hash"`
	EvaluatedUsage               *NormalizedUsage `json:"evaluated_usage"`
	FreezeCacheRate              json.RawMessage  `json:"freeze_cache_rate"`
}
type fixture struct {
	Version  int                        `json:"fixture_version"`
	Identity map[string]json.RawMessage `json:"envelope_identity"`
	Cases    []fixtureCase              `json:"cases"`
}
type fixtureRule struct {
	Name          string   `json:"name"`
	Cases         []string `json:"cases"`
	PositiveCases []string `json:"positive_cases"`
}
type supplement struct {
	Version         int           `json:"fixture_version"`
	BaseFixtureSHA  string        `json:"base_fixture_sha256"`
	BaseRulesSHA    string        `json:"base_rules_sha256"`
	SupersededCases []string      `json:"superseded_cases"`
	SupersededRules []string      `json:"superseded_rules"`
	Cases           []fixtureCase `json:"cases"`
	Rules           []fixtureRule `json:"rules"`
}

func readPinned(t *testing.T, path, sha string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != sha {
		t.Fatalf("%s changed: %s", path, got)
	}
	return raw
}
func loadSupplement(t *testing.T) supplement {
	t.Helper()
	var s supplement
	if err := json.Unmarshal(readPinned(t, supplementPath, supplementSHA), &s); err != nil {
		t.Fatal(err)
	}
	if s.Version != 1 || s.BaseFixtureSHA != fixtureSHA || s.BaseRulesSHA != rulesSHA || len(s.Cases) != supplementCaseCount || len(s.Rules) != supplementRuleCount || len(s.SupersededCases) != supersededCaseCount || len(s.SupersededRules) != supersededRuleCount {
		t.Fatalf("unexpected supplement: version %d, base %s/%s, %d cases, %d rules, %d/%d superseded", s.Version, s.BaseFixtureSHA, s.BaseRulesSHA, len(s.Cases), len(s.Rules), len(s.SupersededCases), len(s.SupersededRules))
	}
	return s
}

// loadFixture returns the merged contract: the base cases without the names
// the supplement supersedes, in base order, then the supplement's cases.
func loadFixture(t *testing.T) fixture {
	t.Helper()
	var f fixture
	if err := json.Unmarshal(readPinned(t, fixturePath, fixtureSHA), &f); err != nil {
		t.Fatal(err)
	}
	if f.Version != 1 || len(f.Cases) != baseCaseCount {
		t.Fatalf("unexpected fixture version/count: %d/%d", f.Version, len(f.Cases))
	}
	s := loadSupplement(t)
	f.Cases = mergeSupplement(t, f.Cases, s.Cases, s.SupersededCases, func(c fixtureCase) string { return c.Name })
	return f
}

// mergeSupplement removes each superseded name from the base exactly once and
// appends the supplement. A supplement entry may take a superseded name (a
// successor rule over the new declaration); every name in the result is unique.
func mergeSupplement[T any](t *testing.T, base, added []T, superseded []string, name func(T) string) []T {
	t.Helper()
	remove := map[string]bool{}
	for _, n := range superseded {
		if remove[n] {
			t.Fatalf("superseded twice: %s", n)
		}
		remove[n] = true
	}
	merged := []T{}
	inBase, kept := map[string]bool{}, map[string]bool{}
	for _, entry := range base {
		n := name(entry)
		if inBase[n] {
			t.Fatalf("duplicate base entry %s", n)
		}
		inBase[n] = true
		if remove[n] {
			delete(remove, n)
			continue
		}
		kept[n] = true
		merged = append(merged, entry)
	}
	for n := range remove {
		t.Fatalf("superseded name absent from the base: %s", n)
	}
	seen := map[string]bool{}
	for _, entry := range added {
		n := name(entry)
		if kept[n] {
			t.Fatalf("supplement entry %s has the name of a base entry that is not superseded", n)
		}
		if seen[n] {
			t.Fatalf("duplicate supplement entry %s", n)
		}
		seen[n] = true
		merged = append(merged, entry)
	}
	return merged
}
func TestFixturePin(t *testing.T) {
	readPinned(t, fixturePath, fixtureSHA)
	readPinned(t, rulesPath, rulesSHA)
	readPinned(t, supplementPath, supplementSHA)
	readPinned(t, supplementSchemaPath, supplementSchemaSHA)
}

// Every literal case executes through the production validator/evaluator. No
// expected charges, normalized counts or hashes are generated by Go or Python.
func TestFixtures(t *testing.T) {
	f := loadFixture(t)
	if len(f.Cases) != baseCaseCount-supersededCaseCount+supplementCaseCount {
		t.Fatalf("unexpected merged count: %d", len(f.Cases))
	}
	executed := map[string]bool{}
	for _, c := range f.Cases {
		if _, exists := executed[c.Name]; exists {
			t.Fatalf("duplicate case %s", c.Name)
		}
		passed := t.Run(c.Name, func(t *testing.T) { runFixture(t, f, c) })
		executed[c.Name] = passed
	}
	t.Run("rules_manifest", func(t *testing.T) { checkRules(t, executed) })
}

// checkRules merges the base rules with the supplement's the same way and
// requires every case a merged rule names to have run successfully, so a rule
// that still names a superseded case fails here.
func checkRules(t *testing.T, executed map[string]bool) {
	t.Helper()
	var base []fixtureRule
	if err := json.Unmarshal(readPinned(t, rulesPath, rulesSHA), &base); err != nil {
		t.Fatal(err)
	}
	if len(base) != baseRuleCount {
		t.Fatalf("rules count: %d", len(base))
	}
	s := loadSupplement(t)
	rules := mergeSupplement(t, base, s.Rules, s.SupersededRules, func(r fixtureRule) string { return r.Name })
	if len(rules) != baseRuleCount-supersededRuleCount+supplementRuleCount {
		t.Fatalf("merged rules count: %d", len(rules))
	}
	for _, r := range rules {
		if r.Name == "" || len(r.Cases) == 0 {
			t.Fatalf("invalid rule %q", r.Name)
		}
		for _, name := range append(r.Cases, r.PositiveCases...) {
			if !executed[name] {
				t.Errorf("rule %s not exercised successfully by %s", r.Name, name)
			}
		}
	}
}
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func checkError(t *testing.T, err error, want *string, c fixtureCase) {
	t.Helper()
	if want == nil {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("expected %s, accepted input", *want)
	}
	var typed *Error
	if !errors.As(err, &typed) {
		t.Fatalf("unclassified error: %v", err)
	}
	if *want == "string_type" {
		field := c.Field
		if c.Operation == "field" {
			field = ""
		}
		if typed.Kind != "string_type" || typed.Field != field {
			t.Fatalf("expected string_type at %q, got %#v", field, typed)
		}
	} else if typed.Code != *want {
		t.Fatalf("want %s, got %#v", *want, typed)
	}
}
func checkHash(t *testing.T, value any, want *string) {
	t.Helper()
	if want == nil {
		return
	}
	var got string
	var err error
	if s, ok := value.(Snapshot); ok {
		got, err = CanonicalHash(s)
	} else {
		raw, e := canonicalBytes(value)
		err = e
		got = fmt.Sprintf("%x", sha256.Sum256(raw))
	}
	if err != nil || got != *want {
		t.Fatalf("hash want %s got %s (%v)", *want, got, err)
	}
}
func runFixture(t *testing.T, f fixture, c fixtureCase) {
	t.Helper()
	if c.Operation != "" {
		value, err := runValidation(t, c)
		checkError(t, err, c.ExpectedError, c)
		if err == nil {
			checkHash(t, value, c.ExpectedHash)
			if c.ExpectedCanonicalASCII != nil {
				raw, e := CanonicalBytes(value)
				if e != nil || string(raw) != *c.ExpectedCanonicalASCII {
					t.Fatalf("canonical bytes: %q, want %q (%v)", raw, *c.ExpectedCanonicalASCII, e)
				}
			}
		}
		return
	}
	s, err := ParseSnapshot(c.Snapshot)
	if err != nil {
		checkError(t, err, c.ExpectedExclusion, c)
		return
	}
	context, err := ParseEligibility(c.Context)
	if err != nil {
		checkError(t, err, c.ExpectedExclusion, c)
		return
	}
	if c.Phase == "requested" {
		endpoints, err := fixtureEndpoints(c.Snapshot, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		_, err = BuildSnapshot(endpoints[:1], context)
		checkError(t, err, c.ExpectedExclusion, c)
		return
	}
	raw, err := ParseRawUsage(c.RawUsage)
	if err != nil {
		checkError(t, err, c.ExpectedExclusion, c)
		return
	}
	result, err := Evaluate(s, c.SelectedEndpoint, raw, context)
	checkError(t, err, c.ExpectedExclusion, c)
	if err != nil {
		return
	}
	if c.ExpectedChargeMicro == nil || result.ChargeMicro != *c.ExpectedChargeMicro {
		t.Fatalf("charge: %+v, want %v", result, c.ExpectedChargeMicro)
	}
	if c.ExpectedNormalizedUsage == nil || result.Usage != *c.ExpectedNormalizedUsage {
		t.Fatalf("usage: %+v, want %+v", result.Usage, c.ExpectedNormalizedUsage)
	}
	envelope := map[string]json.RawMessage{}
	for k, v := range f.Identity {
		envelope[k] = v
	}
	hash, err := CanonicalHash(s)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]any{"selected_endpoint": c.SelectedEndpoint, "snapshot_hash": hash, "usage": result.Usage, "charge_micro": result.ChargeMicro, "route_type": context.RouteType, "streamed": context.Streamed} {
		envelope[k] = mustJSON(t, v)
	}
	e, err := ParseEnvelope(mustJSON(t, envelope))
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateEnvelope(s, e); err != nil {
		t.Fatal(err)
	}
	checkHash(t, e, c.ExpectedTerminalEnvelopeHash)
	encoded, err := CanonicalBytes(s)
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseSnapshot(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := CanonicalBytes(again)
	if err != nil || string(encoded) != string(reencoded) {
		t.Fatal("snapshot round trip changed")
	}
	if c.FreezeCacheRate != nil {
		endpoints, err := fixtureEndpoints(c.Snapshot, c.FreezeCacheRate, true)
		if err != nil {
			t.Fatal(err)
		}
		built, err := BuildSnapshot(endpoints, DefaultEligibility())
		if err != nil {
			t.Fatal(err)
		}
		frozen, err := CanonicalBytes(built)
		if err != nil || string(frozen) != string(encoded) {
			t.Fatalf("freeze mismatch: %s / %s (%v)", frozen, encoded, err)
		}
		evaluated, err := Evaluate(built, c.SelectedEndpoint, raw, context)
		if err != nil || evaluated != result {
			t.Fatalf("built evaluation: %+v (%v)", evaluated, err)
		}
	}
}
func modelTarget(name string) (any, string) {
	switch name {
	case "Frozen":
		return &struct{}{}, "invalid_type"
	case "Eligibility":
		return &Eligibility{}, "invalid_context"
	case "Rates":
		return &Rates{}, "invalid_snapshot"
	case "Tier":
		return &Tier{}, "invalid_snapshot"
	case "Candidate":
		return &Candidate{}, "invalid_snapshot"
	case "BillingSnapshot":
		return &snapshotData{}, "invalid_snapshot"
	case "RawUsage":
		return &RawUsage{}, "invalid_usage"
	case "NormalizedUsage":
		return &NormalizedUsage{}, "invalid_usage"
	case "Evaluation":
		return &Evaluation{}, "invalid_evaluation"
	case "TerminalEnvelope":
		return &TerminalEnvelope{}, "invalid_envelope"
	case "AcceptanceOutcome":
		return &AcceptanceOutcome{}, "invalid_acceptance"
	default:
		panic("unhandled fixture model " + name)
	}
}
func runValidation(t *testing.T, c fixtureCase) (any, error) {
	t.Helper()
	switch c.Operation {
	case "snapshot_json", "envelope_json", "acceptance_json", "eligibility_json", "model_json":
		raw := fixtureJSONInput(t, c)
		switch c.Operation {
		case "snapshot_json":
			return ParseSnapshot(raw)
		case "envelope_json":
			return ParseEnvelope(raw)
		case "acceptance_json":
			return ParseAcceptance(raw)
		case "eligibility_json":
			return ParseEligibility(raw)
		default:
			target, code := modelTarget(c.Model)
			err := parseModel(raw, target, code)
			return reflect.ValueOf(target).Elem().Interface(), err
		}
	case "model", "acceptance":
		name := c.Model
		if c.Operation == "acceptance" {
			name = "AcceptanceOutcome"
		}
		target, code := modelTarget(name)
		err := parseModel(c.Input, target, code)
		return reflect.ValueOf(target).Elem().Interface(), err
	case "field", "type":
		input, err := decodeJSON(c.Input)
		if err != nil {
			t.Fatal(err)
		}
		var dst reflect.Value
		var tag reflect.StructTag
		if c.Operation == "field" {
			target, _ := modelTarget(c.Model)
			typ := reflect.TypeOf(target).Elem()
			found := false
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if field.Tag.Get("json") == c.Field {
					dst = reflect.New(field.Type).Elem()
					tag = field.Tag
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("unknown field %s.%s", c.Model, c.Field)
			}
		} else {
			switch c.Model {
			case "UInt":
				dst = reflect.New(reflect.TypeOf(int64(0))).Elem()
			case "Identity":
				dst = reflect.New(reflect.TypeOf("")).Elem()
				tag = `check:"identity"`
			case "Digest":
				dst = reflect.New(reflect.TypeOf("")).Elem()
				tag = `check:"digest"`
			case "SettlementMode":
				dst = reflect.New(reflect.TypeOf("")).Elem()
				tag = `literal:"sync|async"`
			default:
				t.Fatalf("unhandled primitive %s", c.Model)
			}
		}
		err = validateValue(input, dst, tag, "")
		return dst.Interface(), err
	case "checked":
		// Parse arbitrary-width literal before entering the signed-int64 domain.
		n, err := strconv.ParseInt(string(c.Input), 10, 64)
		if err != nil {
			return nil, failure("arithmetic_overflow")
		}
		return checkedAdd(n, 0)
	case "builder":
		var input struct {
			Candidate json.RawMessage            `json:"candidate"`
			Overrides map[string]json.RawMessage `json:"endpoint_overrides"`
		}
		if err := json.Unmarshal(c.Input, &input); err != nil {
			t.Fatal(err)
		}
		endpoint, err := fixtureEndpoint(input.Candidate, nil, false, input.Overrides)
		if err != nil {
			return nil, err
		}
		return BuildSnapshot([]Endpoint{endpoint}, DefaultEligibility())
	case "envelope":
		s, err := ParseSnapshot(c.Snapshot)
		if err != nil {
			return nil, err
		}
		e, err := ParseEnvelope(c.Input)
		if err != nil {
			return nil, err
		}
		if c.EvaluatedUsage != nil {
			result := Evaluation{Usage: *c.EvaluatedUsage, ChargeMicro: e.ChargeMicro}
			if err = validateGo(result, "invalid_evaluation"); err != nil {
				return nil, err
			}
			err = validateEnvelope(s, e, func(Snapshot, string, RawUsage, Eligibility) (Evaluation, error) { return result, nil })
		} else {
			err = ValidateEnvelope(s, e)
		}
		return e, err
	default:
		t.Fatalf("unhandled operation %q", c.Operation)
		return nil, nil
	}
}

// Match endpoint_from_candidate in the Python harness. Keep raw numeric bytes
// until ParseEndpoint validates them; JSON float/bool/string inputs must not be
// silently coerced by the fixture adapter.
func fixtureEndpoint(raw, cached json.RawMessage, overrideCached bool, overrides map[string]json.RawMessage) (Endpoint, error) {
	var c map[string]json.RawMessage
	if err := json.Unmarshal(raw, &c); err != nil {
		return Endpoint{}, err
	}
	var rates map[string]json.RawMessage
	if err := json.Unmarshal(c["rates"], &rates); err != nil {
		return Endpoint{}, err
	}
	endpoint := map[string]json.RawMessage{"id": c["endpoint_id"], "provider": c["provider"], "model_id": c["model_id"], "usage_type": c["usage_type"], "prompt_price_microdollars_per_million_tokens": rates["input_micro_per_million"], "completion_price_microdollars_per_million_tokens": rates["output_micro_per_million"], "request_price_microdollars": c["request_fee_micro"]}
	var tiers []map[string]json.RawMessage
	if err := json.Unmarshal(c["tiers"], &tiers); err != nil {
		return Endpoint{}, err
	}
	if len(tiers) == 0 {
		tiers = []map[string]json.RawMessage{{"max_prompt_tokens": json.RawMessage("null"), "rates": c["rates"]}}
	}
	converted := []map[string]json.RawMessage{}
	for _, tier := range tiers {
		var r map[string]json.RawMessage
		if err := json.Unmarshal(tier["rates"], &r); err != nil {
			return Endpoint{}, err
		}
		read := r["cached_input_micro_per_million"]
		if overrideCached {
			read = cached
		}
		converted = append(converted, map[string]json.RawMessage{"max_prompt_tokens": tier["max_prompt_tokens"], "prompt_price_microdollars_per_million_tokens": r["input_micro_per_million"], "completion_price_microdollars_per_million_tokens": r["output_micro_per_million"], "prompt_cached_price_microdollars_per_million_tokens": read})
	}
	var err error
	endpoint["price_tiers"], err = json.Marshal(converted)
	if err != nil {
		return Endpoint{}, err
	}
	for key, value := range overrides {
		endpoint[key] = value
	}
	wire, err := json.Marshal(endpoint)
	if err != nil {
		return Endpoint{}, err
	}
	return ParseEndpoint(wire)
}
func fixtureEndpoints(raw, cached json.RawMessage, override bool) ([]Endpoint, error) {
	var s struct {
		Candidates []json.RawMessage `json:"candidates"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	endpoints := []Endpoint{}
	for _, c := range s.Candidates {
		e, err := fixtureEndpoint(c, cached, override, nil)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, e)
	}
	return endpoints, nil
}

// Python strings can hold lone surrogate code points; Go strings cannot represent
// them as valid UTF-8. Preserve those fixture characters as JSON escapes in the
// inner document, so the production decoder sees the same decoded string value.
func fixtureJSONInput(t *testing.T, c fixtureCase) []byte {
	t.Helper()
	if (c.Input != nil) == (c.RawJSONHex != nil) {
		t.Fatal("exactly one of input and raw_json_hex is required")
	}
	if c.RawJSONHex != nil {
		raw, err := hex.DecodeString(*c.RawJSONHex)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var escaped bytes.Buffer
	for i := 0; i < len(c.Input); i++ {
		if c.Input[i] == '\\' {
			u, ok := unicodeEscape(c.Input[i:])
			if ok && u >= 0xd800 && u <= 0xdfff {
				low, paired := unicodeEscape(c.Input[i+6:])
				if u <= 0xdbff && paired && low >= 0xdc00 && low <= 0xdfff {
					escaped.Write(c.Input[i : i+12])
					i += 11
					continue
				}
				escaped.WriteByte('\\')
			}
			escaped.WriteByte(c.Input[i])
			i++
		}
		if i < len(c.Input) {
			escaped.WriteByte(c.Input[i])
		}
	}
	var raw string
	if err := json.Unmarshal(escaped.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	return []byte(raw)
}
