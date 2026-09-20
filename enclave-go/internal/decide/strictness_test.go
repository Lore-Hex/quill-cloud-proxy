package decide

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Every case in this file is an input that once passed Verify while returning
// something the model did not say. Each names the reading that was wrong.

func wantKind(t *testing.T, label string, err error, kind string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: accepted", label)
	}
	if got := ViolationKind(err); got != kind {
		t.Fatalf("%s: kind = %q, want %q (%v)", label, got, kind, err)
	}
}

const oneBoolean = `{"sure":{"type":"boolean","instructions":"Is it?"}}`
const threeWay = `{"pick":{"type":"choice","instructions":"Pick.","criteria":{"a":"A","b":"B","c":"C"}}}`

func TestExtractNativeTakesExactlyOneObjectOrNothing(t *testing.T) {
	specs := questions(t, oneBoolean)
	// STATE is caller text the model may quote. Every arrangement below once
	// returned the QUOTED 0.01 under some version of "find the real answer":
	// first-object-wins; top-level-only search (the answer was in a wrapper); a
	// depth or node budget that ran out before the answer; an answer inside a
	// JSON string; a second answer nested under the first.
	for label, text := range map[string]string{
		"quoted then answered":        `STATE contained {"q0":0.01}. My answer is {"q0":0.99}`,
		"answer in a wrapper":         `STATE contained {"q0":0.01}. My answer is {"answer":{"q0":0.99}}`,
		"answer in a string":          `STATE said {"q0":0.01}. My answer is {"answer":"{\"q0\":0.99}"}`,
		"answer wrapped seven deep":   `{"q0":0.01} then {"a":{"b":{"c":{"d":{"e":{"f":{"g":{"q0":0.99}}}}}}}}`,
		"said twice":                  `{"q0":0.99} Final: {"q0": 0.99}`,
		"said twice, reformatted":     `{"q0":0.5} and {"q0":0.50000000000000001}`,
		"an unrelated object as well": `Config {"temperature":0} gives {"q0":0.99}`,
		"an unusable second object":   `{"q0":0.9} Debug: {"q0":"request-id"}`,
	} {
		_, err := ExtractNative(specs, text)
		wantKind(t, label, err, KindAmbiguous)
	}
	// A second answer hidden UNDER the first, or behind a long array.
	_, err := ExtractNative(specs, `{"q0":0.01,"answer":{"q0":0.99}}`)
	wantKind(t, "a structure under a non-question key", err, KindAmbiguous)
	_, err = ExtractNative(specs, `{"answer":{"q0":0.99}}`)
	wantKind(t, "a wrapper alone: the answer is not at the top of the one object", err, KindAmbiguous)
	padded := `{"q0":0.01,"items":[` + strings.Repeat("0,", 600) + `{"q0":0.99}]}`
	_, err = ExtractNative(specs, padded)
	wantKind(t, "an answer behind 600 array items", err, KindAmbiguous)
	// One object that is not the answer is not an answer.
	for label, text := range map[string]string{
		"something else":    `{"temperature":0}`,
		"no object at all":  `I think it is likely.`,
		"an unclosed brace": `{"q0":0.99`,
	} {
		_, err := ExtractNative(specs, text)
		wantKind(t, label, err, KindNotJSON)
	}
	// Form around the one object is still form.
	for label, text := range map[string]string{
		"stray brace in prose":  "Use { carefully. Answer: {\"q0\":0.99}",
		"fenced":                "```json\n{\"q0\":0.99}\n```",
		"brace inside a string": `{"note":"a } and a { brace","q0":0.99}`,
		"scalar commentary":     `{"q0":0.99,"confidence":"high","checked":true,"n":3,"extra":null}`,
		"in an array":           `[{"q0":0.99}]`,
	} {
		answers, err := ExtractNative(specs, text)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if got := *answers["sure"].Probability; got != 0.99 {
			t.Fatalf("%s: probability = %v", label, got)
		}
	}
}

func TestExtractNativeBoundsItsSearch(t *testing.T) {
	specs := questions(t, oneBoolean)
	_, err := ExtractNative(specs, strings.Repeat("{", 100_000))
	wantKind(t, "nothing but open braces", err, KindNotJSON)
}

func TestExtractNativeRefusesDuplicateKeys(t *testing.T) {
	// Go's decoder keeps the last value silently: this verified as 0.9.
	_, err := ExtractNative(questions(t, oneBoolean), `{"q0":0.1,"q0":0.9}`)
	wantKind(t, "question given twice", err, KindDuplicate)

	_, err = ExtractNative(questions(t, threeWay), `{"q0":{"q0_o0":0.9,"q0_o0":0.1,"q0_o1":0.05,"q0_o2":0.05}}`)
	wantKind(t, "option given twice", err, KindDuplicate)
}

func TestCheckNoDuplicateKeys(t *testing.T) {
	for label, raw := range map[string]string{
		"siblings may share keys": `{"a":{"k":1},"b":{"k":2},"c":[{"k":1},{"k":2}]}`,
		"values equal to a key":   `{"a":"a","b":["a","a"]}`,
		"scalar":                  `3`,
	} {
		if err := CheckNoDuplicateKeys([]byte(raw)); err != nil {
			t.Errorf("%s: %v", label, err)
		}
	}
	for label, raw := range map[string]string{
		"top level":       `{"a":1,"a":2}`,
		"nested":          `{"x":{"a":1,"b":{"c":1,"c":2}}}`,
		"inside an array": `{"x":[{"a":1,"a":1}]}`,
		"after an object": `{"a":{"z":1},"b":2,"a":3}`,
	} {
		wantKind(t, label, CheckNoDuplicateKeys([]byte(raw)), KindDuplicate)
	}
	wantKind(t, "not JSON", CheckNoDuplicateKeys([]byte(`{"a":`)), KindNotJSON)
}

func TestExtractNativeRefusesAKeyWithTwoReadings(t *testing.T) {
	// Options sort to ["a", "q0_o0"], so the alias q0_o0 means "a" while the
	// NAME q0_o0 is the other option. Map order used to pick the name: the
	// model answered "a" and the caller was told "q0_o0".
	specs := questions(t, `{"pick":{"type":"choice","instructions":"Pick.","criteria":{"a":"first","q0_o0":"second"}}}`)
	_, err := ExtractNative(specs, `{"q0":{"q0_o0":1}}`)
	wantKind(t, "alias that is also a name", err, KindAmbiguous)

	for text, want := range map[string]string{
		`{"q0":{"a":1}}`:     "a",     // by name, unambiguous
		`{"q0":{"q0_o1":1}}`: "q0_o0", // by alias, unambiguous
	} {
		answers, err := ExtractNative(specs, text)
		if err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		if got := *answers["pick"].Choice; got != want {
			t.Fatalf("%s: choice = %q, want %q", text, got, want)
		}
	}
}

func TestExtractNativePercentScalesOnlyItsOwnValue(t *testing.T) {
	specs := questions(t, `{"pick":{"type":"choice","instructions":"Pick.","criteria":{"a":"A","b":"B"}}}`)
	// One % used to divide EVERY value by 100: 0.8 and 0.002, "normalized" to
	// 0.9975 / 0.0025.
	answers, err := ExtractNative(specs, `{"q0":{"q0_o0":"80%","q0_o1":0.2}}`)
	if err != nil {
		t.Fatal(err)
	}
	dist := answers["pick"].Probabilities
	if math.Abs(dist["a"]-0.8) > 1e-9 || math.Abs(dist["b"]-0.2) > 1e-9 {
		t.Fatalf("got %v, want a=0.8 b=0.2", dist)
	}
	// A mix with no single scale is not guessed at.
	_, err = ExtractNative(specs, `{"q0":{"q0_o0":"80%","q0_o1":20}}`)
	wantKind(t, "percent beside a bare 20", err, KindMass)
}

func TestExtractNativeRefusesMissingMass(t *testing.T) {
	specs := questions(t, threeWay)
	// An omitted option reads as 0, which is only believable when the rest
	// already sums to 1. These were "normalized" to certainty.
	for _, text := range []string{`{"q0":{"q0_o0":75}}`, `{"q0":{"q0_o0":0.75}}`, `{"q0":{"q0_o0":"75%"}}`} {
		_, err := ExtractNative(specs, text)
		wantKind(t, text, err, KindMass)
	}
	// Certainty stated outright is still certainty, in any of its spellings.
	for _, text := range []string{`{"q0":{"q0_o0":1}}`, `{"q0":{"q0_o0":100}}`, `{"q0":{"q0_o0":"100%"}}`, `{"q0":{"q0_o0":0.98,"q0_o1":0.02}}`} {
		answers, err := ExtractNative(specs, text)
		if err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		if got := *answers["pick"].Choice; got != "a" {
			t.Fatalf("%s: choice = %q", text, got)
		}
	}
	// Every option given: the ratios are all there, so sloppy sums normalize.
	answers, err := ExtractNative(specs, `{"q0":{"q0_o0":0.9,"q0_o1":0.1,"q0_o2":0.1}}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := answers["pick"].Probabilities["a"]; math.Abs(got-0.9/1.1) > 1e-9 {
		t.Fatalf("a = %v, want 0.9/1.1", got)
	}
}

func TestExtractNativeBooleanRefusesAnotherTypesAnswer(t *testing.T) {
	specs := questions(t, oneBoolean)
	for _, text := range []string{
		`{"q0":{"probability":0.9,"type":"score","score":0.1}}`,
		`{"q0":{"probability":0.9,"score":0.1}}`,
		`{"q0":{"probability":0.9,"choice":"x","probabilities":{"x":1}}}`,
		`{"q0":{"probability":0.9,"type":"choice"}}`,
	} {
		_, err := ExtractNative(specs, text)
		wantKind(t, text, err, KindType)
	}
	for _, text := range []string{`{"q0":{"probability":0.9,"type":"boolean"}}`, `{"q0":{"probability":0.9,"why":"it says so"}}`} {
		if _, err := ExtractNative(specs, text); err != nil {
			t.Fatalf("%s: %v", text, err)
		}
	}
}

func scoreSpec(t *testing.T, levels int) []Spec {
	t.Helper()
	labels := make([]string, levels)
	for i := range labels {
		labels[i] = fmt.Sprintf("level %d", i)
	}
	raw, _ := json.Marshal(labels)
	return questions(t, `{"rate":{"type":"score","instructions":"Rate.","criteria":`+string(raw)+`}}`)
}

func TestVerifyReturnsTheMeanOfTheDistributionWhateverTheBackendReported(t *testing.T) {
	five := scoreSpec(t, 5)
	dist := map[string]float64{"0": 0.1, "1": 0.2, "2": 0.4, "3": 0.2, "4": 0.1} // mean 2.0
	// The distribution is the answer. The score handed back is always ITS mean,
	// so the caller's answer is self-consistent whatever the backend's own
	// `score` said. There is no allowance to tune: three versions of one were
	// each wrong in both directions.
	for _, reported := range []float64{2.0, 2.08, 0, 3.5, 4} {
		out, err := Verify(five, map[string]Answer{"rate": {Type: TypeScore, Score: &reported, Probabilities: dist}})
		if err != nil {
			t.Fatalf("reported %v: %v", reported, err)
		}
		if got := *out["rate"].Score; got != 2.0 {
			t.Fatalf("reported %v: returned %v, want the distribution's mean 2.0", reported, got)
		}
	}
	// What a score may never be: absent, not a number, or off the scale.
	for label, reported := range map[string]float64{"below the scale": -0.25, "above the scale": 4.01, "NaN": math.NaN()} {
		score := reported
		_, err := Verify(five, map[string]Answer{"rate": {Type: TypeScore, Score: &score, Probabilities: dist}})
		wantKind(t, label, err, KindRange)
	}
	_, err := Verify(five, map[string]Answer{"rate": {Type: TypeScore, Probabilities: dist}})
	wantKind(t, "no score at all", err, KindDerived)

	// The vendor's own documented example, and a rounded mass.
	if _, err := Verify(scoreSpec(t, 3), map[string]Answer{"rate": {Type: TypeScore, Score: f(1.6), Probabilities: map[string]float64{"0": 0.05, "1": 0.3, "2": 0.65}}}); err != nil {
		t.Fatalf("the vendor's documented answer: %v", err)
	}
	raw := map[string]float64{"0": 0, "1": 0, "2": 0.17, "3": 0.5, "4": 0.3} // mass 0.97
	reported := 2*0.17 + 3*0.5 + 4*0.3
	out, err := Verify(five, map[string]Answer{"rate": {Type: TypeScore, Score: &reported, Probabilities: raw}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := *out["rate"].Score, math.Round(reported/0.97*100)/100; got != want {
		t.Fatalf("score = %v, want the mean of the RETURNED distribution %v", got, want)
	}
}

func TestParseAppliesTheHostedModelsLimitsToEveryModel(t *testing.T) {
	// A request written against one decision model must run on any other, so
	// the vendor's documented ceilings are the contract: 255 options, 10 levels.
	levels := func(n int) map[string]Question {
		labels := make([]string, n)
		for i := range labels {
			labels[i] = fmt.Sprintf("level %d", i)
		}
		criteria, _ := json.Marshal(labels)
		return map[string]Question{"rate": {Type: TypeScore, Instructions: "Rate.", Criteria: criteria}}
	}
	if _, err := Parse(levels(MaxScoreLevels)); err != nil {
		t.Fatalf("%d levels: %v", MaxScoreLevels, err)
	}
	_, err := Parse(levels(MaxScoreLevels + 1))
	invalid, ok := err.(*Error)
	if !ok || invalid.Param != "questions.rate.criteria" {
		t.Fatalf("%d levels: got %v, want a *Error on the criteria", MaxScoreLevels+1, err)
	}
	// A full-size batch of ordinary names is an ordinary request. (A size
	// estimate in Parse once refused this one.)
	batch := map[string]Question{}
	for q := 0; q < MaxQuestions; q++ {
		options := map[string]string{}
		for o := 0; o < MaxOptions; o++ {
			options[fmt.Sprintf("category_%03d", o)] = ""
		}
		criteria, _ := json.Marshal(options)
		batch[fmt.Sprintf("question-%02d", q)] = Question{Type: TypeChoice, Instructions: "Pick.", Criteria: criteria}
	}
	if _, err := Parse(batch); err != nil {
		t.Fatalf("64 x 255 plain options: %v", err)
	}
}

func TestParseRejectsControlCharactersInNames(t *testing.T) {
	for label, raw := range map[string]string{
		"question name": "{\"a\\u0001b\":{\"type\":\"boolean\",\"instructions\":\"x\"}}",
		"option name":   "{\"a\":{\"type\":\"choice\",\"instructions\":\"x\",\"criteria\":{\"ok\":\"1\",\"new\\nline\":\"2\"}}}",
	} {
		var qs map[string]Question
		if err := json.Unmarshal([]byte(raw), &qs); err != nil {
			t.Fatalf("%s: fixture: %v", label, err)
		}
		if _, err := Parse(qs); err == nil {
			t.Errorf("%s: accepted", label)
		}
	}
}

func TestNativeChatRequestNeverAsksForMoreThanTheCeiling(t *testing.T) {
	// Four choice questions of 248 options sit just under the schema limit. With
	// the generic and reasoning allowances the computed budget was 34,400.
	options := map[string]string{}
	for i := 0; i < 248; i++ {
		options[fmt.Sprintf("option-%03d", i)] = "x"
	}
	criteria, _ := json.Marshal(options)
	qs := map[string]Question{}
	for i := 0; i < 4; i++ {
		qs[fmt.Sprintf("pick%d", i)] = Question{Type: TypeChoice, Instructions: "Pick.", Criteria: criteria}
	}
	specs, err := Parse(qs)
	if err != nil {
		t.Fatal(err)
	}
	req, err := NativeChatRequest("some/untuned-model", json.RawMessage(`"state"`), specs, GenericNativeModel, NativeOptions{ReasoningEffort: "high"})
	if err != nil {
		t.Fatal(err)
	}
	if req.MaxTokens == nil || *req.MaxTokens != maxNativeTokens {
		t.Fatalf("max_tokens = %v, want it held at the %d this route promises", *req.MaxTokens, maxNativeTokens)
	}
}

func TestExtractNativeBooleanTreatsNullAsAbsent(t *testing.T) {
	specs := questions(t, oneBoolean)
	answers, err := ExtractNative(specs, `{"q0":{"probability":0.9,"type":"boolean","score":null,"choice":null}}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := *answers["sure"].Probability; got != 0.9 {
		t.Fatalf("probability = %v", got)
	}
}

func TestExtractNativeSparseToleranceFollowsTheValuesWritten(t *testing.T) {
	sixteen := map[string]string{}
	for i := 0; i < 16; i++ {
		sixteen[fmt.Sprintf("option-%02d", i)] = "x"
	}
	criteria, _ := json.Marshal(sixteen)
	specs := questions(t, `{"pick":{"type":"choice","instructions":"Pick.","criteria":`+string(criteria)+`}}`)
	// One value written, nine points of mass nowhere. With the allowance tied to
	// the option COUNT (16 -> 0.10) this normalized to certainty.
	_, err := ExtractNative(specs, `{"q0":{"q0_o0":0.91}}`)
	wantKind(t, "0.91 alone among sixteen", err, KindMass)
	if _, err := ExtractNative(specs, `{"q0":{"q0_o0":0.98}}`); err != nil {
		t.Fatalf("0.98 alone is a rounded certainty: %v", err)
	}
	if _, err := ExtractNative(specs, `{"q0":{"q0_o0":0.5,"q0_o1":0.3,"q0_o2":0.17}}`); err != nil {
		t.Fatalf("three written values summing to 0.97: %v", err)
	}
}

func TestCallerReasoningBecomesOneValidatedEffortWord(t *testing.T) {
	specs := questions(t, triage)
	build := func(options NativeOptions) (*types.OpenAIChatRequest, error) {
		return NativeChatRequest(TrevModelID, json.RawMessage(`"x"`), specs, NativeModels[TrevModelID], options)
	}
	// Every spelling of "think, at this effort" reaches the host as the effort
	// STRING. The object is not portable: Cerebras answers 400 to it, so
	// {"effort":"high"} on trev-1.0 used to fail at the host.
	for label, tc := range map[string]struct {
		options NativeOptions
		want    string
	}{
		"effort string":       {NativeOptions{ReasoningEffort: "high"}, "high"},
		"effort, odd case":    {NativeOptions{ReasoningEffort: " High "}, "high"},
		"object with effort":  {NativeOptions{Reasoning: map[string]any{"effort": "medium"}}, "medium"},
		"object enabled":      {NativeOptions{Reasoning: map[string]any{"enabled": true}}, "medium"},
		"bare true":           {NativeOptions{Reasoning: true}, "medium"},
		"bare word":           {NativeOptions{Reasoning: "minimal"}, "minimal"},
		"string beats object": {NativeOptions{ReasoningEffort: "low", Reasoning: map[string]any{"effort": "high"}}, "low"},
		// Both keys at once. Ranging over the map made this "medium" or "high" by
		// chance; the loop below runs it enough times to see either.
		"enabled with effort": {NativeOptions{Reasoning: map[string]any{"enabled": true, "effort": "high"}}, "high"},
		// An explicit off wins over an effort beside it: the tuned default stays.
		"disabled with effort":  {NativeOptions{Reasoning: map[string]any{"enabled": false, "effort": "high"}}, "low"},
		"false with an effort":  {NativeOptions{Reasoning: false, ReasoningEffort: "high"}, "low"},
		"null fields":           {NativeOptions{Reasoning: map[string]any{"enabled": nil, "effort": "high"}}, "high"},
		"none keeps the tuned":  {NativeOptions{ReasoningEffort: "none"}, "low"},
		"false keeps the tuned": {NativeOptions{Reasoning: false}, "low"},
		"disabled object":       {NativeOptions{Reasoning: map[string]any{"enabled": false}}, "low"},
	} {
		for run := 0; run < 40; run++ { // map order is random per range
			req, err := build(tc.options)
			if err != nil {
				t.Fatalf("%s: %v", label, err)
			}
			if req.ReasoningEffort != tc.want || req.Reasoning != nil {
				t.Fatalf("%s (run %d): effort=%q reasoning=%v, want effort %q and no object", label, run, req.ReasoningEffort, req.Reasoning, tc.want)
			}
		}
	}
	// A value the host would reject is OUR 400, naming the field. Left to the
	// host it comes back as a provider error, which this route reports as 502.
	for label, tc := range map[string]struct {
		options NativeOptions
		param   string
	}{
		"unknown effort":        {NativeOptions{ReasoningEffort: "banana"}, "reasoning_effort"},
		"unknown object effort": {NativeOptions{Reasoning: map[string]any{"effort": "banana"}}, "reasoning.effort"},
		"effort not a string":   {NativeOptions{Reasoning: map[string]any{"effort": 3.0}}, "reasoning.effort"},
		"enabled not a bool":    {NativeOptions{Reasoning: map[string]any{"enabled": "yes"}}, "reasoning.enabled"},
		"unknown key":           {NativeOptions{Reasoning: map[string]any{"max_tokens": 2000.0}}, "reasoning.max_tokens"},
		// A bad effort is refused even when `enabled` would have decided first.
		"bad effort beside enabled":       {NativeOptions{Reasoning: map[string]any{"enabled": true, "effort": "banana"}}, "reasoning.effort"},
		"bad effort beside disabled":      {NativeOptions{Reasoning: map[string]any{"enabled": false, "effort": "banana"}}, "reasoning.effort"},
		"bad field beside an object":      {NativeOptions{ReasoningEffort: "banana", Reasoning: map[string]any{"effort": "high"}}, "reasoning_effort"},
		"two unknown keys, first by name": {NativeOptions{Reasoning: map[string]any{"zeta": 1.0, "alpha": 1.0}}, "reasoning.alpha"},
		"a number":                        {NativeOptions{Reasoning: 3.0}, "reasoning"},
		"an unknown bare word":            {NativeOptions{Reasoning: "banana"}, "reasoning"},
	} {
		for run := 0; run < 40; run++ {
			_, err := build(tc.options)
			invalid, ok := err.(*Error)
			if !ok || invalid.Param != tc.param {
				t.Fatalf("%s (run %d): got %v, want a *Error on %s", label, run, err, tc.param)
			}
		}
	}
}
