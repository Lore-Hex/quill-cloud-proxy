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

func TestExtractNativeRefusesTwoDifferentAnswers(t *testing.T) {
	specs := questions(t, oneBoolean)
	// STATE is caller text the model may quote. Taking the first object would
	// return 0.01, the opposite of the answer.
	_, err := ExtractNative(specs, `STATE contained {"q0":0.01}. My answer is {"q0":0.99}`)
	wantKind(t, "quoted state then answer", err, KindAmbiguous)

	for label, text := range map[string]string{
		"said twice":            `{"q0":0.99} Final: {"q0": 0.99}`,
		"stray brace in prose":  "Use { carefully. Answer: {\"q0\":0.99}",
		"unrelated object":      `Config {"temperature":0} gives {"q0":0.99}`,
		"fenced":                "```json\n{\"q0\":0.99}\n```",
		"brace inside a string": `{"note":"a } and a { brace","q0":0.99}`,
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

func TestVerifyScoreAllowsWhatArithmeticExplainsAndNothingElse(t *testing.T) {
	verifyScore := func(levels int, probabilities map[string]float64, score float64) error {
		_, err := Verify(scoreSpec(t, levels), map[string]Answer{"rate": {Type: TypeScore, Score: &score, Probabilities: probabilities}})
		return err
	}
	// Five levels at two decimals, mean 2.0. Rounding moves the mean by at most
	// 0.005 x (0+1+2+3+4) = 0.05, plus 0.05 for the score's own rounding.
	five := map[string]float64{"0": 0.1, "1": 0.2, "2": 0.4, "3": 0.2, "4": 0.1}
	for _, score := range []float64{2.0, 2.08, 1.92} {
		if err := verifyScore(5, five, score); err != nil {
			t.Errorf("score %v against a mean of 2.0: %v", score, err)
		}
	}
	for _, score := range []float64{2.2, 1.8, 3.5} {
		wantKind(t, fmt.Sprintf("score %v against a mean of 2.0", score), verifyScore(5, five, score), KindDerived)
	}
	// Written to six decimals there is no rounding left to blame.
	precise := map[string]float64{"0": 0.100001, "1": 0.2, "2": 0.399999, "3": 0.2, "4": 0.1}
	wantKind(t, "precise probabilities, score off by 0.08", verifyScore(5, precise, 2.08), KindDerived)

	// TypeSafe's own documented example.
	if err := verifyScore(3, map[string]float64{"0": 0.05, "1": 0.3, "2": 0.65}, 1.6); err != nil {
		t.Errorf("the vendor's documented answer: %v", err)
	}
	// Twenty levels truly at 0.0451 / 0.0549, each written as 0.05: the score
	// computed from the true values is 9.99, the written ones imply 9.5. That
	// is rounding, and a tighter first version of this check refused it.
	twenty := map[string]float64{}
	for i := 0; i < 20; i++ {
		twenty[fmt.Sprintf("%d", i)] = 0.05
	}
	if err := verifyScore(20, twenty, 9.99); err != nil {
		t.Errorf("twenty rounded levels: %v", err)
	}
	wantKind(t, "twenty rounded levels, score 12", verifyScore(20, twenty, 12), KindDerived)

	// Mass 0.97: the score was computed from the raw probabilities, ours from
	// the normalized ones. They differ by exactly mean x |1 - mass|.
	raw := map[string]float64{"0": 0, "1": 0, "2": 0.17, "3": 0.5, "4": 0.3}
	reported := 2*0.17 + 3*0.5 + 4*0.3
	out, err := Verify(scoreSpec(t, 5), map[string]Answer{"rate": {Type: TypeScore, Score: &reported, Probabilities: raw}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := *out["rate"].Score, math.Round(reported/0.97*100)/100; got != want {
		t.Fatalf("score = %v, want the mean of the RETURNED distribution %v", got, want)
	}
	// ...and mass error buys slack in proportion to the MEAN, not to the scale.
	// All of 0.951 on level 0 has mean 0, so renormalizing cannot move it at
	// all: 0.2 is a contradiction. Charging the scale instead, (n-1) x |1-m|,
	// allowed 0.25 here -- and 15 on a 255-level scale.
	low := map[string]float64{"0": 0.951, "1": 0, "2": 0, "3": 0, "4": 0}
	wantKind(t, "mass on level 0, score 0.2", verifyScore(5, low, 0.2), KindDerived)
	if err := verifyScore(5, low, 0.04); err != nil {
		t.Errorf("score 0.04 is the score's own rounding: %v", err)
	}
}

func TestParseBoundsTheWorstCaseAnswer(t *testing.T) {
	// 64 questions x 255 options with 48-byte names passed Parse, and a CORRECT
	// answer then exceeded what the gateway would read: the vendor was paid,
	// the answer discarded, the next host tried, and the caller refunded.
	qs := map[string]Question{}
	for q := 0; q < MaxQuestions; q++ {
		options := map[string]string{}
		for o := 0; o < MaxOptions; o++ {
			options[fmt.Sprintf("%s%03d", strings.Repeat("<", 45), o)] = "x"
		}
		criteria, _ := json.Marshal(options)
		qs[fmt.Sprintf("question-%02d", q)] = Question{Type: TypeChoice, Instructions: "Pick.", Criteria: criteria}
	}
	_, err := Parse(qs)
	invalid, ok := err.(*Error)
	if !ok || invalid.Param != "questions" || !strings.Contains(invalid.Message, "too large") {
		t.Fatalf("got %v, want a too-large *Error on questions", err)
	}

	// ...without refusing a large batch of ordinary names. A first version
	// charged every byte six times and counted each option twice: this request,
	// whose real answer is about 280 KB, was refused at 2.9 MB.
	plain := map[string]Question{}
	for q := 0; q < MaxQuestions; q++ {
		options := map[string]string{}
		for o := 0; o < MaxOptions; o++ {
			options[fmt.Sprintf("category_%03d", o)] = ""
		}
		criteria, _ := json.Marshal(options)
		plain[fmt.Sprintf("question-%02d", q)] = Question{Type: TypeChoice, Instructions: "Pick.", Criteria: criteria}
	}
	plainSpecs, err := Parse(plain)
	if err != nil {
		t.Fatalf("64 x 255 plain options refused: %v", err)
	}
	full := map[string]Answer{}
	for _, spec := range plainSpecs {
		dist := map[string]float64{}
		for _, option := range spec.Options {
			dist[option] = 0.00392156862745098
		}
		choice := spec.Options[0]
		full[spec.Name] = Answer{Type: TypeChoice, Choice: &choice, Probabilities: dist}
	}
	encodedFull, _ := json.Marshal(full)
	if bound := answerBytesUpperBound(plainSpecs); len(encodedFull) > bound {
		t.Fatalf("a real answer is %d bytes, above its own upper bound %d", len(encodedFull), bound)
	}

	// The bound is an UPPER bound: whatever Parse admits, its verified answer fits.
	specs := questions(t, triage)
	answers, err := Verify(specs, valid())
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(answers)
	if bound := answerBytesUpperBound(specs); len(encoded) > bound || bound > MaxAnswerBytes {
		t.Fatalf("answer is %d bytes, bound %d, limit %d", len(encoded), bound, MaxAnswerBytes)
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
	// Four score questions of 249 levels sit just under the schema limit. With
	// the generic and reasoning allowances the computed budget was 34,400.
	levels := make([]string, 249)
	for i := range levels {
		levels[i] = fmt.Sprintf("level %d", i)
	}
	criteria, _ := json.Marshal(levels)
	qs := map[string]Question{}
	for i := 0; i < 4; i++ {
		qs[fmt.Sprintf("rate%d", i)] = Question{Type: TypeScore, Instructions: "Rate.", Criteria: criteria}
	}
	specs, err := Parse(qs)
	if err != nil {
		t.Fatal(err)
	}
	req, err := NativeChatRequest("some/untuned-model", json.RawMessage(`"state"`), specs, GenericNativeModel, NativeOptions{ReasoningEffort: "high"})
	if err != nil {
		t.Fatal(err)
	}
	if req.MaxTokens == nil || *req.MaxTokens > maxNativeTokens {
		t.Fatalf("max_tokens = %v, above the %d this route promises", req.MaxTokens, maxNativeTokens)
	}
}

func TestWireLenIsAtLeastWhatGoWrites(t *testing.T) {
	// An upper bound that undercounts is not one. Go's encoder is the reference
	// for the characters it escapes; the rest are bounded above it.
	for _, text := range []string{"plain", `q"uo\\te`, "<tag>&amp;", "caf\u00e9", "\U0001F600 grin", "tab\there", "\x7f"} {
		encoded, _ := json.Marshal(text)
		if got := wireLen(text); got < len(encoded) {
			t.Errorf("wireLen(%q) = %d, but Go writes %d bytes", text, got, len(encoded))
		}
	}
}

func TestExtractNativeFindsTheAnswerAtAnyDepth(t *testing.T) {
	specs := questions(t, oneBoolean)
	// The real answer is wrapped. Looking only at top-level objects, the quoted
	// 0.01 was the only candidate and was returned.
	_, err := ExtractNative(specs, `STATE contained {"q0":0.01}. My answer is {"answer":{"q0":0.99}}`)
	wantKind(t, "quoted state, then a wrapped answer", err, KindAmbiguous)
	_, err = ExtractNative(specs, `{"echo":{"q0":0.01},"final":[{"q0":0.99}]}`)
	wantKind(t, "two answers inside one wrapper", err, KindAmbiguous)

	for label, text := range map[string]string{
		"wrapped":         `{"answer":{"q0":0.99}}`,
		"wrapped deeper":  `{"result":{"decision":[{"q0":0.99}]}}`,
		"wrapped + prose": "Here you go: {\"answer\": {\"q0\": 0.99}} Hope that helps.",
	} {
		answers, err := ExtractNative(specs, text)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if got := *answers["sure"].Probability; got != 0.99 {
			t.Fatalf("%s: probability = %v", label, got)
		}
	}
	// A wrapper cannot hide a repeated key either: decoding keeps the last.
	_, err = ExtractNative(specs, `{"answer":{"q0":0.1},"answer":{"q0":0.9}}`)
	wantKind(t, "wrapper key given twice", err, KindDuplicate)
}

func TestExtractNativeComparesRepeatedAnswersByValue(t *testing.T) {
	specs := questions(t, `{"a":{"type":"boolean","instructions":"A?"},"b":{"type":"boolean","instructions":"B?"}}`)
	for label, text := range map[string]string{
		"keys reordered":      `{"q0":0.8,"q1":0.2} Final: {"q1":0.2,"q0":0.8}`,
		"numbers reformatted": `{"q0":0.80,"q1":0.2} Final: {"q0":0.8,"q1":0.20}`,
	} {
		answers, err := ExtractNative(specs, text)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if *answers["a"].Probability != 0.8 || *answers["b"].Probability != 0.2 {
			t.Fatalf("%s: got %+v", label, answers)
		}
	}
	// A second object that is NOT a usable answer still counts. Dropping it
	// would make `STATE said {"q0":0.01,"q1":0.5}. Answer: {"q0":"high",...}`
	// return the quoted object, as the only one that parses.
	_, err := ExtractNative(specs, `{"q0":0.9,"q1":0.1} Debug: {"q0":"request-id"}`)
	wantKind(t, "a second, unusable q-object", err, KindAmbiguous)
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
		"effort string":         {NativeOptions{ReasoningEffort: "high"}, "high"},
		"effort, odd case":      {NativeOptions{ReasoningEffort: " High "}, "high"},
		"object with effort":    {NativeOptions{Reasoning: map[string]any{"effort": "medium"}}, "medium"},
		"object enabled":        {NativeOptions{Reasoning: map[string]any{"enabled": true}}, "medium"},
		"bare true":             {NativeOptions{Reasoning: true}, "medium"},
		"bare word":             {NativeOptions{Reasoning: "minimal"}, "minimal"},
		"string beats object":   {NativeOptions{ReasoningEffort: "low", Reasoning: map[string]any{"effort": "high"}}, "low"},
		"none keeps the tuned":  {NativeOptions{ReasoningEffort: "none"}, "low"},
		"false keeps the tuned": {NativeOptions{Reasoning: false}, "low"},
		"disabled object":       {NativeOptions{Reasoning: map[string]any{"enabled": false}}, "low"},
	} {
		req, err := build(tc.options)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if req.ReasoningEffort != tc.want || req.Reasoning != nil {
			t.Errorf("%s: effort=%q reasoning=%v, want effort %q and no object", label, req.ReasoningEffort, req.Reasoning, tc.want)
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
		"a number":              {NativeOptions{Reasoning: 3.0}, "reasoning"},
		"an unknown bare word":  {NativeOptions{Reasoning: "banana"}, "reasoning"},
	} {
		_, err := build(tc.options)
		invalid, ok := err.(*Error)
		if !ok || invalid.Param != tc.param {
			t.Errorf("%s: got %v, want a *Error on %s", label, err, tc.param)
		}
	}
}
