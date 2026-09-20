package decide

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
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

func TestVerifyScoreMustAgreeWithItsOwnDistribution(t *testing.T) {
	specs := scoreSpec(t, 255)
	certainZero := map[string]float64{}
	for i := 0; i < 255; i++ {
		certainZero[fmt.Sprintf("%d", i)] = 0
	}
	certainZero["0"] = 1
	// All mass on level 0, reported score 12. The allowance used to scale with
	// the number of levels alone (12.75 here), so this passed.
	_, err := Verify(specs, map[string]Answer{"rate": {Type: TypeScore, Score: f(12), Probabilities: certainZero}})
	wantKind(t, "score 12 from a distribution certain of 0", err, KindDerived)

	// A backend that rounds is still believed: mass 0.97, score computed from
	// the raw (un-normalized) probabilities.
	five := scoreSpec(t, 5)
	raw := map[string]float64{"0": 0, "1": 0, "2": 0.17, "3": 0.5, "4": 0.3}
	reported := 2*0.17 + 3*0.5 + 4*0.3
	out, err := Verify(five, map[string]Answer{"rate": {Type: TypeScore, Score: &reported, Probabilities: raw}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := *out["rate"].Score, math.Round(reported/0.97*100)/100; got != want {
		t.Fatalf("score = %v, want %v", got, want)
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
