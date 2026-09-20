package decide

import (
	"encoding/json"
	"reflect"
	"testing"
)

func noulQuestions() map[string]Question {
	return map[string]Question{
		"refund":  {Type: TypeNoul, Instructions: "Is a refund requested?", Criteria: json.RawMessage(`{"true":"asks for money back","false":"does not"}`)},
		"damaged": {Type: TypeBoolean, Instructions: "Did it arrive damaged?"},
		"route":   {Type: TypeChoice, Instructions: "Route it.", Criteria: json.RawMessage(`{"billing":"b","shipping":"s"}`)},
	}
}

func TestNoulIsASpellingOfBooleanOnTheWayIn(t *testing.T) {
	asked := noulQuestions()
	canonical, askedNoul := CanonicalQuestions(asked)

	if !reflect.DeepEqual(askedNoul, map[string]bool{"refund": true}) {
		t.Fatalf("asked as noul = %v, want only refund", askedNoul)
	}
	if canonical["refund"].Type != TypeBoolean || canonical["damaged"].Type != TypeBoolean || canonical["route"].Type != TypeChoice {
		t.Fatalf("canonical types = %v", canonical)
	}
	// Everything but the spelling survives, and the caller's map is untouched.
	if canonical["refund"].Instructions != asked["refund"].Instructions || string(canonical["refund"].Criteria) != string(asked["refund"].Criteria) {
		t.Errorf("canonical refund lost content: %+v", canonical["refund"])
	}
	if asked["refund"].Type != TypeNoul {
		t.Errorf("CanonicalQuestions modified the caller's map: %+v", asked["refund"])
	}
	// Parse never learns the word: the canonical questions parse, and "noul"
	// handed to it directly is still not a type it knows.
	specs, err := Parse(canonical)
	if err != nil {
		t.Fatalf("canonical questions do not parse: %v", err)
	}
	for _, spec := range specs {
		if spec.Type == TypeNoul {
			t.Errorf("spec %q kept the noul spelling", spec.Name)
		}
	}
	if _, err := Parse(asked); err == nil {
		t.Error("Parse accepted \"noul\" itself; only CanonicalQuestions should")
	}
}

func TestQuestionsWithoutNoulAreReturnedAsTheyCame(t *testing.T) {
	asked := map[string]Question{"damaged": {Type: TypeBoolean, Instructions: "Damaged?"}}
	canonical, askedNoul := CanonicalQuestions(asked)
	if askedNoul != nil {
		t.Errorf("asked as noul = %v, want nil", askedNoul)
	}
	if reflect.ValueOf(canonical).Pointer() != reflect.ValueOf(asked).Pointer() {
		t.Error("a request with no noul question was copied")
	}
	// A misspelling is not quietly accepted as the spelling.
	for _, wrong := range []string{"Noul", "NOUL", "bool", "yesno"} {
		_, askedNoul := CanonicalQuestions(map[string]Question{"q": {Type: wrong, Instructions: "?"}})
		if askedNoul != nil {
			t.Errorf("%q was treated as noul", wrong)
		}
	}
}

func TestAnswersGoBackInTheSpellingTheyWereAskedIn(t *testing.T) {
	p, choice := 0.97, "billing"
	verified := map[string]Answer{
		"refund":  {Type: TypeBoolean, Probability: &p},
		"damaged": {Type: TypeBoolean, Probability: &p},
		"route":   {Type: TypeChoice, Choice: &choice, Probabilities: map[string]float64{"billing": 0.9, "shipping": 0.1}},
	}
	out := InAskedSpelling(verified, map[string]bool{"refund": true})

	// Exactly TypeSafe's shape: no "probability" beside "noul".
	for name, want := range map[string]string{
		"refund":  `{"type":"noul","noul":0.97}`,
		"damaged": `{"type":"boolean","probability":0.97}`,
		"route":   `{"type":"choice","choice":"billing","probabilities":{"billing":0.9,"shipping":0.1}}`,
	} {
		got, err := json.Marshal(out[name])
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("%s = %s, want %s", name, got, want)
		}
	}
	if verified["refund"].Type != TypeBoolean || verified["refund"].Noul != nil {
		t.Error("InAskedSpelling modified the verified answers it was given")
	}
	// Nothing asked as noul: the same map, not a copy.
	if same := InAskedSpelling(verified, nil); reflect.ValueOf(same).Pointer() != reflect.ValueOf(verified).Pointer() {
		t.Error("answers were copied although nothing was asked as noul")
	}
	// A name asked as noul that is NOT a boolean answer is left alone.
	if odd := InAskedSpelling(verified, map[string]bool{"route": true}); odd["route"].Type != TypeChoice {
		t.Errorf("a choice answer was re-spelled: %+v", odd["route"])
	}
}

func TestVerifyRefusesAnArrivingNoulField(t *testing.T) {
	// "noul" is written by this gateway on the way out. A backend answer that
	// ARRIVES carrying it is a foreign field like any other, on every type.
	specs, err := Parse(map[string]Question{
		"refund":  {Type: TypeBoolean, Instructions: "Refund?"},
		"route":   {Type: TypeChoice, Instructions: "Route.", Criteria: json.RawMessage(`{"billing":"b","shipping":"s"}`)},
		"urgency": {Type: TypeScore, Instructions: "Urgency?", Criteria: json.RawMessage(`["low","high"]`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, choice, score := 0.9, "billing", 0.1
	good := func() map[string]Answer {
		return map[string]Answer{
			"refund":  {Type: TypeBoolean, Probability: &p},
			"route":   {Type: TypeChoice, Choice: &choice, Probabilities: map[string]float64{"billing": 0.9, "shipping": 0.1}},
			"urgency": {Type: TypeScore, Score: &score, Probabilities: map[string]float64{"0": 0.9, "1": 0.1}},
		}
	}
	if _, err := Verify(specs, good()); err != nil {
		t.Fatalf("control: the clean answers must verify: %v", err)
	}
	for _, name := range []string{"refund", "route", "urgency"} {
		answers := good()
		tainted := answers[name]
		tainted.Noul = &p
		answers[name] = tainted
		if _, err := Verify(specs, answers); err == nil {
			t.Errorf("%s: an answer carrying a noul field verified", name)
		}
	}
}
