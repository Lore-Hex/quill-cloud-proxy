// Package decide implements the wire contract of POST /v1/decide (alias
// /v1/evaluate): shared state plus typed questions in, typed answers with
// probabilities out. It is deliberately free of I/O so every rule here can be
// tested exhaustively.
//
// Two backends produce answers: a hosted decision model (TypeSafe AI's Jev, at
// TypeSafe's own API with Vercel AI Gateway as the failover relay) and a native
// path that drives an ordinary chat model with strict structured output.
// NEITHER is trusted. Whatever comes back passes
// through Verify, which checks it against the request question by question, so
// a caller can never receive an answer whose shape, option set, or probability
// mass differs from what a decision model is contracted to return.
package decide

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"unicode"
)

const (
	TypeBoolean = "boolean"
	TypeChoice  = "choice"
	TypeScore   = "score"

	MaxQuestions = 64
	MaxOptions   = 255 // the hosted model's documented ceiling
	MaxNameLen   = 128
	MaxTextLen   = 8192
	// MaxAnswerBytes bounds the WORST-CASE answer a request can legitimately
	// produce (see answerBytesUpperBound). The gateway reads at most twice this
	// from a hosted model, so a request that passes Parse can never be one
	// whose correct answer is then thrown away as oversized -- after the vendor
	// has already been paid for it.
	MaxAnswerBytes = 2 << 20
	probabilityTol = 1e-6
	// A model that reports probabilities summing to 0.97 or 1.04 is rounding;
	// one that reports 0.4 is wrong. Normalize the former, reject the latter.
	massTolerance = 0.05
)

// Question is one typed question. Criteria's shape depends on Type:
// boolean -> optional {"true": "...", "false": "..."}; choice -> required
// {option: description} with 2..255 options; score -> required ordered array of
// at least two level labels, lowest first.
type Question struct {
	Type         string          `json:"type"`
	Instructions string          `json:"instructions"`
	Criteria     json.RawMessage `json:"criteria,omitempty"`
}

// Answer is one typed answer. Exactly the fields for its Type are populated.
type Answer struct {
	Type          string             `json:"type"`
	Probability   *float64           `json:"probability,omitempty"`
	Choice        *string            `json:"choice,omitempty"`
	Score         *float64           `json:"score,omitempty"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
}

// Error is a caller-facing validation failure (HTTP 400).
type Error struct {
	Param   string
	Message string
}

func (e *Error) Error() string { return e.Message }

func bad(param, format string, args ...any) *Error {
	return &Error{Param: param, Message: fmt.Sprintf(format, args...)}
}

// Spec is a validated question with its criteria decoded.
type Spec struct {
	Name         string
	Type         string
	Instructions string
	// Options holds choice option names (declaration order is not preserved by
	// JSON objects, so they are sorted for a deterministic prompt and schema),
	// or score level labels in the caller's order.
	Options      []string
	Descriptions map[string]string // choice option / boolean side -> description
}

// Parse validates the questions object and returns specs in a stable order.
func Parse(questions map[string]Question) ([]Spec, error) {
	if len(questions) == 0 {
		return nil, bad("questions", "questions must contain at least one question")
	}
	if len(questions) > MaxQuestions {
		return nil, bad("questions", "at most %d questions per request", MaxQuestions)
	}
	names := make([]string, 0, len(questions))
	for name := range questions {
		names = append(names, name)
	}
	sort.Strings(names)
	specs := make([]Spec, 0, len(names))
	for _, name := range names {
		param := "questions." + name
		if !validName(name) {
			return nil, bad("questions", "question names must be 1-%d characters with no control characters", MaxNameLen)
		}
		q := questions[name]
		if len(q.Instructions) > MaxTextLen {
			return nil, bad(param+".instructions", "instructions exceed %d characters", MaxTextLen)
		}
		spec := Spec{Name: name, Type: q.Type, Instructions: q.Instructions}
		switch q.Type {
		case TypeBoolean:
			if strings.TrimSpace(q.Instructions) == "" {
				return nil, bad(param+".instructions", "a boolean question requires instructions")
			}
			if hasJSON(q.Criteria) {
				var sides map[string]string
				if err := json.Unmarshal(q.Criteria, &sides); err != nil {
					return nil, bad(param+".criteria", `boolean criteria must be an object with "true" and/or "false" strings`)
				}
				for side := range sides {
					if side != "true" && side != "false" {
						return nil, bad(param+".criteria", `boolean criteria keys must be "true" or "false", got %q`, side)
					}
				}
				spec.Descriptions = sides
			}
		case TypeChoice:
			var options map[string]string
			if !hasJSON(q.Criteria) || json.Unmarshal(q.Criteria, &options) != nil {
				return nil, bad(param+".criteria", "choice criteria must be an object mapping each option to a description")
			}
			if len(options) < 2 || len(options) > MaxOptions {
				return nil, bad(param+".criteria", "a choice question needs 2-%d options, got %d", MaxOptions, len(options))
			}
			for option, description := range options {
				if !validName(option) {
					return nil, bad(param+".criteria", "option names must be 1-%d characters with no control characters", MaxNameLen)
				}
				if len(description) > MaxTextLen {
					return nil, bad(param+".criteria", "option descriptions exceed %d characters", MaxTextLen)
				}
				spec.Options = append(spec.Options, option)
			}
			sort.Strings(spec.Options)
			spec.Descriptions = options
		case TypeScore:
			var levels []string
			if !hasJSON(q.Criteria) || json.Unmarshal(q.Criteria, &levels) != nil {
				return nil, bad(param+".criteria", "score criteria must be an array of level labels ordered lowest to highest")
			}
			if len(levels) < 2 || len(levels) > MaxOptions {
				return nil, bad(param+".criteria", "a score question needs 2-%d levels, got %d", MaxOptions, len(levels))
			}
			for _, level := range levels {
				if strings.TrimSpace(level) == "" || len(level) > MaxTextLen {
					return nil, bad(param+".criteria", "score levels must be non-empty strings")
				}
			}
			spec.Options = levels
		default:
			return nil, bad(param+".type", `question type must be "boolean", "choice", or "score", got %q`, q.Type)
		}
		specs = append(specs, spec)
	}
	if bound := answerBytesUpperBound(specs); bound > MaxAnswerBytes {
		return nil, bad("questions", "questions are too large: their answer could reach %d bytes, above the %d byte limit; use fewer or shorter options", bound, MaxAnswerBytes)
	}
	return specs, nil
}

// validName accepts a question or option name: non-blank, bounded, and free of
// control characters. A name is echoed into prompts and upstream JSON, where a
// control character has no legitimate use and escapes to six bytes.
func validName(name string) bool {
	if strings.TrimSpace(name) == "" || len(name) > MaxNameLen {
		return false
	}
	return !strings.ContainsFunc(name, unicode.IsControl)
}

// answerBytesUpperBound is the largest JSON answer these questions can yield
// from any backend. Every byte of a name may escape to six on the wire (a JSON
// \uXXXX), a probability needs at most 32 bytes with its punctuation, and a
// hosted score answer also echoes each level label back as its legend.
func answerBytesUpperBound(specs []Spec) int {
	const perAnswer, perNumber = 96, 32
	wire := func(text string) int { return 6*len(text) + 2 }
	total := 64
	for _, spec := range specs {
		total += wire(spec.Name) + perAnswer
		for index, option := range spec.Options {
			if spec.Type == TypeScore {
				total += len(fmt.Sprintf("%d", index)) + 2 + perNumber // probability
				total += wire(option) + 8                              // legend
				continue
			}
			total += 2*wire(option) + perNumber // probability key, and once as `choice`
		}
	}
	return total
}

func hasJSON(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	return trimmed != "" && trimmed != "null"
}

// VerifyError reports that a backend's answers violate the decision contract.
// It is never shown to the caller verbatim; the gateway retries or fails.
//
// Reason names the caller's own questions and options, so it is for tests and
// local debugging only. Kind is one of a fixed set of words and is the ONLY
// part that may be written to a log: request content never reaches one.
type VerifyError struct {
	Kind   string
	Reason string
}

func (e *VerifyError) Error() string { return "decision output failed verification: " + e.Reason }

// Violation kinds. Fixed strings: safe to log, enough to tell a model that
// cannot follow the format from one that answers outside the option set.
const (
	KindNotJSON   = "not_json"          // no JSON object, or an unterminated one
	KindCount     = "answer_count"      // a question unanswered, or an extra answer
	KindType      = "answer_type"       // wrong answer type, or fields of another type
	KindNumber    = "not_a_number"      // a word, null, or object where a number belongs
	KindRange     = "probability_range" // outside [0,1], negative, NaN or infinite
	KindOptions   = "option_set"        // an option missing, invented, or given twice
	KindMass      = "probability_mass"  // a distribution that does not sum to ~1
	KindDerived   = "derived_value"     // choice is not the argmax, or score is not the mean
	KindAmbiguous = "ambiguous_output"  // two different answers in one output, or a key with two readings
	KindDuplicate = "duplicate_key"     // a JSON key given twice: the decoder would silently keep the last
	kindUnlabeled = "contract"
)

func violation(format string, args ...any) *VerifyError {
	return &VerifyError{Kind: kindUnlabeled, Reason: fmt.Sprintf(format, args...)}
}

func (e *VerifyError) as(kind string) *VerifyError {
	e.Kind = kind
	return e
}

// ViolationKind is the loggable category of err, or "" if err is not a
// verification failure.
func ViolationKind(err error) string {
	var failed *VerifyError
	if errors.As(err, &failed) {
		return failed.Kind
	}
	return ""
}

// Verify is the second pass. It accepts answers from ANY backend and returns a
// canonical copy that is guaranteed to satisfy the decision contract for specs:
//
//   - exactly one answer per question, no extras, with the question's type;
//   - boolean: only `probability`, finite, within [0,1];
//   - choice: `probabilities` keyed by EXACTLY the declared options, each in
//     [0,1], mass ~1; `choice` is a declared option and is the argmax;
//   - score: `probabilities` keyed by EXACTLY "0".."n-1", mass ~1; `score` is
//     their expectation and lies in [0, n-1].
//
// Mass within massTolerance of 1 is renormalized (models round); anything
// further off is rejected rather than silently repaired. Derived fields
// (choice, score) are recomputed from the distribution, and a backend value
// that disagrees with the recomputation is a violation, not an override.
func Verify(specs []Spec, answers map[string]Answer) (map[string]Answer, error) {
	if len(answers) != len(specs) {
		return nil, violation("expected %d answers, got %d", len(specs), len(answers)).as(KindCount)
	}
	out := make(map[string]Answer, len(specs))
	for _, spec := range specs {
		answer, ok := answers[spec.Name]
		if !ok {
			return nil, violation("no answer for question %q", spec.Name).as(KindCount)
		}
		if answer.Type != spec.Type {
			return nil, violation("question %q is %s but the answer is %q", spec.Name, spec.Type, answer.Type).as(KindType)
		}
		switch spec.Type {
		case TypeBoolean:
			if answer.Probability == nil || answer.Choice != nil || answer.Score != nil || answer.Probabilities != nil {
				return nil, violation("boolean answer %q must carry only a probability", spec.Name).as(KindType)
			}
			p, err := unit(*answer.Probability)
			if err != nil {
				return nil, violation("boolean answer %q: %v", spec.Name, err).as(kindOf(err))
			}
			out[spec.Name] = Answer{Type: TypeBoolean, Probability: &p}
		case TypeChoice:
			if answer.Probability != nil || answer.Score != nil {
				return nil, violation("choice answer %q carries fields of another type", spec.Name).as(KindType)
			}
			dist, _, err := distribution(spec.Options, answer.Probabilities)
			if err != nil {
				return nil, violation("choice answer %q: %v", spec.Name, err).as(kindOf(err))
			}
			best := argmax(spec.Options, dist)
			if answer.Choice == nil {
				return nil, violation("choice answer %q has no choice", spec.Name).as(KindDerived)
			}
			if _, declared := dist[*answer.Choice]; !declared {
				return nil, violation("choice answer %q picked undeclared option %q", spec.Name, *answer.Choice).as(KindOptions)
			}
			if dist[*answer.Choice] < dist[best]-probabilityTol {
				return nil, violation("choice answer %q picked %q but %q has higher probability", spec.Name, *answer.Choice, best).as(KindDerived)
			}
			choice := *answer.Choice
			out[spec.Name] = Answer{Type: TypeChoice, Choice: &choice, Probabilities: dist}
		case TypeScore:
			if answer.Probability != nil || answer.Choice != nil {
				return nil, violation("score answer %q carries fields of another type", spec.Name).as(KindType)
			}
			rungs := make([]string, len(spec.Options))
			for i := range spec.Options {
				rungs[i] = fmt.Sprintf("%d", i)
			}
			dist, reportedMass, err := distribution(rungs, answer.Probabilities)
			if err != nil {
				return nil, violation("score answer %q: %v", spec.Name, err).as(kindOf(err))
			}
			expected := 0.0
			for i, rung := range rungs {
				expected += float64(i) * dist[rung]
			}
			if answer.Score == nil {
				return nil, violation("score answer %q has no score", spec.Name).as(KindDerived)
			}
			// The backend's own score must agree with its own distribution.
			// Honest disagreement has two sources, and the allowance is
			// exactly their size: renormalizing mass that was off by d moves
			// the mean by at most d x (n-1), and rounding the probabilities
			// moves it by a little more (1% of the scale is generous). What is
			// left over is a backend contradicting itself.
			scale := float64(len(rungs) - 1)
			allowed := 0.05 + scale*(math.Abs(reportedMass-1)+0.01)
			if math.IsNaN(*answer.Score) || math.Abs(*answer.Score-expected) > allowed {
				return nil, violation("score answer %q reports %.4f but its distribution implies %.4f", spec.Name, *answer.Score, expected).as(KindDerived)
			}
			score := math.Round(expected*100) / 100
			out[spec.Name] = Answer{Type: TypeScore, Score: &score, Probabilities: dist}
		}
	}
	return out, nil
}

func unit(p float64) (float64, error) {
	if math.IsNaN(p) || math.IsInf(p, 0) {
		return 0, kinded(KindRange, "probability is not finite")
	}
	if p < -probabilityTol || p > 1+probabilityTol {
		return 0, kinded(KindRange, "probability %v is outside [0,1]", p)
	}
	return math.Min(1, math.Max(0, p)), nil
}

// distribution returns the normalized distribution and the mass it had as
// reported, before normalization.
func distribution(keys []string, raw map[string]float64) (map[string]float64, float64, error) {
	if len(raw) != len(keys) {
		return nil, 0, kinded(KindOptions, "expected probabilities for %d options, got %d", len(keys), len(raw))
	}
	total := 0.0
	clean := make(map[string]float64, len(keys))
	for _, key := range keys {
		value, ok := raw[key]
		if !ok {
			return nil, 0, kinded(KindOptions, "no probability for %q", key)
		}
		p, err := unit(value)
		if err != nil {
			return nil, 0, kinded(kindOf(err), "option %q: %v", key, err)
		}
		clean[key] = p
		total += p
	}
	if math.Abs(total-1) > massTolerance {
		return nil, 0, kinded(KindMass, "probabilities sum to %.4f, not 1", total)
	}
	for key := range clean {
		clean[key] /= total
	}
	return clean, total, nil
}

// CheckNoDuplicateKeys rejects JSON in which any object repeats a key, at any
// depth. Go's decoder keeps the LAST value and says nothing, so without this
// `{"q0":0.1,"q0":0.9}` would verify as 0.9: an answer chosen by the decoder
// rather than given by the model. It reads tokens only and holds no values.
func CheckNoDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	type frame struct {
		keys      map[string]bool // nil for an array
		expectKey bool
	}
	var stack []frame
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			// A token stream that simply stops is a truncated document: EOF
			// is only success once every object and array has closed.
			if len(stack) != 0 {
				return violation("output is truncated JSON").as(KindNotJSON)
			}
			return nil
		}
		if err != nil {
			return violation("output is not valid JSON").as(KindNotJSON)
		}
		top := len(stack) - 1
		if delim, isDelim := token.(json.Delim); isDelim {
			switch delim {
			case '{':
				stack = append(stack, frame{keys: map[string]bool{}, expectKey: true})
			case '[':
				stack = append(stack, frame{})
			default: // '}' or ']'
				stack = stack[:top]
				if top > 0 && stack[top-1].keys != nil {
					stack[top-1].expectKey = true
				}
			}
			continue
		}
		if top < 0 || stack[top].keys == nil {
			continue // a scalar at the top level or inside an array
		}
		if stack[top].expectKey {
			key, _ := token.(string)
			if stack[top].keys[key] {
				return violation("a JSON key is given twice").as(KindDuplicate)
			}
			stack[top].keys[key] = true
			stack[top].expectKey = false
			continue
		}
		stack[top].expectKey = true // that was the value of the last key
	}
}

// argmax breaks ties by key order so the result is deterministic.
func argmax(keys []string, dist map[string]float64) string {
	best := keys[0]
	for _, key := range keys[1:] {
		if dist[key] > dist[best]+probabilityTol {
			best = key
		}
	}
	return best
}
