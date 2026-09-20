// Package decide implements the wire contract of POST /v1/decide (alias
// /v1/evaluate): shared state plus typed questions in, typed answers with
// probabilities out. It is deliberately free of I/O so every rule here can be
// tested exhaustively.
//
// Two backends produce answers: a hosted decision model (TypeSafe AI's Jev via
// Vercel AI Gateway) and a native path that drives an ordinary chat model with
// strict structured output. NEITHER is trusted. Whatever comes back passes
// through Verify, which checks it against the request question by question, so
// a caller can never receive an answer whose shape, option set, or probability
// mass differs from what a decision model is contracted to return.
package decide

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
)

const (
	TypeBoolean = "boolean"
	TypeChoice  = "choice"
	TypeScore   = "score"

	MaxQuestions   = 64
	MaxOptions     = 255 // the hosted model's documented ceiling
	MaxNameLen     = 128
	MaxTextLen     = 8192
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
		if strings.TrimSpace(name) == "" || len(name) > MaxNameLen {
			return nil, bad("questions", "question names must be 1-%d characters", MaxNameLen)
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
				if strings.TrimSpace(option) == "" || len(option) > MaxNameLen {
					return nil, bad(param+".criteria", "option names must be 1-%d characters", MaxNameLen)
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
	return specs, nil
}

func hasJSON(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	return trimmed != "" && trimmed != "null"
}

// VerifyError reports that a backend's answers violate the decision contract.
// It is never shown to the caller verbatim; the gateway retries or fails.
type VerifyError struct{ Reason string }

func (e *VerifyError) Error() string { return "decision output failed verification: " + e.Reason }

func violation(format string, args ...any) *VerifyError {
	return &VerifyError{Reason: fmt.Sprintf(format, args...)}
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
		return nil, violation("expected %d answers, got %d", len(specs), len(answers))
	}
	out := make(map[string]Answer, len(specs))
	for _, spec := range specs {
		answer, ok := answers[spec.Name]
		if !ok {
			return nil, violation("no answer for question %q", spec.Name)
		}
		if answer.Type != spec.Type {
			return nil, violation("question %q is %s but the answer is %q", spec.Name, spec.Type, answer.Type)
		}
		switch spec.Type {
		case TypeBoolean:
			if answer.Probability == nil || answer.Choice != nil || answer.Score != nil || answer.Probabilities != nil {
				return nil, violation("boolean answer %q must carry only a probability", spec.Name)
			}
			p, err := unit(*answer.Probability)
			if err != nil {
				return nil, violation("boolean answer %q: %v", spec.Name, err)
			}
			out[spec.Name] = Answer{Type: TypeBoolean, Probability: &p}
		case TypeChoice:
			if answer.Probability != nil || answer.Score != nil {
				return nil, violation("choice answer %q carries fields of another type", spec.Name)
			}
			dist, err := distribution(spec.Options, answer.Probabilities)
			if err != nil {
				return nil, violation("choice answer %q: %v", spec.Name, err)
			}
			best := argmax(spec.Options, dist)
			if answer.Choice == nil {
				return nil, violation("choice answer %q has no choice", spec.Name)
			}
			if _, declared := dist[*answer.Choice]; !declared {
				return nil, violation("choice answer %q picked undeclared option %q", spec.Name, *answer.Choice)
			}
			if dist[*answer.Choice] < dist[best]-probabilityTol {
				return nil, violation("choice answer %q picked %q but %q has higher probability", spec.Name, *answer.Choice, best)
			}
			choice := *answer.Choice
			out[spec.Name] = Answer{Type: TypeChoice, Choice: &choice, Probabilities: dist}
		case TypeScore:
			if answer.Probability != nil || answer.Choice != nil {
				return nil, violation("score answer %q carries fields of another type", spec.Name)
			}
			rungs := make([]string, len(spec.Options))
			for i := range spec.Options {
				rungs[i] = fmt.Sprintf("%d", i)
			}
			dist, err := distribution(rungs, answer.Probabilities)
			if err != nil {
				return nil, violation("score answer %q: %v", spec.Name, err)
			}
			expected := 0.0
			for i, rung := range rungs {
				expected += float64(i) * dist[rung]
			}
			if answer.Score == nil {
				return nil, violation("score answer %q has no score", spec.Name)
			}
			// The hosted model rounds score to two decimals.
			if math.IsNaN(*answer.Score) || math.Abs(*answer.Score-expected) > 0.05+massTolerance*float64(len(rungs)-1) {
				return nil, violation("score answer %q reports %.4f but its distribution implies %.4f", spec.Name, *answer.Score, expected)
			}
			score := math.Round(expected*100) / 100
			out[spec.Name] = Answer{Type: TypeScore, Score: &score, Probabilities: dist}
		}
	}
	return out, nil
}

func unit(p float64) (float64, error) {
	if math.IsNaN(p) || math.IsInf(p, 0) {
		return 0, fmt.Errorf("probability is not finite")
	}
	if p < -probabilityTol || p > 1+probabilityTol {
		return 0, fmt.Errorf("probability %v is outside [0,1]", p)
	}
	return math.Min(1, math.Max(0, p)), nil
}

func distribution(keys []string, raw map[string]float64) (map[string]float64, error) {
	if len(raw) != len(keys) {
		return nil, fmt.Errorf("expected probabilities for %d options, got %d", len(keys), len(raw))
	}
	total := 0.0
	clean := make(map[string]float64, len(keys))
	for _, key := range keys {
		value, ok := raw[key]
		if !ok {
			return nil, fmt.Errorf("no probability for %q", key)
		}
		p, err := unit(value)
		if err != nil {
			return nil, fmt.Errorf("option %q: %v", key, err)
		}
		clean[key] = p
		total += p
	}
	if math.Abs(total-1) > massTolerance {
		return nil, fmt.Errorf("probabilities sum to %.4f, not 1", total)
	}
	for key := range clean {
		clean[key] /= total
	}
	return clean, nil
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
