package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
)

// Tinfoil exposes the OpenAI Decisions wire format, not SystemOne. Translate
// only structure; the existing decide.Verify still checks every answer.
func invokeTinfoilDecide(ctx context.Context, httpc *http.Client, baseURL, apiKey, model string, req *DecideRequest) (*DecideResponse, error) {
	fail := func() (*DecideResponse, error) {
		return nil, &DecideError{Provider: "tinfoil", Class: DecideErrDecode}
	}
	if httpc == nil || baseURL != "https://inference.tinfoil.sh/v1" || !decide.IsTinfoilModel("tinfoil/"+model) || len(req.Images) != 0 {
		return nil, &DecideError{Provider: "tinfoil", Class: DecideErrConfig}
	}
	specs, err := decide.Parse(req.Questions)
	if err != nil {
		return nil, &DecideError{Provider: "tinfoil", Class: DecideErrConfig}
	}
	input, err := decide.StateText(req.State)
	if err != nil {
		return nil, &DecideError{Provider: "tinfoil", Class: DecideErrConfig}
	}
	questions := make([]map[string]any, 0, len(specs))
	for _, spec := range specs {
		instructions := spec.Instructions
		if len(spec.Descriptions) != 0 {
			descriptions, _ := json.Marshal(spec.Descriptions)
			instructions += "\nCriteria descriptions: " + string(descriptions)
		}
		q := map[string]any{"name": spec.Name, "type": spec.Type, "instructions": instructions}
		switch spec.Type {
		case decide.TypeBoolean:
			q["type"] = "predicate"
		case decide.TypeChoice:
			if len(spec.Options) > 26 {
				return nil, &DecideError{Provider: "tinfoil", Class: DecideErrConfig}
			}
			choices := make([]map[string]string, 0, len(spec.Options))
			for _, option := range spec.Options {
				choices = append(choices, map[string]string{"value": option})
			}
			q["choices"] = choices
		case decide.TypeScore:
			levels := make([]map[string]string, 0, len(spec.Options))
			for _, label := range spec.Options {
				levels = append(levels, map[string]string{"label": label})
			}
			q["levels"] = levels
		}
		questions = append(questions, q)
	}
	raw, err := postDecideJSON(ctx, httpc, "tinfoil", baseURL+"/decisions", apiKey, map[string]any{
		"model": model, "input": input, "questions": questions,
	})
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Model   string `json:"model"`
		Answers []struct {
			Name          string   `json:"name"`
			Type          string   `json:"type"`
			Probability   *float64 `json:"probability"`
			Noul          *float64 `json:"noul"`
			Choice        *string  `json:"choice"`
			Score         *float64 `json:"score"`
			Probabilities []struct {
				Value       json.RawMessage `json:"value"`
				Probability *float64        `json:"probability"`
			} `json:"probabilities"`
		} `json:"answers"`
		Usage struct {
			Input  *int `json:"input_tokens"`
			Output *int `json:"output_tokens"`
			Total  *int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := decodeDecideBody("tinfoil", raw, &parsed); err != nil {
		return nil, err
	}
	u := parsed.Usage
	if parsed.Model != model || u.Input == nil || *u.Input <= 0 || u.Output == nil || *u.Output != 0 || u.Total == nil || *u.Total != *u.Input {
		return fail()
	}
	answers := make(map[string]decide.Answer, len(parsed.Answers))
	for _, source := range parsed.Answers {
		if _, exists := answers[source.Name]; exists {
			return fail()
		}
		kind := source.Type
		if kind == "predicate" {
			kind = decide.TypeBoolean
		} else if kind != decide.TypeChoice && kind != decide.TypeScore {
			return fail()
		}
		answer := decide.Answer{Type: kind, Probability: source.Probability, Noul: source.Noul, Choice: source.Choice, Score: source.Score}
		if source.Probabilities != nil {
			answer.Probabilities = make(map[string]float64, len(source.Probabilities))
			for _, option := range source.Probabilities {
				var key string
				if kind == decide.TypeScore {
					var index int
					if json.Unmarshal(option.Value, &index) != nil || string(option.Value) == "null" {
						return fail()
					}
					key = strconv.Itoa(index)
				} else if json.Unmarshal(option.Value, &key) != nil || string(option.Value) == "null" {
					return fail()
				}
				if _, exists := answer.Probabilities[key]; exists || option.Probability == nil {
					return fail()
				}
				answer.Probabilities[key] = *option.Probability
			}
		}
		answers[source.Name] = answer
	}
	return &DecideResponse{Answers: answers, InputTokens: *u.Input}, nil
}
