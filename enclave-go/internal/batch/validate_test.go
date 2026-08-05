package batch

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseCreateRequiresOpenRouterFieldOrder(t *testing.T) {
	t.Parallel()

	_, apiErr := ParseCreate([]byte(`{"requests":[{"custom_id":"one","body":{"messages":[]}}],"endpoint":"/v1/chat/completions","model":"test/model"}`))
	if apiErr == nil || apiErr.Status != 400 || apiErr.Param != "requests" {
		t.Fatalf("apiErr = %#v, want requests field-order error", apiErr)
	}
}

func TestParseCreateNormalizesBodiesAndPreservesRequestOrder(t *testing.T) {
	t.Parallel()

	req, apiErr := ParseCreate([]byte(`{
        "endpoint":"/v1/chat/completions",
        "model":"test/model",
        "requests":[
          {"custom_id":"first","body":{"messages":[{"role":"user","content":"A"}]}},
          {"custom_id":"second","body":{"model":"test/model","messages":[{"role":"user","content":"B"}]}}
        ]
      }`))
	if apiErr != nil {
		t.Fatalf("ParseCreate: %v", apiErr)
	}
	if len(req.Requests) != 2 || req.Requests[0].CustomID != "first" || req.Requests[1].CustomID != "second" {
		t.Fatalf("request order changed: %#v", req.Requests)
	}
	for index, request := range req.Requests {
		var body map[string]any
		if err := json.Unmarshal(request.Body, &body); err != nil {
			t.Fatalf("request %d body: %v", index, err)
		}
		if body["model"] != "test/model" {
			t.Fatalf("request %d model = %#v", index, body["model"])
		}
	}
}

func TestParseCreateRejectsInvalidBatchShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		code string
	}{
		{"empty requests", `{"endpoint":"/v1/chat/completions","model":"m","requests":[]}`, "bad_request"},
		{"duplicate id", `{"endpoint":"/v1/chat/completions","model":"m","requests":[{"custom_id":"x","body":{}},{"custom_id":"x","body":{}}]}`, "duplicate_custom_id"},
		{"model mismatch", `{"endpoint":"/v1/chat/completions","model":"m","requests":[{"custom_id":"x","body":{"model":"other"}}]}`, "model_mismatch"},
		{"streaming", `{"endpoint":"/v1/responses","model":"m","requests":[{"custom_id":"x","body":{"stream":true,"input":"hello"}}]}`, "unsupported_parameter"},
		{"unknown endpoint", `{"endpoint":"/v1/fine_tuning/jobs","model":"m","requests":[{"custom_id":"x","body":{}}]}`, "unsupported_endpoint"},
		{"unknown top field", `{"endpoint":"/v1/messages","model":"m","metadata":{},"requests":[{"custom_id":"x","body":{}}]}`, "bad_request"},
		{"trailing json", `{"endpoint":"/v1/messages","model":"m","requests":[{"custom_id":"x","body":{}}]} {}`, "bad_request"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, apiErr := ParseCreate([]byte(test.body))
			if apiErr == nil || apiErr.Status != 400 || apiErr.Code != test.code {
				t.Fatalf("apiErr = %#v, want code %q", apiErr, test.code)
			}
		})
	}
}

func TestParseCreateAcceptsDocumentedEmbeddingInputs(t *testing.T) {
	t.Parallel()

	inputs := []string{
		`"one"`,
		`["one","two"]`,
		`[1,2,3]`,
		`[[1,2],[3,4]]`,
	}
	for _, input := range inputs {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			body := `{"endpoint":"/v1/embeddings","model":"embed/model","requests":[{"custom_id":"one","body":{"input":` + input + `}}]}`
			if _, apiErr := ParseCreate([]byte(body)); apiErr != nil {
				t.Fatalf("ParseCreate(%s): %v", input, apiErr)
			}
		})
	}
}

func TestParseCreateRejectsUnsupportedEmbeddingInputs(t *testing.T) {
	t.Parallel()

	inputs := []string{
		`""`,
		`[]`,
		`["one",2]`,
		`[1,[2]]`,
		`[[1],"two"]`,
		`[["one"]]`,
		`{"image":"data:image/png;base64,AA=="}`,
	}
	for _, input := range inputs {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			body := `{"endpoint":"/v1/embeddings","model":"embed/model","requests":[{"custom_id":"one","body":{"input":` + input + `}}]}`
			_, apiErr := ParseCreate([]byte(body))
			if apiErr == nil || apiErr.Code != "unsupported_parameter" {
				t.Fatalf("apiErr = %#v", apiErr)
			}
		})
	}
}

func TestParseCreateRejectsEmbeddingProviderAndInputType(t *testing.T) {
	t.Parallel()

	for _, extra := range []string{`,"provider":{"order":["openai"]}`, `,"input_type":"query"`} {
		body := `{"endpoint":"/v1/embeddings","model":"embed/model","requests":[{"custom_id":"one","body":{"input":"hello"` + extra + `}}]}`
		_, apiErr := ParseCreate([]byte(body))
		if apiErr == nil || apiErr.Code != "unsupported_parameter" {
			t.Fatalf("extra %s: apiErr = %#v", extra, apiErr)
		}
	}
}

func TestParseCreateBoundsCustomIDByBytes(t *testing.T) {
	t.Parallel()

	customID := strings.Repeat("a", maxCustomIDBytes+1)
	body := `{"endpoint":"/v1/messages","model":"m","requests":[{"custom_id":"` + customID + `","body":{}}]}`
	_, apiErr := ParseCreate([]byte(body))
	if apiErr == nil || apiErr.Param != "requests[0].custom_id" {
		t.Fatalf("apiErr = %#v", apiErr)
	}
}

func TestValidateCreateBoundsRequestCountBeforePerItemWork(t *testing.T) {
	t.Parallel()

	req := CreateRequest{
		Endpoint: "/v1/chat/completions",
		Model:    "test/model",
		Requests: make([]Request, maxBatchRequests+1),
	}
	apiErr := validateCreate(&req)
	if apiErr == nil || apiErr.Code != "batch_too_large" || apiErr.Param != "requests" {
		t.Fatalf("apiErr = %#v", apiErr)
	}
}

func TestBatchPlaintextLimitLeavesEnvelopeEncryptionHeadroom(t *testing.T) {
	t.Parallel()

	if batchPlaintextTooLarge(maxBatchPlaintextBytes) ||
		!batchPlaintextTooLarge(maxBatchPlaintextBytes+1) {
		t.Fatal("batch plaintext boundary is not enforced exactly")
	}
	if maxBatchPlaintextBytes*4/3 >= maxGCSObjectSize {
		t.Fatalf(
			"plaintext cap %d does not leave envelope headroom below object cap %d",
			maxBatchPlaintextBytes, maxGCSObjectSize,
		)
	}
}

func TestValidateCreateBoundsTotalEmbeddingInputs(t *testing.T) {
	t.Parallel()

	inputs := make([]string, maxBatchRequests)
	for index := range inputs {
		inputs[index] = "x"
	}
	encodedInputs, err := json.Marshal(inputs)
	if err != nil {
		t.Fatalf("marshal inputs: %v", err)
	}
	req := CreateRequest{
		Endpoint: "/v1/embeddings",
		Model:    "embed/model",
		Requests: []Request{
			{CustomID: "many", Body: json.RawMessage(`{"input":` + string(encodedInputs) + `}`)},
			{CustomID: "one-more", Body: json.RawMessage(`{"input":"overflow"}`)},
		},
	}
	apiErr := validateCreate(&req)
	if apiErr == nil || apiErr.Code != "batch_too_large" || apiErr.Param != "requests" {
		t.Fatalf("apiErr = %#v", apiErr)
	}
}
