package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
)

func TestRepeatPenaltyCompatibility(t *testing.T) {
	for _, tc := range []struct {
		fields string
		want   float64
		bad    bool
	}{
		{`"repeat_penalty":1.12`, 1.12, false},
		{`"repeat_penalty":1`, 1, false},
		{`"repeat_penalty":0.5`, 0.5, false},
		{`"repeat_penalty":null`, 0, false},
		{`"repeat_penalty":null,"repetition_penalty":1.12`, 1.12, false},
		{`"repeat_penalty":1.12,"repetition_penalty":null`, 1.12, false},
		{`"repeat_penalty":1.0,"repetition_penalty":1`, 1, false},
		{`"repeat_penalty":1.12,"repetition_penalty":1.2`, 0, true},
		{`"repeat_penalty":0`, 0, true},
		{`"repeat_penalty":-1`, 0, true},
		{`"repeat_penalty":"private-value"`, 0, true},
		{`"repeat_penalty":true`, 0, true},
		{`"repeat_penalty":[]`, 0, true},
		{`"repeat_penalty":1e999`, 0, true},
	} {
		t.Run(tc.fields, func(t *testing.T) {
			req, err := parseChatRequest([]byte(`{"model":"test","messages":[],` + tc.fields + `}`))
			if tc.bad {
				var aerr *adapter.AdapterError
				if !errors.As(err, &aerr) || aerr.Status != 400 || aerr.Context != "repeat_penalty" {
					t.Fatalf("expected precise pre-authorization rejection, got %v", err)
				}
				if strings.Contains(err.Error(), "private-value") {
					t.Fatal("error leaked rejected value")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == 0 {
				if req.RepetitionPenalty != nil || len(req.RequestedParameters) != 0 {
					t.Fatal("null penalty must not introduce a capability")
				}
				return
			}
			if req.RepetitionPenalty == nil || *req.RepetitionPenalty != tc.want {
				t.Fatal("lost the requested penalty")
			}
			if len(req.RequestedParameters) != 1 || req.RequestedParameters[0] != "repetition_penalty" {
				t.Fatalf("lost capability or duplicate capability: %v", req.RequestedParameters)
			}
			wire, err := json.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(wire), `"repeat_penalty"`) || !strings.Contains(string(wire), `"repetition_penalty"`) {
				t.Fatal("provider must receive only canonical spelling")
			}
		})
	}
}
