package adapter

import (
	"testing"
)

func TestValidateChatStorePolicy(t *testing.T) {
	for _, tc := range []struct {
		value  string
		status int
	}{
		{"false", 0}, {"null", 0}, {"true", 501},
		{`"false"`, 400}, {`"true"`, 400}, {"0", 400}, {"1", 400},
		{"[]", 400}, {"{}", 400},
	} {
		t.Run(tc.value, func(t *testing.T) {
			result, err := ValidateChatRequestFields(rawChatRequest(t,
				`{"model":"m","messages":[{"role":"user","content":"hi"}],"provider":{"require_parameters":true},"store":`+tc.value+`}`))
			if tc.status != 0 {
				assertRequestFieldError(t, err, tc.status, "store")
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(result.RequestedParameters) != 0 {
				t.Fatalf("router-owned no-storage policy became a provider capability: %v", result.RequestedParameters)
			}
		})
	}
}
