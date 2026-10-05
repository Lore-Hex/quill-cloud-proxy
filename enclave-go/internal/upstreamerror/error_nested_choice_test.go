package upstreamerror

import (
	"errors"
	"strings"
	"testing"
)

func TestNestedErrorsBeforeTypedDecode(t *testing.T) {
	for _, location := range []string{"choice", "delta"} {
		for _, value := range []string{`{"code":403,"message":"refused"}`, `{"type":"rate_limit_error"}`, `null`} {
			t.Run(location+"/"+value, func(t *testing.T) {
				choice := `{"error":` + value + `}`
				if location == "delta" {
					choice = `{"delta":` + choice + `}`
				}
				payload := `{"choices":[` + choice + `],"usage":{"prompt_tokens":` + strings.Repeat("9", 400) + `}}`
				err := FromEvent(payload)
				if value == "null" {
					if err != nil {
						t.Fatalf("null is not an error: %v", err)
					}
					return
				}
				want := 403
				if strings.Contains(value, "rate_limit_error") {
					want = 429
				}
				var failure *Error
				if !errors.As(err, &failure) || failure.Status != want || failure.Body != payload {
					t.Fatalf("nested error lost: %#v", err)
				}
			})
		}
	}
}
