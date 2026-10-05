package upstreamerror

import (
	"fmt"
	"testing"

	"github.com/aws/smithy-go"
)

type sdkHTTPError struct {
	error
	status int
}

func (e sdkHTTPError) HTTPStatusCode() int { return e.status }
func (e sdkHTTPError) Unwrap() error       { return e.error }

func TestSDKErrorStatusFallsBackToCodeWithoutHTTPStatus(t *testing.T) {
	for _, tc := range []struct {
		code   string
		status int
	}{
		{"ValidationException", 400}, {"AccessDeniedException", 403}, {"ResourceNotFoundException", 404},
		{"ModelTimeoutException", 408}, {"ThrottlingException", 429}, {"ServiceQuotaExceededException", 429},
		{"InternalServerException", 500}, {"ServiceUnavailableException", 503}, {"ModelNotReadyException", 503},
		{"ModelStreamErrorException", 502}, {"ModelErrorException", 502}, {"UnknownException", 502},
	} {
		t.Run(tc.code, func(t *testing.T) {
			sdkErr := &smithy.GenericAPIError{Code: tc.code, Message: "refused"}
			for _, wrapped := range []bool{false, true} {
				var err error = fmt.Errorf("operation: %w", sdkErr)
				want := tc.status
				if wrapped {
					err = sdkHTTPError{err, 418}
					want = 418
				}
				detail := Parse(err)
				if detail.Status != want || detail.Code != tc.code || detail.Message != "refused" || !detail.Parsed {
					t.Fatalf("HTTP status present=%t detail=%+v want status=%d", wrapped, detail, want)
				}
			}
		})
	}
}
