//go:build cloud_aws

package main

import (
	"errors"

	"github.com/aws/smithy-go"
)

// classifyUpstreamError unwraps AWS SDK errors to surface the API code/
// message verbatim. Anything non-AWS falls through with a generic label.
func classifyUpstreamError(err error) (string, string) {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode(), apiErr.ErrorMessage()
	}
	return "InternalError", err.Error()
}
