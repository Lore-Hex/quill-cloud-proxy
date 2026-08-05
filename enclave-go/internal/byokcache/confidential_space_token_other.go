//go:build !cloud_gcp

package byokcache

import (
	"context"
	"fmt"
	"net/http"
)

type ConfidentialSpaceTokenSource struct{}

func NewConfidentialSpaceTokenSource(string, *http.Client) (*ConfidentialSpaceTokenSource, error) {
	return nil, fmt.Errorf("confidential identity: Confidential Space is unavailable in this build")
}

func (*ConfidentialSpaceTokenSource) Token(context.Context) (string, error) {
	return "", fmt.Errorf("confidential identity: Confidential Space is unavailable in this build")
}
