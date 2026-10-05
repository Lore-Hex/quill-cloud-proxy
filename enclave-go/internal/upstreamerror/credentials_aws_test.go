//go:build cloud_aws

package upstreamerror

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

func TestBedrockStreamExceptionRedactsRecordedCredentialAndBoundsClientFields(t *testing.T) {
	const credential = "recorded-provider-credential"
	const prompt = "private echoed prompt"
	for _, suffix := range []string{"", strings.Repeat("x", 1500)} {
		ctx, redact := WithCredentialRedaction(t.Context())
		RecordCredential(ctx, credential)
		message := prompt + " " + credential + suffix
		sdkErr := &bedrocktypes.ModelStreamErrorException{Message: &message}
		if _, ok := any(sdkErr).(interface{ HTTPStatusCode() int }); ok {
			t.Fatal("fixture unexpectedly has HTTP status")
		}
		err := redact(fmt.Errorf("event stream: %w", sdkErr))
		detail := Parse(err)
		fields, _ := json.Marshal(detail)
		if strings.Contains(err.Error(), credential) || strings.Contains(err.Error(), prompt) || strings.Contains(string(fields), credential) {
			t.Fatalf("SDK error retained private error text or credential: err=%v detail=%s", err, fields)
		}
		if detail.Status != 502 || detail.Code != "ModelStreamErrorException" || !detail.Parsed || !strings.Contains(detail.Message, prompt+" ***") || !strings.Contains(detail.Raw, prompt+" ***") || len(detail.Message) > 1200 || len(detail.Raw) > 1200 {
			t.Fatalf("SDK error lost mapped/redacted/bounded detail: %+v", detail)
		}
	}
}

func TestBedrockValidationWithoutHTTPStatusReturnsBadRequest(t *testing.T) {
	message := "invalid request"
	err := &bedrocktypes.ValidationException{Message: &message}
	if _, ok := any(err).(interface{ HTTPStatusCode() int }); ok {
		t.Fatal("fixture unexpectedly has HTTP status")
	}
	if d := Parse(err); d.Status != 400 || d.Message != message || d.Code != "ValidationException" {
		t.Fatalf("validation exception detail=%+v", d)
	}
}
