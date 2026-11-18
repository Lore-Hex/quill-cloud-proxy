//go:build cloud_aws && llm_multi

package llm

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

func TestNitroGatewaysRefuseCloudBYOKAsTheirOwnLimit(t *testing.T) {
	for _, provider := range []string{"amazon-bedrock", "google-vertex", "azure"} {
		handled, err := invokeCloudBYOKStreaming(context.Background(), provider, nil, nil, io.Discard, InvokeOptions{ProviderAPIKey: "x", Provider: provider})
		var local *upstreamerror.Local
		if !handled || !errors.As(err, &local) {
			t.Fatalf("%s: handled=%v err=%v", provider, handled, err)
		}
	}
}
