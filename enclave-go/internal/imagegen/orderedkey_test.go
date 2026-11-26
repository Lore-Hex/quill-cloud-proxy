package imagegen

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/orderedkey"
)

func TestFALManagedCutoverNeverReplaysOrReplacesBYOK(t *testing.T) {
	gen := orderedkey.Generation("fal", "top", "bottom")
	for _, tc := range []struct{ decision, byok, want string }{
		{"primary:" + gen, "", "top"}, {gen, "", "bottom"}, {gen, "customer", "customer"},
		{"unknown", "", ""}, {"", "", ""},
	} {
		n := 0
		client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			n++
			if req.Header.Get("Authorization") != "Key "+tc.want {
				t.Fatal("wrong account")
			}
			return &http.Response{StatusCode: 402, Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header)}, nil
		})}
		resolved, err := Parse([]byte(`{"model":"fal/flux-1-schnell","prompt":"test"}`))
		if err != nil {
			t.Fatal(err)
		}
		resolved.ManagedKeyGeneration = tc.decision
		_, err = NewRegistry(ProviderKeys{FAL: "top", FALStandby: "bottom"}, client).Generate(t.Context(), resolved, tc.byok, "test")
		if err == nil || (tc.want != "" && n != 1) || (tc.want == "" && n != 0) {
			t.Fatal("incorrect number of attempts")
		}
	}
}
