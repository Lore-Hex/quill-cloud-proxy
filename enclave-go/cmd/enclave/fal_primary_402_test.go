//go:build llm_multi

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/imagegen"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/orderedkey"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/video"
)

func TestFALPrimary402ReportsOnceWithoutReplayingSubmission(t *testing.T) {
	gen := orderedkey.Generation("fal", "top", "bottom")
	for _, kind := range []string{"image", "video"} {
		for _, tc := range []struct {
			status                           int
			slot, standby, override, wantKey string
			wantReports                      int
		}{
			{402, "primary:" + gen, "bottom", "", "top", 1},
			{429, "primary:" + gen, "bottom", "", "top", 0},
			{403, "primary:" + gen, "bottom", "", "top", 0},
			{502, "primary:" + gen, "bottom", "", "top", 0},
			{402, gen, "bottom", "", "bottom", 0},
			{402, "primary:" + gen, "", "", "top", 0},
			{402, "primary:" + gen, "bottom", "customer", "customer", 0},
		} {
			if kind == "video" && tc.override != "" {
				continue
			}
			t.Run(fmt.Sprintf("%s/%d/%s/%s/%s", kind, tc.status, tc.wantKey, tc.standby, tc.override), func(t *testing.T) {
				endpoint := "fal/flux-1-schnell@fal/prepaid"
				if kind == "video" {
					endpoint = "minimax/h3-max@fal/prepaid"
				}
				paid, reports := 0, 0
				mock := func(status int, body string) *http.Response {
					return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
				}
				transport := &http.Client{Transport: imageRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.URL.Host == "fal.run" || r.URL.Host == "queue.fal.run" {
						paid++
						if r.Method != "POST" || r.Header.Get("Authorization") != "Key "+tc.wantKey {
							t.Fatal("incorrect submission")
						}
						return mock(tc.status, "{}"), nil
					}
					if r.URL.Host != "127.0.0.2" {
						t.Fatal("report escaped issuing authority")
					}
					switch r.URL.Path {
					case "/internal/gateway/fal-primary-402":
						reports++
						var fields map[string]any
						if err := json.NewDecoder(r.Body).Decode(&fields); err != nil || len(fields) != 4 ||
							fields["upstream_status"] != float64(402) || fields["primary_generation"] != gen || fields["endpoint_id"] != endpoint ||
							fields["authorization_id"] != "auth-test" || r.Header.Get("x-trustedrouter-internal-token") != "test-service" {
							t.Fatal("bad rejection report")
						}
						return mock(200, fmt.Sprintf(`{"accepted":true,"generation":%q}`, gen)), nil
					case "/internal/gateway/refund":
						return mock(200, `{"data":{"settled":true,"finalization_outcome":"refunded"}}`), nil
					default:
						t.Fatalf("unexpected control request %s", r.URL.Path)
						return nil, nil
					}
				})}
				control := trustedrouter.New("http://127.0.0.1,http://127.0.0.2", "test-service", transport)
				auth := &trustedrouter.Authorization{AuthorizationID: "auth-test", EndpointID: endpoint, Provider: "fal", UsageType: "Credits",
					ManagedKeyCutovers: map[string]string{"fal": tc.slot}, ControlPlaneEndpoint: 1, ControlPlaneEndpointSet: true}
				if kind == "video" {
					s := videoService{control: control, providers: video.NewRegistry(video.ProviderKeys{FAL: "top", FALStandby: tc.standby}, transport)}
					req, err := video.ResolveRequest(&video.CreateRequest{Model: "minimax/h3-max", Prompt: "test", Duration: 5, Resolution: "768p", AspectRatio: "16:9"})
					if err != nil {
						t.Fatal(err)
					}
					_, _, err = s.queueVideoJob(t.Context(), req, []authorizedVideoRoute{{Provider: "fal", EndpointID: endpoint, ManagedKeyGeneration: tc.slot}}, auth)
					if err == nil {
						t.Fatal("expected rejected submission")
					}
				} else {
					prev := imageProviderGateway
					imageProviderGateway = imagegen.NewRegistry(imagegen.ProviderKeys{FAL: "top", FALStandby: tc.standby}, transport)
					t.Cleanup(func() { imageProviderGateway = prev })
					resolved, err := parseImageGenerationRequest([]byte(`{"model":"fal/flux-1-schnell","prompt":"test"}`))
					if err != nil {
						t.Fatal(err)
					}
					option := llm.InvokeOptions{Provider: "fal", UsageType: "Credits", EndpointID: endpoint, ManagedKeyGeneration: tc.slot, UpstreamModel: "fal-ai/flux/schnell", ProviderAPIKey: tc.override}
					if tc.override != "" {
						option.UsageType = "BYOK"
					}
					serveNativeImageAuthorized(context.Background(), new(bytes.Buffer), resolved, &types.OpenAIChatRequest{Model: "fal/flux-1-schnell"}, control, auth, option, "", time.Now())
				}
				if paid != 1 || reports != tc.wantReports {
					t.Fatalf("submissions=%d reports=%d want %d", paid, reports, tc.wantReports)
				}
			})
		}
	}
}
