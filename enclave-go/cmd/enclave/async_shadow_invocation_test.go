package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/imagegen"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/video"
)

// The signature is intentionally unchanged: these exercise local echo facts,
// never authenticated exclusion or router B. Fixtures remain untouched.
func invocationProjection(t *testing.T, route, model, provider, upstream string, streamed bool) map[string]any {
	t.Helper()
	t.Setenv("TR_ASYNC_SETTLE_SHADOW", "on")
	t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", "off")
	old := trustedrouter.ShadowBuildRevision
	trustedrouter.ShadowBuildRevision = strings.Repeat("a", 40)
	t.Cleanup(func() { trustedrouter.ShadowBuildRevision = old })
	var response map[string]any
	if err := json.Unmarshal(streamV2Fixture(t, "authorize_excluded")["object"], &response); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(response["billing_shadow_exclusion"].(string), ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(raw, &claims)
	claims["requested_route"], claims["requested_streamed"] = route, streamed
	raw, _ = json.Marshal(claims)
	parts[1] = base64.RawURLEncoding.EncodeToString(raw)
	response["billing_shadow_exclusion"] = strings.Join(parts, ".")
	for _, k := range []string{"authorization_id", "generation_id", "invocation_nonce", "workspace_id"} {
		response[k] = claims[k]
	}
	response["api_key_hash"], response["credit_reservation_id"] = claims["key_id"], claims["reservation_id"]
	response["model"], response["endpoint_id"], response["provider"], response["usage_type"] = model, "authorized-primary", "cohere", "BYOK"
	response["additional_cost_reservation_microdollars"] = 1000000
	if route == "images" {
		response["additional_cost_reservation_microdollars"] = 63300
	}
	response["route_candidates"] = []any{
		map[string]any{"endpoint_id": "authorized-primary", "provider": "cohere", "model": model, "usage_type": "BYOK", "byok_secret_ref": "byok://missing"},
		map[string]any{"endpoint_id": "invoked-fallback", "provider": provider, "model": model, "upstream_model": upstream, "usage_type": "Credits"},
	}
	return response
}

type invocationTerminal struct {
	path, header string
	body         map[string]any
}

func invocationGateway(t *testing.T, projection map[string]any) (*trustedrouter.Client, *[]invocationTerminal) {
	t.Helper()
	reply, _ := json.Marshal(map[string]any{"data": projection})
	terminals := new([]invocationTerminal)
	c := &http.Client{Transport: shadowV2StreamTransport(func(r *http.Request) (*http.Response, error) {
		answer := string(reply)
		if r.URL.Path != "/internal/gateway/authorize" {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			*terminals = append(*terminals, invocationTerminal{r.URL.Path, r.Header.Get("X-TR-Settlement-Shadow"), body})
			answer = `{"data":{"settled":true,"cost_microdollars":2}}`
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(answer))}, nil
	})}
	return trustedrouter.New("https://trustedrouter.com", "test", c), terminals
}
func checkInvocationTerminal(t *testing.T, terminals []invocationTerminal, fail, suppress bool, provider string) {
	t.Helper()
	if len(terminals) != 1 {
		t.Fatalf("terminal count %d", len(terminals))
	}
	term := terminals[0]
	kind := "settle"
	if fail {
		kind = "refund"
	}
	if term.path != "/internal/gateway/"+kind {
		t.Fatalf("terminal %s", term.path)
	}
	if suppress {
		if term.header != "" {
			t.Fatal("false exclusion on conflicting legacy endpoint")
		}
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(term.header)
	if err != nil {
		t.Fatal(err)
	}
	var obj struct {
		Attempt struct {
			Endpoint string `json:"selected_endpoint"`
			Adapter  string `json:"adapter"`
			Kind     string `json:"terminal_kind"`
		} `json:"attempt"`
	}
	if err = json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("missing/invalid echo: %s %v", raw, err)
	}
	if provider != "openai" && provider != "anthropic" {
		provider = "other"
	}
	if obj.Attempt.Endpoint != "invoked-fallback" || obj.Attempt.Adapter != provider || obj.Attempt.Kind != kind {
		t.Fatalf("actual invocation lost: %+v", obj)
	}
}

type invocationEmbedder struct {
	fakeEmbeddingLLM
	actual llm.InvokeOptions
	fail   bool
}

func (f *invocationEmbedder) InvokeEmbedding(ctx context.Context, r *types.EmbeddingRequest, o ...llm.InvokeOptions) (*types.EmbeddingResponse, error) {
	f.actual = o[0]
	if f.fail {
		return nil, errors.New("provider failed")
	}
	return f.fakeEmbeddingLLM.InvokeEmbedding(ctx, r, o...)
}
func TestShadowV2InvocationEmbeddings(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			gateway, terminals := invocationGateway(t, invocationProjection(t, "embeddings", "embedding-model", "openai", "", false))
			provider := &invocationEmbedder{fail: fail}
			var out bytes.Buffer
			serveEmbeddings(t.Context(), &out, provider, []byte(`{"model":"embedding-model","input":"hello"}`), gateway, true, "key", nil, "review", requestAttributionHeaders{}, "review")
			if provider.actual.EndpointID != "invoked-fallback" {
				t.Fatalf("not dispatched fallback: %+v; %s", provider.actual, out.String())
			}
			checkInvocationTerminal(t, *terminals, fail, true, "openai")
			if !fail && (*terminals)[0].body["selected_endpoint"] != "authorized-primary" {
				t.Fatalf("legacy body changed: %v", (*terminals)[0].body)
			}
		})
	}
}

type invocationDecider struct {
	fakeDecider
	actual llm.InvokeOptions
	fail   bool
}

func (f *invocationDecider) InvokeDecide(ctx context.Context, r *llm.DecideRequest, o ...llm.InvokeOptions) (*llm.DecideResponse, error) {
	f.actual = o[0]
	if f.fail {
		return nil, errors.New("provider failed")
	}
	return f.fakeDecider.InvokeDecide(ctx, r, o...)
}
func TestShadowV2InvocationDecide(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			gateway, terminals := invocationGateway(t, invocationProjection(t, "decide", "typesafe-ai/jev", "openai", "", false))
			provider := &invocationDecider{fail: fail, fakeDecider: fakeDecider{answers: map[string]decide.Answer{"refund": {Type: "boolean", Probability: pf(.9)}, "route": {Type: "choice", Choice: ps("billing"), Probabilities: map[string]float64{"billing": .9, "shipping": .1}}}}}
			var out bytes.Buffer
			serveDecide(t.Context(), &out, provider, []byte(decideBody), gateway, true, "key", nil, "review", requestAttributionHeaders{}, "review")
			if provider.actual.EndpointID != "invoked-fallback" {
				t.Fatalf("not dispatched fallback: %+v; %s", provider.actual, out.String())
			}
			checkInvocationTerminal(t, *terminals, fail, fail, "openai")
		})
	}
}

func TestShadowV2InvocationStream(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
			t.Setenv("QUILL_TERMINATE_AT_CAP", "off")
			gateway, terminals := invocationGateway(t, invocationProjection(t, "chat.completions", "openai/billing-v1", "openai", "", true))
			req := &types.OpenAIChatRequest{Model: "openai/billing-v1", Stream: true}
			a, err := gateway.AuthorizeWithRoute(t.Context(), "key", req, "chat.completions")
			if err != nil {
				t.Fatal(err)
			}
			options, err := invokeOptionsForAuthorization(t.Context(), nil, a)
			if err != nil || len(options) != 1 || options[0].EndpointID != "invoked-fallback" {
				t.Fatalf("filter: %v %v", options, err)
			}
			var out bytes.Buffer
			serveStreaming(t.Context(), &out, shadowStreamProvider{fail: fail}, req, &types.AnthropicMessagesRequest{}, options, gateway, a, nil, time.Now(), nil, "chat.completions", "review", req.Model)
			checkInvocationTerminal(t, *terminals, fail, fail, "openai")
		})
	}
}

func TestShadowV2InvocationImages(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			gateway, terminals := invocationGateway(t, invocationProjection(t, "images", "x-ai/grok-imagine-image-2.0", "grok", "grok-imagine-image-2.0", false))
			calls := 0
			provider := &http.Client{Transport: shadowV2StreamTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				status := 200
				body := `{"data":[{"b64_json":"` + invocationJPEG(t) + `"}]}`
				if fail {
					status = 400
					body = `{"error":"failed"}`
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			old := imageProviderGateway
			imageProviderGateway = imagegen.NewRegistry(imagegen.ProviderKeys{XAI: "key"}, provider)
			t.Cleanup(func() { imageProviderGateway = old })
			var out bytes.Buffer
			serveImages(t.Context(), &out, chatOnlyClient{}, []byte(`{"model":"x-ai/grok-imagine-image-2.0","prompt":"cat","aspect_ratio":"1:1"}`), gateway, "key", nil, "review", requestAttributionHeaders{}, "review")
			if calls != 1 {
				t.Fatalf("provider calls %d: %s", calls, out.String())
			}
			checkInvocationTerminal(t, *terminals, fail, fail, "grok")
		})
	}
}

// Speech has no candidate walk: the catalog/provider equality check precedes
// provider entry. Contradictory candidates cannot change the dispatch.
func TestShadowV2InvocationSpeech(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			p := invocationProjection(t, "audio.speech", "x-ai/grok-voice-tts-1.0", "grok", "grok-voice-tts-1.0", false)
			p["provider"], p["usage_type"], p["upstream_model"], p["endpoint_id"] = "grok", "Credits", "grok-voice-tts-1.0", "invoked-fallback"
			gateway, terminals := invocationGateway(t, p)
			generator := &fakeSpeech{fail: fail}
			old := speechProviderGateway
			speechProviderGateway = generator
			t.Cleanup(func() { speechProviderGateway = old })
			var out bytes.Buffer
			serveSpeech(t.Context(), &out, []byte(`{"model":"x-ai/grok-voice-tts-1.0","input":"hello","voice":"eve"}`), gateway, "key", "review", requestAttributionHeaders{}, "review")
			if generator.called != 1 {
				t.Fatalf("calls %d: %s", generator.called, out.String())
			}
			checkInvocationTerminal(t, *terminals, fail, false, "grok")
		})
	}
}

// User models dispatch the single signed custom-model block. RouteCandidates
// are not an alternative owner URL and must not redirect the request.
func TestShadowV2InvocationUserModel(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			p := invocationProjection(t, "chat.completions", "trustedrouter/user-demo", "custom", "owner-private", false)
			p["provider"], p["usage_type"], p["endpoint_id"] = "custom", "Credits", "invoked-fallback"
			dek := bytes.Repeat([]byte{6}, 32)
			cache := byokcache.New(byokcache.Options{Unwrapper: &userModelTestUnwrapper{dek: dek}})
			p["custom_model"] = &trustedrouter.CustomModel{
				ID: "trustedrouter/user-demo", Kind: "user_provided", UserModelKind: "machine", OwnerWorkspaceID: "owner-ws", EndpointURL: "https://example.com/v1", UpstreamModelID: "owner-private",
				SecretNamespace: userModelSecretNamespace, SigningEncryptedSecret: sealUserModelTestSecret(t, dek, "owner-ws", userModelSigningSecretPurpose, "signing-secret"), SigningSecretPurpose: userModelSigningSecretPurpose,
				ConnectTimeoutSeconds: 10, FirstByteTimeoutSeconds: 30, IdleTimeoutSeconds: 60, TotalTimeoutSeconds: 300,
			}
			gateway, terminals := invocationGateway(t, p)
			calls := 0
			old := newUserModelHTTPClient
			newUserModelHTTPClient = func(string, llm.EgressGuardOptions) (*http.Client, error) {
				return &http.Client{Transport: shadowV2StreamTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					if r.URL.Host != "example.com" {
						t.Error("candidate redirected owner")
					}
					status := 200
					body := `{"object":"chat.completion","choices":[{"message":{"role":"assistant","content":"answer"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`
					if fail {
						status = 400
						body = `{"error":"failed"}`
					}
					return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
				})}, nil
			}
			t.Cleanup(func() { newUserModelHTTPClient = old })
			req := &types.OpenAIChatRequest{Model: "trustedrouter/user-demo", Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hello"}}}
			a, err := gateway.AuthorizeWithRoute(t.Context(), "key", req, "chat.completions")
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			serveUserModel(t.Context(), &out, req, map[string]any{"messages": []any{map[string]any{"role": "user", "content": "hello"}}}, nil, "chat.completions", gateway, a, cache, nil, nil, "review")
			if calls != 1 {
				t.Fatalf("calls %d: %s", calls, out.String())
			}
			checkInvocationTerminal(t, *terminals, fail, false, "custom")
		})
	}
}

func TestShadowV2InvocationVideo(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			p := invocationProjection(t, "videos", "minimax/hailuo-3", "venice", "minimax-h3-text-to-video", false)
			gateway, terminals := invocationGateway(t, p)
			calls := 0
			providerClient := &http.Client{Transport: shadowV2StreamTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				status := 200
				body := `{"model":"minimax-h3-text-to-video","queue_id":"provider-job"}`
				if fail {
					status = 400
					body = `{"error":"failed"}`
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			service := &videoService{control: gateway, providers: video.NewRegistryWithProviders(video.NewVeniceClientAt("key", "https://provider.test", providerClient))}
			a, err := gateway.AuthorizeWithRoute(t.Context(), "key", &types.OpenAIChatRequest{Model: "minimax/hailuo-3"}, "videos")
			if err != nil {
				t.Fatal(err)
			}
			req, err := video.ResolveRequest(&video.CreateRequest{Model: "minimax/hailuo-3", Prompt: "hello", Duration: 5})
			if err != nil {
				t.Fatal(err)
			}
			routes := authorizedVideoRoutes(a, map[string]videoQuote{"venice": {Microdollars: 1000000}}, req.Resolution)
			chosen, _, err := service.queueVideoJob(t.Context(), req, routes, a)
			if calls != 1 {
				t.Fatalf("calls %d: %v", calls, err)
			}
			if fail {
				if err == nil {
					t.Fatal("missing provider error")
				}
				err = gateway.Refund(t.Context(), a, 502, "provider_error", 1, nil)
			} else {
				if err != nil {
					t.Fatal(err)
				}
				_, err = gateway.Settle(t.Context(), a, trustedrouter.Usage{RouteType: "videos", SelectedEndpoint: chosen.EndpointID, SelectedModel: a.Model})
			}
			if err != nil {
				t.Fatal(err)
			}
			checkInvocationTerminal(t, *terminals, fail, fail, "venice")
		})
	}
}

func invocationJPEG(t *testing.T) string {
	t.Helper()
	var out bytes.Buffer
	if err := jpeg.Encode(&out, image.NewRGBA(image.Rect(0, 0, 1024, 1024)), nil); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(out.Bytes())
}

// The full create handler reaches both immediate failure/refund and the queued
// transition after a real provider fallback. Success is deferred; its later
// reconstructed authorization intentionally cannot carry a v2 exclusion.
func TestShadowV2InvocationVideoHandler(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			p := invocationProjection(t, "videos", "minimax/hailuo-3", "venice", "minimax-h3-text-to-video", false)
			p["provider"], p["usage_type"] = "minimax", "Credits"
			p["route_candidates"] = []any{
				map[string]any{"endpoint_id": "authorized-primary", "provider": "minimax", "model": "minimax/hailuo-3", "usage_type": "Credits"},
				map[string]any{"endpoint_id": "invoked-fallback", "provider": "venice", "model": "minimax/hailuo-3", "usage_type": "Credits"},
			}
			var terminals []invocationTerminal
			var queued map[string]any
			control := &http.Client{Transport: shadowV2StreamTransport(func(r *http.Request) (*http.Response, error) {
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				answer := map[string]any{"data": map[string]any{"settled": true}}
				switch {
				case r.URL.Path == "/internal/gateway/authorize":
					answer["data"] = p
				case r.URL.Path == "/internal/gateway/video/jobs/prepare":
					body["id"] = "job-review"
					body["created"] = true
					answer["data"] = body
				case strings.HasSuffix(r.URL.Path, "/queued"):
					queued = body
					body["id"] = "job-review"
					body["status"] = "pending"
					answer["data"] = body
				case r.URL.Path == "/internal/gateway/refund" || r.URL.Path == "/internal/gateway/settle":
					terminals = append(terminals, invocationTerminal{r.URL.Path, r.Header.Get("X-TR-Settlement-Shadow"), body})
				}
				raw, _ := json.Marshal(answer)
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}, nil
			})}
			var called []string
			providerClient := &http.Client{Transport: shadowV2StreamTransport(func(r *http.Request) (*http.Response, error) {
				status := 200
				body := `{"quote":0.8}`
				if r.URL.Path != "/quote" {
					called = append(called, r.URL.Host)
					body = `{"model":"minimax-h3-text-to-video","queue_id":"provider-job"}`
					if r.URL.Host == "primary.test" {
						status = 503
						body = `{"error":"temporary"}`
					} else if fail {
						status = 400
						body = `{"error":"failed"}`
					}
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			gateway := trustedrouter.New("https://trustedrouter.com", "test", control)
			service := &videoService{control: gateway, providers: video.NewRegistryWithProviders(video.NewMiniMaxClientAt("key", "https://primary.test", providerClient), video.NewVeniceClientAt("key", "https://fallback.test", providerClient))}
			var out bytes.Buffer
			service.serveCreate(t.Context(), &out, []byte(`{"model":"minimax/hailuo-3","prompt":"hello","duration":5}`), "key", "review")
			if strings.Join(called, ",") != "primary.test,fallback.test" {
				t.Fatalf("fallback dispatch %v: %s", called, out.String())
			}
			if fail {
				checkInvocationTerminal(t, terminals, true, true, "venice")
			} else {
				if queued["endpoint_id"] != "invoked-fallback" || len(terminals) != 0 {
					t.Fatalf("queued fallback lost: %v", queued)
				}
				// Exercise the same reconstruction used by the completion handler.
				a := authorizationForVideoJob(&trustedrouter.VideoJob{AuthorizationID: p["authorization_id"].(string), EndpointID: "invoked-fallback", Provider: "venice", ControlPlaneEndpoint: 0, ControlPlaneEndpointSet: true})
				if _, err := gateway.Settle(t.Context(), a, trustedrouter.Usage{RouteType: "videos", SelectedEndpoint: "invoked-fallback"}); err != nil {
					t.Fatal(err)
				}
				if len(terminals) != 1 || terminals[0].header != "" {
					t.Fatal("deferred reconstruction synthesized exclusion")
				}
			}
		})
	}
}
