package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/video"
)

func TestBytePlusVideoSubmissionReservesTokensBeforePaidQueue(t *testing.T) {
	events := []string{}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		events = append(events, "queue")
		if r.URL.Path != "/contents/generations/tasks" {
			t.Fatal(r.URL.Path)
		}
		io.WriteString(w, `{"id":"cgt-test"}`)
	}))
	defer provider.Close()
	var job map[string]any
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		switch {
		case strings.HasSuffix(r.URL.Path, "/authorize"):
			events = append(events, "authorize")
			if body["max_output_tokens"] != float64(80000) || body["additional_cost_reservation_microdollars"] != nil && body["additional_cost_reservation_microdollars"] != float64(0) {
				t.Fatalf("invalid hold %#v", body)
			}
			if strings.Contains(fmt.Sprint(body), "private prompt") {
				t.Fatal("prompt leaked to billing")
			}
			io.WriteString(w, `{"data":{"authorization_id":"auth-native","workspace_id":"ws","api_key_hash":"hash","model":"bytedance/seedance-2.5","endpoint_id":"bytedance/seedance-2.5@byteplus/prepaid","provider":"byteplus","usage_type":"Credits","video_token_billing":true,"estimated_cost_microdollars":856000}}`)
		case strings.HasSuffix(r.URL.Path, "/prepare"):
			events = append(events, "prepare")
			if body["quoted_microdollars"] != float64(0) || body["output_token_limit"] != float64(80000) {
				t.Fatalf("invalid job %#v", body)
			}
			job = body
			job["id"], job["created"], job["status"] = "job-native", true, "submitting"
			json.NewEncoder(w).Encode(map[string]any{"data": job})
		case strings.HasSuffix(r.URL.Path, "/queued"):
			events = append(events, "queued")
			if body["provider"] != "byteplus" || body["provider_model"] != "dreamina-seedance-2-5-260628" || body["quoted_microdollars"] != float64(0) {
				t.Fatalf("non-native route %#v", body)
			}
			job["status"] = "pending"
			json.NewEncoder(w).Encode(map[string]any{"data": job})
		default:
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
	}))
	defer control.Close()
	s := &videoService{providers: video.NewRegistryWithProviders(video.NewBytePlusClientAt("test", provider.URL, provider.Client())), control: trustedrouter.New(control.URL, "test", control.Client())}
	var out bytes.Buffer
	s.serveCreate(context.Background(), &out, []byte(`{"model":"bytedance/seedance-2.5","prompt":"private prompt","duration":4,"resolution":"480p","provider":{"only":["byteplus"]}}`), "test", "idem")
	if !strings.Contains(out.String(), "202") || strings.Join(events, ",") != "authorize,prepare,queue,queued" {
		t.Fatalf("events=%v response=%s", events, out.String())
	}
}

func TestBytePlusVideoSettlementRequiresActualBoundedUsage(t *testing.T) {
	for _, tokens := range []int{38_830, 80_001, 0} {
		t.Run(fmt.Sprint(tokens), func(t *testing.T) {
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, `{"id":"cgt-test","model":"native","status":"succeeded","usage":{"completion_tokens":%d},"content":{"video_url":"https://ark-acg-ap-southeast-1.tos-ap-southeast-1.volces.com/a.mp4"}}`, tokens)
			}))
			defer provider.Close()
			settles := 0
			control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				json.NewDecoder(r.Body).Decode(&body)
				switch {
				case strings.HasSuffix(r.URL.Path, "/settle"):
					settles++
					if body["actual_output_tokens"] != float64(tokens) || body["actual_input_tokens"] != float64(0) || body["additional_cost_microdollars"] != nil && body["additional_cost_microdollars"] != float64(0) {
						t.Fatalf("invalid settlement %#v", body)
					}
					io.WriteString(w, `{"data":{"generation_id":"gen-native","cost_microdollars":415481}}`)
				case strings.HasSuffix(r.URL.Path, "/update"):
					if settles != 1 {
						t.Fatal("published completed before settlement")
					}
					io.WriteString(w, `{"data":{"id":"job-native","status":"completed","output_token_limit":80000,"settled_microdollars":415481,"output_tokens":38830}}`)
				default:
					t.Fatal(r.URL.Path)
				}
			}))
			defer control.Close()
			s := &videoService{providers: video.NewRegistryWithProviders(video.NewBytePlusClientAt("test", provider.URL, provider.Client())), control: trustedrouter.New(control.URL, "test", control.Client())}
			job := &trustedrouter.VideoJob{ID: "job-native", AuthorizationID: "auth-native", Model: "bytedance/seedance-2.5", EndpointID: "bytedance/seedance-2.5@byteplus/prepaid", Provider: "byteplus", ProviderModel: "native", ProviderJobID: "cgt-test", Status: "pending", OutputTokenLimit: 80_000}
			updated, err := s.pollAndFinalize(context.Background(), job, "")
			if tokens != 38830 {
				if err == nil || settles != 0 {
					t.Fatal("invalid usage settled")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			writeVideoJobResponse(&out, 200, updated)
			usage := videoHTTPBody(t, out.String())["usage"].(map[string]any)
			if usage["cost_microdollars"] != float64(415481) || usage["completion_tokens"] != float64(38830) {
				t.Fatalf("wrong public usage %#v", usage)
			}
		})
	}
}
