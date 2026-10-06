package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/video"
)

type tariffTestProvider struct {
	*refundTestProvider
	video.TokenBilledProvider
}

func tariffService(client *trustedrouter.Client) (*videoService, *refundTestProvider) {
	bp := video.NewBytePlusClient("test", nil)
	spy := &refundTestProvider{Provider: bp}
	return &videoService{control: client, providers: video.NewRegistryWithProviders(&tariffTestProvider{spy, bp}), workerID: "worker"}, spy
}

func tariffCreate(t *testing.T, s *videoService, seeded bool) string {
	t.Helper()
	seed := ""
	if seeded {
		seed = `,"seed":1101`
	}
	var out bytes.Buffer
	s.serveCreate(t.Context(), &out, []byte(`{"model":"bytedance/seedance-2.5","prompt":"cube","resolution":"1080p","duration":4`+seed+`}`), "test", "tariff")
	return out.String()
}

func TestVideoTariffDurableRejection(t *testing.T) {
	for _, seeded := range []bool{false, true} {
		for _, failure := range []string{"none", "refund", "update", "prepare", "existing"} {
			t.Run(fmt.Sprintf("seed=%t/%s", seeded, failure), func(t *testing.T) {
				a := newRefundAuthority(t)
				a.tariff = true
				a.failRefund, a.failUpdate = failure == "refund", failure == "update"
				a.failPrepare, a.existingPrepare = failure == "prepare", failure == "existing"
				client := trustedrouter.New("http://127.0.0.1:18082,http://127.0.0.1:18081", "internal", &http.Client{Transport: a})
				s, spy := tariffService(client)
				out := tariffCreate(t, s, seeded)
				if spy.queues != 0 {
					t.Fatal("tariff rejection dispatched")
				}
				if failure == "existing" {
					if !strings.HasPrefix(out, "HTTP/1.1 202 ") || len(a.refunds) != 0 {
						t.Fatal(out)
					}
					return
				}
				failureBody := videoHTTPBody(t, out)["error"].(map[string]any)
				code := "video_tariff_unavailable"
				if failure == "prepare" {
					code = "video_job_store_unavailable"
				}
				if !strings.HasPrefix(out, "HTTP/1.1 503 ") || failureBody["code"] != code || failureBody["type"] != "server_error" || failureBody["source"] != "router" {
					t.Fatal(out)
				}
				if len(a.refunds) != 1 || a.refunds[0]["error_type"] != code {
					t.Fatalf("refunds: %v", a.refunds)
				}
				if failure == "prepare" {
					if len(a.jobs) != 0 {
						t.Fatal("failed prepare stored a row")
					}
					return
				}
				job := a.jobs[trustedrouter.VideoJobID("auth-tariff")]
				if a.prepares != 1 || job.ProviderJobID != "" || job.Provider != "byteplus" || job.EndpointID != "primary" || job.QuotedMicrodollars != 0 || job.OutputTokenLimit != 400000 {
					t.Fatalf("invalid durable row: %+v", job)
				}
				if failure == "none" {
					if job.Status != "failed" || job.LastError != "tariff_unavailable" || a.held[job.AuthorizationID] {
						t.Fatalf("unreleased hold: %+v", job)
					}
					return
				}
				if job.Status != "submitting" {
					t.Fatalf("lost obligation: %+v", job)
				}
				// Restart and retry: stored job only, no new hold, prepare, refund or queue.
				freshClient := trustedrouter.New("http://127.0.0.1:18081,http://127.0.0.1:18082", "internal", &http.Client{Transport: a})
				// Replay uses the authority that can authorize; use original order first.
				replayClient := trustedrouter.New("http://127.0.0.1:18082,http://127.0.0.1:18081", "internal", &http.Client{Transport: a})
				replay, replaySpy := tariffService(replayClient)
				retry := tariffCreate(t, replay, seeded)
				if !strings.HasPrefix(retry, "HTTP/1.1 202 ") || videoHTTPBody(t, retry)["id"] != job.ID || a.newHolds != 1 || a.prepares != 1 || len(a.refunds) != 1 || replaySpy.queues != 0 {
					t.Fatalf("retry duplicated work: %s", retry)
				}
				fresh, _ := tariffService(freshClient)
				a.failRefund, a.failUpdate = false, false
				if n, err := fresh.drain(t.Context()); n != 0 || err != nil {
					t.Fatalf("early claim: %d %v", n, err)
				}
				a.now = a.now.Add(300 * time.Second)
				if n, err := fresh.drain(t.Context()); n != 1 || err != nil {
					t.Fatalf("restart claim: %d %v", n, err)
				}
				if a.jobs[job.ID].Status != "failed" || a.held[job.AuthorizationID] || a.releases != 1 || len(a.refunds) != 2 || a.refunds[1]["error_type"] != "video_submission_interrupted" {
					t.Fatalf("recovery failed: %+v", a)
				}
			})
		}
	}
}

// Preserve the control-plane transport's private dial-failure marker while
// using loopback HTTP for reachable authorities (Nitro's transport forbids it).
// After the first failure, all requests reach the actual local HTTP servers.
type tariffFailoverTransport struct {
	primary string
	dialErr error
}

func (tr *tariffFailoverTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host == tr.primary && tr.dialErr != nil {
		err := tr.dialErr
		tr.dialErr = nil
		return nil, err
	}
	return http.DefaultTransport.RoundTrip(r)
}

func TestVideoTariffRefundAfterAuthorizationFailover(t *testing.T) {
	for _, seeded := range []bool{false, true} {
		t.Run(fmt.Sprint(seeded), func(t *testing.T) {
			var primaryCalls atomic.Int32
			// Reserve a loopback address, then close it to cause a real tagged dial failure.
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := listener.Addr().String()
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			primary := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				primaryCalls.Add(1)
				w.WriteHeader(404)
			}))
			defer primary.Close()
			a := newRefundAuthority(t)
			a.tariff = true
			secondary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/authorize") {
					restored, err := net.Listen("tcp", address)
					if err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					_ = primary.Listener.Close()
					primary.Listener = restored
					primary.Start()
				}
				response, err := a.RoundTrip(r)
				if err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				defer response.Body.Close()
				w.WriteHeader(response.StatusCode)
				_, _ = io.Copy(w, response.Body)
			}))
			defer secondary.Close()
			// Capture an actual tagged dial failure with no listening authority.
			// On Nitro this is the transport's loopback allowlist rejection;
			// on the other clouds it is TCP connection refused.
			probe := trustedrouter.New("http://"+address, "internal", nil)
			_, _, dialErr := probe.AuthorizeVideo(t.Context(), "test", "bytedance/seedance-2.5", "1080p", "probe", strings.Repeat("a", 64), nil, 0, 400000)
			if dialErr == nil {
				t.Fatal("expected primary dial failure")
			}
			httpClient := &http.Client{Transport: &tariffFailoverTransport{primary: address, dialErr: dialErr}}
			client := trustedrouter.New("http://"+address+","+secondary.URL, "internal", httpClient)
			s, spy := tariffService(client)
			out := tariffCreate(t, s, seeded)
			if !strings.Contains(out, `"code":"video_tariff_unavailable"`) || a.prepares != 1 || len(a.refunds) != 1 || a.refunds[0]["error_type"] != "video_tariff_unavailable" || spy.queues != 0 || primaryCalls.Load() != 0 {
				t.Fatalf("failover rejection: %s primary=%d refunds=%v", out, primaryCalls.Load(), a.refunds)
			}
			// The durable row lives only at secondary; scoped lookup also restores its pin.
			job, err := client.LookupVideoJob(t.Context(), "test", trustedrouter.VideoJobID("auth-tariff"))
			if err != nil || job == nil || !job.ControlPlaneEndpointSet || job.ControlPlaneEndpoint != 1 {
				t.Fatalf("row not pinned: %+v %v", job, err)
			}
		})
	}
}
