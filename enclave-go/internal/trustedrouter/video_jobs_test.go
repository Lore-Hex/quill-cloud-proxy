package trustedrouter

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestClaimedVideoJobKeepsItsBillingAuthority(t *testing.T) {
	const (
		primaryHost  = "127.0.0.1:18081"
		fallbackHost = "127.0.0.1:18082"
	)
	primaryUpdates, fallbackUpdates, fallbackSettles := 0, 0, 0
	response := func(request *http.Request, body string) *http.Response {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    request,
		}
	}
	client := New(
		"http://"+primaryHost+",http://"+fallbackHost,
		"internal",
		&http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			switch request.URL.Path {
			case "/internal/gateway/video/jobs/claim":
				if request.URL.Host == primaryHost {
					return response(request, `{"data":[]}`), nil
				}
				return response(request, `{"data":[{"id":"job-fallback","authorization_id":"auth-fallback","workspace_id":"ws","key_hash":"key","model":"minimax/hailuo-3","provider":"venice","endpoint_id":"video@venice/prepaid","quoted_microdollars":500000,"status":"in_progress"}]}`), nil
			case "/internal/gateway/video/jobs/job-fallback/update":
				if request.URL.Host == primaryHost {
					primaryUpdates++
				} else {
					fallbackUpdates++
				}
				return response(request, `{"data":{"id":"job-fallback","authorization_id":"auth-fallback","status":"in_progress"}}`), nil
			case "/internal/gateway/settle":
				if request.URL.Host != fallbackHost {
					t.Fatalf("settlement moved to %q, want %q", request.URL.Host, fallbackHost)
				}
				fallbackSettles++
				return response(request, `{"data":{"generation_id":"gen-fallback","settled":true}}`), nil
			default:
				t.Fatalf("unexpected request %s %s", request.URL.Host, request.URL.Path)
				return nil, nil
			}
		})},
	)

	jobs, err := client.ClaimVideoJobs(t.Context(), "worker", 10, 30)
	if err != nil {
		t.Fatalf("ClaimVideoJobs: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("claimed %d jobs, want 1", len(jobs))
	}
	job := &jobs[0]
	if !job.ControlPlaneEndpointSet || job.ControlPlaneEndpoint != 1 {
		t.Fatalf("claimed job authority = (%d, %t), want (1, true)", job.ControlPlaneEndpoint, job.ControlPlaneEndpointSet)
	}
	updated, err := client.UpdateVideoJob(t.Context(), job, "in_progress", "worker", "RUNNING", "", "", 5)
	if err != nil {
		t.Fatalf("UpdateVideoJob: %v", err)
	}
	if !updated.ControlPlaneEndpointSet || updated.ControlPlaneEndpoint != 1 {
		t.Fatalf("updated job authority = (%d, %t), want (1, true)", updated.ControlPlaneEndpoint, updated.ControlPlaneEndpointSet)
	}
	auth := &Authorization{
		AuthorizationID:         job.AuthorizationID,
		ControlPlaneEndpoint:    job.ControlPlaneEndpoint,
		ControlPlaneEndpointSet: job.ControlPlaneEndpointSet,
	}
	if _, err := client.Settle(t.Context(), auth, Usage{RouteType: "videos"}); err != nil {
		t.Fatalf("Settle: %v", err)
	}
	if primaryUpdates != 0 || fallbackUpdates != 1 || fallbackSettles != 1 {
		t.Fatalf("requests: primary updates=%d fallback updates=%d fallback settles=%d", primaryUpdates, fallbackUpdates, fallbackSettles)
	}
}

func TestVideoJobMutationRejectsMissingAuthorityWithMultipleControlPlanes(t *testing.T) {
	client := New("http://127.0.0.1:18081,http://127.0.0.1:18082", "internal", nil)
	_, err := client.UpdateVideoJob(t.Context(), &VideoJob{ID: "job-unpinned"}, "failed", "", "", "", "", 0)
	if err == nil || !strings.Contains(err.Error(), "no pinned control-plane authority") {
		t.Fatalf("UpdateVideoJob error = %v, want missing-authority failure", err)
	}
}
