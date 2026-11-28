package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestGCPCertificateTaskDispatch(t *testing.T) {
	failed := errors.New("test operation failed")
	for _, tc := range []struct{ task, want string }{
		{"gcp-acme-custody-check", "custody"},
		{"gcp-acme-preissue", "issue"}, {"gcp-acme-rehearse", "issue"},
		{"gcp-acme-rehearse-read", "issue"}, {"gcp-acme-rehearse-renew", "issue"},
		{"", ""}, {"acme", ""}, {"off", ""}, {"self-signed", ""}, {"gcp-acme-preissue-renew", ""},
	} {
		t.Run(tc.task, func(t *testing.T) {
			const host = "api.trustedrouter.com"
			calls := ""
			err := runGCPCertificateTask(tc.task, host,
				func() error { calls += "custody"; return failed },
				func(mode, gotHost string) error {
					if mode != tc.task || gotHost != host {
						t.Fatalf("unexpected issuer inputs: %q %q", mode, gotHost)
					}
					calls += "issue"
					return failed
				})
			if calls != tc.want || err == nil || errors.Is(err, failed) != (tc.want != "") {
				t.Fatalf("calls=%q err=%v", calls, err)
			}
		})
	}
}

func TestGCPCertificateTaskRejectsBeforeGatewayStartup(t *testing.T) {
	if os.Getenv("TR_TEST_ACME_TASK_CHILD") == "1" {
		main()
		return
	}
	for _, value := range []string{"", "acme", "off"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestGCPCertificateTaskRejectsBeforeGatewayStartup$")
		cmd.Env = append(os.Environ(), "TR_TEST_ACME_TASK_CHILD=1", "QUILL_GCP_ACME_TASK="+value)
		out, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if !errors.As(err, &exit) || exit.ExitCode() != 1 || lines[len(lines)-1] != "acme_task: invalid GCP certificate task" {
			t.Fatalf("selector %q: exit=%v, output=%q", value, err, out)
		}
	}
}
