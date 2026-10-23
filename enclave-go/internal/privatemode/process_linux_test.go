//go:build linux

package privatemode

import (
	"io"
	"os"
	"os/exec"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

func TestTLSPrivateKeyMemfdCannotBeMutated(t *testing.T) {
	f, err := sealedFile([]byte("synthetic-private-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt([]byte("replacement"), 0); err == nil {
		t.Fatal("memfd is writable")
	}
	if err := f.Truncate(0); err == nil {
		t.Fatal("memfd can be truncated")
	}
	got, err := io.ReadAll(f)
	if err != nil || string(got) != "synthetic-private-key" {
		t.Fatal("sealed bytes changed")
	}
}

func TestProxyExplicitSecureArguments(t *testing.T) {
	args := proxyArguments("/tmp/synthetic-collateral")
	for _, required := range []string{
		"--privatemode-proxy-child", "--listen-address=127.0.0.1",
		"--api-endpoint=api.privatemode.ai", "--manifest-path=/proc/self/fd/5",
		"--tls-cert-path=/proc/self/fd/3", "--tls-key-path=/proc/self/fd/4",
		"--nvidia-ocsp-allow-unknown=false", "--nvidia-ocsp-revoked-grace-period=0",
		"--insecure-api-connection=false", "--dump-requests=false", "--log-level=error",
	} {
		if !slices.Contains(args, required) {
			t.Errorf("missing required flag %q", required)
		}
	}
}

func TestCoreDumpsDisabled(t *testing.T) {
	if os.Getenv("TR_TEST_CORE_LIMIT_CHILD") == "1" {
		if err := disableCoreDumps(); err != nil {
			t.Fatal(err)
		}
		var limit unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_CORE, &limit); err != nil {
			t.Fatal(err)
		}
		if limit.Cur != 0 || limit.Max != 0 {
			t.Fatal("core dump limit is not zero")
		}
		return
	}
	// The hard limit cannot be raised again: isolate this assertion from other tests.
	cmd := exec.Command("/proc/self/exe", "-test.run=^TestCoreDumpsDisabled$")
	cmd.Env = append(os.Environ(), "TR_TEST_CORE_LIMIT_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child failed: %v %s", err, out)
	}
}
