//go:build linux

package privatemode

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Start is non-fatal to other providers. The returned client exists only once
// the pinned child is ready; it never connects to the public plaintext API.
func Start(ctx context.Context) (*http.Client, error) {
	client, _, err := startProcess(ctx)
	return client, err
}

// ProxyEntrypoint is called before bootstrap. The trusted launcher drops its
// identity before exec, then disables privilege gains before running vendor code.
func ProxyEntrypoint() bool {
	if len(os.Args) < 2 || os.Args[1] != "--privatemode-proxy-child" {
		return false
	}
	if os.Geteuid() != 65532 || os.Getegid() != 65532 || unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil {
		os.Exit(1)
	}
	// #nosec G204 -- fixed measured binary; only our launcher supplies these arguments, never a request or shell.
	if err := syscall.Exec(proxyBinary, append([]string{proxyBinary}, os.Args[2:]...), os.Environ()); err != nil {
		os.Exit(1)
	}
	return true
}

func startProcess(ctx context.Context) (*http.Client, <-chan struct{}, error) {
	return startProcessWithManifest(ctx, manifest)
}

func startProcessWithManifest(ctx context.Context, expectedManifest []byte) (*http.Client, <-chan struct{}, error) {
	if _, err := os.Stat(proxyBinary); err != nil {
		return nil, nil, errors.New("privatemode: proxy binary unavailable")
	}
	certPEM, keyPEM, cert, err := localIdentity(time.Now())
	if err != nil {
		return nil, nil, err
	}
	var files []*os.File
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	for _, data := range [][]byte{certPEM, keyPEM, expectedManifest} {
		f, err := sealedFile(data)
		if err != nil {
			return nil, nil, err
		}
		files = append(files, f)
	}
	// Only public attestation collateral goes in this cache. Prompt secrets and
	// local TLS keys stay in memory; request dumping is never enabled.
	workspace, err := os.MkdirTemp("", "privatemode-collateral-")
	if err != nil {
		return nil, nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(workspace)
		}
	}()
	if err := os.Chown(workspace, 65532, 65532); err != nil {
		return nil, nil, errors.New("privatemode: cannot isolate collateral directory")
	}
	networkCtx, cancelNetwork := context.WithCancel(ctx)
	env, stopNetwork, err := platformEnvironment(networkCtx)
	if err != nil {
		cancelNetwork()
		return nil, nil, err
	}
	client := localClient(cert)
	// #nosec G204 -- fixed launcher and flags; workspace is a private MkdirTemp path, not caller input.
	cmd := exec.CommandContext(ctx, "/quill-enclave", "--privatemode-proxy-child",
		"--listen-address=127.0.0.1", "--port=18489",
		"--apiEndpoint=api.privatemode.ai",
		"--tlsCertPath=/proc/self/fd/3", "--tlsKeyPath=/proc/self/fd/4",
		"--manifestPath=/proc/self/fd/5", "--workspace="+workspace,
		"--nvidiaOCSPAllowUnknown=false", "--nvidiaOCSPRevokedGracePeriod=0",
		"--log-level=error",
	)
	cmd.Env = env // Do not inherit provider keys, proxy settings, or debug flags.
	cmd.ExtraFiles = files
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65532, Gid: 65532, Groups: []uint32{}}}
	// Upstream error bodies are untrusted. Emit lifecycle metadata only below.
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		cancelNetwork()
		stopNetwork()
		return nil, nil, errors.New("privatemode: proxy start failed")
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		client.Transport.(restrictedTransport).base.CloseIdleConnections()
		cancelNetwork()
		stopNetwork()
		_ = os.RemoveAll(workspace)
		fmt.Fprintf(os.Stderr, "privatemode.proxy_exit exit_code=%d\n", cmd.ProcessState.ExitCode())
		close(done)
	}()
	deadline := time.NewTimer(60 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			<-done
			return nil, nil, ctx.Err()
		case <-done:
			return nil, nil, errors.New("privatemode: proxy exited before ready")
		case <-deadline.C:
			_ = cmd.Process.Kill()
			<-done
			return nil, nil, errors.New("privatemode: proxy readiness timed out")
		case <-tick.C:
			probeCtx, cancel := context.WithTimeout(ctx, time.Second)
			req, _ := http.NewRequestWithContext(probeCtx, http.MethodGet, "https://"+proxyAuthority+"/readyz", nil)
			resp, err := client.Do(req)
			cancel()
			if err != nil {
				continue
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				continue
			}
			cleanup = false
			fmt.Fprintf(os.Stderr, "privatemode.proxy_listening version=v1.57.0 manifest=%x\n", sha256.Sum256(expectedManifest))
			return client, done, nil
		}
	}
}

func sealedFile(data []byte) (*os.File, error) {
	fd, err := unix.MemfdCreate("privatemode", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "privatemode")
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, err
	}
	if _, err := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
