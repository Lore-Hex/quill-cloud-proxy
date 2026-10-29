//go:build linux

package maple

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const helperBinary = "/maple-transport"

// HelperEntrypoint requires an explicit launcher argument. It never probes or
// closes arbitrary inherited descriptors such as the Go runtime's poller.
func HelperEntrypoint() bool {
	if len(os.Args) != 2 || os.Args[1] != "--maple-transport-child" {
		return false
	}
	uid := os.Geteuid()
	if uid < childUID || uid >= childUID+concurrency || os.Getegid() != uid ||
		unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil ||
		unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}) != nil {
		os.Exit(1)
	}
	// #nosec G204 -- immutable measured executable, no caller arguments.
	if syscall.Exec(helperBinary, []string{helperBinary}, os.Environ()) != nil {
		os.Exit(1)
	}
	return true
}

func startProcess(ctx context.Context, input []byte, uid uint32) (process, error) {
	env, stopNetwork, err := platformEnvironment(ctx)
	if err != nil {
		return process{}, err
	}
	cmd := helperCommand(ctx, env, uid)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		stopNetwork()
		return process{}, errors.New("maple: adapter input unavailable")
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		stopNetwork()
		return process{}, errors.New("maple: adapter output unavailable")
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		stopNetwork()
		return process{}, errors.New("maple: adapter start failed")
	}
	// Complete the bounded pipe write before the caller wipes its envelope.
	_, writeErr := stdin.Write(input)
	closeErr := stdin.Close()
	if writeErr != nil || closeErr != nil {
		_ = cmd.Process.Kill()
		_ = stdout.Close()
		_ = cmd.Wait()
		stopNetwork()
		return process{}, errors.New("maple: adapter input failed")
	}
	return process{stdout: stdout, wait: func() error {
		err := cmd.Wait()
		stopNetwork()
		return err
	}}, nil
}

func helperCommand(ctx context.Context, env []string, uid uint32) *exec.Cmd {
	// Distinct live child identities prevent one concurrent request's helper
	// from inspecting another's credentials or plaintext through /proc/ptrace.
	// #nosec G204 -- fixed launcher and argument, never request-controlled.
	cmd := exec.CommandContext(ctx, "/quill-enclave", "--maple-transport-child")
	cmd.Env = append([]string{}, env...)
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: uid, Gid: uid, Groups: []uint32{},
	}}
	cmd.WaitDelay = 2 * time.Second
	cmd.Stderr = io.Discard
	return cmd
}
