//go:build linux

package polyclass

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	helperBinary = "/polyphemus-classifier"
	childFlag    = "--polyphemus-classifier-child"
	// childUID is used by nothing else in the image (Maple: 65200-65231,
	// Privatemode: 65532), so the helper cannot read another child's memory.
	childUID = 65300
)

// HelperEntrypoint drops privileges in the re-executed gateway binary, then
// execs the measured classifier with no arguments and an empty environment.
func HelperEntrypoint() bool {
	if len(os.Args) != 2 || os.Args[1] != childFlag {
		return false
	}
	if os.Geteuid() != childUID || os.Getegid() != childUID ||
		unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil ||
		unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}) != nil {
		os.Exit(1)
	}
	// #nosec G204 -- immutable measured executable, no caller arguments.
	if syscall.Exec(helperBinary, []string{helperBinary}, []string{}) != nil {
		os.Exit(1)
	}
	return true
}

func startHelper() (*process, error) {
	// #nosec G204 -- fixed launcher and argument, never request-controlled.
	cmd := exec.Command("/quill-enclave", childFlag)
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: childUID, Gid: childUID, Groups: []uint32{}},
		Pdeathsig:  syscall.SIGKILL,
	}
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 2 * time.Second
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, ErrUnavailable
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, ErrUnavailable
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, ErrUnavailable
	}
	stop := func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	stdout := bufio.NewReaderSize(stdoutPipe, 4096)
	if err := awaitReady(stdout, startupTimeout); err != nil {
		stop()
		return nil, ErrUnavailable
	}
	return &process{stdin: stdin, stdout: stdout, stop: stop}, nil
}
