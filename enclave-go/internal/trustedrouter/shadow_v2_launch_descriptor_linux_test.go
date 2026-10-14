//go:build linux

package trustedrouter

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// An epoll descriptor at fd 3 reproduces the kernel object that the startup
// harness mistook for a launcher pipe. It must remain usable even if declared.
func TestStartupDescriptorDoesNotOwnEpoll(t *testing.T) {
	if os.Getenv("SHADOW_STARTUP_EPOLL_TEST") == "1" {
		fd, present := inheritedStartupDescriptor()
		if fd != nil || !present {
			t.Fatal("claimed an epoll descriptor as startup input")
		}
		if _, err := unix.EpollWait(3, make([]unix.EpollEvent, 1), 0); err != nil {
			t.Fatalf("startup damaged the epoll descriptor: %v", err)
		}
		return
	}
	fd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "epoll-test")
	defer f.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStartupDescriptorDoesNotOwnEpoll$") // #nosec G204 -- Re-exec this test binary with a fixed selector.
	command.ExtraFiles = []*os.File{f}
	command.Env = append(os.Environ(), "SHADOW_STARTUP_EPOLL_TEST=1", "TR_SHADOW_V2_LAUNCH_FD=3")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("epoll ownership child: %v %s", err, output)
	}
}
