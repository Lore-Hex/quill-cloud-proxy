//go:build linux

package polyclass

import (
	"io"
	"os"
	"slices"
	"syscall"
	"testing"
)

func TestHelperLaunchHasNoAmbientSecretsOrPrivileges(t *testing.T) {
	t.Setenv("UNRELATED_PROVIDER_KEY", "must-not-inherit")
	cmd := helperCommand()
	if !slices.Equal(cmd.Args, []string{"/quill-enclave", childFlag}) || cmd.Env == nil || len(cmd.Env) != 0 ||
		len(cmd.ExtraFiles) != 0 || cmd.Stderr != io.Discard || cmd.Dir != "/" {
		t.Fatal("helper launch isolation changed")
	}
	attr := cmd.SysProcAttr
	if attr.Credential.Uid != childUID || attr.Credential.Gid != childUID || len(attr.Credential.Groups) != 0 ||
		attr.Credential.NoSetGroups || attr.Pdeathsig != syscall.SIGKILL {
		t.Fatal("helper did not drop identity or outlive protection")
	}
	if childUID == 65532 || (childUID >= 65200 && childUID < 65232) {
		t.Fatal("helper uid collides with another child's")
	}
}

func TestHelperEntrypointIgnoresOrdinaryStartup(t *testing.T) {
	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	for _, args := range [][]string{{"/quill-enclave"}, {"/quill-enclave", "--unrelated"}, {"/quill-enclave", childFlag, "injected"}} {
		os.Args = args
		if HelperEntrypoint() {
			t.Fatalf("%v entered the helper", args)
		}
	}
}
