//go:build linux

package maple

import (
	"io"
	"os"
	"slices"
	"testing"
)

func TestHelperHasNoAmbientSecretsOrDescriptors(t *testing.T) {
	t.Setenv("UNRELATED_PROVIDER_KEY", "must-not-inherit")
	t.Setenv("HTTPS_PROXY", "http://untrusted.example")
	env := []string{"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"}
	cmd := helperCommand(t.Context(), env, childUID)
	if !slices.Equal(cmd.Args, []string{"/quill-enclave", "--maple-transport-child"}) ||
		!slices.Equal(cmd.Env, env) || len(cmd.ExtraFiles) != 0 || cmd.Stderr != io.Discard || cmd.Dir != "/" {
		t.Fatal("helper launch isolation changed")
	}
	credential := cmd.SysProcAttr.Credential
	if credential.Uid != childUID || credential.Gid != childUID || len(credential.Groups) != 0 || credential.NoSetGroups {
		t.Fatal("helper did not drop identity and supplementary groups")
	}
}

func TestHelperIgnoresNormalStartupWithoutTouchingFiles(t *testing.T) {
	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	f, err := os.CreateTemp(t.TempDir(), "descriptor-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, args := range [][]string{{"/quill-enclave"}, {"/quill-enclave", "--unrelated"}, {"/quill-enclave", "--maple-transport-child", "injected"}} {
		os.Args = args
		if HelperEntrypoint() {
			t.Fatal("ordinary startup entered helper")
		}
		if _, err := f.WriteString("still-open"); err != nil {
			t.Fatal("startup closed an unrelated descriptor")
		}
	}
}
