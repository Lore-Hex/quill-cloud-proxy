package trustedrouter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestStartupDescriptor(t *testing.T) {
	d := startupLaunchDescriptor{"instance:a", "launch:a", "enclave", strings.Repeat("a", 40), "us-central1"}
	raw, _ := canonicalShadow(d)
	for _, test := range []struct {
		name string
		raw  []byte
		good bool
	}{{"good", raw, true}, {"malformed", []byte(`{}`), false}, {"oversized", bytes.Repeat([]byte{'a'}, 2049), false}, {"trailing", append(bytes.Clone(raw), '\n'), false}, {"two", append(bytes.Clone(raw), raw...), false}, {"wrong-role", bytes.Replace(raw, []byte(`"enclave"`), []byte(`"router"`), 1), false}, {"missing", bytes.Replace(raw, []byte(`"region":"us-central1",`), nil, 1), false}, {"extra", append([]byte(`{"extra":0,`), raw[1:]...), false}, {"duplicate", append([]byte(`{"role":"enclave",`), raw[1:]...), false}} {
		t.Run(test.name, func(t *testing.T) {
			got, err := readStartupDescriptor(context.Background(), io.NopCloser(bytes.NewReader(test.raw)))
			if (err == nil) != test.good || (test.good && got != d) {
				t.Fatal("descriptor result")
			}
		})
	}
}
func TestStartupDescriptorEOF(t *testing.T) {
	d := startupLaunchDescriptor{"instance:a", "launch:a", "enclave", strings.Repeat("a", 40), "us-central1"}
	raw, _ := canonicalShadow(d)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err = w.Write(raw); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err = readStartupDescriptor(ctx, r); err == nil {
		t.Fatal("accepted descriptor without EOF")
	}
}
func TestStartupDescriptorPipe(t *testing.T) {
	d := startupLaunchDescriptor{"instance:a", "launch:a", "enclave", strings.Repeat("a", 40), "us-central1"}
	raw, _ := canonicalShadow(d)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(raw); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	got, err := readStartupDescriptor(context.Background(), r)
	if err != nil || got != d {
		t.Fatal("inherited descriptor")
	}
}
func TestStartupInstanceLaunch(t *testing.T) {
	a, err := startupInstanceLaunch("project", "zone", "123456789", "vm-boot", strings.Repeat("a", 40), "region")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"coordinate":{"instance_id":"123456789","project":"project","zone":"zone"},"source":"launcher_start"}`)
	sum := sha256.Sum256(raw)
	if a.descriptor.Instance != "instance:"+hex.EncodeToString(sum[:]) || a.descriptor.Launch != "launch:"+hex.EncodeToString(sum[:]) || a.mode != "instance-as-launch" || a.startInsertIDKnown || a.coordinate["vm_boot_id"] != "vm-boot" {
		t.Fatal("scoped instance join")
	}
	if _, err = startupInstanceLaunch("project", "zone", "not-numeric", "vm-boot", strings.Repeat("a", 40), "region"); err == nil {
		t.Fatal("instance ID must be numeric")
	}
}
func TestStartupMalformedDescriptorNoFallback(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "fd3")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{}`)
	_, _ = f.Seek(0, 0)
	if _, err = acquireStartupLaunch(context.Background(), f, true, strings.Repeat("a", 40), "region"); err == nil {
		t.Fatal("malformed descriptor replaced")
	}
}

func TestStartupFD3(t *testing.T) {
	if mode := os.Getenv("SHADOW_STARTUP_FD3_TEST"); mode != "" {
		fd, present := inheritedStartupDescriptor()
		if !present || fd == nil {
			t.Fatal("fd 3 missing")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		_, err := acquireStartupLaunch(ctx, fd, present, strings.Repeat("a", 40), "us-central1")
		if (err == nil) != (mode == "good") {
			t.Fatal("fd 3 outcome")
		}
		return
	}
	d := startupLaunchDescriptor{"instance:a", "launch:a", "enclave", strings.Repeat("a", 40), "us-central1"}
	raw, _ := canonicalShadow(d)
	for _, mode := range []string{"good", "malformed", "oversized", "missing-eof"} {
		t.Run(mode, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			data := raw
			switch mode {
			case "malformed":
				data = []byte(`{}`)
			case "oversized":
				data = bytes.Repeat([]byte{'x'}, 2049)
			}
			if _, err = w.Write(data); err != nil {
				t.Fatal(err)
			}
			if mode != "missing-eof" {
				_ = w.Close()
			}
			command := exec.Command(os.Args[0], "-test.run=^TestStartupFD3$") // #nosec G204 -- Re-exec this test binary with a fixed selector.
			command.ExtraFiles = []*os.File{r}
			command.Env = append(os.Environ(), "SHADOW_STARTUP_FD3_TEST="+mode)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("fd 3 child: %v %s", err, output)
			}
		})
	}
}
