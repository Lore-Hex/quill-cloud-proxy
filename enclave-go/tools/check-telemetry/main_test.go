package main

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

func TestRejectTelemetryIncludingReplacements(t *testing.T) {
	for _, path := range []string{"go.opentelemetry.io/otel", "go.opentelemetry.io/auto/sdk", "github.com/getsentry/sentry-go", "gopkg.in/DataDog/dd-trace-go.v1", "github.com/prometheus/client_golang"} {
		m := &debug.Module{Path: path}
		if checkModule(m) == nil {
			t.Fatalf("accepted %s", path)
		}
		if checkModule(&debug.Module{Path: "example.com/fork", Replace: m}) == nil {
			t.Fatalf("accepted replacement %s", path)
		}
		m.Replace = &debug.Module{Path: "../stub"}
		if checkModule(m) == nil {
			t.Fatalf("accepted stubbed %s", path)
		}
	}
	if err := checkModule(&debug.Module{Path: "github.com/sigstore/rekor", Replace: &debug.Module{Path: "../third_party/rekor-offline"}}); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeInventoryFailsClosed(t *testing.T) {
	for _, name := range []string{"missing", "extra", "script", "symlink"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			for _, binary := range []string{"quill-enclave", "attest-sidecar", "privatemode-proxy"} {
				if name == "missing" && binary == "attest-sidecar" {
					continue
				}
				if err := os.WriteFile(filepath.Join(root, binary), []byte("\x7fELF"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "extra":
				if err := os.WriteFile(filepath.Join(root, "unexpected"), []byte("\x7fELF"), 0600); err != nil {
					t.Fatal(err)
				}
			case "script":
				// An executable test fixture is required to exercise script rejection.
				if err := os.WriteFile(filepath.Join(root, "unexpected"), []byte("#!/bin/sh\n"), 0700); err != nil { // #nosec G306 -- never executed; isolated t.TempDir fixture
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("/outside", filepath.Join(root, "unexpected")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := runtimePaths(root); err == nil {
				t.Fatal("accepted invalid runtime")
			}
		})
	}
}

func TestUninspectableBinaryFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "binary")
	if err := os.WriteFile(path, []byte("\x7fELFnot-a-real-binary"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspect(path); err == nil || !strings.Contains(err.Error(), "expected ELF") {
		t.Fatalf("got %v", err)
	}
}
