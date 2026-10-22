// Check the actual runtime files, not the broader test/tool module graph.
package main

import (
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
)

var denied = []string{
	"go.opentelemetry.io", "go.opencensus.io", "github.com/getsentry",
	"github.com/dataDog", "gopkg.in/DataDog", "github.com/newrelic",
	"github.com/bugsnag", "go.elastic.co/apm", "github.com/elastic/apm",
	"github.com/honeycombio", "github.com/lightstep", "github.com/segmentio/analytics-go",
	"github.com/posthog", "github.com/axiomhq", "github.com/prometheus/client_golang",
}

type record struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	GoVersion string `json:"go_version"`
	Modules   int    `json:"modules"`
}

func main() {
	root := flag.String("root", "", "scan the complete scratch runtime root")
	flag.Parse()
	paths := flag.Args()
	if *root != "" {
		var err error
		paths, err = runtimePaths(*root)
		if err != nil {
			fail(err)
		}
	}
	if len(paths) == 0 {
		fail(fmt.Errorf("no runtime binaries supplied"))
	}
	var report []record
	for _, path := range paths {
		r, err := inspect(path)
		if err != nil {
			fail(err)
		}
		if *root != "" {
			rel, err := filepath.Rel(*root, path)
			if err != nil {
				fail(err)
			}
			r.Path = "/" + filepath.ToSlash(rel)
		}
		report = append(report, r)
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		fail(err)
	}
}

func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }

func checkModule(m *debug.Module) error {
	for ; m != nil; m = m.Replace {
		for _, prefix := range denied {
			path, prefix := strings.ToLower(m.Path), strings.ToLower(prefix)
			if path == prefix || strings.HasPrefix(path, prefix+"/") {
				return fmt.Errorf("forbidden telemetry module: %s", m.Path)
			}
		}
	}
	return nil
}

func inspect(path string) (record, error) {
	r := record{Path: path}
	e, err := elf.Open(path)
	if err != nil {
		return r, fmt.Errorf("%s: expected ELF: %w", path, err)
	}
	libs, err := e.ImportedLibraries()
	e.Close()
	if err != nil || len(libs) != 0 {
		return r, fmt.Errorf("%s: unreviewed dynamic libraries: %v (%v)", path, libs, err)
	}
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return r, fmt.Errorf("%s: missing Go build information: %w", path, err)
	}
	for _, mod := range append([]*debug.Module{&info.Main}, info.Deps...) {
		if err := checkModule(mod); err != nil {
			return r, fmt.Errorf("%s: %w", path, err)
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return r, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return r, err
	}
	r.SHA256, r.GoVersion, r.Modules = fmt.Sprintf("%x", h.Sum(nil)), info.GoVersion, len(info.Deps)
	return r, nil
}

func runtimePaths(root string) ([]string, error) {
	expected := map[string]bool{"quill-enclave": false, "attest-sidecar": false, "privatemode-proxy": false}
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		_, required := expected[rel]
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unreviewed nonregular runtime file: %s", rel)
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		header := make([]byte, 4)
		n, readErr := f.Read(header)
		f.Close()
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		isELF := n == 4 && string(header) == "\x7fELF"
		if required || isELF || info.Mode().Perm()&0111 != 0 {
			if !required {
				return fmt.Errorf("unreviewed runtime executable: %s", rel)
			}
			if !isELF {
				return fmt.Errorf("runtime executable is not ELF: %s", rel)
			}
			expected[rel] = true
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for path, found := range expected {
		if !found {
			return nil, fmt.Errorf("missing runtime executable: %s", path)
		}
	}
	return paths, nil
}
