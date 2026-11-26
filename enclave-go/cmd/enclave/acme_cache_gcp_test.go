//go:build cloud_gcp

package main

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/enclavetls"
	"golang.org/x/crypto/acme/autocert"
)

func TestGCPCertificateCacheIgnoresLegacyLocations(t *testing.T) {
	t.Setenv("QUILL_ACME_CACHE_DIR", "/not-a-cache")
	t.Setenv("QUILL_ACME_CACHE_GCS_BUCKET", "not-a-production-bucket")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/not-a-credential")
	cache, err := configuredACMECache(context.Background(), nil)
	if err != nil || cache == nil {
		t.Fatal(err)
	}
	if _, err := enclavetls.NewACMECache("", "other"); err == nil {
		t.Fatal("unsealed shared cache available")
	}
}

type custodyFixture struct {
	stage   string
	name    string
	value   []byte
	deletes int
}

func (f *custodyFixture) Get(_ context.Context, name string) ([]byte, error) {
	if f.name == "" {
		if f.stage == "present" {
			return []byte("existing"), nil
		}
		if f.stage == "unavailable" {
			return nil, errors.New("private fixture detail")
		}
		return nil, autocert.ErrCacheMiss
	}
	if name != f.name || f.stage == "read" {
		return nil, errors.New("private fixture detail")
	}
	if f.stage == "corrupt" {
		return []byte("wrong"), nil
	}
	return bytes.Clone(f.value), nil
}

func (f *custodyFixture) Put(_ context.Context, name string, v []byte) error {
	f.name, f.value = name, bytes.Clone(v)
	if f.stage == "write" {
		return errors.New("private fixture detail")
	}
	return nil
}

func (f *custodyFixture) Delete(_ context.Context, name string) error {
	f.deletes++
	if f.name != name || f.stage == "cleanup" {
		return errors.New("private fixture detail")
	}
	return nil
}

func TestGCPCustodyProbe(t *testing.T) {
	validName := regexp.MustCompile("^__tr_custody_probe__/[0-9a-f]{32}$")
	seen := make(map[string]bool)
	for _, stage := range []string{"", "present", "unavailable", "write", "read", "corrupt", "cleanup", ""} {
		f := &custodyFixture{stage: stage}
		err := probeGCPCache(context.Background(), f)
		if (err == nil) != (stage == "") || (err != nil && strings.Contains(err.Error(), "private fixture")) {
			t.Fatalf("%q: wrong result or unredacted failure", stage)
		}
		if stage == "present" || stage == "unavailable" {
			if f.name != "" || f.deletes != 0 {
				t.Fatal("probe modified an existing or unverified name")
			}
			continue
		}
		if !validName.MatchString(f.name) || seen[f.name] || len(f.value) != 32 || f.deletes != 1 {
			t.Fatal("probe did not isolate and clean its synthetic write")
		}
		seen[f.name] = true
	}
}
