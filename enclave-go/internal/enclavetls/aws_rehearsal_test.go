//go:build aws_tls_rehearsal && !cloud_aws

package enclavetls

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// Operator-only test binary. No production cache, CA selector, AWS seed, or
// provider secrets. Each invocation is a new process; each order gets a
// durable exclusive marker before the first network request.
type rehearsalWrap struct{ cipher.AEAD }

func (w rehearsalWrap) WrapDEK(_ context.Context, _ string, key, aad []byte) ([]byte, error) {
	return w.Seal(nil, nil, key, aad), nil
}
func (w rehearsalWrap) UnwrapDEK(_ context.Context, _ string, b, aad []byte) ([]byte, error) {
	return w.Open(nil, nil, b, aad)
}
func rehearsalCreate(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	return errors.Join(err, f.Sync(), f.Close())
}

func TestAWSStagingDNSRehearsal(t *testing.T) {
	const host = "api-aws.trustedrouter.com"
	const staging = "https://acme-staging-v02.api.letsencrypt.org/directory"
	d, phase := os.Getenv("TR_AWS_REHEARSAL_DIRECTORY"), os.Getenv("TR_AWS_REHEARSAL_PHASE")
	if d == "" && phase == "" {
		t.Skip("explicit staging rehearsal only")
	}
	info, err := os.Lstat(d)
	if !filepath.IsAbs(d) || err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("private rehearsal directory required")
	}
	switch phase {
	case "init":
		names, err := os.ReadDir(d)
		if err != nil || len(names) != 0 {
			t.Fatal("new empty rehearsal directory required")
		}
		root := make([]byte, 32)
		defer clear(root)
		if _, err = rand.Read(root); err != nil {
			t.Fatal(err)
		}
		if err = rehearsalCreate(filepath.Join(d, "staging-key"), root); err != nil {
			t.Fatal(err)
		}
		return
	case "read", "issue", "renew":
	default:
		t.Fatal("unknown rehearsal phase")
	}
	root, err := os.ReadFile(filepath.Join(d, "staging-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(root)
	a, err := cacheCipher(root)
	if err != nil {
		t.Fatal("invalid rehearsal key")
	}
	cache := &sealedACMECache{store: autocert.DirCache(filepath.Join(d, "staging-cache")), wrapper: rehearsalWrap{a}, bucket: "local-rehearsal-only", kmsKey: "staging-only"}
	ctx, cancel := context.WithTimeout(t.Context(), 9*time.Minute)
	defer cancel()
	prior, err := CachedDNS01PublicPin(ctx, cache, host)
	if phase == "read" {
		if err != nil {
			t.Fatal("staging cold read failed")
		}
		t.Logf("cold read: host=%s staging_spki_sha256=%s", host, prior)
		return
	}
	if phase == "issue" && !errors.Is(err, autocert.ErrCacheMiss) || phase == "renew" && err != nil {
		t.Fatal("unexpected initial state, no order placed")
	}
	if err = rehearsalCreate(filepath.Join(d, phase+"-used"), []byte("used\n")); err != nil {
		t.Fatal("order marker exists or was not created")
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	provider := NewCloudDNSProvider("quill-cloud-proxy", "trustedrouter-com", client)
	provider.AccessToken = func(ctx context.Context) (string, error) {
		out, err := exec.CommandContext(ctx, "gcloud", "auth", "print-access-token", "--account=tr-deploy@quill-cloud-proxy.iam.gserviceaccount.com", "--quiet").Output()
		defer clear(out)
		if err != nil {
			return "", errors.New("rehearsal DNS authentication unavailable")
		}
		return strings.TrimSpace(string(out)), nil
	}
	err = PreissueDNS01(ctx, DNS01Config{nitroFirstOrder: true, DNSName: host, DirectoryURL: staging, Email: "acme@trustedrouter.com", Provider: provider, HTTPClient: client, Cache: cache}, phase == "renew")
	if err != nil {
		t.Fatal("staging order failed; retain marker and reconcile DNS before further action")
	}
	fresh, err := CachedDNS01PublicPin(ctx, cache, host)
	if err != nil || fresh == prior {
		t.Fatal("rehearsal did not produce a new key")
	}
	t.Logf("%s: host=%s staging_spki_sha256=%s", phase, host, fresh)
}
