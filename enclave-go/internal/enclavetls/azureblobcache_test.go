//go:build cloud_azure

package enclavetls

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

type staticAzureTokenSource struct{ token string }

func (s staticAzureTokenSource) Token(context.Context) (string, error) { return s.token, nil }

func TestAzureBlobCacheRoundTripEncryptsAtClient(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	objects := map[string][]byte{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer cache-token" {
			t.Errorf("authorization = %q", got)
		}
		if got := r.Header.Get("x-ms-version"); got != azureBlobAPIVersion {
			t.Errorf("x-ms-version = %q", got)
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			if got := r.Header.Get("x-ms-blob-type"); got != "BlockBlob" {
				t.Errorf("x-ms-blob-type = %q", got)
			}
			body, _ := io.ReadAll(r.Body)
			objects[r.URL.Path] = append([]byte(nil), body...)
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			body, ok := objects[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(body)
		case http.MethodDelete:
			delete(objects, r.URL.Path)
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	}))
	defer server.Close()

	key := bytes.Repeat([]byte{0x42}, azureCacheKeyBytes)
	cache, err := newAzureBlobCache(azureBlobCacheConfig{
		account:   "trcache",
		container: "acme-cache",
		key:       key,
		endpoint:  server.URL,
		blobHTTP:  server.Client(),
		tokens:    staticAzureTokenSource{token: "cache-token"},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	plaintext := []byte("PRIVATE KEY MATERIAL MUST NOT REACH BLOB STORAGE")
	if err := cache.Put(ctx, "api.trustedrouter.com", plaintext); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	var stored []byte
	for _, value := range objects {
		stored = append([]byte(nil), value...)
	}
	mu.Unlock()
	if len(stored) == 0 {
		t.Fatal("no blob was written")
	}
	if bytes.Contains(stored, plaintext) {
		t.Fatal("blob contains plaintext certificate material")
	}
	got, err := cache.Get(ctx, "api.trustedrouter.com")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip = %q", got)
	}
	if err := cache.Delete(ctx, "api.trustedrouter.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Get(ctx, "api.trustedrouter.com"); err != autocert.ErrCacheMiss {
		t.Fatalf("after delete error = %v, want cache miss", err)
	}
}

func TestAzureBlobCacheBindsCiphertextToCoordinateAndCacheKey(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x24}, azureCacheKeyBytes)
	cache, err := newAzureBlobCache(azureBlobCacheConfig{
		account:   "accounta",
		container: "acme-cache",
		key:       key,
		endpoint:  "https://example.invalid",
		blobHTTP:  http.DefaultClient,
		tokens:    staticAzureTokenSource{token: "unused"},
	})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := cache.seal("host-a", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.open("host-b", sealed); err == nil {
		t.Fatal("ciphertext opened under a different autocert key")
	}
	other := *cache
	other.account = "accountb"
	if _, err := other.open("host-a", sealed); err == nil {
		t.Fatal("ciphertext opened under a different storage account")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := cache.open("host-a", sealed); err == nil {
		t.Fatal("tampered ciphertext opened")
	}
}

func TestAzureBlobCacheOpensMigrationToolWireVector(t *testing.T) {
	t.Parallel()
	cache, err := newAzureBlobCache(azureBlobCacheConfig{
		account:   "trcache",
		container: "acme-cache",
		key:       []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
		endpoint:  "https://example.invalid",
		blobHTTP:  http.DefaultClient,
		tokens:    staticAzureTokenSource{token: "unused"},
	})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := base64.StdEncoding.DecodeString("AQABAgMEBQYHCAkKCyRnpG+sg6t47DXyA9VuHTzTFI8RQ4VwJ5OO9A==")
	if err != nil {
		t.Fatal(err)
	}
	got, err := cache.open("api.example", sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "certificate" {
		t.Fatalf("plaintext = %q", got)
	}
}

func TestNewAzureBlobCacheValidatesCoordinatesAndKey(t *testing.T) {
	t.Parallel()
	validKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, azureCacheKeyBytes))
	for _, test := range []struct {
		name string
		opts AzureBlobCacheOptions
		want string
	}{
		{"missing key", AzureBlobCacheOptions{Account: "abc", Container: "cache"}, "key is empty"},
		{"short key", AzureBlobCacheOptions{Account: "abc", Container: "cache", EncryptionKey: base64.StdEncoding.EncodeToString([]byte("short"))}, "want 32"},
		{"account", AzureBlobCacheOptions{Account: "UPPER", Container: "cache", EncryptionKey: validKey}, "lowercase"},
		{"container", AzureBlobCacheOptions{Account: "abc", Container: "bad--name", EncryptionKey: validKey}, "invalid container"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewAzureBlobCache(test.opts)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestAzureManagedIdentityTokenSourceCachesToken(t *testing.T) {
	t.Parallel()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Metadata") != "true" {
			t.Error("Metadata header missing")
		}
		if got := r.URL.Query().Get("resource"); got != azureStorageResource {
			t.Errorf("resource = %q", got)
		}
		if got := r.URL.Query().Get("client_id"); got != "managed-client" {
			t.Errorf("client_id = %q", got)
		}
		_, _ = fmt.Fprint(w, `{"access_token":"token-1","expires_in":"3600"}`)
	}))
	defer server.Close()

	source := newAzureManagedIdentityTokenSource(server.Client(), "managed-client")
	source.endpoint = server.URL
	source.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	for range 2 {
		got, err := source.Token(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got != "token-1" {
			t.Fatalf("token = %q", got)
		}
	}
	if requests != 1 {
		t.Fatalf("metadata requests = %d, want 1", requests)
	}
}

func TestAzureBlobStatusErrorDoesNotPersistResponseBody(t *testing.T) {
	t.Parallel()
	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     http.Header{"X-Ms-Error-Code": []string{"AuthorizationPermissionMismatch"}},
		Body:       io.NopCloser(strings.NewReader("reflected-secret-value")),
	}
	err := azureBlobStatusError("get", resp)
	if strings.Contains(err.Error(), "reflected-secret-value") {
		t.Fatalf("error persisted the response body: %v", err)
	}
	if !strings.Contains(err.Error(), "AuthorizationPermissionMismatch") {
		t.Fatalf("error omitted the safe Azure error code: %v", err)
	}
}
