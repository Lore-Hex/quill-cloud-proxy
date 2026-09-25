package privatemode

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestManifestIsPinnedAndImmutable(t *testing.T) {
	sum := sha256.Sum256(manifest)
	if hex.EncodeToString(sum[:]) != "928724d7a536442715aed927d9fb9fc8718c1d67a77ce888dca8f0ea9078bb39" {
		t.Fatal("manifest changed without a reviewed deployment pin")
	}
	var mf struct {
		Policies                map[string]struct{ Role string }
		WorkloadOwnerKeyDigests []string
	}
	if err := json.Unmarshal(manifest, &mf); err != nil {
		t.Fatal(err)
	}
	if len(mf.Policies) != 9 || len(mf.WorkloadOwnerKeyDigests) != 0 {
		t.Fatal("unexpected deployment mutation policy")
	}
	coordinators := 0
	for _, p := range mf.Policies {
		if p.Role == "coordinator" {
			coordinators++
		}
	}
	if coordinators != 1 {
		t.Fatal("expected one immutable coordinator")
	}
}

func TestOnlyPinnedModels(t *testing.T) {
	for _, model := range []string{"glm-5.3", "glm-5.3-flash", "gpt-oss-120b"} {
		if !AllowedModel(model) {
			t.Errorf("missing %s", model)
		}
	}
	for _, model := range []string{"glm-5.2", "glm-latest", "kimi-k2.6", "openai/gpt-oss-120b", "", "../models"} {
		if AllowedModel(model) {
			t.Errorf("unpinned %s", model)
		}
	}
}

func TestLocalTransportRejectsBypass(t *testing.T) {
	_, _, cert, err := localIdentity(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	client := localClient(cert)
	for _, target := range []string{"https://api.privatemode.ai/v1/chat/completions", "http://privatemode.internal:18489/v1/chat/completions", BaseURL + "/models", BaseURL + "/chat/completions?plaintext=true"} {
		r, _ := http.NewRequest(http.MethodPost, target, nil)
		if _, err := client.Do(r); err == nil {
			t.Errorf("accepted %s", target)
		}
	}
	if err := client.CheckRedirect(nil, nil); err == nil {
		t.Fatal("redirect accepted")
	}
}

func TestLocalIdentityDoesNotTrustAnImpostor(t *testing.T) {
	_, _, cert, _ := localIdentity(time.Now())
	client := localClient(cert)
	tlsCfg := client.Transport.(restrictedTransport).base.TLSClientConfig.Clone()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("sent plaintext to impostor") }))
	defer srv.Close()
	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), tlsCfg)
	if err == nil {
		_ = conn.Close()
		t.Fatal("impostor accepted")
	}
}
