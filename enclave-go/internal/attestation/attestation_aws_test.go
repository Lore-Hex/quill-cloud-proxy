//go:build cloud_aws

package attestation

import (
	"bytes"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/enclavetls"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
)

type fakeNSMSession struct {
	send func(request.Request) (response.Response, error)
}

func (s fakeNSMSession) Send(req request.Request) (response.Response, error) {
	return s.send(req)
}

func (s fakeNSMSession) Close() error {
	return nil
}

func TestGetBindsExporterInAWSUserData(t *testing.T) {
	srv, err := enclavetls.NewSelfSigned("test.quill.local")
	if err != nil {
		t.Fatalf("NewSelfSigned: %v", err)
	}

	nonce := bytes.Repeat([]byte{0xa5}, 32)
	exporter := bytes.Repeat([]byte{0x5a}, 32)
	var captured *request.Attestation
	oldOpenNSMSession := openNSMSession
	defer func() { openNSMSession = oldOpenNSMSession }()
	openNSMSession = func() (nsmSession, error) {
		return fakeNSMSession{
			send: func(req request.Request) (response.Response, error) {
				attestationReq, ok := req.(*request.Attestation)
				if !ok {
					t.Fatalf("request = %T, want *request.Attestation", req)
				}
				captured = attestationReq
				return response.Response{
					Attestation: &response.Attestation{Document: []byte("signed-doc")},
				}, nil
			},
		}, nil
	}

	doc, err := Get(srv.Certificate.Certificate[0], []byte("devices"), nonce, exporter)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(doc) != "signed-doc" {
		t.Fatalf("doc = %q, want signed-doc", doc)
	}
	if captured == nil {
		t.Fatal("NSM attestation request was not captured")
	}
	if !bytes.Equal(captured.Nonce, nonce) {
		t.Fatalf("Nonce = %x, want %x", captured.Nonce, nonce)
	}
	if len(captured.UserData) != 96 {
		t.Fatalf("user_data length = %d, want 96", len(captured.UserData))
	}
	boundExporter := captured.UserData[64:96]
	if len(boundExporter) != 32 {
		t.Fatalf("bound exporter length = %d, want 32", len(boundExporter))
	}
	if !bytes.Equal(boundExporter, exporter) {
		t.Fatalf("user_data[64:96] = %x, want exporter %x", boundExporter, exporter)
	}
	if bytes.Equal(boundExporter, captured.Nonce) {
		t.Fatal("exporter binding was conflated with the NSM Nonce field")
	}
}
