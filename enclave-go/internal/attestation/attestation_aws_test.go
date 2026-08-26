//go:build cloud_aws

package attestation

import (
	"bytes"
	"crypto/sha256"
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

	doc, err := Get(srv.Certificate.Certificate[0], []byte("devices"), nonce, exporter, nil)
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

func TestNilReceiptKeyFingerprintPreservesLegacyAWSUserDataBytes(t *testing.T) {
	srv, err := enclavetls.NewSelfSigned("test.quill.local")
	if err != nil {
		t.Fatalf("NewSelfSigned: %v", err)
	}
	leafDER := srv.Certificate.Certificate[0]
	deviceBlob := []byte("devices")
	certFP := sha256.Sum256(leafDER)
	deviceHash := sha256.Sum256(deviceBlob)
	legacy64 := append(append([]byte(nil), certFP[:]...), deviceHash[:]...)
	exporter := bytes.Repeat([]byte{0x5a}, sha256.Size)

	for _, test := range []struct {
		name     string
		exporter []byte
		want     []byte
	}{
		{name: "64 byte legacy shape", want: legacy64},
		{name: "96 byte legacy shape", exporter: exporter, want: append(append([]byte(nil), legacy64...), exporter...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			captured := captureAWSAttestationRequest(t, leafDER, deviceBlob, nil, test.exporter, nil)
			if !bytes.Equal(captured.UserData, test.want) {
				t.Fatalf("user_data = %x, want exact legacy bytes %x", captured.UserData, test.want)
			}
		})
	}
}

func TestReceiptKeyFingerprintUsesFixed128ByteAWSLayout(t *testing.T) {
	srv, err := enclavetls.NewSelfSigned("test.quill.local")
	if err != nil {
		t.Fatalf("NewSelfSigned: %v", err)
	}
	leafDER := srv.Certificate.Certificate[0]
	deviceBlob := []byte("devices")
	receiptFP := bytes.Repeat([]byte{0x7c}, sha256.Size)
	exporter := bytes.Repeat([]byte{0x5a}, sha256.Size)

	for _, test := range []struct {
		name         string
		exporter     []byte
		wantExporter []byte
	}{
		{name: "exporter present", exporter: exporter, wantExporter: exporter},
		{name: "exporter absent is zero filled", wantExporter: make([]byte, sha256.Size)},
	} {
		t.Run(test.name, func(t *testing.T) {
			captured := captureAWSAttestationRequest(t, leafDER, deviceBlob, nil, test.exporter, receiptFP)
			if len(captured.UserData) != 128 {
				t.Fatalf("user_data length = %d, want 128", len(captured.UserData))
			}
			certFP := sha256.Sum256(leafDER)
			deviceHash := sha256.Sum256(deviceBlob)
			if !bytes.Equal(captured.UserData[:32], certFP[:]) {
				t.Fatalf("cert slot = %x, want %x", captured.UserData[:32], certFP)
			}
			if !bytes.Equal(captured.UserData[32:64], deviceHash[:]) {
				t.Fatalf("device slot = %x, want %x", captured.UserData[32:64], deviceHash)
			}
			if !bytes.Equal(captured.UserData[64:96], test.wantExporter) {
				t.Fatalf("exporter slot = %x, want %x", captured.UserData[64:96], test.wantExporter)
			}
			if !bytes.Equal(captured.UserData[96:128], receiptFP) {
				t.Fatalf("receipt slot = %x, want %x", captured.UserData[96:128], receiptFP)
			}
		})
	}
}

func captureAWSAttestationRequest(t *testing.T, leafDER, deviceBlob, nonce, exporter, receiptFP []byte) *request.Attestation {
	t.Helper()
	var captured *request.Attestation
	oldOpenNSMSession := openNSMSession
	openNSMSession = func() (nsmSession, error) {
		return fakeNSMSession{send: func(req request.Request) (response.Response, error) {
			var ok bool
			captured, ok = req.(*request.Attestation)
			if !ok {
				t.Fatalf("request = %T, want *request.Attestation", req)
			}
			return response.Response{Attestation: &response.Attestation{Document: []byte("signed-doc")}}, nil
		}}, nil
	}
	t.Cleanup(func() { openNSMSession = oldOpenNSMSession })
	if _, err := Get(leafDER, deviceBlob, nonce, exporter, receiptFP); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if captured == nil {
		t.Fatal("NSM attestation request was not captured")
	}
	return captured
}
