package awssealed

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
)

func TestPythonProducerGoConsumer(t *testing.T) {
	python := os.Getenv("QUILL_AWS_SEALER_PYTHON")
	if python == "" {
		python = os.Getenv("QUILL_AZURE_SEALER_PYTHON")
	}
	if python == "" {
		python = "python3"
	}
	cmd := exec.Command(python, "-c", "import json; from tools.test_aws_sealed_bundle import contract_fixture; print(json.dumps(contract_fixture()))") // #nosec G204 -- operator/CI Python, fixed test-only producer
	cmd.Dir = "../../../.."
	data, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Python sealer contract must run (cryptography required, not skipped): %v\n%s", err, data)
	}
	var fixture struct {
		Bundle    Bundle `json:"bundle"`
		PublicKey []byte `json:"public_key"`
		Key       []byte `json:"key"`
		Plaintext []byte `json:"plaintext"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	public, err := x509.ParsePKIXPublicKey(fixture.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := public.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("producer signer is not ECDSA")
	}
	response, _ := json.Marshal(Response{Bundle: fixture.Bundle, CiphertextForRecipient: []byte("test unwrap")})
	plaintext, manifest, err := Open(response, signer, 7, func([]byte) ([]byte, error) { return bytes.Clone(fixture.Key), nil })
	if err != nil || !bytes.Equal(plaintext, fixture.Plaintext) || manifest.Region != "eu-west-3" {
		t.Fatalf("Python seal -> Go authenticate/open failed: %v", err)
	}
}
