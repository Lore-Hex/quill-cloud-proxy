//go:build cloud_aws

// This isolated test image never loads bootstrap credentials or serves inference.
// Its only output is public Nitro evidence for recipient-policy denial tests.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/mdlayher/vsock"
)

const protocol = "trustedrouter.aws-bootstrap.denial-probe.v1"

type evidence struct {
	Document  []byte `json:"attestation_document"`
	PublicKey []byte `json:"public_key"`
	Nonce     []byte `json:"nonce"`
	Protocol  string `json:"protocol"`
}

func attest(publicKey, nonce []byte) ([]byte, error) {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, errors.New("NSM unavailable")
	}
	defer session.Close()
	result, err := session.Send(&request.Attestation{
		PublicKey: publicKey, Nonce: nonce, UserData: []byte(protocol),
	})
	if err != nil || result.Error != "" || result.Attestation == nil {
		return nil, errors.New("NSM attestation failed")
	}
	return result.Attestation.Document, nil
}

func handle(conn net.Conn, attestDocument func([]byte, []byte) ([]byte, error)) error {
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(conn, nonce); err != nil {
		return errors.New("challenge read failed")
	}
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return errors.New("recipient key generation failed")
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		return errors.New("recipient public key encoding failed")
	}
	document, err := attestDocument(publicKey, nonce)
	if err != nil || len(document) == 0 || len(document) > 16<<10 {
		return errors.New("attestation unavailable or oversized")
	}
	body, err := json.Marshal(evidence{document, publicKey, nonce, protocol})
	if err != nil || len(body) > 32<<10 {
		return errors.New("evidence encoding failed")
	}
	if err := binary.Write(conn, binary.BigEndian, uint32(len(body))); err != nil {
		return errors.New("evidence header write failed")
	}
	if _, err := io.Copy(conn, bytes.NewReader(body)); err != nil {
		return errors.New("evidence write failed")
	}
	return nil
}

func main() {
	// A test instance must not accumulate forgotten probe enclaves.
	time.AfterFunc(90*time.Second, func() { os.Exit(1) })
	listener, err := vsock.Listen(19102, nil)
	if err != nil {
		log.Fatal("probe listener unavailable")
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
		log.Fatal("probe listener deadline failed")
	}
	conn, err := listener.Accept()
	if err != nil {
		log.Fatal("probe connection unavailable")
	}
	defer conn.Close()
	if err := handle(conn, attest); err != nil {
		log.Fatal(err)
	}
}
