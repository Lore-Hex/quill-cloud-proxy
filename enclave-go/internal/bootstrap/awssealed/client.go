package awssealed

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"
)

const (
	Protocol         = "trustedrouter.aws-bootstrap.v2"
	MaxRequestBytes  = 32 << 10
	MaxDocumentBytes = 16 << 10
)

type Request struct {
	AttestationDocument []byte `json:"attestation_document"`
	Protocol            string `json:"protocol"`
}

// Attester must bind publicDER and nonce into a fresh hardware document. It is
// supplied by the cloud_aws NSM adapter, never by the parent or the wire.
type Attester func(ctx context.Context, publicDER, nonce []byte) ([]byte, error)
type Dialer func(ctx context.Context) (net.Conn, error)

func writeFrame(conn net.Conn, data []byte) error {
	length := len(data)
	if length <= 0 || length > MaxResponseBytes {
		return errors.New("aws sealed bootstrap: frame size")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(length))
	frame := append(size[:], data...)
	for len(frame) > 0 {
		written, err := conn.Write(frame)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
		frame = frame[written:]
	}
	return nil
}

func readFrame(conn net.Conn, maximum uint32) ([]byte, error) {
	var size [4]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(size[:])
	if length == 0 || length > maximum {
		return nil, errors.New("aws sealed bootstrap: frame size")
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	return data, nil
}

// Fetch performs one bounded, enclave-first exchange. Boot retry/transition
// policy belongs to the AWS adapter. There is no plaintext fallback here.
func Fetch(ctx context.Context, dial Dialer, attest Attester, signer *ecdsa.PublicKey, minimum uint64) ([]byte, Manifest, error) {
	if signer == nil || minimum == 0 {
		return nil, Manifest{}, errors.New("aws sealed bootstrap: missing measured configuration")
	}
	data, private, err := recipientExchange(ctx, dial, attest, Protocol)
	if err != nil {
		return nil, Manifest{}, err
	}
	return Open(data, signer, minimum, func(cms []byte) ([]byte, error) { return UnwrapCMS(cms, private) })
}

func recipientExchange(ctx context.Context, dial Dialer, attest Attester, protocol string) ([]byte, *rsa.PrivateKey, error) {
	if dial == nil || attest == nil {
		return nil, nil, errors.New("aws sealed bootstrap: missing recipient transport")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, errors.New("aws sealed bootstrap: recipient key generation")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		return nil, nil, errors.New("aws sealed bootstrap: recipient public key")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, errors.New("aws sealed bootstrap: nonce generation")
	}
	document, err := attest(ctx, publicDER, nonce)
	if err != nil || len(document) == 0 || len(document) > MaxDocumentBytes {
		return nil, nil, errors.New("aws sealed bootstrap: hardware attestation unavailable")
	}
	request, err := json.Marshal(Request{AttestationDocument: document, Protocol: protocol})
	if err != nil || len(request) > MaxRequestBytes {
		return nil, nil, errors.New("aws sealed bootstrap: request size")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	conn, err := dial(ctx)
	if err != nil {
		return nil, nil, errors.New("aws sealed bootstrap: parent unavailable")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline := time.Now().Add(8 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, nil, errors.New("aws sealed bootstrap: transport deadline")
	}
	if err := writeFrame(conn, request); err != nil {
		return nil, nil, errors.New("aws sealed bootstrap: request write failed")
	}
	data, err := readFrame(conn, MaxResponseBytes)
	if err != nil {
		return nil, nil, errors.New("aws sealed bootstrap: response read failed")
	}
	return data, private, nil
}
