package llm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

// One report on a fresh authenticated connection. No inference, even on pass.
func TestFortanixQualificationLive(t *testing.T) {
	mode := os.Getenv("FORTANIX_QUALIFICATION")
	if mode == "" {
		t.Skip("opt-in qualification only")
	}
	if mode != "cpu" && mode != "devices" {
		t.Fatal("unknown qualification mode")
	}
	bin, key := os.Getenv("FORTANIX_QUALIFICATION_BINARY"), os.Getenv("FORTANIX_API_KEY")
	if bin == "" || key == "" {
		t.Fatal("qualification verifier and credential required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: &tls.Config{ServerName: fortanixAuthority, MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}}
	c, err := dialer.DialContext(ctx, "tcp", fortanixAuthority+":443")
	if err != nil {
		t.Fatal("Fortanix TLS connection failed")
	}
	defer c.Close()
	err = fortanixCheckConn(ctx, c.(*tls.Conn), key, func(ctx context.Context, raw []byte, n, s [32]byte) error {
		data, err := json.Marshal(struct {
			Nonce, SPKI string
			Report      json.RawMessage
		}{hex.EncodeToString(n[:]), hex.EncodeToString(s[:]), raw})
		if err != nil {
			return errors.New("invalid Fortanix report JSON")
		}
		cmd := exec.CommandContext(ctx, bin, "-test.run=^TestFortanixQualificationPipe$")
		cmd.Env = []string{"FORTANIX_QUALIFICATION=" + mode, "PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
		cmd.Stdin = bytes.NewReader(data)
		cmd.Stdout = os.Stderr
		return cmd.Run()
	})
	if err != nil {
		t.Fatal(err)
	}
}
