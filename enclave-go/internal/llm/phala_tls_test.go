package llm

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPhalaTLSBindsOneVerifiedConnection(t *testing.T) {
	for _, test := range []string{"bound", "redial", "redirect", "other-host"} {
		t.Run(test, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if test == "redial" {
					w.Header().Set("Connection", "close")
				}
				if test == "redirect" {
					http.Redirect(w, r, "https://other.test", 302)
					return
				}
				w.WriteHeader(204)
			}))
			defer server.Close()
			dials := 0
			client, fp, closeConnection, err := newPhalaConnectionWithDial(func(ctx context.Context, network, address string) (net.Conn, error) {
				dials++
				if address != phalaACIDomain+":443" {
					t.Fatal("unapproved host reached dialer")
				}
				dialer := &tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()}
				return dialer.DialContext(ctx, network, server.Listener.Addr().String())
			})
			if err != nil {
				t.Fatal(err)
			}
			defer closeConnection()
			endpoint := "https://" + phalaACIDomain + "/v1/aci/attestation"
			if test == "other-host" {
				endpoint = "https://other.test"
			}
			response, err := client.Get(endpoint)
			if test == "other-host" || test == "redirect" {
				if err == nil {
					response.Body.Close()
					t.Fatal("unapproved request accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			digest := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
			if fp() != hex.EncodeToString(digest[:]) {
				t.Fatal("wrong TLS SPKI observed")
			}
			response, err = client.Get(endpoint)
			if test == "redial" {
				if err == nil {
					response.Body.Close()
					t.Fatal("reconnected without a new attestation")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
			}
			if dials != 1 {
				t.Fatalf("actual TLS dials=%d", dials)
			}
		})
	}
}
