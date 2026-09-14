package llm

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

func newPhalaConnection() (*http.Client, func() string, func(), error) {
	return newPhalaConnectionWithDial(dialTinfoilTLS)
}

func newPhalaConnectionWithDial(dial func(context.Context, string, string) (net.Conn, error)) (*http.Client, func() string, func(), error) {
	var mu sync.Mutex
	fingerprint := ""
	dialed := false
	transport := &http.Transport{Proxy: nil, DisableCompression: true, MaxConnsPerHost: 1,
		MaxIdleConns: 1, MaxIdleConnsPerHost: 1, ResponseHeaderTimeout: time.Minute, IdleConnTimeout: 5 * time.Minute,
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		if address != phalaACIDomain+":443" || dialed {
			return nil, errors.New("Phala attested connection cannot redirect or redial")
		}
		dialed = true
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			conn.Close()
			return nil, errors.New("Phala transport did not establish TLS")
		}
		state := tlsConn.ConnectionState()
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			conn.Close()
			return nil, errors.New("Phala TLS certificate not verified")
		}
		digest := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
		fingerprint = hex.EncodeToString(digest[:])
		return conn, nil
	}
	httpc := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("Phala attested redirects forbidden") }}
	return httpc, func() string { mu.Lock(); defer mu.Unlock(); return fingerprint }, transport.CloseIdleConnections, nil
}
