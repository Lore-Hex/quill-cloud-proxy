package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/attestation"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/enclavetls"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
)

var receiptSigner *receipt.Signer
var receiptIssuer = "https://api.trustedrouter.com"
var receiptPublicEnabled = true

type cachedReceiptAttestation struct {
	receiptAttestationDocument
	previous []receiptAttestationDocument
}

type receiptAttestationDocument struct {
	document []byte
	kind     string
	sha256   string
}

const (
	receiptAttestationHistoryCapacity = 64
	// 32 previous documents ≈ 16 hours at the 30-minute re-mint cadence (~650 KB on the
	// wire, under the router collector's 2 MB cap). The collector runs every 5
	// minutes, so a version leaves this window only after ~190 chances to be logged;
	// the 64-entry ring behind /receipt-attestation?sha256= covers the rest of the
	// instance's life.
	receiptKeyAttestationHistoryCapacity = 32
)

type receiptKeyAttestation struct {
	Attestation       string `json:"att"`
	AttestationKind   string `json:"att_kind"`
	AttestationSHA256 string `json:"att_sha256"`
}

// receiptKeyEnvelope declaration order is the fixed JSON wire order.
type receiptKeyEnvelope struct {
	KID                string                  `json:"kid"`
	JWK                receipt.JWK             `json:"jwk"`
	Attestation        string                  `json:"att"`
	AttestationKind    string                  `json:"att_kind"`
	AttestationSHA256  string                  `json:"att_sha256"`
	AttestationHistory []receiptKeyAttestation `json:"att_history"`
}

var receiptAttestationCache atomic.Pointer[cachedReceiptAttestation]

// A duration seam keeps the background lifecycle testable without waiting for
// production's half-hour refresh cadence. Each actual wait is jittered by 10%.
var receiptAttestationRemintInterval = 30 * time.Minute

// initializeReceiptSigner runs only after entropy seeding and TLS setup. A
// A disabled public receipt subsystem leaves both signer and cache nil unless
// spend-lease shadow needs the same boot identity; in that case the key exists
// only for control-plane boot auth and public receipt behavior stays disabled.
func initializeReceiptSigner(ctx context.Context, tlsServer *enclavetls.Server, deviceBlob []byte, apiHosts ...string) error {
	return initializeReceiptSignerWithSpendLease(ctx, tlsServer, deviceBlob, false, nil, apiHosts...)
}

func initializeReceiptSignerWithSpendLease(ctx context.Context, tlsServer *enclavetls.Server, deviceBlob []byte, spendLeaseNeedsSigner bool, launchConfigNonce []byte, apiHosts ...string) error {
	receiptAttestationCache.Store(nil)
	receiptPublicEnabled = !strings.EqualFold(strings.TrimSpace(os.Getenv("QUILL_RECEIPTS")), "off")
	if !receiptPublicEnabled && !spendLeaseNeedsSigner {
		receiptSigner = nil
		return nil
	}
	issuer, err := configuredReceiptIssuer(apiHosts)
	if err != nil {
		return err
	}
	receiptIssuer = issuer

	signer, err := receipt.NewSigner()
	if err != nil {
		return err
	}
	receiptSigner = signer
	commitment := signer.KeyCommitment()
	leafDER := currentReceiptLeafDER(tlsServer)
	if err := remintReceiptAttestationBound(leafDER, deviceBlob, commitment[:], launchConfigNonce); err != nil {
		fmt.Fprintf(os.Stderr, "receipt.attestation_initial_mint_failed err=%q\n", err.Error())
	}
	if ctx.Err() == nil {
		go runReceiptAttestationReminterBound(ctx, tlsServer, deviceBlob, commitment, launchConfigNonce, os.Stderr)
	}
	return nil
}

func inferenceReceiptsEnabled() bool {
	return receiptPublicEnabled && receiptSigner != nil
}

func configuredReceiptIssuer(apiHosts []string) (string, error) {
	issuer := strings.TrimSpace(os.Getenv("QUILL_RECEIPT_ISS"))
	if issuer == "" && len(apiHosts) > 0 {
		host, _, _ := strings.Cut(apiHosts[0], ",")
		host = strings.TrimSpace(host)
		if host != "" {
			issuer = "https://" + host
		}
	}
	if issuer == "" {
		issuer = receiptIssuer
	}
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", fmt.Errorf("receipt: QUILL_RECEIPT_ISS must be a canonical https origin")
	}
	return strings.TrimSuffix(issuer, "/"), nil
}

func currentReceiptLeafDER(tlsServer *enclavetls.Server) []byte {
	if tlsServer == nil {
		return nil
	}
	return tlsServer.CurrentLeafDER()
}

func remintReceiptAttestation(leafDER, deviceBlob, receiptKeyFP []byte) error {
	return remintReceiptAttestationBound(leafDER, deviceBlob, receiptKeyFP, nil)
}

func remintReceiptAttestationBound(leafDER, deviceBlob, receiptKeyFP, launchConfigNonce []byte) error {
	document, err := getAttestation(leafDER, deviceBlob, launchConfigNonce, nil, receiptKeyFP)
	if err != nil {
		return err
	}
	current := newReceiptAttestationDocument(document, attestation.Kind)
	for {
		previousCache := receiptAttestationCache.Load()
		// A re-mint that produced the byte-identical document is a no-op: pushing it
		// would spend a history slot on nothing and evict a document some receipt
		// still pins. History holds distinct hashes only, newest first.
		if previousCache != nil && previousCache.sha256 == current.sha256 {
			return nil
		}
		next := &cachedReceiptAttestation{receiptAttestationDocument: current}
		if previousCache != nil && len(previousCache.document) > 0 {
			candidates := make([]receiptAttestationDocument, 0, 1+len(previousCache.previous))
			candidates = append(candidates, previousCache.receiptAttestationDocument)
			candidates = append(candidates, previousCache.previous...)
			seen := map[string]bool{current.sha256: true}
			for _, candidate := range candidates {
				if seen[candidate.sha256] {
					continue
				}
				seen[candidate.sha256] = true
				next.previous = append(next.previous, candidate)
				if len(next.previous) == receiptAttestationHistoryCapacity {
					break
				}
			}
		}
		if receiptAttestationCache.CompareAndSwap(previousCache, next) {
			return nil
		}
	}
}

func newCachedReceiptAttestation(document []byte, kind string) *cachedReceiptAttestation {
	return &cachedReceiptAttestation{receiptAttestationDocument: newReceiptAttestationDocument(document, kind)}
}

func newReceiptAttestationDocument(document []byte, kind string) receiptAttestationDocument {
	return receiptAttestationDocument{
		document: append([]byte(nil), document...),
		kind:     kind,
		sha256:   receiptAttestationDigest(document),
	}
}

func receiptAttestationDigest(document []byte) string {
	digest := sha256.Sum256(document)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func runReceiptAttestationReminter(
	ctx context.Context,
	tlsServer *enclavetls.Server,
	deviceBlob []byte,
	receiptKeyFP [32]byte,
	logWriter io.Writer,
) {
	runReceiptAttestationReminterBound(ctx, tlsServer, deviceBlob, receiptKeyFP, nil, logWriter)
}

func runReceiptAttestationReminterBound(
	ctx context.Context,
	tlsServer *enclavetls.Server,
	deviceBlob []byte,
	receiptKeyFP [32]byte,
	launchConfigNonce []byte,
	logWriter io.Writer,
) {
	for {
		timer := time.NewTimer(jitteredReceiptAttestationInterval(receiptAttestationRemintInterval))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if err := remintReceiptAttestationBound(currentReceiptLeafDER(tlsServer), deviceBlob, receiptKeyFP[:], launchConfigNonce); err != nil {
			fmt.Fprintf(logWriter, "receipt.attestation_remint_failed err=%q\n", err.Error())
		}
	}
}

func jitteredReceiptAttestationInterval(base time.Duration) time.Duration {
	if base <= 0 {
		return time.Nanosecond
	}
	span := base / 10
	if span == 0 {
		return base
	}
	randomOffset, err := rand.Int(rand.Reader, big.NewInt(int64(2*span)+1))
	if err != nil {
		return base
	}
	return base - span + time.Duration(randomOffset.Int64())
}

func serveReceiptAttestation(conn io.Writer, requestTarget string) bool {
	cached := receiptAttestationCache.Load()
	if cached == nil || len(cached.document) == 0 {
		disableResponseReuse(conn)
		writeError(conn, 503, "receipt attestation unavailable")
		return false
	}
	wantedSHA256, byHash, err := receiptAttestationSHA256Query(requestTarget)
	if err != nil {
		disableResponseReuse(conn)
		writeError(conn, 400, "invalid receipt attestation sha256")
		return false
	}
	document := cached.receiptAttestationDocument
	if byHash {
		found := document.sha256 == wantedSHA256
		if !found {
			for _, previous := range cached.previous {
				if previous.sha256 == wantedSHA256 {
					document = previous
					found = true
					break
				}
			}
		}
		if !found {
			disableResponseReuse(conn)
			writeError(conn, 404, "unknown receipt attestation")
			return false
		}
	}
	fmt.Fprintf(conn,
		"HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nCache-Control: no-store\r\nx-receipt-att-kind: %s\r\nConnection: %s\r\n\r\n",
		receiptAttestationContentType(document.kind), len(document.document), document.kind, responseConnection(conn))
	_, _ = conn.Write(document.document)
	return true
}

func receiptAttestationSHA256Query(requestTarget string) (string, bool, error) {
	target, err := url.ParseRequestURI(requestTarget)
	if err != nil {
		return "", false, err
	}
	query, err := url.ParseQuery(target.RawQuery)
	if err != nil {
		return "", false, err
	}
	values, present := query["sha256"]
	if !present {
		return "", false, nil
	}
	if len(values) != 1 {
		return "", false, fmt.Errorf("receipt attestation sha256 must appear once")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(values[0])
	if err != nil || len(decoded) != sha256.Size || base64.RawURLEncoding.EncodeToString(decoded) != values[0] {
		return "", false, fmt.Errorf("receipt attestation sha256 must be unpadded base64url of 32 bytes")
	}
	return values[0], true, nil
}

func receiptAttestationContentType(kind string) string {
	switch kind {
	case "gcp-cs-jwt", "azure-maa-jwt":
		return "application/jwt"
	case "aws-nitro-cose":
		return "application/cbor"
	default:
		return "application/octet-stream"
	}
}

func serveReceiptKey(conn io.Writer) bool {
	cached := receiptAttestationCache.Load()
	if cached == nil || len(cached.document) == 0 {
		disableResponseReuse(conn)
		writeError(conn, 503, "receipt attestation unavailable")
		return false
	}
	attestationValue, err := receipt.EncodeAttestation(cached.document, cached.kind)
	if err != nil {
		disableResponseReuse(conn)
		writeError(conn, 503, "receipt attestation unavailable")
		return false
	}
	historyCount := min(len(cached.previous), receiptKeyAttestationHistoryCapacity)
	history := make([]receiptKeyAttestation, historyCount)
	for i, previous := range cached.previous[:historyCount] {
		encoded, err := receipt.EncodeAttestation(previous.document, previous.kind)
		if err != nil {
			disableResponseReuse(conn)
			writeError(conn, 503, "receipt attestation unavailable")
			return false
		}
		history[i] = receiptKeyAttestation{
			Attestation:       encoded,
			AttestationKind:   previous.kind,
			AttestationSHA256: previous.sha256,
		}
	}
	body, err := json.Marshal(receiptKeyEnvelope{
		KID:                receiptSigner.Kid(),
		JWK:                receiptSigner.JWK(),
		Attestation:        attestationValue,
		AttestationKind:    cached.kind,
		AttestationSHA256:  cached.sha256,
		AttestationHistory: history,
	})
	if err != nil {
		disableResponseReuse(conn)
		writeError(conn, 500, "receipt key unavailable")
		return false
	}
	fmt.Fprintf(conn,
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: %s\r\n\r\n",
		len(body), responseConnection(conn))
	_, _ = conn.Write(body)
	return true
}
