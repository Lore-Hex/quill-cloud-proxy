//go:build cloud_aws

package llm

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/url"
	"strconv"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/vsockhttp"
)

// Legacy adapters predate directproviders. Every fixed URL they return must
// also be reachable from Nitro; table-only checks missed Atlas Cloud entirely.
func TestAWSLegacyProviderHostsHaveTunnels(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "byok.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	hosts := map[string]bool{}
	for _, tunnel := range AWSProviderTunnels() {
		hosts[tunnel.Host] = true
	}
	checked := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "directBaseURL" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			ret, ok := node.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			for _, result := range ret.Results {
				literal, ok := result.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				raw, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatal(err)
				}
				if raw == "" {
					continue
				}
				u, err := url.Parse(raw)
				if err != nil || u.Scheme != "https" || u.Hostname() == "" {
					t.Fatalf("invalid provider URL: %q", raw)
				}
				checked++
				if !hosts[u.Hostname()] {
					t.Errorf("provider host %s has no AWS enclave tunnel", u.Hostname())
				}
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no legacy provider URLs checked")
	}
}

func TestAWSProviderTunnelsRejectUnknownHost(t *testing.T) {
	client := defaultHTTPClient()
	_, err := client.Get("https://unconfigured.example.invalid/v1/models")
	var unconfigured *vsockhttp.UnconfiguredHostError
	if !errors.As(err, &unconfigured) || unconfigured.Host != "unconfigured.example.invalid" {
		t.Fatalf("unconfigured host must fail closed: %v", err)
	}
	// The exported copy must not allow a caller to alter the enclave allowlist.
	copy := AWSProviderTunnels()
	copy[0] = vsockhttp.Tunnel{Host: "unconfigured.example.invalid", CID: 3, Port: 1}
	if AWSProviderTunnels()[0].Host == copy[0].Host {
		t.Fatal("AWSProviderTunnels exposed mutable shared state")
	}
}
