//go:build llm_vertex && !llm_multi

// Single-backend Vertex build: the package's New() returns the Vertex
// client unconditionally. For multi-backend builds, multi.go owns New()
// and dispatches by provider.
package llm

import (
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func New(boot *qtypes.BootstrapData) Client {
	return newVertex(boot)
}
