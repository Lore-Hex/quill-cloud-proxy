//go:build llm_openrouter && !llm_multi

package llm

import qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"

func New(boot *qtypes.BootstrapData) Client {
	return newOpenRouter(boot)
}
