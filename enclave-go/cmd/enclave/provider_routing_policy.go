package main

import "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"

const providerJurisdictionUS = "us"

func forceProviderJurisdiction(req *types.OpenAIChatRequest, jurisdiction string) {
	if jurisdiction == "" {
		return
	}
	if req.Provider == nil {
		req.Provider = &types.ProviderRouting{}
	}
	req.Provider.Jurisdiction = jurisdiction
}
