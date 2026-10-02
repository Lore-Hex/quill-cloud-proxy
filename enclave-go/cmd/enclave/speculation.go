package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/shadowcoord"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/shadowobserve"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/speculation"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func initializeSpeculation(ctx context.Context, c *trustedrouter.Client, mode shadowcoord.Mode) error {
	if mode != shadowcoord.Shadow {
		return nil
	}
	// Provisioned through authenticated deployment configuration; never from a
	// caller or from the presented grant. Empty evidence intentionally admits none.
	var cfg shadowcoord.Config
	if raw := os.Getenv("QUILL_SPECULATIVE_PROVIDER_CONFIG"); raw != "" {
		if len(raw) > 1<<20 || json.Unmarshal([]byte(raw), &cfg) != nil {
			return fmt.Errorf("invalid speculative provider configuration")
		}
	}
	if len(cfg.Evidence) > shadowcoord.MaxIdentities || cfg.ClockUncertainty < 0 {
		return fmt.Errorf("invalid speculative provider evidence bounds")
	}
	for i := range cfg.Evidence {
		e := &cfg.Evidence[i]
		e.Local.StageDEnabled = e.Local.StageDEnabled && stageDConfigFromEnv().usageHeartbeat
		if e.Local.Bindings["region"] != os.Getenv("TR_REGION") {
			e.Local.PolicyFresh = false
		}
		for j := range e.Local.Certificates {
			e.Local.Certificates[j].ProviderCacheScope = providerCacheScope(e.Identity.WorkspaceID)
		}
		if receiptSigner == nil || e.Local.OwnerBootID != receiptSigner.Kid() {
			e.Local.BootVerified = false
		}
	}
	c.ConfigureSpeculation(ctx, shadowcoord.New(mode, cfg, nil))
	if observer := c.Speculation(); observer != nil {
		go func() {
			defer func() {
				if recover() != nil {
					c.Fault()
				}
			}()
			for {
				select {
				case <-ctx.Done():
					return
				case r := <-observer.Records():
					// The sole serializer accepts only the closed, content-free record type.
					b, err := json.Marshal(r)
					if err == nil {
						fmt.Fprintf(os.Stderr, "enclave.speculation_shadow %s\n", b)
					}
				}
			}
		}()
	}
	return nil
}
func predecideSpeculation(ctx context.Context, c *trustedrouter.Client, bearer string, raw []byte, header bool, route string, confidential bool, req *types.OpenAIChatRequest, custom bool) context.Context {
	if c.Speculation() == nil {
		return ctx
	}
	body := shadowcoord.ParseRequest(raw)
	provenance := speculation.CaptureCallerIdempotency(header, body)
	if body != nil && (req.App != "" || req.HTTPReferer != "" || len(req.AppCategories) > 0 || req.OpenRouterMetadata) {
		body["app"] = true
	}
	observer, ok := c.Speculation().(*shadowcoord.Coordinator)
	if !ok {
		return ctx
	}
	if speculation.CheckInputLength(len(raw)) != speculation.ReasonEligible {
		return shadowobserve.WithExecution(ctx, observer.InputMiss())
	}
	return shadowobserve.WithExecution(ctx, observer.Predecision(c.ShadowLookup(ctx, bearer), speculation.ParsedRequest{Body: body, RouteType: route, CallerIdempotency: provenance, ConfidentialOnly: confidential, InferenceReceipts: req.InferenceReceipt.Requested, CustomModel: custom, ExtraReservationCost: int64(req.AdditionalCostReservationMicrodollars), ResponseModel: req.ResponseModel}))
}
