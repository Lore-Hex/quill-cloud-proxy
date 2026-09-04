package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func initializeSpendLeaseShadow(ctx context.Context, gateway *trustedrouter.Client, boot *types.BootstrapData) {
	if boot == nil || (!boot.SpendLeaseShadow && !boot.SpendLeaseLocalAdmission) || gateway == nil || receiptSigner == nil {
		return
	}
	var verifier *spendlease.Verifier
	if boot.SpendLeaseConfigError != "" {
		fmt.Fprintf(os.Stderr, "spendlease.config_rejected err=%q\n", boot.SpendLeaseConfigError)
	} else {
		var err error
		verifier, err = spendlease.NewVerifier(boot.SpendLeaseIssuerConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "spendlease.config_rejected err=%q\n", err.Error())
		}
	}
	// Configure even without a valid verifier so every authorize still carries
	// the flag-on dormant echo and boot signature. Invalid issuer config can
	// never accidentally become authority.
	gateway.ConfigureSpendLeaseShadow(receiptSigner, verifier)
	gateway.ConfigureSpendLeaseLocalAdmission(boot.SpendLeaseLocalAdmission)
	gateway.StartSpendLeaseBootRegistration(ctx, receiptSigner, currentSpendLeaseEvidence())
}

func spendLeaseIssuerConfigNonce(boot *types.BootstrapData) []byte {
	if boot == nil || (!boot.SpendLeaseShadow && !boot.SpendLeaseLocalAdmission) || len(boot.SpendLeaseIssuerConfig) == 0 {
		return nil
	}
	commitment := spendlease.IssuerConfigCommitment(boot.SpendLeaseIssuerConfig)
	return commitment[:]
}

func currentSpendLeaseEvidence() trustedrouter.BootRegistrationEvidence {
	cached := receiptAttestationCache.Load()
	if cached == nil || len(cached.document) == 0 {
		return trustedrouter.BootRegistrationEvidence{}
	}
	encoded, err := receipt.EncodeAttestation(cached.document, cached.kind)
	if err != nil {
		return trustedrouter.BootRegistrationEvidence{}
	}
	return trustedrouter.BootRegistrationEvidence{
		Attestation: encoded, AttestationKind: cached.kind,
	}
}
