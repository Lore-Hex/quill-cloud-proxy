package main

import (
	"sync/atomic"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

var awsBootstrapEvidence atomic.Pointer[types.AWSBootstrapEvidence]

func recordAWSBootstrapEvidence(evidence *types.AWSBootstrapEvidence) {
	if evidence == nil {
		awsBootstrapEvidence.Store(nil)
		return
	}
	snapshot := *evidence
	awsBootstrapEvidence.Store(&snapshot)
}
