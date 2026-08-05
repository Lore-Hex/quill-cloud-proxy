//go:build !cloud_gcp

package main

func productionBatchConfig() (batchRuntimeConfig, bool) {
	return batchRuntimeConfig{}, false
}
