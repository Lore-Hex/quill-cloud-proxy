//go:build !cloud_gcp

package main

import "time"

// Keep the total request, cancellation and queue drain below 30 seconds on
// platforms which do not provide Confidential Space's shutdown allowance.
const requestDrainTimeout = 15 * time.Second
