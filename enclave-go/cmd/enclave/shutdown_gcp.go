//go:build cloud_gcp

package main

import "time"

// Confidential Space gives workloads up to 120 seconds after SIGTERM.
// Reserve the remaining time for canceled-handler refunds and queued billing.
// https://docs.cloud.google.com/confidential-computing/confidential-space/docs/create-customize-workloads
const requestDrainTimeout = 90 * time.Second
