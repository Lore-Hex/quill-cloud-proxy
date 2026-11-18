//go:build !cloud_aws

package llm

// Gateways with direct egress reach native cloud BYOK hosts through the
// compiled provider egress patterns.
const cloudBYOKReachable = true
