package main

import "errors"

// The measured launch policy permits one-shot tasks, not serving TLS mode overrides.
func runGCPCertificateTask(task, host string, custody func() error, issue func(string, string) error) error {
	switch task {
	case "gcp-acme-custody-check":
		return custody()
	case "gcp-acme-preissue", "gcp-acme-rehearse", "gcp-acme-rehearse-renew", "gcp-acme-rehearse-read":
		return issue(task, host)
	default:
		return errors.New("invalid GCP certificate task")
	}
}
