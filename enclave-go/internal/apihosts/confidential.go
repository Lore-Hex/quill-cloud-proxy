// Package apihosts owns the public confidential-only gateway names.
package apihosts

import (
	"net"
	"strings"
)

var publicDomains = [...]string{"trustedrouter.com", "quillrouter.com", "allyrouter.com", "uptimerouter.com"}

func hostname(authority string) string {
	if host, _, err := net.SplitHostPort(authority); err == nil {
		authority = host
	}
	return strings.TrimSuffix(strings.ToLower(authority), ".")
}

// Confidential checks an HTTP authority or TLS server name, never forwarding headers.
func Confidential(authority string) bool {
	host := hostname(authority)
	for _, domain := range publicDomains {
		if host == "api.confidential."+domain {
			return true
		}
	}
	return false
}

// WithConfidentialAliases preserves the primary certificate name and only adds
// aliases for public domains this deployment already serves.
func WithConfidentialAliases(configured string) string {
	names := strings.Split(configured, ",")
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		seen[hostname(strings.TrimSpace(name))] = true
	}
	for _, domain := range publicDomains {
		alias := "api.confidential." + domain
		if seen["api."+domain] && !seen[alias] {
			names = append(names, alias)
		}
	}
	return strings.Join(names, ",")
}
