package rules

import "strings"

// protectedHosts are used by the egress verifier and leak tests (GEO-002,
// GEO-004..GEO-006). Traffic to them always goes through the tunnel,
// otherwise the checks would report the user's real address.
var protectedHosts = []string{
	"api.ipify.org",
	"api64.ipify.org",
	"icanhazip.com",
	"ifconfig.co",
	"www.cloudflare.com",
	"stun.l.google.com",
	"stun.cloudflare.com",
	"browserleaks.com",
	"dnsleaktest.com",
}

// protectedRegistrable are domains that exist only to serve self-checks, so a
// rule covering them (for example "ipify.org") is rejected outright. Rules for
// broad domains such as "google.com" are allowed; the router still sends the
// protected subdomains through the tunnel.
var protectedRegistrable = []string{
	"ipify.org",
	"icanhazip.com",
	"ifconfig.co",
	"browserleaks.com",
	"dnsleaktest.com",
}

// ProtectedHosts returns the hosts that are always routed through the tunnel.
func ProtectedHosts() []string { return append([]string(nil), protectedHosts...) }

// IsProtectedHost reports whether a normalized host is, or is a subdomain of,
// a protected host.
func IsProtectedHost(h string) bool {
	for _, p := range protectedHosts {
		if h == p || strings.HasSuffix(h, "."+p) {
			return true
		}
	}
	return false
}

// IsProtectedRule reports whether the rule must be rejected (SPLIT-005).
func IsProtectedRule(r Rule) bool {
	if IsProtectedHost(r.Domain) {
		return true
	}
	if r.Kind == Suffix {
		for _, p := range protectedRegistrable {
			if p == r.Domain || strings.HasSuffix(p, "."+r.Domain) {
				return true
			}
		}
	}
	return false
}
