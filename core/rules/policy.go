package rules

// Policy decides which hosts go directly and which through the tunnel.
//
//   - VPN is the list of domains that use the tunnel. Empty or "*" means
//     everything; otherwise only the listed domains do and the rest goes
//     directly.
//   - Exclusions always go directly.
//   - When both lists cover a host, the more specific rule wins; on a tie
//     the tunnel wins. Protected self-check hosts always use the tunnel.
type Policy struct {
	Exclusions *Set
	VPN        *Set
}

// Direct reports whether host bypasses the tunnel. An empty host (unknown
// destination) follows the default: tunnel in full-tunnel mode, direct when
// only listed domains use the VPN.
func (p Policy) Direct(host string) bool {
	h := NormalizeHost(host)
	if h == "" {
		return !p.VPN.FullTunnel()
	}
	if IsProtectedHost(h) {
		return false
	}
	vpnScore, inVPN := p.VPN.specificity(h)
	if p.VPN.Len() == 0 {
		inVPN = true // no list: everything uses the tunnel
	}
	exclScore, excluded := p.Exclusions.specificity(h)
	switch {
	case excluded && (!inVPN || exclScore > vpnScore):
		return true
	case inVPN:
		return false
	default:
		return true // only listed domains use the VPN
	}
}

// Tunneled reports whether host must use the tunnel (the inverse of Direct
// for a known host).
func (p Policy) Tunneled(host string) bool { return !p.Direct(host) }
