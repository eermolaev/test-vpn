package platform

import (
	"fmt"
	"net/netip"
	"strings"
)

// Anchor is the pf anchor used by the kill switch. The default macOS
// /etc/pf.conf evaluates anchors under com.apple/.
const Anchor = "com.apple/250.TestVPN"

// PFRules renders the kill switch ruleset for the anchor. Everything leaving
// the machine is dropped except: the tunnel, loopback, DHCP, IPv6 link-local
// and multicast (neighbor discovery), the VPN servers, addresses of excluded
// domains (<direct>, filled at runtime) and optionally the local network.
func PFRules(k KillSwitch) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	servers := make([]string, 0, len(k.Servers))
	for _, s := range k.Servers {
		if s.Is4() {
			servers = append(servers, s.String())
		}
	}
	w("table <servers> persist { %s }", strings.Join(servers, " "))
	w("table <direct> persist")
	w("pass quick on lo0 all")
	if k.Tun != "" {
		w("pass quick on %s all", k.Tun)
	}
	w("pass out quick inet proto udp from any port 68 to any port 67")
	w("pass in quick inet proto udp from any port 67 to any port 68")
	w("pass out quick inet6 to fe80::/10")
	w("pass out quick inet6 to ff00::/8")
	w("pass out quick inet to <servers>")
	w("pass out quick inet to <direct>")
	if k.AllowLAN {
		if k.LAN.IsValid() && k.LAN.Addr().Is4() {
			w("pass out quick inet to %s", k.LAN.Masked())
		}
		w("pass out quick inet to { 169.254.0.0/16 224.0.0.0/4 255.255.255.255 }")
	}
	w("block drop out quick all")
	return b.String()
}

// TunCommands configures the tunnel interface and captures all traffic with
// split default routes; the physical default route stays in place for
// sockets bound to the interface.
func TunCommands(name string, mtu int) [][]string {
	return [][]string{
		{"ifconfig", name, "inet", TunAddr4.String(), TunPeer4.String(), "netmask", "255.255.255.255", "mtu", fmt.Sprint(mtu), "up"},
		{"ifconfig", name, "inet6", TunAddr6.String(), "prefixlen", "128"},
		{"route", "-q", "-n", "add", "-inet", "0.0.0.0/1", "-interface", name},
		{"route", "-q", "-n", "add", "-inet", "128.0.0.0/1", "-interface", name},
		{"route", "-q", "-n", "add", "-inet6", "::/1", "-interface", name},
		{"route", "-q", "-n", "add", "-inet6", "8000::/1", "-interface", name},
	}
}

// ServerRouteCommand adds or deletes a host route to a VPN server.
func ServerRouteCommand(add bool, server netip.Addr, gw netip.Addr) []string {
	if add {
		return []string{"route", "-q", "-n", "add", "-inet", "-host", server.String(), gw.String()}
	}
	return []string{"route", "-q", "-n", "delete", "-inet", "-host", server.String()}
}

// ScopedDefaultCommand adds or deletes the interface-scoped default route.
// Sockets bound with IP_BOUND_IF (direct connections for excluded domains)
// only use routes scoped to their interface; without one they fail with
// "network is unreachable".
func ScopedDefaultCommand(add bool, gw netip.Addr, ifname string) []string {
	if add {
		return []string{"route", "-q", "-n", "add", "-inet", "default", gw.String(), "-ifscope", ifname}
	}
	return []string{"route", "-q", "-n", "delete", "-inet", "default", "-ifscope", ifname}
}

// DNSConfig is the resolver part of a network service in SystemConfiguration.
type DNSConfig struct {
	ServerAddresses []string `json:"serverAddresses,omitempty"`
	SearchDomains   []string `json:"searchDomains,omitempty"`
	DomainName      string   `json:"domainName,omitempty"`
	Present         bool     `json:"present"` // the key existed
}

// ScutilSetDNS returns a scutil script that writes cfg to key.
func ScutilSetDNS(key string, cfg DNSConfig) string {
	var b strings.Builder
	b.WriteString("d.init\n")
	if len(cfg.ServerAddresses) > 0 {
		b.WriteString("d.add ServerAddresses * " + strings.Join(cfg.ServerAddresses, " ") + "\n")
	}
	if len(cfg.SearchDomains) > 0 {
		b.WriteString("d.add SearchDomains * " + strings.Join(cfg.SearchDomains, " ") + "\n")
	}
	if cfg.DomainName != "" {
		b.WriteString("d.add DomainName " + cfg.DomainName + "\n")
	}
	b.WriteString("set " + key + "\nquit\n")
	return b.String()
}

// ScutilRemove returns a scutil script removing key.
func ScutilRemove(key string) string { return "remove " + key + "\nquit\n" }

// ParseScutilDNS parses `scutil` "show <key>" output.
func ParseScutilDNS(out string) DNSConfig {
	var cfg DNSConfig
	if strings.Contains(out, "No such key") || !strings.Contains(out, "<dictionary>") {
		return cfg
	}
	cfg.Present = true
	var arrayKey string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasSuffix(line, ": <array> {"):
			arrayKey = strings.TrimSpace(strings.TrimSuffix(line, ": <array> {"))
		case line == "}":
			arrayKey = ""
		case arrayKey != "":
			if _, v, ok := strings.Cut(line, " : "); ok {
				switch arrayKey {
				case "ServerAddresses":
					cfg.ServerAddresses = append(cfg.ServerAddresses, v)
				case "SearchDomains":
					cfg.SearchDomains = append(cfg.SearchDomains, v)
				}
			}
		default:
			if k, v, ok := strings.Cut(line, " : "); ok && k == "DomainName" {
				cfg.DomainName = v
			}
		}
	}
	return cfg
}

// ParsePrimaryService extracts PrimaryService from
// `show State:/Network/Global/IPv4`.
func ParsePrimaryService(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), " : "); ok && k == "PrimaryService" {
			return v
		}
	}
	return ""
}

// ParsePFToken extracts the reference token printed by `pfctl -E`.
func ParsePFToken(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "Token" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ServiceDNSKey is the dynamic store key with the DNS of a service.
func ServiceDNSKey(service string) string { return "State:/Network/Service/" + service + "/DNS" }

// ParseNCList returns the VPN configurations that are connected or
// connecting, from `scutil --nc list` output, e.g.
//
//   - (Connected)  7A3B... VPN (com.amnezia.AmneziaVPN.network-extension) "AmneziaVPN"  [VPN/...]
func ParseNCList(out string) []string {
	var active []string
	for _, line := range strings.Split(out, "\n") {
		open := strings.Index(line, "(")
		closeIdx := strings.Index(line, ")")
		if open < 0 || closeIdx < open {
			continue
		}
		status := line[open+1 : closeIdx]
		if status != "Connected" && status != "Connecting" && status != "Reasserting" {
			continue
		}
		name := ""
		if q1 := strings.Index(line, "\""); q1 >= 0 {
			if q2 := strings.Index(line[q1+1:], "\""); q2 >= 0 {
				name = line[q1+1 : q1+1+q2]
			}
		}
		if name == "" {
			name = strings.TrimSpace(line[closeIdx+1:])
		}
		active = append(active, fmt.Sprintf("VPN %q is %s", name, strings.ToLower(status)))
	}
	return active
}

// pfNoise reports pfctl informational lines (printed on stderr), e.g.
// "No ALTQ support in kernel".
func pfNoise(line string) bool {
	return strings.Contains(line, "ALTQ") || strings.HasPrefix(line, "pf enabled") || strings.HasPrefix(line, "pf disabled")
}

// ParsePFAnchors returns top-level anchors other than Apple's and ours from
// `pfctl -s Anchors` output.
func ParsePFAnchors(out string) []string {
	var other []string
	for _, line := range strings.Split(out, "\n") {
		a := strings.TrimSpace(line)
		if a == "" || strings.HasPrefix(a, "com.apple") || pfNoise(a) || strings.ContainsRune(a, ' ') {
			continue
		}
		other = append(other, a)
	}
	return other
}

// PFRuleCount counts rules in `pfctl -a NAME -sr` output.
func PFRuleCount(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		if l != "" && !pfNoise(l) {
			n++
		}
	}
	return n
}
