package platform

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Linux helpers are kept free of build tags so that they are tested on every
// platform; linux.go uses them.

// NftTable is the nftables table (family inet) of the Linux kill switch.
const NftTable = "testvpn"

// LinuxTunPrefix names the tunnel interface ("testvpn0", "testvpn1", ...).
const LinuxTunPrefix = "testvpn"

// NftRules renders an nft script that atomically replaces the kill switch
// table. It mirrors PFRules: everything leaving the machine is dropped except
// the tunnel, loopback, DHCP, IPv6 link-local and multicast, the VPN servers,
// addresses of excluded domains (@direct, filled at runtime), local container
// bridges and optionally the local network. Replacing the table empties
// @direct, so the caller re-adds known addresses.
func NftRules(k KillSwitch) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	var servers []string
	for _, s := range k.Servers {
		if s.Is4() {
			servers = append(servers, s.String())
		}
	}
	// Declaring the table first makes the delete succeed when it is absent;
	// nft applies the whole script as one transaction.
	w("table inet %s {}", NftTable)
	w("delete table inet %s", NftTable)
	w("table inet %s {", NftTable)
	if len(servers) > 0 {
		w("\tset servers { type ipv4_addr; elements = { %s } }", strings.Join(servers, ", "))
	} else {
		w("\tset servers { type ipv4_addr; }")
	}
	w("\tset direct { type ipv4_addr; }")
	w("\tchain output {")
	w("\t\ttype filter hook output priority 0; policy accept;")
	w("\t\toifname \"lo\" accept")
	if k.Tun != "" {
		w("\t\toifname %q accept", k.Tun)
	}
	if k.EngineTun != "" {
		w("\t\toifname %q accept", k.EngineTun)
	}
	w("\t\tudp sport 68 udp dport 67 accept")
	w("\t\tip6 daddr fe80::/10 accept")
	w("\t\tip6 daddr ff00::/8 accept")
	w("\t\tip daddr @servers accept")
	w("\t\tip daddr @direct accept")
	if k.AllowLAN {
		if k.LAN.IsValid() && k.LAN.Addr().Is4() {
			w("\t\tip daddr %s accept", k.LAN.Masked())
		}
		w("\t\tip daddr { 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } accept")
	}
	// Local container bridges (Docker, Podman, libvirt) never leave the host,
	// so they are allowed even without AllowLAN; otherwise replies from host
	// services to containers are dropped while the VPN is connected. Traffic
	// the containers send to the internet is routed into the tunnel.
	for _, ifc := range localBridgeIfnames {
		w("\t\toifname %q accept", ifc)
	}
	w("\t\tdrop")
	w("\t}")
	w("}")
	return b.String()
}

// localBridgeIfnames are host-local bridge interfaces that are always allowed
// (nft matches a trailing * as a prefix wildcard).
var localBridgeIfnames = []string{"docker0", "br-*", "veth*", "cni*", "podman*", "virbr*"}

// NftAddDirect returns the nft arguments that add ips to @direct.
func NftAddDirect(ips []netip.Addr) []string {
	el := make([]string, len(ips))
	for i, ip := range ips {
		el[i] = ip.String()
	}
	return []string{"add", "element", "inet", NftTable, "direct", "{ " + strings.Join(el, ", ") + " }"}
}

// LinuxTunCommands configures the tunnel interface and captures all IPv4
// traffic with split default routes; the physical default route stays for
// sockets bound to the interface with SO_BINDTODEVICE. IPv6 is in a separate
// list because it may be disabled on the host; the caller treats it as best
// effort.
func LinuxTunCommands(name string, mtu int) (v4, v6 [][]string) {
	v4 = [][]string{
		{"ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu), "up"},
		{"ip", "-4", "addr", "replace", TunAddr4.String(), "peer", TunPeer4.String(), "dev", name},
		{"ip", "-4", "route", "replace", "0.0.0.0/1", "dev", name},
		{"ip", "-4", "route", "replace", "128.0.0.0/1", "dev", name},
	}
	v6 = [][]string{
		{"ip", "-6", "addr", "replace", TunAddr6.String() + "/128", "dev", name},
		{"ip", "-6", "route", "replace", "::/1", "dev", name},
		{"ip", "-6", "route", "replace", "8000::/1", "dev", name},
	}
	return v4, v6
}

// LinuxServerRoute adds (via gw on dev) or deletes the host route to a server.
func LinuxServerRoute(add bool, server, gw netip.Addr, dev string) []string {
	if add {
		return []string{"ip", "-4", "route", "replace", server.String() + "/32", "via", gw.String(), "dev", dev}
	}
	return []string{"ip", "-4", "route", "del", server.String() + "/32"}
}

// Route flags from <linux/route.h>.
const (
	rtfUp      = 0x1
	rtfGateway = 0x2
	rtfHost    = 0x4
)

// ProcRoute is one line of /proc/net/route.
type ProcRoute struct {
	Iface   string
	Dst     netip.Addr
	Gateway netip.Addr
	Bits    int // prefix length of the mask
	Flags   uint32
	Metric  int
}

// Up reports whether the route is usable.
func (r ProcRoute) Up() bool { return r.Flags&rtfUp != 0 }

// HasGateway reports whether the route goes via a gateway.
func (r ProcRoute) HasGateway() bool { return r.Flags&rtfGateway != 0 }

// procAddr decodes an address of /proc/net/route: a hex u32 in host byte
// order holding the address in network order.
func procAddr(s string) (netip.Addr, bool) {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return netip.Addr{}, false
	}
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], uint32(v))
	return netip.AddrFrom4(b), true
}

// ParseProcRoute parses /proc/net/route (IPv4 routes of the main table).
func ParseProcRoute(s string) []ProcRoute {
	var out []ProcRoute
	for i, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 8 {
			continue
		}
		dst, ok1 := procAddr(f[1])
		gw, ok2 := procAddr(f[2])
		mask, ok3 := procAddr(f[7])
		flags, err1 := strconv.ParseUint(f[3], 16, 32)
		metric, err2 := strconv.Atoi(f[6])
		if !ok1 || !ok2 || !ok3 || err1 != nil || err2 != nil {
			continue
		}
		bits := 0
		for _, b := range mask.As4() {
			for ; b&0x80 != 0; b <<= 1 {
				bits++
			}
		}
		out = append(out, ProcRoute{Iface: f[0], Dst: dst, Gateway: gw, Bits: bits, Flags: uint32(flags), Metric: metric})
	}
	return out
}

// PickDefaultRoute returns the IPv4 default route via a gateway with the
// lowest metric, ignoring interfaces for which skip returns true.
func PickDefaultRoute(routes []ProcRoute, skip func(iface string) bool) (ProcRoute, bool) {
	var cands []ProcRoute
	for _, r := range routes {
		if r.Up() && r.HasGateway() && r.Bits == 0 && r.Dst == netip.IPv4Unspecified() && !skip(r.Iface) {
			cands = append(cands, r)
		}
	}
	if len(cands) == 0 {
		return ProcRoute{}, false
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].Metric < cands[j].Metric })
	return cands[0], true
}

// HostRoutes returns the destinations of IPv4 host routes.
func HostRoutes(routes []ProcRoute) map[netip.Addr]bool {
	m := map[netip.Addr]bool{}
	for _, r := range routes {
		if r.Bits == 32 || r.Flags&rtfHost != 0 {
			m[r.Dst] = true
		}
	}
	return m
}

// ForeignTunnels lists interfaces other than own that capture all IPv4
// traffic: a split default (0/1, 128/1) or a default route without a gateway
// (a point-to-point tunnel such as wg0 or tun0).
func ForeignTunnels(routes []ProcRoute, own string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range routes {
		if !r.Up() || r.Iface == own || seen[r.Iface] {
			continue
		}
		split := r.Bits == 1 && (r.Dst == netip.IPv4Unspecified() || r.Dst == netip.AddrFrom4([4]byte{128}))
		devDefault := r.Bits == 0 && r.Dst == netip.IPv4Unspecified() && !r.HasGateway()
		if split || devDefault {
			seen[r.Iface] = true
			out = append(out, r.Iface)
		}
	}
	return out
}

// ForeignPolicyRules returns `ip -4 rule` lines that send marked or all
// traffic to a non-standard table, as wg-quick and some VPN apps do.
func ForeignPolicyRules(out string) []string {
	var rules []string
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		_, rule, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		rule = strings.TrimSpace(rule)
		i := strings.Index(rule, "lookup ")
		if i < 0 {
			continue
		}
		table := strings.Fields(rule[i+len("lookup "):])
		if len(table) == 0 {
			continue
		}
		switch table[0] {
		case "local", "main", "default", "255", "254", "253":
			continue
		}
		rules = append(rules, rule)
	}
	return rules
}

// ResolvConfHeader marks a resolv.conf written by the daemon.
const ResolvConfHeader = "# Written by testvpn; the original is restored on disconnect."

// RenderResolvConf returns orig with its nameserver lines replaced by
// servers; search, domain and options lines are kept.
func RenderResolvConf(orig string, servers []netip.Addr) string {
	var b strings.Builder
	b.WriteString(ResolvConfHeader + "\n")
	for _, s := range servers {
		fmt.Fprintf(&b, "nameserver %s\n", s)
	}
	for _, line := range strings.Split(orig, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "search", "domain", "options":
			b.WriteString(strings.TrimSpace(line) + "\n")
		}
	}
	return b.String()
}

// UsesResolvedStub reports whether a resolv.conf points to the local
// systemd-resolved stub, so per-link DNS settings apply to all programs.
func UsesResolvedStub(resolvConf string) bool {
	for _, line := range strings.Split(resolvConf, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" && (f[1] == "127.0.0.53" || f[1] == "127.0.0.54") {
			return true
		}
	}
	return false
}
