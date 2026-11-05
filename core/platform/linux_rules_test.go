package platform

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestNftRules(t *testing.T) {
	k := KillSwitch{
		Tun:       "testvpn0",
		EngineTun: "tun1",
		Servers:   []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8::1")},
		AllowLAN:  true,
		LAN:       netip.MustParsePrefix("192.168.1.217/24"),
	}
	got := NftRules(k)
	for _, want := range []string{
		"table inet testvpn {}\ndelete table inet testvpn\ntable inet testvpn {",
		"set servers { type ipv4_addr; elements = { 203.0.113.7 } }",
		"set direct { type ipv4_addr; }",
		"type filter hook output priority 0; policy accept;",
		`oifname "lo" accept`,
		`oifname "testvpn0" accept`,
		`oifname "tun1" accept`,
		"udp sport 68 udp dport 67 accept",
		"ip daddr @servers accept",
		"ip daddr @direct accept",
		"ip daddr 192.168.1.0/24 accept",
		"ip daddr { 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } accept",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rules miss %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "2001:db8::1") {
		t.Error("IPv6 server must not be allowed")
	}
	if !strings.HasSuffix(got, "\t\tdrop\n\t}\n}\n") {
		t.Errorf("drop must be the last rule:\n%s", got)
	}

	min := NftRules(KillSwitch{})
	if strings.Contains(min, "oifname \"\"") || strings.Contains(min, "192.168") || strings.Contains(min, "169.254") {
		t.Errorf("unexpected rules without tunnel and LAN:\n%s", min)
	}
	if !strings.Contains(min, "set servers { type ipv4_addr; }") {
		t.Errorf("empty server set must be declared:\n%s", min)
	}
}

func TestNftAddDirect(t *testing.T) {
	got := NftAddDirect([]netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8")})
	want := []string{"add", "element", "inet", "testvpn", "direct", "{ 1.2.3.4, 5.6.7.8 }"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q", got)
	}
}

func TestLinuxTunCommands(t *testing.T) {
	v4, v6 := LinuxTunCommands("testvpn0", 9000)
	if got := strings.Join(v4[0], " "); got != "ip link set dev testvpn0 mtu 9000 up" {
		t.Errorf("link: %s", got)
	}
	if got := strings.Join(v4[1], " "); got != "ip -4 addr replace 10.255.0.2 peer 10.255.0.1 dev testvpn0" {
		t.Errorf("addr: %s", got)
	}
	if len(v4) != 4 || len(v6) != 3 {
		t.Fatalf("v4 %d, v6 %d commands", len(v4), len(v6))
	}
	if got := strings.Join(v6[2], " "); got != "ip -6 route replace 8000::/1 dev testvpn0" {
		t.Errorf("v6 route: %s", got)
	}
	s, gw := netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("192.168.1.1")
	if got := strings.Join(LinuxServerRoute(true, s, gw, "eth0"), " "); got != "ip -4 route replace 203.0.113.7/32 via 192.168.1.1 dev eth0" {
		t.Errorf("add server route: %s", got)
	}
	if got := strings.Join(LinuxServerRoute(false, s, gw, "eth0"), " "); got != "ip -4 route del 203.0.113.7/32" {
		t.Errorf("del server route: %s", got)
	}
}

// procRouteSample is /proc/net/route on a little-endian host with a VPN up.
const procRouteSample = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
wlan0	00000000	0101A8C0	0003	0	0	600	00000000	0	0	0
eth0	00000000	0100000A	0003	0	0	100	00000000	0	0	0
testvpn0	00000000	00000000	0001	0	0	0	00000080	0	0	0
testvpn0	00000080	00000000	0001	0	0	0	00000080	0	0	0
wlan0	0001A8C0	00000000	0001	0	0	600	00FFFFFF	0	0	0
eth0	077100CB	0100000A	0007	0	0	0	FFFFFFFF	0	0	0
wg0	00000000	00000000	0001	0	0	0	00000000	0	0	0
`

func TestParseProcRoute(t *testing.T) {
	routes := ParseProcRoute(procRouteSample)
	if len(routes) != 7 {
		t.Fatalf("parsed %d routes", len(routes))
	}
	r := routes[0]
	if r.Iface != "wlan0" || r.Gateway != netip.MustParseAddr("192.168.1.1") || r.Bits != 0 || r.Metric != 600 || !r.HasGateway() {
		t.Errorf("first route: %+v", r)
	}
	if routes[2].Bits != 1 || routes[3].Dst != netip.MustParseAddr("128.0.0.0") {
		t.Errorf("split routes: %+v %+v", routes[2], routes[3])
	}
	if routes[4].Dst != netip.MustParseAddr("192.168.1.0") || routes[4].Bits != 24 {
		t.Errorf("subnet route: %+v", routes[4])
	}

	def, ok := PickDefaultRoute(routes, func(i string) bool { return strings.HasPrefix(i, LinuxTunPrefix) })
	if !ok || def.Iface != "eth0" || def.Gateway != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("default route: %+v %v", def, ok)
	}
	def, ok = PickDefaultRoute(routes, func(i string) bool { return i == "eth0" })
	if !ok || def.Iface != "wlan0" {
		t.Errorf("default route without eth0: %+v %v", def, ok)
	}

	hosts := HostRoutes(routes)
	if !hosts[netip.MustParseAddr("203.0.113.7")] || len(hosts) != 1 {
		t.Errorf("host routes: %v", hosts)
	}

	if got := ForeignTunnels(routes, "testvpn0"); !reflect.DeepEqual(got, []string{"wg0"}) {
		t.Errorf("foreign tunnels: %v", got)
	}
	if got := ForeignTunnels(routes, "other"); !reflect.DeepEqual(got, []string{"testvpn0", "wg0"}) {
		t.Errorf("foreign tunnels for another own: %v", got)
	}
}

func TestForeignPolicyRules(t *testing.T) {
	out := `0:	from all lookup local
32764:	from all lookup main suppress_prefixlength 0
32765:	not from all fwmark 0xca6c lookup 51820
32766:	from all lookup main
32767:	from all lookup default
`
	got := ForeignPolicyRules(out)
	if !reflect.DeepEqual(got, []string{"not from all fwmark 0xca6c lookup 51820"}) {
		t.Fatalf("got %q", got)
	}
}

func TestRenderResolvConf(t *testing.T) {
	orig := "# from DHCP\nnameserver 192.168.1.1\nsearch lan\noptions edns0 trust-ad\n"
	got := RenderResolvConf(orig, []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.4.4")})
	want := ResolvConfHeader + "\nnameserver 8.8.8.8\nnameserver 8.8.4.4\nsearch lan\noptions edns0 trust-ad\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	if !UsesResolvedStub("nameserver 127.0.0.53\noptions edns0\n") || UsesResolvedStub(orig) {
		t.Error("UsesResolvedStub")
	}
}
