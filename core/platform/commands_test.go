package platform

import (
	"net/netip"
	"strings"
	"testing"
)

func TestPFRules(t *testing.T) {
	got := PFRules(KillSwitch{
		Tun:      "utun7",
		Servers:  []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("2001:db8::1")},
		AllowLAN: true,
		LAN:      netip.MustParsePrefix("192.168.1.23/24"),
	})
	want := `table <servers> persist { 203.0.113.10 }
table <direct> persist
pass quick on lo0 all
pass quick on utun7 all
pass out quick inet proto udp from any port 68 to any port 67
pass in quick inet proto udp from any port 67 to any port 68
pass out quick inet6 to fe80::/10
pass out quick inet6 to ff00::/8
pass out quick inet to <servers>
pass out quick inet to <direct>
pass out quick inet to 192.168.1.0/24
pass out quick inet to { 169.254.0.0/16 224.0.0.0/4 255.255.255.255 }
block drop out quick all
`
	if got != want {
		t.Fatalf("rules:\n%s", got)
	}
	// Without a tunnel (failed state) nothing but servers/direct may leave.
	strict := PFRules(KillSwitch{})
	if strings.Contains(strict, "utun") || strings.Contains(strict, "192.168") || !strings.HasSuffix(strict, "block drop out quick all\n") {
		t.Fatalf("strict rules:\n%s", strict)
	}
}

func TestTunCommands(t *testing.T) {
	cmds := TunCommands("utun9", 1400)
	if strings.Join(cmds[0], " ") != "ifconfig utun9 inet 10.255.0.2 10.255.0.1 netmask 255.255.255.255 mtu 1400 up" {
		t.Fatal(cmds[0])
	}
	joined := ""
	for _, c := range cmds {
		joined += strings.Join(c, " ") + "\n"
	}
	for _, want := range []string{"add -inet 0.0.0.0/1 -interface utun9", "add -inet 128.0.0.0/1 -interface utun9", "add -inet6 ::/1", "add -inet6 8000::/1"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q", want)
		}
	}
	if got := strings.Join(ServerRouteCommand(true, netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("192.168.1.1")), " "); got != "route -q -n add -inet -host 203.0.113.10 192.168.1.1" {
		t.Fatal(got)
	}
	if got := strings.Join(ServerRouteCommand(false, netip.MustParseAddr("203.0.113.10"), netip.Addr{}), " "); got != "route -q -n delete -inet -host 203.0.113.10" {
		t.Fatal(got)
	}
}

const scutilShow = `<dictionary> {
  DomainName : lan
  SearchDomains : <array> {
    0 : lan
    1 : home.arpa
  }
  ServerAddresses : <array> {
    0 : 192.168.1.1
    1 : fe80::1%en0
  }
}
`

func TestScutil(t *testing.T) {
	cfg := ParseScutilDNS(scutilShow)
	if !cfg.Present || cfg.DomainName != "lan" || len(cfg.SearchDomains) != 2 || len(cfg.ServerAddresses) != 2 || cfg.ServerAddresses[0] != "192.168.1.1" {
		t.Fatalf("%+v", cfg)
	}
	if ParseScutilDNS("  No such key\n").Present {
		t.Fatal("missing key")
	}
	set := ScutilSetDNS(ServiceDNSKey("ABC"), DNSConfig{ServerAddresses: []string{"8.8.8.8", "8.8.4.4"}, SearchDomains: cfg.SearchDomains, DomainName: "lan"})
	want := "d.init\nd.add ServerAddresses * 8.8.8.8 8.8.4.4\nd.add SearchDomains * lan home.arpa\nd.add DomainName lan\nset State:/Network/Service/ABC/DNS\nquit\n"
	if set != want {
		t.Fatalf("%q", set)
	}
	if ParsePrimaryService("<dictionary> {\n  PrimaryInterface : en0\n  PrimaryService : 1234-ABCD\n  Router : 192.168.1.1\n}\n") != "1234-ABCD" {
		t.Fatal("primary service")
	}
	if ParsePFToken("No ALTQ support in kernel\npf enabled\nToken : 13833372283563544635\n") != "13833372283563544635" {
		t.Fatal("token")
	}
}
