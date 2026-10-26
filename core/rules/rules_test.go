package rules

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestSuffixAndFull(t *testing.T) {
	s, errs := NewSet([]string{"example.com", "full:exact.org", "*.wild.net"})
	if errs != nil {
		t.Fatal(errs)
	}
	cases := map[string]bool{
		"example.com":       true,
		"www.example.com":   true,
		"a.b.example.com":   true,
		"EXAMPLE.COM.":      true,
		"notexample.com":    false,
		"example.com.evil":  false,
		"exact.org":         true,
		"www.exact.org":     false,
		"wild.net":          true,
		"x.wild.net":        true,
		"":                  false,
		"api.ipify.org":     false,
		"unrelated.example": false,
	}
	for host, want := range cases {
		if got := s.Match(host); got != want {
			t.Errorf("Match(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestIDN(t *testing.T) {
	s, errs := NewSet([]string{"пример.рф"})
	if errs != nil {
		t.Fatal(errs)
	}
	if got := s.Rules()[0].Domain; got != "xn--e1afmkfd.xn--p1ai" {
		t.Fatalf("punycode = %q", got)
	}
	if !s.Match("www.ПРИМЕР.рф") || !s.Match("www.xn--e1afmkfd.xn--p1ai") {
		t.Fatal("IDN host not matched")
	}
}

func TestInvalid(t *testing.T) {
	for in, want := range map[string]error{
		"":                  ErrEmpty,
		"[::1]":             ErrIPv6,
		"2001:db8::/32":     ErrIPv6,
		"1.2.3.4/33":        ErrInvalid,
		"bad_domain!.com":   ErrInvalid,
		"full:localhost":    ErrInvalid,
		"api.ipify.org":     ErrProtected,
		"ipify.org":         ErrProtected,
		"com":               ErrProtected, // covers icanhazip.com
		"stun.l.google.com": ErrProtected,
	} {
		if _, err := ParseRule(in); !errors.Is(err, want) {
			t.Errorf("ParseRule(%q) err = %v, want %v", in, err, want)
		}
	}
}

func TestBroadRuleKeepsProtectedInTunnel(t *testing.T) {
	s, errs := NewSet([]string{"google.com"})
	if errs != nil {
		t.Fatal(errs)
	}
	if !s.Match("mail.google.com") {
		t.Fatal("google.com rule must match mail.google.com")
	}
	if s.Match("stun.l.google.com") {
		t.Fatal("protected STUN host must not be excluded")
	}
}

func TestListErrorsAndLimits(t *testing.T) {
	_, errs := ParseList("# comment\nexample.com\n\nexample.com\n2001:db8::1\n")
	if len(errs) != 2 || errs[0].Line != 4 || !errors.Is(errs[0].Err, ErrDuplicate) || errs[1].Line != 5 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	var b strings.Builder
	for i := 0; i <= MaxRules; i++ {
		fmt.Fprintf(&b, "d%d.example\n", i)
	}
	_, errs = ParseList(b.String())
	if len(errs) != 1 || !errors.Is(errs[0].Err, ErrTooMany) {
		t.Fatalf("limit not enforced: %v", errs)
	}
}

func TestExportRoundTrip(t *testing.T) {
	in := "example.com\nfull:a.example.org\nxn--e1afmkfd.xn--p1ai\n"
	s, errs := ParseList(in)
	if errs != nil {
		t.Fatal(errs)
	}
	if s.Export() != in {
		t.Fatalf("export = %q", s.Export())
	}
}

func TestTunnelSet(t *testing.T) {
	s, errs := NewTunnelSet([]string{"mail.ru", "com"})
	if errs != nil {
		t.Fatalf("VPN-only list may cover broad zones: %v", errs)
	}
	if !s.Covers("e.mail.ru") || !s.Covers("icanhazip.com") || s.Covers("yandex.ru") {
		t.Fatal("covers")
	}
}

func TestPolicy(t *testing.T) {
	set := func(l ...string) *Set { s, _ := NewSet(l); return s }
	vpn := func(l ...string) *Set {
		s, errs := NewTunnelSet(l)
		if errs != nil {
			t.Fatal(errs)
		}
		return s
	}
	cases := []struct {
		name   string
		p      Policy
		host   string
		direct bool
	}{
		{"no lists: tunnel", Policy{}, "example.com", false},
		{"no lists: unknown host tunnel", Policy{}, "", false},
		{"star + exclusion", Policy{Exclusions: set("vk.com"), VPN: vpn("*")}, "m.vk.com", true},
		{"star: rest tunnel", Policy{Exclusions: set("vk.com"), VPN: vpn("*")}, "google.com", false},
		{"include mode: listed", Policy{VPN: vpn("youtube.com")}, "www.youtube.com", false},
		{"include mode: other direct", Policy{VPN: vpn("youtube.com")}, "yandex.ru", true},
		{"include mode: unknown direct", Policy{VPN: vpn("youtube.com")}, "", true},
		{"more specific VPN wins", Policy{Exclusions: set("ru"), VPN: vpn("mail.ru")}, "e.mail.ru", false},
		{"more specific exclusion wins", Policy{Exclusions: set("vk.com"), VPN: vpn("ru", "com")}, "vk.com", true},
		{"tie: tunnel", Policy{Exclusions: set("vk.com"), VPN: vpn("vk.com")}, "vk.com", false},
		{"full beats suffix", Policy{Exclusions: set("full:a.b.com"), VPN: vpn("a.b.com")}, "a.b.com", true},
		{"protected always tunnel", Policy{VPN: vpn("youtube.com")}, "api.ipify.org", false},
	}
	for _, c := range cases {
		if got := c.p.Direct(c.host); got != c.direct {
			t.Errorf("%s: Direct(%q) = %v, want %v", c.name, c.host, got, c.direct)
		}
	}
	if _, err := ParseRule("*"); !errors.Is(err, ErrWildcard) {
		t.Fatal("* must be rejected in exclusions")
	}
	if s := vpn("*"); s.Export() != "*\n" || !s.FullTunnel() {
		t.Fatal("wildcard round trip")
	}
}

func TestIPExclusions(t *testing.T) {
	s, errs := NewSet([]string{"31.172.77.119", "10.20.0.0/16", "192.168.1.5/24", "example.com"})
	if errs != nil {
		t.Fatal(errs)
	}
	for addr, want := range map[string]bool{
		"31.172.77.119": true, "31.172.77.120": false,
		"10.20.3.4": true, "10.21.0.1": false,
		"192.168.1.200":        true, // the prefix is masked to 192.168.1.0/24
		"::ffff:31.172.77.119": true,
	} {
		if got := s.MatchAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("MatchAddr(%s) = %v, want %v", addr, got, want)
		}
	}
	if got := s.Export(); got != "31.172.77.119\n10.20.0.0/16\n192.168.1.0/24\nexample.com\n" {
		t.Fatalf("export %q", got)
	}
	if s.Match("31.172.77.119") {
		t.Fatal("an address rule must not match host names")
	}
	if _, errs := NewSet([]string{"31.172.77.119", "31.172.77.119/32"}); len(errs) != 1 || !errors.Is(errs[0].Err, ErrDuplicate) {
		t.Fatalf("duplicate: %v", errs)
	}
	if _, err := ParseTunnelRule("31.172.77.119"); !errors.Is(err, ErrIPAddress) {
		t.Fatalf("VPN list must reject addresses: %v", err)
	}
	p := Policy{Exclusions: s}
	if !p.DirectAddr(netip.MustParseAddr("31.172.77.119"), "") || p.DirectAddr(netip.MustParseAddr("31.172.77.119"), "api.ipify.org") {
		t.Fatal("DirectAddr")
	}
}
