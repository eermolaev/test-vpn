package rules

import (
	"errors"
	"fmt"
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
		"1.2.3.4":           ErrIPAddress,
		"10.0.0.0/8":        ErrIPAddress,
		"[::1]":             ErrIPAddress,
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
	_, errs := ParseList("# comment\nexample.com\n\nexample.com\n1.1.1.1\n")
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
