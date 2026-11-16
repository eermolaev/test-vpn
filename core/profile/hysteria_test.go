package profile

import (
	"errors"
	"strings"
	"testing"
)

func TestParseHysteriaLinks(t *testing.T) {
	pin := strings.Repeat("AB:", 31) + "AB"
	for _, c := range []struct {
		link string
		want HysteriaConfig
		pol  Policy
	}{
		{"hysteria2://secret@hy.example.com:8443/?sni=cdn.example.com&obfs=salamander&obfs-password=ob%2Bfs#My%20HY",
			HysteriaConfig{Address: "hy.example.com", Port: 8443, Auth: "secret", SNI: "cdn.example.com", ObfsPassword: "ob+fs"}, PolicyFallback},
		{"hy2://user:pass@1.2.3.4?insecure=1",
			HysteriaConfig{Address: "1.2.3.4", Port: 443, Auth: "user:pass", Insecure: true}, PolicyManualOnly},
		{"hy2://pw@1.2.3.4:443?insecure=1&pinSHA256=" + pin,
			HysteriaConfig{Address: "1.2.3.4", Port: 443, Auth: "pw", Insecure: true, PinSHA256: strings.Repeat("ab", 32)}, PolicyFallback},
		{"hysteria2://pw@hy.example.com:443,20000-30000/?sni=x.com",
			HysteriaConfig{Address: "hy.example.com", Port: 443, Ports: "443,20000-30000", Auth: "pw", SNI: "x.com"}, PolicyFallback},
		{"hysteria2://pw@hy.example.com:20000-30000",
			HysteriaConfig{Address: "hy.example.com", Port: 20000, Ports: "20000-30000", Auth: "pw", SNI: "hy.example.com"}, PolicyFallback},
		{"hy2://pw@hy.example.com:443?mport=5000-6000",
			HysteriaConfig{Address: "hy.example.com", Port: 443, Ports: "5000-6000", Auth: "pw", SNI: "hy.example.com"}, PolicyFallback},
	} {
		p, err := Parse(c.link)
		if err != nil {
			t.Fatalf("%s: %v", c.link, err)
		}
		tr := p.Transports[0]
		if *tr.Hysteria != c.want || tr.Kind != KindHysteria2 || tr.Policy != c.pol {
			t.Errorf("%s:\n got %+v %s %s\nwant %+v %s", c.link, *tr.Hysteria, tr.Kind, tr.Policy, c.want, c.pol)
		}
		if !tr.UDPBased() {
			t.Error("hysteria is UDP based")
		}
	}
	p, _ := Parse("hysteria2://secret@hy.example.com/?obfs=salamander&obfs-password=obfspw#My%20HY")
	if p.Name != "My HY" {
		t.Fatalf("name %q", p.Name)
	}
	secrets := p.Secrets()
	for _, s := range []string{"secret", "obfspw", "hy.example.com"} {
		if !contains(secrets, s) {
			t.Errorf("secret %q is not redacted", s)
		}
	}
	if d := p.Summarize().Transports[0].Detail; d != "salamander" {
		t.Errorf("detail %q", d)
	}
}

func TestParseHysteriaErrors(t *testing.T) {
	for _, s := range []string{
		"hysteria2://hy.example.com",           // no password
		"hysteria2://pw@1.2.3.4",               // IP without sni, pin or insecure
		"hysteria2://pw@h.com?obfs=salamander", // no obfs password
		"hysteria2://pw@h.com?pinSHA256=abcd",  // short pin
		"hysteria2://pw@h.com:70000",           // bad port
		"hysteria2://pw@h.com:30000-20000",     // reversed range
	} {
		if _, err := Parse(s); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", s, err)
		}
	}
	if _, err := Parse("hysteria2://pw@h.com?obfs=gost"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("unknown obfs: %v", err)
	}
}
