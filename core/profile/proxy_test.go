package profile

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestParseProxyLinks(t *testing.T) {
	ss := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:s3cret"))
	legacy := base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw@198.51.100.7:8388"))
	cases := []struct {
		link string
		kind Kind
		want ProxyConfig
		name string
	}{
		{"socks5://user:pass@198.51.100.1:1080#Home", KindSOCKS, ProxyConfig{Protocol: ProxySOCKS, Address: "198.51.100.1", Port: 1080, Username: "user", Password: "pass"}, "Home"},
		{"socks://198.51.100.1:1080", KindSOCKS, ProxyConfig{Protocol: ProxySOCKS, Address: "198.51.100.1", Port: 1080}, ""},
		{"http://u:p@proxy.example:3128/", KindHTTPProxy, ProxyConfig{Protocol: ProxyHTTP, Address: "proxy.example", Port: 3128, Username: "u", Password: "p"}, ""},
		{"https://proxy.example:443?sni=front.example", KindHTTPProxy, ProxyConfig{Protocol: ProxyHTTP, Address: "proxy.example", Port: 443, TLS: true, SNI: "front.example"}, ""},
		{"ss://" + ss + "@198.51.100.7:8388#SS%20one", KindShadowsocks, ProxyConfig{Protocol: ProxyShadowsocks, Address: "198.51.100.7", Port: 8388, Method: "aes-256-gcm", Password: "s3cret"}, "SS one"},
		{"ss://2022-blake3-aes-128-gcm:a2V5a2V5a2V5a2V5a2V5aw%3D%3D@198.51.100.7:443", KindShadowsocks, ProxyConfig{Protocol: ProxyShadowsocks, Address: "198.51.100.7", Port: 443, Method: "2022-blake3-aes-128-gcm", Password: "a2V5a2V5a2V5a2V5a2V5aw=="}, ""},
		{"ss://" + legacy + "#Old", KindShadowsocks, ProxyConfig{Protocol: ProxyShadowsocks, Address: "198.51.100.7", Port: 8388, Method: "chacha20-poly1305", Password: "pw"}, "Old"},
	}
	for _, c := range cases {
		p, err := Parse(c.link)
		if err != nil {
			t.Fatalf("%s: %v", c.link, err)
		}
		tr := p.Transports[0]
		if tr.Kind != c.kind || tr.Policy != PolicyManualOnly || *tr.Proxy != c.want {
			t.Fatalf("%s: %s %s %+v", c.link, tr.Kind, tr.Policy, *tr.Proxy)
		}
		if c.name != "" && p.Name != c.name {
			t.Fatalf("%s: name %q", c.link, p.Name)
		}
	}
}

func TestParseProxyErrors(t *testing.T) {
	for _, link := range []string{
		"http://example.com/index.html",
		"socks5://198.51.100.1",
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("rc4-md5:pw")) + "@198.51.100.7:8388",
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw")) + "@198.51.100.7:8388/?plugin=v2ray-plugin",
		"socks5://:pass@198.51.100.1:1080",
	} {
		if _, err := Parse(link); err == nil {
			t.Fatalf("%s: want error", link)
		}
	}
}

func TestMixedLinksMakeOneProfile(t *testing.T) {
	p, err := Parse("vless://b831381d-6324-4d53-ad4f-8cda48b30811@198.51.100.1:443?type=tcp&security=reality&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sni=a.example&flow=xtls-rprx-vision#Main\nsocks5://198.51.100.2:1080")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Transports) != 2 || p.Transports[1].Kind != KindSOCKS || p.Name != "Main" {
		t.Fatalf("%+v", p.Summarize())
	}
}

func TestProxySecretsAreRedacted(t *testing.T) {
	p, _ := Parse("socks5://alice:hunter22@198.51.100.1:1080")
	r := NewRedactor(p.Secrets())
	if out := r.Redact("dial 198.51.100.1 as alice with hunter22"); strings.Contains(out, "hunter22") || strings.Contains(out, "198.51.100.1") {
		t.Fatal(out)
	}
}

func TestProxyNeedsExactlyOneEngine(t *testing.T) {
	tr := Transport{Proxy: &ProxyConfig{Protocol: ProxySOCKS, Address: "a", Port: 1}, OpenVPN: &OpenVPNConfig{}}
	if err := tr.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}
