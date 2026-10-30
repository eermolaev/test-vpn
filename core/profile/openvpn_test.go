package profile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const ovpnCA = "<ca>\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n</ca>"

func TestParseOpenVPN(t *testing.T) {
	conf := `# provider config
client
dev tun
proto udp
remote vpn1.example 1194
remote 198.51.100.9 443 tcp
resolv-retry infinite
nobind
persist-key
cipher AES-256-GCM
redirect-gateway def1
dhcp-option DNS 10.8.0.1
up /etc/openvpn/update-resolv-conf
script-security 2
verb 3
` + ovpnCA + `
<tls-crypt>
-----BEGIN OpenVPN Static key V1-----
abcd
-----END OpenVPN Static key V1-----
</tls-crypt>
`
	p, err := Parse(conf)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Transports) != 2 {
		t.Fatalf("%d transports", len(p.Transports))
	}
	a, b := p.Transports[0], p.Transports[1]
	if a.Kind != KindOpenVPN || a.Policy != PolicyManualOnly || a.OpenVPN.Host != "vpn1.example" || a.OpenVPN.Port != 1194 || a.OpenVPN.Proto != "udp" {
		t.Fatalf("%+v", a.OpenVPN)
	}
	if b.OpenVPN.Port != 443 || b.OpenVPN.Proto != "tcp" || b.ID() != "openvpn:198.51.100.9:443:tcp" {
		t.Fatalf("%+v %s", b.OpenVPN, b.ID())
	}
	cfg := a.OpenVPN.Config
	for _, gone := range []string{"remote", "redirect-gateway", "dhcp-option", "/etc/openvpn", "script-security", "dev tun", "proto", "verb"} {
		if strings.Contains(cfg, gone) {
			t.Fatalf("%q must be dropped:\n%s", gone, cfg)
		}
	}
	for _, kept := range []string{"client", "cipher AES-256-GCM", "<ca>", "<tls-crypt>", "abcd", "persist-key"} {
		if !strings.Contains(cfg, kept) {
			t.Fatalf("%q must be kept:\n%s", kept, cfg)
		}
	}
	if p.Name != "vpn1.example" || p.Summarize().Transports[1].Detail != "tcp" {
		t.Fatalf("%+v", p.Summarize())
	}
}

func TestOpenVPNCredentials(t *testing.T) {
	conf := "client\nremote 198.51.100.9\nauth-user-pass\n" + ovpnCA + "\n"
	if _, err := Parse(conf); !errors.Is(err, ErrOpenVPNCredentials) {
		t.Fatalf("want credentials error, got %v", err)
	}
	p, err := Parse(WithOpenVPNCredentials(conf, "alice", "pw"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := p.Transports[0].OpenVPN.Config
	if !strings.Contains(cfg, "<auth-user-pass>\nalice\npw\n</auth-user-pass>") || strings.Count(cfg, "\nauth-user-pass\n") != 1 {
		t.Fatalf("credentials:\n%s", cfg)
	}
}

func TestOpenVPNFileReferences(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "ta.key"), []byte("static\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "pass.txt"), []byte("bob\nsecret\n"), 0o600)
	conf := "client\nremote 198.51.100.9 1194\nca ca.crt\ntls-auth ta.key 1\nauth-user-pass pass.txt\n"
	if _, err := Parse(conf); err == nil || !strings.Contains(err.Error(), "refers to file") {
		t.Fatalf("file reference must be refused: %v", err)
	}
	inl, err := InlineOpenVPNFiles(conf, dir)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(inl)
	if err != nil {
		t.Fatal(err)
	}
	cfg := p.Transports[0].OpenVPN.Config
	for _, want := range []string{"<ca>\n-----BEGIN CERTIFICATE-----", "key-direction 1", "<tls-auth>\nstatic\n</tls-auth>", "<auth-user-pass>\nbob\nsecret\n</auth-user-pass>"} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("%q missing:\n%s", want, cfg)
		}
	}
	if s, _ := InlineOpenVPNFiles("[Interface]\nPrivateKey = x\n", dir); s != "[Interface]\nPrivateKey = x\n" {
		t.Fatal("non-OpenVPN text must pass through")
	}
}

func TestOpenVPNRejects(t *testing.T) {
	for _, conf := range []string{
		"client\nremote 198.51.100.9\n",                                      // no CA
		"client\nremote 198.51.100.9 1194 sctp\n" + ovpnCA,                   // bad proto
		"client\nremote 198.51.100.9\n<ca>\nx\n",                             // unclosed
		"client\n<connection>\nremote a\n</connection>\nremote b\n" + ovpnCA, // connection blocks
	} {
		if _, err := Parse(conf); err == nil {
			t.Fatalf("want error for:\n%s", conf)
		}
	}
}
