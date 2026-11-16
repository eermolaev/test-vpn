package profile

import (
	"encoding/base64"
	"errors"
	"testing"
)

const testPBK = "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc"

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

func TestParseTrojanLink(t *testing.T) {
	p, err := Parse("trojan://p%40ss@example.com:8443?type=ws&path=%2Fws&host=cdn.example.com&sni=example.com#Troj")
	if err != nil {
		t.Fatal(err)
	}
	tr := p.Transports[0]
	c := tr.VLESS
	if tr.Kind != KindTrojan || tr.Policy != PolicyManualOnly || p.Name != "Troj" {
		t.Fatalf("kind %s policy %s name %q", tr.Kind, tr.Policy, p.Name)
	}
	if c.Password != "p@ss" || c.Security != "tls" || c.Network != "ws" || c.Path != "/ws" || c.Host != "cdn.example.com" || c.SNI != "example.com" || c.Port != 8443 {
		t.Fatalf("%+v", c)
	}
	// Trojan over REALITY may be an automatic fallback.
	p, err = Parse("trojan://pw@1.2.3.4:443?security=reality&sni=www.example.com&pbk=" + testPBK + "&sid=ab12&fp=chrome")
	if err != nil {
		t.Fatal(err)
	}
	if p.Transports[0].Policy != PolicyFallback {
		t.Fatalf("policy %s", p.Transports[0].Policy)
	}
	// The old peer= parameter is the SNI.
	p, err = Parse("trojan://pw@1.2.3.4:443?peer=example.org")
	if err != nil || p.Transports[0].VLESS.SNI != "example.org" {
		t.Fatalf("peer: %v %+v", err, p)
	}
}

func vmessLinkOf(js string) string {
	return "vmess://" + base64.StdEncoding.EncodeToString([]byte(js))
}

func TestParseVMessLink(t *testing.T) {
	p, err := Parse(vmessLinkOf(`{"v":"2","ps":"VM","add":"example.com","port":"443","id":"` + testUUID + `","aid":"0","scy":"auto","net":"ws","type":"none","host":"cdn.example.com","path":"/vm","tls":"tls","sni":"","fp":"chrome"}`))
	if err != nil {
		t.Fatal(err)
	}
	tr := p.Transports[0]
	c := tr.VLESS
	if tr.Kind != KindVMess || tr.Policy != PolicyManualOnly || p.Name != "VM" {
		t.Fatalf("kind %s policy %s name %q", tr.Kind, tr.Policy, p.Name)
	}
	if c.UUID != testUUID || c.Network != "ws" || c.Path != "/vm" || c.Security != "tls" || c.SNI != "cdn.example.com" || c.Port != 443 || c.Cipher != "auto" {
		t.Fatalf("%+v", c)
	}
	// gRPC keeps the service name in path; numbers may be numbers.
	p, err = Parse(vmessLinkOf(`{"ps":"g","add":"1.2.3.4","port":8443,"id":"` + testUUID + `","aid":0,"net":"grpc","path":"svc","tls":""}`))
	if err != nil {
		t.Fatal(err)
	}
	if c := p.Transports[0].VLESS; c.ServiceName != "svc" || c.Security != "none" || c.Cipher != "auto" {
		t.Fatalf("%+v", c)
	}
	// vmess and trojan links mix with vless in one profile.
	p, err = Parse(vmessLinkOf(`{"add":"1.2.3.4","port":80,"id":"`+testUUID+`","net":"tcp"}`) + "\ntrojan://pw@5.6.7.8:443")
	if err != nil || len(p.Transports) != 2 {
		t.Fatalf("mixed: %v %+v", err, p)
	}
}

func TestParseVMessTrojanErrors(t *testing.T) {
	for _, s := range []string{
		vmessLinkOf(`{"add":"h.com","port":443,"id":"not-a-uuid"}`),
		vmessLinkOf(`{"add":"h.com","port":443,"id":"` + testUUID + `","scy":"none"}`), // clear text
		"vmess://%%%",
		"trojan://@h.com:443",                 // no password
		"trojan://pw@h.com:443?security=none", // clear text
	} {
		if _, err := Parse(s); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range []string{
		vmessLinkOf(`{"add":"h.com","port":443,"id":"` + testUUID + `","aid":"64"}`),
		vmessLinkOf(`{"add":"h.com","port":443,"id":"` + testUUID + `","net":"tcp","type":"http"}`),
		vmessLinkOf(`{"add":"h.com","port":443,"id":"` + testUUID + `","net":"kcp"}`),
		"trojan://pw@h.com:443?flow=xtls-rprx-direct",
	} {
		if _, err := Parse(s); !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s: %v", s, err)
		}
	}
}

func TestParseXrayJSONVMessTrojan(t *testing.T) {
	js := `{"remarks":"mix","outbounds":[
	 {"protocol":"vmess","tag":"vm","settings":{"vnext":[{"address":"1.2.3.4","port":443,"users":[{"id":"` + testUUID + `","security":"aes-128-gcm","alterId":0}]}]},
	  "streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"example.com"},"wsSettings":{"path":"/vm"}}},
	 {"protocol":"trojan","tag":"tj","settings":{"servers":[{"address":"5.6.7.8","port":443,"password":"trojan-secret"}]},
	  "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.org"}}},
	 {"protocol":"freedom"}]}`
	p, err := Parse(js)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Transports) != 2 {
		t.Fatalf("%d transports", len(p.Transports))
	}
	vm, tj := p.Transports[0], p.Transports[1]
	if vm.Kind != KindVMess || vm.VLESS.Cipher != "aes-128-gcm" || vm.VLESS.Path != "/vm" || vm.VLESS.SNI != "example.com" {
		t.Fatalf("vmess %+v", vm.VLESS)
	}
	if tj.Kind != KindTrojan || tj.VLESS.Password != "trojan-secret" || tj.VLESS.SNI != "example.org" {
		t.Fatalf("trojan %+v", tj.VLESS)
	}
	if s := p.Secrets(); !contains(s, "trojan-secret") {
		t.Fatalf("trojan password is not redacted: %v", s)
	}
}
