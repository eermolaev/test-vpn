package profile

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

var (
	key1 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	key2 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	key3 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
)

const uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"

func awgConf() string {
	return `# exported
[Interface]
PrivateKey = ` + key1 + `
Address = 10.8.0.2/32
DNS = 1.1.1.1, search.local
MTU = 1380
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 68
S3 = 20
S4 = 8
H1 = 100000-100100
H2 = 200000-200100
H3 = 300000
H4 = 400000
I1 = <b 0xc6000000><r 16>
PostUp = iptables -A FORWARD

[Peer]
PublicKey = ` + key2 + `
PresharedKey = ` + key3 + `
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`
}

func TestAWGConf(t *testing.T) {
	p, err := Parse(awgConf())
	if err != nil {
		t.Fatal(err)
	}
	tr := p.Transports[0]
	if tr.Kind != KindAmneziaWG || tr.Policy != PolicyPrimary {
		t.Fatalf("kind/policy = %s/%s", tr.Kind, tr.Policy)
	}
	c := tr.AWG
	if c.Jc != 4 || c.S3 != 20 || c.S4 != 8 || c.H1 != "100000-100100" || c.I1 != "<b 0xc6000000><r 16>" {
		t.Fatalf("obfuscation params lost: %+v", c)
	}
	if len(c.DNS) != 1 || c.MTU != 1380 || len(c.Peer.AllowedIPs) != 2 || c.Peer.Keepalive != 25 {
		t.Fatalf("bad interface/peer: %+v", c)
	}
	if p.Name != "vpn.example.com" {
		t.Fatalf("name = %q", p.Name)
	}
	// Round trip through FormatAWGConf.
	back, err := ParseAWGConf(FormatAWGConf(c))
	if err != nil {
		t.Fatal(err)
	}
	if FormatAWGConf(back.AWG) != FormatAWGConf(c) {
		t.Fatal("format round trip differs")
	}
}

func TestAWGConfErrors(t *testing.T) {
	cases := map[string]string{
		"unknown key": strings.Replace(awgConf(), "MTU = 1380", "Foo = 1", 1),
		"bad H range": strings.Replace(awgConf(), "H3 = 300000", "H3 = 9-1", 1),
		"jmin > jmax": strings.Replace(awgConf(), "Jmin = 40", "Jmin = 80", 1),
		"bad key":     strings.Replace(awgConf(), key1, "abc", 1),
		"no endpoint": strings.Replace(awgConf(), "Endpoint = vpn.example.com:51820\n", "", 1),
		"two peers":   awgConf() + "[Peer]\nPublicKey = " + key2 + "\n",
		"bad section": awgConf() + "[Other]\n",
		"bad mtu":     strings.Replace(awgConf(), "MTU = 1380", "MTU = 9000", 1),
	}
	for name, in := range cases {
		if _, err := Parse(in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestPlainWireGuardIsManualOnly(t *testing.T) {
	conf := "[Interface]\nPrivateKey = " + key1 + "\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = " + key2 + "\nEndpoint = 1.2.3.4:51820\n"
	p, err := Parse(conf)
	if err != nil {
		t.Fatal(err)
	}
	if tr := p.Transports[0]; tr.Kind != KindWireGuard || tr.Policy != PolicyManualOnly || tr.Policy.Automatic() {
		t.Fatalf("plain WireGuard must be manual-only, got %s/%s", tr.Kind, tr.Policy)
	}
}

const realityURL = "vless://" + uuid + "@203.0.113.10:443?encryption=none&type=tcp&security=reality&flow=xtls-rprx-vision&sni=www.microsoft.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179e30d4fc2#My%20Server"

func TestVLESSLinks(t *testing.T) {
	xhttp := "vless://" + uuid + "@203.0.113.10:8443?type=xhttp&security=reality&sni=www.microsoft.com&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=ab&path=%2Fx&mode=auto"
	p, err := Parse(realityURL + "\n\n" + xhttp + "\n" + realityURL)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "My Server" || len(p.Transports) != 2 {
		t.Fatalf("name=%q transports=%d", p.Name, len(p.Transports))
	}
	a, b := p.Transports[0], p.Transports[1]
	if a.Kind != KindVLESSReality || a.Policy != PolicyPrimary || a.VLESS.Network != "raw" || a.VLESS.ShortID != "6ba85179e30d4fc2" {
		t.Fatalf("vision transport: %+v %+v", a, a.VLESS)
	}
	if b.Policy != PolicyFallback || b.VLESS.Network != "xhttp" || b.VLESS.Path != "/x" || b.VLESS.Fingerprint != DefaultFingerprint {
		t.Fatalf("xhttp transport: %+v %+v", b, b.VLESS)
	}
	// Round trip.
	t2, _, err := ParseVLESSURL(FormatVLESSURL(a.VLESS, "n"))
	if err != nil || !reflect.DeepEqual(t2.VLESS, a.VLESS) {
		t.Fatalf("round trip: %v\n%+v\n%+v", err, t2.VLESS, a.VLESS)
	}
}

func TestVLESSPolicies(t *testing.T) {
	plain := "vless://" + uuid + "@h.example:80?type=tcp&security=none"
	p, err := Parse(plain)
	if err != nil {
		t.Fatal(err)
	}
	if p.Transports[0].Policy != PolicyForbidden {
		t.Fatalf("plain vless must be forbidden, got %s", p.Transports[0].Policy)
	}
	tls := "vless://" + uuid + "@h.example:443?type=ws&security=tls&sni=h.example&path=/ws"
	p, err = Parse(tls)
	if err != nil {
		t.Fatal(err)
	}
	if p.Transports[0].Policy != PolicyManualOnly {
		t.Fatalf("vless+tls must be manual-only, got %s", p.Transports[0].Policy)
	}
	for name, bad := range map[string]string{
		"no pbk":       strings.Replace(realityURL, "pbk=", "x=", 1),
		"bad sid":      strings.Replace(realityURL, "sid=6ba85179e30d4fc2", "sid=xyz", 1),
		"bad uuid":     strings.Replace(realityURL, uuid, "nope", 1),
		"vision+xhttp": strings.Replace(realityURL, "type=tcp", "type=xhttp", 1),
		"encryption":   strings.Replace(realityURL, "encryption=none", "encryption=mlkem", 1),
		"unknown flow": strings.Replace(realityURL, "xtls-rprx-vision", "xtls-rprx-direct", 1),
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func xrayJSON() string {
	return `{
  "remarks": "JSON server",
  "outbounds": [
    {"protocol": "vless", "tag": "proxy",
     "settings": {"vnext": [{"address": "203.0.113.10", "port": 443,
        "users": [{"id": "` + uuid + `", "flow": "xtls-rprx-vision", "encryption": "none"}]}]},
     "streamSettings": {"network": "tcp", "security": "reality",
        "realitySettings": {"serverName": "www.microsoft.com", "fingerprint": "safari",
           "publicKey": "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc", "shortId": "6ba85179e30d4fc2", "spiderX": "/"}}},
    {"protocol": "vless", "tag": "xhttp",
     "settings": {"address": "203.0.113.10", "port": "8443", "id": "` + uuid + `"},
     "streamSettings": {"network": "xhttp", "security": "reality",
        "realitySettings": {"serverName": "www.microsoft.com", "password": "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc"},
        "xhttpSettings": {"path": "/p", "mode": "packet-up"}}},
    {"protocol": "freedom", "tag": "direct"},
    {"protocol": "blackhole", "tag": "block"}
  ]
}`
}

func TestXrayJSON(t *testing.T) {
	p, err := Parse(xrayJSON())
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "JSON server" || len(p.Transports) != 2 {
		t.Fatalf("name=%q n=%d", p.Name, len(p.Transports))
	}
	if v := p.Transports[0].VLESS; v.Fingerprint != "safari" || v.Flow != "xtls-rprx-vision" || v.SpiderX != "/" {
		t.Fatalf("first: %+v", v)
	}
	if v := p.Transports[1].VLESS; v.Port != 8443 || v.Mode != "packet-up" || v.PublicKey == "" {
		t.Fatalf("second: %+v", v)
	}
	if _, err := Parse(`{"outbounds":[{"protocol":"shadowsocks","settings":{}}]}`); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("expected unsupported, got %v", err)
	}
}

// makeAmneziaKey builds a key the same way Amnezia VPN does:
// vpn:// + base64url(qCompress(json)).
func makeAmneziaKey(t *testing.T, v any) string {
	t.Helper()
	js, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(js)))
	zw := zlib.NewWriter(&buf)
	zw.Write(js)
	zw.Close()
	return "vpn://" + base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

func TestAmneziaKey(t *testing.T) {
	conf := strings.Replace(awgConf(), "DNS = 1.1.1.1, search.local", "DNS = $PRIMARY_DNS, $SECONDARY_DNS", 1)
	lastAWG, _ := json.Marshal(map[string]any{"config": conf, "hostName": "vpn.example.com", "port": 51820})
	key := makeAmneziaKey(t, map[string]any{
		"containers": []any{
			map[string]any{"container": "amnezia-xray", "xray": map[string]any{"last_config": xrayJSON()}},
			map[string]any{"container": "amnezia-awg", "awg": map[string]any{"last_config": string(lastAWG), "port": "51820"}},
			map[string]any{"container": "amnezia-dns"},
		},
		"defaultContainer": "amnezia-awg",
		"description":      "Amnezia server",
		"dns1":             "8.8.8.8",
		"dns2":             "8.8.4.4",
		"hostName":         "vpn.example.com",
	})
	p, err := Parse(key)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "Amnezia server" || len(p.Transports) != 3 {
		t.Fatalf("name=%q n=%d", p.Name, len(p.Transports))
	}
	if p.Transports[0].Kind != KindAmneziaWG {
		t.Fatalf("default container must come first, got %s", p.Transports[0].Kind)
	}
	if d := p.Transports[0].AWG.DNS; len(d) != 2 || d[0].String() != "8.8.8.8" {
		t.Fatalf("DNS placeholders not substituted: %v", d)
	}
	if len(p.ServerDNS) != 2 {
		t.Fatalf("server dns: %v", p.ServerDNS)
	}
	if _, err := Parse("vpn://AAAA"); err == nil {
		t.Fatal("garbage key must fail")
	}
}

func TestUnknownFormat(t *testing.T) {
	if _, err := Parse("hello"); !errors.Is(err, ErrUnknownFormat) {
		t.Fatal(err)
	}
}

func TestRedaction(t *testing.T) {
	p, err := Parse(realityURL)
	if err != nil {
		t.Fatal(err)
	}
	r := NewRedactor(p.Secrets())
	logLine := "dial " + uuid + " via 203.0.113.10 sid=6ba85179e30d4fc2"
	out := r.Redact(logLine)
	for _, s := range []string{uuid, "203.0.113.10", "6ba85179e30d4fc2"} {
		if strings.Contains(out, s) {
			t.Fatalf("secret %q leaked: %s", s, out)
		}
	}
	if strings.Contains(p.Summarize().JSON(), uuid) {
		t.Fatal("summary must not contain uuid")
	}
}

func TestAmneziaSubscriptionKey(t *testing.T) {
	key := makeAmneziaKey(t, map[string]any{
		"name": "Amnezia Premium", "config_version": 2,
		"api_config": map[string]any{"service_type": "amnezia-premium"},
		"auth_data":  map[string]any{"api_key": "secret"},
	})
	_, err := ParseAmneziaKey(key)
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "Configuration files") {
		t.Fatalf("subscription key: %v", err)
	}
}
