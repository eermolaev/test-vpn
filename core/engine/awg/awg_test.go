package awg

import (
	"context"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/eermolaev/test-vpn/core/errclass"
	"github.com/eermolaev/test-vpn/core/internal/testenv"
	"github.com/eermolaev/test-vpn/core/profile"
)

func TestEndToEnd(t *testing.T) {
	srv := testenv.StartAWG(t, testenv.Obfuscation(), [4]byte{1, 2, 3, 4})
	tr := profile.Transport{AWG: srv.Client}
	if err := tr.Validate(); err != nil {
		t.Fatal(err)
	}
	if tr.Kind != profile.KindAmneziaWG {
		t.Fatalf("kind %s", tr.Kind)
	}
	ctx := context.Background()
	e, err := Start(ctx, srv.Client, Options{HandshakeTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.LastHandshake().IsZero() {
		t.Fatal("no handshake recorded")
	}

	c, err := e.DialTCP(ctx, netip.AddrPortFrom(testenv.AWGServerIP, 7))
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("hello"))
	buf := make([]byte, 64)
	n, err := io.ReadAtLeast(c, buf, len("awg:hello"))
	if err != nil || string(buf[:n]) != "awg:hello" {
		t.Fatalf("tcp echo: %q %v", buf[:n], err)
	}
	c.Close()

	u, err := e.DialUDP(ctx, netip.AddrPortFrom(testenv.AWGServerIP, 7))
	if err != nil {
		t.Fatal(err)
	}
	u.SetDeadline(time.Now().Add(5 * time.Second))
	u.Write([]byte("dgram"))
	n, err = u.Read(buf)
	if err != nil || string(buf[:n]) != "awg:dgram" {
		t.Fatalf("udp echo: %q %v", buf[:n], err)
	}
	u.Close()
}

// TestAWG3 connects with the AmneziaWG 3 options exported by Amnezia
// Premium configs, going through the .conf format like a real import.
func TestAWG3(t *testing.T) {
	srv := testenv.StartAWG(t, testenv.ObfuscationV3(), [4]byte{1, 2, 3, 4})
	srv.Client.Peer.KeepaliveRange = "20-30"
	srv.Client.KeepaliveTimeout = "8-12"
	tr, err := profile.ParseAWGConf(profile.FormatAWGConf(srv.Client))
	if err != nil {
		t.Fatal(err)
	}
	if tr.AWG.HeaderProtectionKey == "" || !tr.AWG.RandomTrailers || tr.AWG.Peer.KeepaliveRange != "20-30" {
		t.Fatalf("round trip lost AWG 3 fields: %+v", tr.AWG)
	}
	ctx := context.Background()
	e, err := Start(ctx, tr.AWG, Options{HandshakeTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	c, err := e.DialTCP(ctx, netip.AddrPortFrom(testenv.AWGServerIP, 7))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("v3"))
	buf := make([]byte, 64)
	if n, err := io.ReadAtLeast(c, buf, len("awg:v3")); err != nil || string(buf[:n]) != "awg:v3" {
		t.Fatalf("tcp echo: %q %v", buf[:n], err)
	}

	// A wrong header protection key must not connect.
	bad := *tr.AWG
	bad.HeaderProtectionKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	if e2, err := Start(ctx, &bad, Options{HandshakeTimeout: 2 * time.Second}); err == nil {
		e2.Close()
		t.Fatal("wrong header protection key must fail")
	}
}

func TestObfuscationMismatch(t *testing.T) {
	srv := testenv.StartAWG(t, testenv.Obfuscation(), [4]byte{1, 2, 3, 4})
	client := *srv.Client
	client.H1 = "999" // server expects 100000-100999
	start := time.Now()
	_, err := Start(context.Background(), &client, Options{HandshakeTimeout: 1500 * time.Millisecond})
	if err == nil {
		t.Fatal("mismatched parameters must not connect")
	}
	// The server drops packets it cannot parse, so for us it is silent.
	if c := errclass.Classify(err); c != errclass.UDPTimeout || !strings.Contains(err.Error(), "received 0") {
		t.Fatalf("class %s: %v", c, err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("timeout not respected")
	}
}

// TestResponseMismatch: the server answers, but the client expects another
// response header, so it cannot use the reply.
func TestResponseMismatch(t *testing.T) {
	srv := testenv.StartAWG(t, testenv.Obfuscation(), [4]byte{1, 2, 3, 4})
	client := *srv.Client
	client.H2 = "999" // server sends 200000-200999
	_, err := Start(context.Background(), &client, Options{HandshakeTimeout: 1500 * time.Millisecond})
	if err == nil {
		t.Fatal("mismatched parameters must not connect")
	}
	if c := errclass.Classify(err); c != errclass.AWGMismatch || strings.Contains(err.Error(), "received 0") {
		t.Fatalf("class %s: %v", c, err)
	}
}

func TestUAPI(t *testing.T) {
	c := testenv.Obfuscation()
	c.PrivateKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	c.Peer = profile.AWGPeer{PublicKey: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}}
	u, err := UAPI(&c, netip.MustParseAddrPort("1.2.3.4:51820"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"private_key=0101", "h1=100000-100999", "s3=12", "i1=<b 0xc6000000><r 16>", "endpoint=1.2.3.4:51820", "allowed_ip=0.0.0.0/0", "persistent_keepalive_interval=25"} {
		if !contains(u, want) {
			t.Errorf("UAPI missing %q:\n%s", want, u)
		}
	}
	if contains(u, "::/0") {
		t.Error("IPv6 allowed IPs must be dropped")
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0) }

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
