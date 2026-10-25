package awg

import (
	"context"
	"io"
	"net/netip"
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

func TestObfuscationMismatch(t *testing.T) {
	srv := testenv.StartAWG(t, testenv.Obfuscation(), [4]byte{1, 2, 3, 4})
	client := *srv.Client
	client.H1 = "999" // server expects 100000-100999
	start := time.Now()
	_, err := Start(context.Background(), &client, Options{HandshakeTimeout: 1500 * time.Millisecond})
	if err == nil {
		t.Fatal("mismatched parameters must not connect")
	}
	if c := errclass.Classify(err); c != errclass.UDPTimeout {
		t.Fatalf("class %s", c)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("timeout not respected")
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
