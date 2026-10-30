package xray

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/eermolaev/test-vpn/core/errclass"
	"github.com/eermolaev/test-vpn/core/internal/testenv"
	"github.com/eermolaev/test-vpn/core/profile"
)

func diagnose(t *testing.T, c *profile.VLESSConfig, dns netip.AddrPort, timeout time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return Diagnose(ctx, c, dns)
}

func wantClass(t *testing.T, err error, want errclass.Class, text string) {
	t.Helper()
	if errclass.Classify(err) != want || !strings.Contains(err.Error(), text) {
		t.Fatalf("want %s containing %q, got %v", want, text, err)
	}
}

func TestDiagnoseWorkingServer(t *testing.T) {
	srv := testenv.StartReality(t)
	dns := testenv.StartDNS(t, [4]byte{1, 2, 3, 4})
	if err := diagnose(t, srv.Vision, dns, 20*time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestDiagnoseWrongRealityKey(t *testing.T) {
	srv := testenv.StartReality(t)
	bad := *srv.Vision
	_, pub := testenv.X25519()
	bad.PublicKey = b64url(pub)
	wantClass(t, diagnose(t, &bad, testenv.StartDNS(t, [4]byte{1, 2, 3, 4}), 20*time.Second), errclass.TLS, "ordinary certificate")
}

func TestDiagnoseWrongUUID(t *testing.T) {
	srv := testenv.StartReality(t)
	bad := *srv.Vision
	bad.UUID = "00000000-1111-2222-3333-444444444444"
	wantClass(t, diagnose(t, &bad, testenv.StartDNS(t, [4]byte{1, 2, 3, 4}), 20*time.Second), errclass.ServerClosed, "user ID 00000000…")
}

func TestDiagnoseSilentResolver(t *testing.T) {
	srv := testenv.StartReality(t)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dns := netip.MustParseAddrPort(pc.LocalAddr().String())
	wantClass(t, diagnose(t, srv.Vision, dns, 8*time.Second), errclass.ServerSilent, "got no answer")
}

func TestDiagnoseXHTTPStopsAfterHandshake(t *testing.T) {
	srv := testenv.StartReality(t)
	wantClass(t, diagnose(t, srv.XHTTP, testenv.StartDNS(t, [4]byte{1, 2, 3, 4}), 20*time.Second), errclass.Routing, "xhttp transport over it was not checked")
}

// listen returns a VLESS config pointing at a local listener that handles
// each connection with serve.
func listen(t *testing.T, serve func(net.Conn)) *profile.VLESSConfig {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go serve(c)
		}
	}()
	srv := testenv.StartReality(t)
	c := *srv.Vision
	c.Port = l.Addr().(*net.TCPAddr).Port
	return &c
}

func TestDiagnoseSilentHandshake(t *testing.T) {
	c := listen(t, func(c net.Conn) { time.Sleep(5 * time.Second); c.Close() })
	wantClass(t, diagnose(t, c, netip.MustParseAddrPort("127.0.0.1:53"), time.Second), errclass.TLSTimeout, "REALITY handshake got no answer")
}

func TestDiagnoseHandshakeCutOff(t *testing.T) {
	c := listen(t, func(c net.Conn) {
		c.Read(make([]byte, 1))
		c.(*net.TCPConn).SetLinger(0)
		c.Close()
	})
	wantClass(t, diagnose(t, c, netip.MustParseAddrPort("127.0.0.1:53"), 5*time.Second), errclass.TCPReset, "was cut off")
}

func TestDiagnoseUnreachable(t *testing.T) {
	c := listen(t, func(net.Conn) {})
	l, _ := net.Listen("tcp4", "127.0.0.1:0")
	c.Port = l.Addr().(*net.TCPAddr).Port
	l.Close()
	wantClass(t, diagnose(t, c, netip.MustParseAddrPort("127.0.0.1:53"), 5*time.Second), errclass.TCPReset, "not reachable over TCP")
}
