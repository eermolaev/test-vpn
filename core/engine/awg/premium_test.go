package awg

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/eermolaev/test-vpn/core/internal/testenv"
	"github.com/eermolaev/test-vpn/core/profile"
)

// TestPremiumShape uses the parameter shape of an Amnezia Premium native
// config: large S1-S3, single-value headers, header protection, timings and
// randomized keepalive.
func TestPremiumShape(t *testing.T) {
	obf := testenv.ObfuscationV3()
	obf.Jc, obf.Jmin, obf.Jmax = 7, 10, 80
	obf.S1, obf.S2, obf.S3, obf.S4 = 782, 727, 422, 12
	obf.H1, obf.H2, obf.H3, obf.H4 = "1", "2", "3", "4"
	obf.I1 = ""
	obf.RandomTrailers = false
	obf.ContentPaddingAddition = "10-100"
	srv := testenv.StartAWG(t, obf, [4]byte{1, 2, 3, 4})
	c := srv.Client
	c.RekeyAfterTime, c.RekeyTimeout, c.RejectAfterTime = "100-120", "3-8", "150-180"
	c.KeepaliveTimeout, c.MaxHandshakeAttempts = "7-13", "15-20"
	c.Peer.KeepaliveRange = "25-35"
	tr, err := profile.ParseAWGConf(profile.FormatAWGConf(c))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	e, err := Start(ctx, tr.AWG, Options{HandshakeTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	conn, err := e.DialTCP(ctx, netip.AddrPortFrom(testenv.AWGServerIP, 7))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte("premium"))
	buf := make([]byte, 64)
	if n, err := io.ReadAtLeast(conn, buf, len("awg:premium")); err != nil || string(buf[:n]) != "awg:premium" {
		t.Fatalf("tcp echo: %q %v", buf[:n], err)
	}
}
