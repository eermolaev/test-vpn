package xray

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/eermolaev/test-vpn/core/internal/testenv"
	"github.com/eermolaev/test-vpn/core/profile"
)

func roundTrip(t *testing.T, e *Engine, echo testenv.Echo) {
	t.Helper()
	ctx := context.Background()
	c, err := e.DialTCP(ctx, echo.TCP)
	if err != nil {
		t.Fatal(err)
	}
	// The first connection per process takes ~5s: REALITY probes the
	// target site once to learn its post-handshake record sizes.
	c.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := io.ReadAtLeast(c, buf, len("echo:ping"))
	if err != nil || string(buf[:n]) != "echo:ping" {
		t.Fatalf("tcp: %q %v", buf[:n], err)
	}
	c.Close()

	u, err := e.DialUDP(ctx, echo.UDP)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.SetDeadline(time.Now().Add(10 * time.Second))
	for i := 0; i < 3; i++ {
		u.Write([]byte("dgram"))
		n, err = u.Read(buf)
		if err != nil || string(buf[:n]) != "echo:dgram" {
			t.Fatalf("udp %d: %q %v", i, buf[:n], err)
		}
	}
}

func TestRealityVision(t *testing.T) {
	srv := testenv.StartReality(t)
	echo := testenv.StartEcho(t, "echo:")
	tr := profile.Transport{VLESS: srv.Vision}
	if err := tr.Validate(); err != nil || tr.Policy != profile.PolicyPrimary {
		t.Fatalf("%v %s", err, tr.Policy)
	}
	e, err := Start(srv.Vision, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.NativeUDP() {
		t.Fatal("VLESS does not carry UDP natively")
	}
	roundTrip(t, e, echo)
}

func TestRealityXHTTP(t *testing.T) {
	srv := testenv.StartReality(t)
	echo := testenv.StartEcho(t, "echo:")
	e, err := Start(srv.XHTTP, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	roundTrip(t, e, echo)
}

func TestWrongKeyFails(t *testing.T) {
	srv := testenv.StartReality(t)
	echo := testenv.StartEcho(t, "echo:")
	bad := *srv.Vision
	_, pub := testenv.X25519()
	bad.PublicKey = b64url(pub)
	e, err := Start(&bad, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	c, err := e.DialTCP(context.Background(), echo.TCP)
	if err != nil {
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("ping"))
	buf := make([]byte, 64)
	if n, err := c.Read(buf); err == nil && string(buf[:n]) == "echo:ping" {
		t.Fatal("wrong REALITY key must not reach the server's outbound")
	}
}

func TestForbidsPlain(t *testing.T) {
	if _, err := BuildConfig(&profile.VLESSConfig{Security: "none"}); err == nil {
		t.Fatal("plain VLESS must be refused")
	}
}
