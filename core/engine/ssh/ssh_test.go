package ssh

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/eermolaev/test-vpn/core/errclass"
	"github.com/eermolaev/test-vpn/core/internal/testenv"
	"github.com/eermolaev/test-vpn/core/profile"
)

type mapKeys map[string]string

func (m mapKeys) Get(k string) string { return m[k] }
func (m mapKeys) Set(k, v string)     { m[k] = v }

func start(t *testing.T, c *profile.SSHConfig, keys HostKeys) (*Engine, error) {
	t.Helper()
	tr := profile.Transport{SSH: c}
	if err := tr.Validate(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return Start(ctx, c, Options{HostKeys: keys})
}

func roundTrip(t *testing.T, e *Engine, echo testenv.Echo) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := e.DialTCP(ctx, echo.TCP)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("echo:ping"))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "echo:ping" {
		t.Fatalf("got %q", buf)
	}
}

func TestPasswordAndKeyLogin(t *testing.T) {
	srv := testenv.StartSSH(t)
	echo := testenv.StartEcho(t, "echo:")
	withKey := srv.Config()
	withKey.Password, withKey.PrivateKey = "", srv.ClientKey
	for _, c := range []*profile.SSHConfig{srv.Config(), withKey} {
		e, err := start(t, c, nil)
		if err != nil {
			t.Fatal(err)
		}
		roundTrip(t, e, echo)
		if _, err := e.DialUDP(context.Background(), echo.UDP); err != ErrUDP {
			t.Fatalf("udp: %v", err)
		}
		e.Close()
		if _, err := e.DialTCP(context.Background(), echo.TCP); errclass.Classify(err) != errclass.ServerClosed {
			t.Fatalf("dial after close: %v", err)
		}
	}
	if srv.Forwards() != 2 {
		t.Fatalf("forwards %d", srv.Forwards())
	}
}

func TestWrongPassword(t *testing.T) {
	srv := testenv.StartSSH(t)
	c := srv.Config()
	c.Password = "wrong"
	_, err := start(t, c, nil)
	if errclass.Classify(err) != errclass.Auth {
		t.Fatalf("got %v", err)
	}
}

func TestHostKeyPinning(t *testing.T) {
	srv := testenv.StartSSH(t)
	c := srv.Config()
	c.HostKey = srv.Fingerprint
	e, err := start(t, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.Close()

	other := testenv.StartSSH(t) // different host key
	c.HostKey = other.Fingerprint
	if _, err := start(t, c, nil); errclass.Classify(err) != errclass.HostKey {
		t.Fatalf("pinned mismatch: %v", err)
	}
}

func TestTrustOnFirstUse(t *testing.T) {
	srv := testenv.StartSSH(t)
	keys := mapKeys{}
	e, err := start(t, srv.Config(), keys)
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	if len(keys) != 1 {
		t.Fatalf("keys %v", keys)
	}
	// A different server on the same address must be rejected.
	for k := range keys {
		keys[k] = testenv.StartSSH(t).Fingerprint
	}
	if _, err := start(t, srv.Config(), keys); errclass.Classify(err) != errclass.HostKey {
		t.Fatalf("changed key: %v", err)
	}
}

func TestKeepAliveDropsDeadServer(t *testing.T) {
	srv := testenv.StartSSH(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e, err := Start(ctx, srv.Config(), Options{KeepAlive: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.client.Conn.Close() // the network drops the connection
	select {
	case <-e.done:
	case <-time.After(2 * time.Second):
		t.Fatal("engine not closed after the connection died")
	}
}
