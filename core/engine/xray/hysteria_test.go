package xray

import (
	"strings"
	"testing"
	"time"

	"github.com/eermolaev/test-vpn/core/internal/testenv"
	"github.com/eermolaev/test-vpn/core/profile"
)

func startHy(t *testing.T, c *profile.HysteriaConfig) *Engine {
	t.Helper()
	tr := profile.Transport{Hysteria: c}
	if err := tr.Validate(); err != nil {
		t.Fatal(err)
	}
	e, err := StartHysteria(c, func(s string) { t.Log(s) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	if e.Name() != string(profile.KindHysteria2) || !e.NativeUDP() {
		t.Fatalf("name %q, native UDP %v", e.Name(), e.NativeUDP())
	}
	return e
}

func TestHysteria(t *testing.T) {
	echo := testenv.StartEcho(t, "echo:")
	for _, obfs := range []string{"", "salamander-pw"} {
		srv := testenv.StartHysteria(t, obfs)
		roundTrip(t, startHy(t, srv.Config), echo)

		// insecure=1 without a pin accepts the self-signed certificate.
		c := *srv.Config
		c.PinSHA256, c.Insecure = "", true
		tcpRoundTrip(t, startHy(t, &c), echo)
	}
}

// failsWithin reports whether TCP through the engine fails (or hangs) for
// the whole wait.
func failsWithin(e *Engine, echo testenv.Echo, wait time.Duration) bool {
	works := make(chan bool, 1)
	go func() { works <- tcpWorks(e, echo) }()
	select {
	case ok := <-works:
		return !ok
	case <-time.After(wait):
		return true
	}
}

func TestHysteriaRejects(t *testing.T) {
	echo := testenv.StartEcho(t, "echo:")
	srv := testenv.StartHysteria(t, "obfs-pw")
	for name, mut := range map[string]func(*profile.HysteriaConfig){
		"password":      func(c *profile.HysteriaConfig) { c.Auth = "wrong" },
		"pin":           func(c *profile.HysteriaConfig) { c.PinSHA256 = strings.Repeat("ab", 32) },
		"obfs":          func(c *profile.HysteriaConfig) { c.ObfsPassword = "other" },
		"no pin, no CA": func(c *profile.HysteriaConfig) { c.PinSHA256 = "" },
	} {
		c := *srv.Config
		mut(&c)
		if !failsWithin(startHy(t, &c), echo, 4*time.Second) {
			t.Errorf("%s: traffic must not pass", name)
		}
	}
}

// TestHysteriaSettingsChange checks that a new engine for the same server
// uses its own settings, not the client xray cached for the address.
func TestHysteriaSettingsChange(t *testing.T) {
	echo := testenv.StartEcho(t, "echo:")
	srv := testenv.StartHysteria(t, "obfs-pw")
	bad := *srv.Config
	bad.Auth = "wrong"

	good := startHy(t, srv.Config)
	tcpRoundTrip(t, good, echo)
	good.Close()
	if !failsWithin(startHy(t, &bad), echo, 4*time.Second) {
		t.Fatal("a wrong password must fail after a good connection to the same server")
	}
	tcpRoundTrip(t, startHy(t, srv.Config), echo)
}
