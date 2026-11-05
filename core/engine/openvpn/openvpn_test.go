package openvpn

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eermolaev/test-vpn/core/errclass"
	"github.com/eermolaev/test-vpn/core/profile"
)

var cfg = &profile.OpenVPNConfig{Config: "client\n<ca>\nx\n</ca>\n", Host: "198.51.100.9", Port: 443, Proto: "tcp"}

// fakeBinary writes a shell script standing in for openvpn.
func fakeBinary(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "openvpn")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func start(t *testing.T, body string, timeout time.Duration) (*Engine, []string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var logs []string
	e, err := Start(ctx, cfg, Options{Binary: fakeBinary(t, body), Dir: t.TempDir(), Logf: func(s string) { logs = append(logs, s) }})
	return e, logs, err
}

func TestArgsKeepRoutingWithDaemon(t *testing.T) {
	a := Args("/x/client.ovpn", cfg)
	for _, want := range []string{"--route-noexec", "--route-nopull", "tcp4-client", "198.51.100.9"} {
		if !slices.Contains(a, want) {
			t.Fatalf("%q missing in %v", want, a)
		}
	}
	if a[0] != "--config" {
		t.Fatal("overrides must follow --config")
	}
}

func TestStartUp(t *testing.T) {
	// An existing interface stands in for openvpn's.
	var ifc, line string
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		switch runtime.GOOS {
		case "darwin":
			if strings.HasPrefix(i.Name, "utun") {
				ifc, line = i.Name, "Opened utun device "+i.Name
			}
		case "linux":
			if i.Flags&net.FlagLoopback != 0 {
				ifc, line = i.Name, "TUN/TAP device "+i.Name+" opened"
			}
		}
	}
	if ifc == "" {
		t.Skip("no interface to stand in for openvpn's")
	}
	e, logs, err := start(t, "echo '"+line+"'; echo 'Initialization Sequence Completed'; exec sleep 30", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if e.Interface() != ifc || !e.NativeUDP() || e.Name() != "openvpn" {
		t.Fatalf("%s %v %s", e.Interface(), e.NativeUDP(), e.Name())
	}
	dir := e.dir
	if b, err := os.ReadFile(filepath.Join(dir, "client.ovpn")); err != nil || string(b) != cfg.Config {
		t.Fatalf("config file: %q %v", b, err)
	}
	begin := time.Now()
	e.Close()
	if time.Since(begin) > 2*time.Second {
		t.Fatal("SIGTERM must stop openvpn")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("config with keys must be removed")
	}
	if len(logs) != 2 || logs[0] != "openvpn: "+line {
		t.Fatalf("logs: %q", logs)
	}
}

func TestStartFailures(t *testing.T) {
	cases := []struct {
		body  string
		class errclass.Class
	}{
		{"echo 'AUTH: Received control message: AUTH_FAILED'; exec sleep 30", errclass.Config},
		{"echo 'TLS Error: TLS handshake failed'; exit 1", errclass.TLS},
		{"echo 'TCP: connect to [AF_INET]198.51.100.9:443 failed: Connection refused'; exit 1", errclass.TCPReset},
		{"echo 'Options error: Unrecognized option'; exit 1", errclass.Config},
		{"exec sleep 30", errclass.TCPTimeout},
	}
	for _, c := range cases {
		begin := time.Now()
		_, _, err := start(t, c.body, time.Second)
		if errclass.Classify(err) != c.class {
			t.Fatalf("%s: got %v, want %s", c.body, err, c.class)
		}
		if time.Since(begin) > 3*time.Second {
			t.Fatalf("%s: took %s", c.body, time.Since(begin))
		}
	}
}

func TestRefusesWritableBinary(t *testing.T) {
	p := fakeBinary(t, "exit 0")
	os.Chmod(p, 0o777)
	if _, err := Start(context.Background(), cfg, Options{Binary: p}); errclass.Classify(err) != errclass.Config {
		t.Fatalf("got %v", err)
	}
}
