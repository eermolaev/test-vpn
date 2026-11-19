package xray

import (
	"encoding/json"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/eermolaev/test-vpn/core/internal/testenv"
	"github.com/eermolaev/test-vpn/core/profile"
)

// countingProxy forwards TCP to target and counts accepted connections.
func countingProxy(t *testing.T, target string) (int, *atomic.Int32) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var n atomic.Int32
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			go func() {
				defer c.Close()
				up, err := net.Dial("tcp4", target)
				if err != nil {
					return
				}
				defer up.Close()
				go io.Copy(up, c)
				io.Copy(c, up)
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, &n
}

func TestMux(t *testing.T) {
	srv := testenv.StartReality(t)
	echo := testenv.StartEcho(t, "echo:")
	for _, base := range []*profile.VLESSConfig{srv.Plain, srv.Trojan, srv.VMess, srv.VMessWS} {
		c := *base
		port, conns := countingProxy(t, net.JoinHostPort(c.Address, strconv.Itoa(c.Port)))
		c.Port, c.Mux = port, 8
		tr := profile.Transport{VLESS: &c}
		if err := tr.Validate(); err != nil {
			t.Fatal(err)
		}
		e, err := Start(&c, nil)
		if err != nil {
			t.Fatal(err)
		}
		roundTrip(t, e, echo)

		// Parallel flows share the mux connections instead of opening one
		// server connection each.
		before := conns.Load()
		var wg sync.WaitGroup
		var failed atomic.Int32
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if !tcpWorks(e, echo) {
					failed.Add(1)
				}
			}()
		}
		wg.Wait()
		if failed.Load() > 0 {
			t.Fatalf("%s: %d of 16 flows failed", tr.ID(), failed.Load())
		}
		if opened := conns.Load() - before; opened > 4 {
			t.Fatalf("%s: 16 flows opened %d server connections, mux is not used", tr.ID(), opened)
		}
		t.Logf("%s: 16 flows, %d new server connections", tr.ID(), conns.Load()-before)
		e.Close()
	}
}

func TestMuxConfig(t *testing.T) {
	c := &profile.VLESSConfig{Address: "1.2.3.4", Port: 443, UUID: "u", Security: "tls", Network: "raw", Mux: 8}
	js, err := BuildConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Outbounds []struct {
			Mux *struct {
				Enabled     bool   `json:"enabled"`
				Concurrency int    `json:"concurrency"`
				UDP443      string `json:"xudpProxyUDP443"`
			} `json:"mux"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(js, &cfg); err != nil {
		t.Fatal(err)
	}
	m := cfg.Outbounds[0].Mux
	if m == nil || !m.Enabled || m.Concurrency != 8 || m.UDP443 != "skip" {
		t.Fatalf("mux: %+v", m)
	}
	c.Mux = 0
	js, _ = BuildConfig(c)
	cfg.Outbounds = nil
	json.Unmarshal(js, &cfg)
	if cfg.Outbounds[0].Mux != nil {
		t.Fatal("mux must be off by default")
	}
}
