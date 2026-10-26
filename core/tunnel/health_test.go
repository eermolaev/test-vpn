package tunnel

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eermolaev/test-vpn/core/engine"
	"github.com/eermolaev/test-vpn/core/internal/clientstack"
	"github.com/eermolaev/test-vpn/core/internal/testenv"
	"github.com/eermolaev/test-vpn/core/netstack"
	"github.com/eermolaev/test-vpn/core/profile"
	"golang.org/x/net/dns/dnsmessage"
)

var echoAddr = netip.MustParseAddrPort("203.0.113.10:7")

// slowEngine is a TCP-only tunnel (like a VLESS server without UDP relay)
// whose DNS answers arrive after tcpDelay. Its echo service at echoAddr
// carries ordinary traffic.
type slowEngine struct {
	tcpDelay time.Duration
	dnsDown  atomic.Bool // DNS probes get no answer
}

func (e *slowEngine) Name() string    { return "fake" }
func (e *slowEngine) NativeUDP() bool { return false }
func (e *slowEngine) Close() error    { return nil }

func (e *slowEngine) DialUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	a, b := net.Pipe()
	go io.Copy(io.Discard, b) // swallow datagrams, never answer
	return a, nil
}

func (e *slowEngine) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	a, b := net.Pipe()
	if dst == echoAddr {
		go func() { io.Copy(b, b); b.Close() }()
		return a, nil
	}
	go func() {
		defer b.Close()
		var l [2]byte
		if _, err := io.ReadFull(b, l[:]); err != nil {
			return
		}
		q := make([]byte, int(l[0])<<8|int(l[1]))
		if _, err := io.ReadFull(b, q); err != nil || e.dnsDown.Load() {
			io.Copy(io.Discard, b)
			return
		}
		var p dnsmessage.Parser
		h, err := p.Start(q)
		if err != nil {
			return
		}
		time.Sleep(e.tcpDelay)
		rb := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true})
		resp, _ := rb.Finish()
		b.Write(append([]byte{byte(len(resp) >> 8), byte(len(resp))}, resp...))
	}()
	return a, nil
}

// TestHealthCheckSlowTCPOnly: with two resolvers and no UDP relay, a TCP
// answer that takes most of the budget must still count. Splitting the
// budget into one slice per probe dropped such working tunnels.
func TestHealthCheckSlowTCPOnly(t *testing.T) {
	e := &slowEngine{tcpDelay: 1500 * time.Millisecond}
	tun := &Tunnel{dnsAddrs: []netip.AddrPort{netip.MustParseAddrPort("8.8.8.8:53"), netip.MustParseAddrPort("8.8.4.4:53")}}
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	if err := tun.healthCheck(ctx, e); err != nil {
		t.Fatalf("slow TCP-only tunnel must pass: %v", err)
	}
	if tun.udpWarned != e {
		t.Fatal("UDP failure must be noticed")
	}
	// Known TCP-only: later checks skip UDP and still pass.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel2()
	if err := tun.healthCheck(ctx2, e); err != nil {
		t.Fatal(err)
	}
	e.dnsDown.Store(true)
	ctx3, cancel3 := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel3()
	if err := tun.healthCheck(ctx3, e); err == nil {
		t.Fatal("no DNS answer must fail the check")
	}
}

// TestBusyTunnelSkipsProbe: while data arrives from the tunnel, failing DNS
// probes must not drop it; once it is idle they do.
func TestBusyTunnelSkipsProbe(t *testing.T) {
	srv := testenv.StartAWG(t, testenv.Obfuscation(), [4]byte{1, 1, 1, 1}) // only for a valid profile
	e := &slowEngine{}
	cfg := Config{
		Profile:        &profile.Profile{Transports: []profile.Transport{{AWG: srv.Client}}},
		Settings:       Settings{DNSServers: []string{"8.8.8.8"}},
		Policy:         fastPolicy(),
		HealthInterval: 150 * time.Millisecond,
		HealthTimeout:  300 * time.Millisecond,
	}
	tunEnd, appEnd := netstack.NewPipe(1024)
	tun, err := Start(tunEnd, cfg, Deps{
		Starter: func(context.Context, profile.Transport) (engine.Engine, error) { return e, nil },
		Logf:    func(s string) { t.Log(s) },
	})
	if err != nil {
		t.Fatal(err)
	}
	client := clientstack.New(appEnd)
	t.Cleanup(func() { client.Close(); tun.Stop() })
	waitState(t, tun, StateConnected, 5*time.Second)

	e.dnsDown.Store(true)
	conn, err := client.DialTCP(echoAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, 16)
	for end := time.Now().Add(1500 * time.Millisecond); time.Now().Before(end); {
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			t.Fatal(err)
		}
		if s := tun.Status(); s.State != StateConnected {
			t.Fatalf("busy tunnel dropped: %+v", s)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Idle: the failing probes now drop the engine.
	deadline := time.Now().Add(5 * time.Second)
	for tun.Status().State == StateConnected {
		if time.Now().After(deadline) {
			t.Fatal("idle tunnel with failing probes must be dropped")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
