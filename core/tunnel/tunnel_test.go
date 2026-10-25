package tunnel

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eermolaev/test-vpn/core/engine/xray"
	"github.com/eermolaev/test-vpn/core/errclass"
	"github.com/eermolaev/test-vpn/core/fallback"
	"github.com/eermolaev/test-vpn/core/internal/clientstack"
	"github.com/eermolaev/test-vpn/core/internal/quictest"
	"github.com/eermolaev/test-vpn/core/internal/testenv"
	"github.com/eermolaev/test-vpn/core/netstack"
	"github.com/eermolaev/test-vpn/core/profile"
	"golang.org/x/net/dns/dnsmessage"
)

type statusLog struct {
	mu sync.Mutex
	s  []Status
}

func (l *statusLog) add(s Status) { l.mu.Lock(); l.s = append(l.s, s); l.mu.Unlock() }

func waitState(t *testing.T, tun *Tunnel, want State, timeout time.Duration) Status {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s := tun.Status(); s.State == want {
			return s
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("state %s not reached, current %+v", want, tun.Status())
	return Status{}
}

func startTunnel(t *testing.T, cfg Config, mem *fallback.Memory) (*Tunnel, *clientstack.Client, *statusLog) {
	t.Helper()
	tunEnd, appEnd := netstack.NewPipe(1024)
	log := &statusLog{}
	tun, err := Start(tunEnd, cfg, Deps{Memory: mem, OnStatus: log.add, Logf: func(s string) { t.Log(s) }})
	if err != nil {
		t.Fatal(err)
	}
	client := clientstack.New(appEnd)
	t.Cleanup(func() { client.Close(); tun.Stop() })
	return tun, client, log
}

func tcpExchange(c *clientstack.Client, dst netip.AddrPort, payload []byte) (string, error) {
	conn, err := c.DialTCP(dst, 3*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return "", err
	}
	buf := make([]byte, 32<<10)
	n, err := io.ReadAtLeast(conn, buf, len(payload))
	return string(buf[:n]), err
}

func tlsHello(sni string) []byte {
	ch := quictest.ClientHello(sni)
	return append([]byte{0x16, 3, 1, byte(len(ch) >> 8), byte(len(ch))}, ch...)
}

func resolve(t *testing.T, c *clientstack.Client, name string) (string, dnsmessage.RCode) {
	t.Helper()
	u, err := c.DialUDP(netip.MustParseAddrPort("8.8.8.8:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 77, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	u.Write(q)
	u.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1500)
	n, err := u.Read(buf)
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	var p dnsmessage.Parser
	h, _ := p.Start(buf[:n])
	p.SkipAllQuestions()
	if a, err := p.AnswerHeader(); err == nil && a.Type == dnsmessage.TypeA {
		r, _ := p.AResource()
		return netip.AddrFrom4(r.A).String(), h.RCode
	}
	return "", h.RCode
}

func fastPolicy() fallback.Policy {
	return fallback.Policy{Attempts: 1, FailTimeout: 3 * time.Second, BackoffBase: 10 * time.Millisecond, BackoffMax: 50 * time.Millisecond, MaxRounds: 1}
}

func TestAmneziaWGWithExclusions(t *testing.T) {
	host := testenv.HostIP(t)
	direct := testenv.StartEchoOn(t, host, "direct:")
	srv := testenv.StartAWG(t, testenv.Obfuscation(), [4]byte{93, 184, 216, 34})
	cfg := Config{
		Profile:  &profile.Profile{Name: "test", Transports: []profile.Transport{{AWG: srv.Client}}},
		Settings: Settings{Exclusions: []string{"bank.example"}, DNSServers: []string{testenv.AWGServerIP.String()}},
		Policy:   fastPolicy(),
	}
	tun, client, _ := startTunnel(t, cfg, nil)
	st := waitState(t, tun, StateConnected, 10*time.Second)
	if st.TransportKind != string(profile.KindAmneziaWG) {
		t.Fatalf("kind %s", st.TransportKind)
	}
	if resp, err := tcpExchange(client, netip.AddrPortFrom(testenv.AWGServerIP, 7), []byte("hi")); err != nil || resp != "awg:hi" {
		t.Fatalf("tunnel flow: %q %v", resp, err)
	}
	if ip, rc := resolve(t, client, "news.example"); ip != "93.184.216.34" || rc != dnsmessage.RCodeSuccess {
		t.Fatalf("tunnel DNS: %s %v", ip, rc)
	}
	payload := tlsHello("www.bank.example")
	if resp, err := tcpExchange(client, direct.TCP, payload); err != nil || !strings.HasPrefix(resp, "direct:") {
		t.Fatalf("excluded flow: %q %v", resp[:min(len(resp), 20)], err)
	}
	s := tun.Status()
	if s.Stats.TCPDirect != 1 || s.Stats.TCPTunnel != 1 || s.Exclusions != 1 {
		t.Fatalf("stats %+v", s.Stats)
	}
}

func TestFallbackToReality(t *testing.T) {
	host := testenv.HostIP(t)
	echo := testenv.StartEchoOn(t, host, "echo:")
	dns := testenv.StartDNSOn(t, host, [4]byte{1, 2, 3, 4})
	reality := testenv.StartReality(t)
	warmUp(t, reality.Vision, echo)

	srv := testenv.StartAWG(t, testenv.Obfuscation(), [4]byte{1, 1, 1, 1})
	blocked := *srv.Client
	blocked.Peer.Endpoint = "127.0.0.1:9" // UDP "blocked": no answer
	prof := &profile.Profile{Transports: []profile.Transport{{AWG: &blocked}, {VLESS: reality.Vision}}}
	mem := fallback.NewMemory(nil)
	cfg := Config{
		Profile:   prof,
		NetworkID: "office-wifi",
		Settings:  Settings{DNSServers: []string{dns.String()}},
		Policy:    fastPolicy(),
	}
	cfg.Policy.FailTimeout = 2 * time.Second
	start := time.Now()
	tun, client, log := startTunnel(t, cfg, mem)
	st := waitState(t, tun, StateConnected, 15*time.Second)
	if st.TransportKind != string(profile.KindVLESSReality) {
		t.Fatalf("connected via %s", st.TransportKind)
	}
	if limit := cfg.Policy.FailTimeout*time.Duration(cfg.Policy.Attempts) + 5*time.Second; time.Since(start) > limit {
		t.Fatalf("fallback took %v, limit %v", time.Since(start), limit)
	}
	sawUDPTimeout := false
	log.mu.Lock()
	for _, s := range log.s {
		if s.ErrorClass == errclass.UDPTimeout {
			sawUDPTimeout = true
		}
	}
	log.mu.Unlock()
	if !sawUDPTimeout {
		t.Fatal("AmneziaWG failure must be classified as udp_timeout")
	}
	if got := mem.Preferred(fallback.NetworkKey("office-wifi")); got != reality.Vision2ID() {
		t.Fatalf("memory = %q", got)
	}
	if resp, err := tcpExchange(client, echo.TCP, []byte("via-reality")); err != nil || resp != "echo:via-reality" {
		t.Fatalf("flow through REALITY: %q %v", resp, err)
	}
	if tun.Status().Stats.TCPTunnel != 1 {
		t.Fatal("flow must go through the tunnel")
	}
	// QUIC is blocked inside the TCP-based tunnel.
	u, _ := client.DialUDP(netip.AddrPortFrom(host, 443))
	u.Write(quictest.Initial(quictest.V1, []byte{1, 2, 3, 4, 5, 6, 7, 8}, 0, []quictest.CryptoFrame{{Data: quictest.ClientHello("video.example")}}))
	time.Sleep(200 * time.Millisecond)
	u.Close()
	if tun.Status().Stats.UDPReject != 1 {
		t.Fatalf("QUIC not blocked: %+v", tun.Status().Stats)
	}
}

// warmUp absorbs the one-time REALITY target probe (~5s) so that test
// timeouts measure the client.
func warmUp(t *testing.T, c *profile.VLESSConfig, echo testenv.Echo) {
	t.Helper()
	e, err := xray.Start(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	conn, err := e.DialTCP(context.Background(), echo.TCP)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	conn.Write([]byte("w"))
	buf := make([]byte, 16)
	io.ReadAtLeast(conn, buf, 2)
}

func TestKillSwitchOnServerLoss(t *testing.T) {
	host := testenv.HostIP(t)
	direct := testenv.StartEchoOn(t, host, "direct:")
	srv := testenv.StartAWG(t, testenv.Obfuscation(), [4]byte{1, 1, 1, 1})
	cfg := Config{
		Profile:        &profile.Profile{Transports: []profile.Transport{{AWG: srv.Client}}},
		Settings:       Settings{Exclusions: []string{"bank.example"}, DNSServers: []string{testenv.AWGServerIP.String()}},
		Policy:         fastPolicy(),
		HealthInterval: 200 * time.Millisecond,
		HealthTimeout:  500 * time.Millisecond,
	}
	cfg.Policy.FailTimeout = 1 * time.Second
	tun, client, _ := startTunnel(t, cfg, nil)
	waitState(t, tun, StateConnected, 10*time.Second)

	srv.Close()
	st := waitState(t, tun, StateFailed, 10*time.Second)
	if st.ErrorClass == errclass.None {
		t.Fatal("failure must carry an error class")
	}
	if _, err := tcpExchange(client, netip.AddrPortFrom(testenv.AWGServerIP, 7), []byte("x")); err == nil {
		t.Fatal("tunneled flow must be rejected while the server is down")
	}
	if _, rc := resolve(t, client, "news.example"); rc != dnsmessage.RCodeServerFailure {
		t.Fatalf("DNS while down: %v", rc)
	}
	if resp, err := tcpExchange(client, direct.TCP, tlsHello("bank.example")); err != nil || !strings.HasPrefix(resp, "direct:") {
		t.Fatalf("excluded flow while down: %v", err)
	}
}

func TestUpdateSettings(t *testing.T) {
	srv := testenv.StartAWG(t, testenv.Obfuscation(), [4]byte{1, 1, 1, 1})
	cfg := Config{
		Profile:  &profile.Profile{Transports: []profile.Transport{{AWG: srv.Client}}},
		Settings: Settings{DNSServers: []string{testenv.AWGServerIP.String()}},
		Policy:   fastPolicy(),
	}
	tun, _, _ := startTunnel(t, cfg, nil)
	waitState(t, tun, StateConnected, 10*time.Second)
	err := tun.UpdateSettings(Settings{Exclusions: []string{"ok.example", "1.2.3.4", "api.ipify.org"}, DNSServers: []string{"2001:4860::8888"}})
	var serr *SettingsError
	if !errors.As(err, &serr) || len(serr.Exclusions) != 2 || len(serr.Other) != 1 {
		t.Fatalf("expected 3 problems, got %v", err)
	}
	if err := tun.UpdateSettings(Settings{Exclusions: []string{"ok.example"}, DNSServers: []string{testenv.AWGServerIP.String(), "8.8.4.4"}}); err != nil {
		t.Fatal(err)
	}
	if s := tun.Status(); s.Exclusions != 1 || len(s.DNSServers) != 2 || s.State != StateConnected {
		t.Fatalf("status after update: %+v", s)
	}
}

func TestStartValidation(t *testing.T) {
	tunEnd, _ := netstack.NewPipe(4)
	if _, err := Start(tunEnd, Config{}, Deps{}); errclass.Classify(err) != errclass.Config {
		t.Fatalf("no profile: %v", err)
	}
	plain := &profile.Profile{Transports: []profile.Transport{{VLESS: &profile.VLESSConfig{Address: "h", Port: 80, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Security: "none"}}}}
	if _, err := Start(tunEnd, Config{Profile: plain}, Deps{}); errclass.Classify(err) != errclass.Config {
		t.Fatalf("forbidden-only profile: %v", err)
	}
}
