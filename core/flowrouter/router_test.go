package flowrouter

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eermolaev/test-vpn/core/dnsintercept"
	"github.com/eermolaev/test-vpn/core/internal/clientstack"
	"github.com/eermolaev/test-vpn/core/internal/quictest"
	"github.com/eermolaev/test-vpn/core/netstack"
	"github.com/eermolaev/test-vpn/core/rules"
	"golang.org/x/net/dns/dnsmessage"
)

// echoServers reply with "<name>:<payload>" so tests can see the path taken.
type echoServers struct {
	name string
	tcp  net.Listener
	udp  *net.UDPConn
}

func startEcho(t *testing.T, name string) *echoServers {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close(); u.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				// The client half-closes after sending: read to EOF, so a
				// request split by the router (sniffed prefix, then the rest)
				// arrives whole regardless of timing.
				c.SetDeadline(time.Now().Add(10 * time.Second))
				req, err := io.ReadAll(c)
				if err != nil || len(req) == 0 {
					return
				}
				c.Write([]byte(name + ":" + string(req)))
			}()
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, a, err := u.ReadFromUDP(buf)
			if err != nil {
				return
			}
			u.WriteToUDP([]byte(name+":"+string(buf[:min(n, 32)])), a)
		}
	}()
	return &echoServers{name: name, tcp: l, udp: u}
}

// fakeDialer sends every flow to its echo servers and records destinations.
type fakeDialer struct {
	echo   *echoServers
	native bool
	mu     sync.Mutex
	dsts   []netip.AddrPort
	down   bool
}

func (f *fakeDialer) record(dst netip.AddrPort) {
	f.mu.Lock()
	f.dsts = append(f.dsts, dst)
	f.mu.Unlock()
}

func (f *fakeDialer) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	f.record(dst)
	var d net.Dialer
	return d.DialContext(ctx, "tcp4", f.echo.tcp.Addr().String())
}

func (f *fakeDialer) DialUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	f.record(dst)
	var d net.Dialer
	return d.DialContext(ctx, "udp4", f.echo.udp.LocalAddr().String())
}

func (f *fakeDialer) Name() string    { return "fake" }
func (f *fakeDialer) NativeUDP() bool { return f.native }
func (f *fakeDialer) Close() error    { return nil }

type harness struct {
	client *clientstack.Client
	router *Router
	direct *fakeDialer
	tunnel *fakeDialer
	cache  *dnsintercept.Cache
	mu     sync.Mutex
	log    []string
}

func newHarness(t *testing.T, exclusions []string, dnsCfg func(*dnsintercept.Config)) *harness {
	t.Helper()
	set, errs := rules.NewSet(exclusions)
	if errs != nil {
		t.Fatal(errs)
	}
	h := &harness{
		direct: &fakeDialer{echo: startEcho(t, "D")},
		tunnel: &fakeDialer{echo: startEcho(t, "T")},
		cache:  dnsintercept.NewCache(0),
	}
	loop := func(ctx context.Context, network string, s netip.AddrPort) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, s.String())
	}
	cfg := dnsintercept.Config{Exclusions: set}
	if dnsCfg != nil {
		dnsCfg(&cfg)
	}
	res := dnsintercept.NewResolver(h.cache, loop, cfg)
	h.router = New(h.direct, res, h.cache, Settings{Exclusions: set, BlockQUICInTunnel: true})
	h.router.OnDecision = func(f netstack.Flow, proto string, d Decision) {
		h.mu.Lock()
		h.log = append(h.log, proto+" "+f.Dst.String()+" "+d.Route.String()+" "+d.Host+" "+string(d.Source))
		h.mu.Unlock()
	}
	tunEnd, appEnd := netstack.NewPipe(1024)
	st, err := netstack.New(tunEnd, h.router, netstack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	h.client = clientstack.New(appEnd)
	t.Cleanup(func() {
		h.client.Close()
		st.Close()
	})
	return h
}

func (h *harness) tcp(t *testing.T, dst string, payload []byte) (string, error) {
	t.Helper()
	c, err := h.client.DialTCP(netip.MustParseAddrPort(dst), 3*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(payload); err != nil {
		return "", err
	}
	// Half-close: the echo server answers after EOF, which also checks that
	// the router propagates FIN.
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
	resp, err := io.ReadAll(c)
	return string(resp), err
}

func (h *harness) udp(t *testing.T, dst string, payloads ...[]byte) (string, error) {
	t.Helper()
	c, err := h.client.DialUDP(netip.MustParseAddrPort(dst))
	if err != nil {
		return "", err
	}
	defer c.Close()
	for _, p := range payloads {
		if _, err := c.Write(p); err != nil {
			return "", err
		}
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, err := c.Read(buf)
	return string(buf[:n]), err
}

func tlsHello(sni string) []byte {
	ch := quictest.ClientHello(sni)
	return append([]byte{0x16, 3, 1, byte(len(ch) >> 8), byte(len(ch))}, ch...)
}

func path(resp string) string { return strings.SplitN(resp, ":", 2)[0] }

func TestTCPRouting(t *testing.T) {
	h := newHarness(t, []string{"bank.example", "google.com"}, nil)
	h.router.SetEngine(h.tunnel)

	cases := []struct {
		name, dst string
		payload   []byte
		want      string
	}{
		{"excluded SNI", "198.51.100.10:443", tlsHello("online.bank.example"), "D"},
		{"other SNI on the same IP", "198.51.100.10:443", tlsHello("news.example"), "T"},
		{"excluded HTTP host", "198.51.100.11:80", []byte("GET / HTTP/1.1\r\nHost: bank.example\r\n\r\n"), "D"},
		{"protected host under broad rule", "198.51.100.12:443", tlsHello("stun.l.google.com"), "T"},
		{"broad rule", "198.51.100.12:443", tlsHello("mail.google.com"), "D"},
		{"unknown protocol", "198.51.100.13:22", []byte("SSH-2.0-test\r\n"), "T"},
	}
	for _, c := range cases {
		resp, err := h.tcp(t, c.dst, c.payload)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if path(resp) != c.want {
			t.Errorf("%s: went %s, want %s", c.name, path(resp), c.want)
		}
		// The sniffed prefix must reach the server unchanged.
		if !strings.HasSuffix(resp, string(c.payload)) {
			t.Errorf("%s: payload corrupted", c.name)
		}
	}
}

func TestDNSCacheRouting(t *testing.T) {
	h := newHarness(t, []string{"bank.example"}, nil)
	h.router.SetEngine(h.tunnel)
	h.cache.Put(netip.MustParseAddr("203.0.113.5"), "api.bank.example", time.Minute)
	if resp, err := h.tcp(t, "203.0.113.5:9000", []byte("raw")); err != nil || path(resp) != "D" {
		t.Fatalf("cached excluded IP: %q %v", resp, err)
	}
	if resp, err := h.tcp(t, "203.0.113.6:9000", []byte("raw")); err != nil || path(resp) != "T" {
		t.Fatalf("unknown IP: %q %v", resp, err)
	}
	// SNI of another domain beats the DNS cache.
	if resp, err := h.tcp(t, "203.0.113.5:443", tlsHello("other.example")); err != nil || path(resp) != "T" {
		t.Fatalf("SNI priority: %q %v", resp, err)
	}
}

func TestKillSwitch(t *testing.T) {
	h := newHarness(t, []string{"bank.example"}, nil)
	// Engine down: excluded traffic still works, everything else is reset.
	if resp, err := h.tcp(t, "198.51.100.10:443", tlsHello("bank.example")); err != nil || path(resp) != "D" {
		t.Fatalf("excluded while down: %q %v", resp, err)
	}
	if resp, err := h.tcp(t, "198.51.100.10:443", tlsHello("news.example")); err == nil {
		t.Fatalf("non-excluded flow must be rejected while down, got %q", resp)
	}
	if len(h.tunnel.dsts) != 0 {
		t.Fatal("tunnel used while down")
	}
	if h.router.Stats.TCPReject.Load() == 0 || h.router.Stats.TCPDirect.Load() != 1 {
		t.Fatalf("stats: reject=%d direct=%d", h.router.Stats.TCPReject.Load(), h.router.Stats.TCPDirect.Load())
	}
	// Recovers when the engine comes back.
	h.router.SetEngine(h.tunnel)
	if resp, err := h.tcp(t, "198.51.100.10:443", tlsHello("news.example")); err != nil || path(resp) != "T" {
		t.Fatalf("after recovery: %q %v", resp, err)
	}
}

// expectRST dials dst and checks that the router answered with RST rather
// than dropping the SYN. A silent drop would end in a dial timeout (3s); an
// RST to a retransmitted SYN arrives after the 1s SYN RTO, which still counts
// as a reset, so the bound is below the dial timeout, not below the RTO.
func expectRST(t *testing.T, h *harness, dst string) {
	t.Helper()
	start := time.Now()
	_, err := h.client.DialTCP(netip.MustParseAddrPort(dst), 3*time.Second)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("connect to %s must fail", dst)
	}
	syns := h.rejectsFor(dst)
	// Diagnostics: syns=2 means the first RST was lost on the client side,
	// syns=1 after ~1s means the first SYN never reached the router.
	t.Logf("reject %s: %v after %v, router saw %d SYN(s)", dst, err, elapsed.Round(time.Millisecond), syns)
	if !strings.Contains(err.Error(), "refused") && !strings.Contains(err.Error(), "reset") {
		t.Fatalf("expected connection refused/reset (RST), got %v", err)
	}
	if elapsed > 2500*time.Millisecond {
		t.Fatalf("reject took %v: SYN dropped instead of reset", elapsed)
	}
	if syns == 0 {
		t.Fatal("router never saw the SYN")
	}
}

func (h *harness) rejectsFor(dst string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, l := range h.log {
		if strings.HasPrefix(l, "tcp "+dst+" reject") {
			n++
		}
	}
	return n
}

func TestNoExclusionsRejectsBeforeHandshake(t *testing.T) {
	h := newHarness(t, nil, nil)
	expectRST(t, h, "198.51.100.10:443")
}

func TestIPv6Rejected(t *testing.T) {
	h := newHarness(t, []string{"bank.example"}, nil)
	h.router.SetEngine(h.tunnel)
	expectRST(t, h, "[2001:db8::1]:443")
	if _, err := h.udp(t, "[2001:db8::1]:443", []byte("x")); err == nil {
		t.Fatal("IPv6 UDP must get no answer")
	}
	if len(h.direct.dsts)+len(h.tunnel.dsts) != 0 {
		t.Fatal("IPv6 flow reached a dialer")
	}
}

// TestConnectLatency guards against the stack losing the first SYN of
// accepted connections, which would add the 1s SYN RTO to every connection.
func TestConnectLatency(t *testing.T) {
	h := newHarness(t, nil, nil)
	h.router.SetEngine(h.tunnel)
	var d []time.Duration
	for i := 0; i < 20; i++ {
		start := time.Now()
		c, err := h.client.DialTCP(netip.MustParseAddrPort(fmt.Sprintf("198.51.100.40:%d", 1000+i)), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		d = append(d, time.Since(start))
		c.Close()
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	t.Logf("connect latency: median %v, max %v", d[len(d)/2], d[len(d)-1])
	if d[len(d)/2] > 200*time.Millisecond {
		t.Fatalf("median connect latency %v: the first SYN is being lost", d[len(d)/2])
	}
}

func TestUDPRouting(t *testing.T) {
	h := newHarness(t, []string{"bank.example"}, nil)
	h.tunnel.native = false // VLESS-like engine
	h.router.SetEngine(h.tunnel)
	dcid := []byte{9, 8, 7, 6, 5, 4, 3, 2}

	excluded := quictest.Initial(quictest.V1, dcid, 0, []quictest.CryptoFrame{{Data: quictest.ClientHello("app.bank.example")}})
	if resp, err := h.udp(t, "198.51.100.20:443", excluded); err != nil || path(resp) != "D" {
		t.Fatalf("excluded QUIC: %q %v", resp, err)
	}
	other := quictest.Initial(quictest.V1, dcid, 0, []quictest.CryptoFrame{{Data: quictest.ClientHello("video.example")}})
	if _, err := h.udp(t, "198.51.100.20:443", other); err == nil {
		t.Fatal("QUIC in a VLESS tunnel must be blocked")
	}
	if resp, err := h.udp(t, "198.51.100.21:5000", []byte("game")); err != nil || resp != "T:game" {
		t.Fatalf("plain UDP: %q %v", resp, err)
	}
	// With a native UDP engine (AmneziaWG) QUIC goes through the tunnel.
	h.tunnel.native = true
	if resp, err := h.udp(t, "198.51.100.22:443", other); err != nil || path(resp) != "T" {
		t.Fatalf("QUIC over native UDP: %q %v", resp, err)
	}
	// ClientHello split across two Initials.
	ch := quictest.ClientHello("cdn.bank.example")
	mid := len(ch) / 2
	p1 := quictest.Initial(quictest.V1, dcid, 0, []quictest.CryptoFrame{{Offset: uint64(mid), Data: ch[mid:]}})
	p2 := quictest.Initial(quictest.V1, dcid, 1, []quictest.CryptoFrame{{Data: ch[:mid]}})
	if resp, err := h.udp(t, "198.51.100.23:443", p1, p2); err != nil || path(resp) != "D" {
		t.Fatalf("split QUIC: %q %v", resp, err)
	}
}

func dnsQuery(name string) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 42, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	out, _ := b.Finish()
	return out
}

// startDNS answers A queries with ip.
func startDNS(t *testing.T, ip [4]byte) netip.AddrPort {
	t.Helper()
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { u.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, a, err := u.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			hd, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, _ := p.Question()
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: hd.ID, Response: true})
			b.StartQuestions()
			b.Question(q)
			b.StartAnswers()
			b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 120}, dnsmessage.AResource{A: ip})
			out, _ := b.Finish()
			u.WriteToUDP(out, a)
		}
	}()
	return netip.MustParseAddrPort(u.LocalAddr().String())
}

func TestDNSThroughStack(t *testing.T) {
	network := startDNS(t, [4]byte{10, 1, 1, 1})
	public := startDNS(t, [4]byte{20, 2, 2, 2})
	h := newHarness(t, []string{"bank.example"}, func(c *dnsintercept.Config) {
		c.DirectServers = []netip.AddrPort{network}
		c.TunnelServers = []netip.AddrPort{public}
	})
	// The fake engine "tunnel" is a real loopback dialer for DNS purposes.
	h.router.SetEngine(&loopEngine{})
	ask := func(name string) string {
		c, err := h.client.DialUDP(netip.MustParseAddrPort("8.8.8.8:53"))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write(dnsQuery(name))
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 1500)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var p dnsmessage.Parser
		p.Start(buf[:n])
		p.SkipAllQuestions()
		a, err := p.AnswerHeader()
		if err != nil || a.Type != dnsmessage.TypeA {
			return ""
		}
		r, _ := p.AResource()
		return netip.AddrFrom4(r.A).String()
	}
	if ip := ask("www.bank.example"); ip != "10.1.1.1" {
		t.Fatalf("excluded name resolved via %s, want network DNS", ip)
	}
	if ip := ask("news.example"); ip != "20.2.2.2" {
		t.Fatalf("other name resolved via %s, want public DNS through tunnel", ip)
	}
	// The answer for the excluded name is now used for routing without SNI.
	if h.cache.Lookup(netip.MustParseAddr("10.1.1.1")) != "www.bank.example" {
		t.Fatal("DNS answer not cached for routing")
	}
}

// loopEngine dials loopback directly; used where the test only needs a
// working tunnel path.
type loopEngine struct{}

func (loopEngine) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp4", dst.String())
}
func (loopEngine) DialUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "udp4", dst.String())
}
func (loopEngine) Name() string    { return "loop" }
func (loopEngine) NativeUDP() bool { return true }
func (loopEngine) Close() error    { return nil }

func TestSettingsChangeLive(t *testing.T) {
	h := newHarness(t, nil, nil)
	h.router.SetEngine(h.tunnel)
	if resp, _ := h.tcp(t, "198.51.100.30:443", tlsHello("bank.example")); path(resp) != "T" {
		t.Fatal("no exclusions: must use tunnel")
	}
	set, _ := rules.NewSet([]string{"bank.example"})
	h.router.SetSettings(Settings{Exclusions: set})
	if resp, _ := h.tcp(t, "198.51.100.30:443", tlsHello("bank.example")); path(resp) != "D" {
		t.Fatal("new exclusion must apply to new flows without reconnect")
	}
}

func TestFlowAccounting(t *testing.T) {
	h := newHarness(t, []string{"bank.example"}, nil)
	h.router.SetEngine(h.tunnel)

	// An open connection shows up in the flow table with live byte counts.
	payload := tlsHello("online.bank.example")
	c, err := h.client.DialTCP(netip.MustParseAddrPort("198.51.100.50:443"), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.Write(payload)
	var flows []FlowInfo
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		flows = h.router.Flows(10)
		if len(flows) == 1 && flows[0].Up == int64(len(payload)) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(flows) != 1 || flows[0].Host != "online.bank.example" || flows[0].Route != "direct" || flows[0].Proto != "tcp" || flows[0].Up != int64(len(payload)) {
		t.Fatalf("flows: %+v", flows)
	}
	c.Close()
	for time.Now().Before(deadline) && h.router.ActiveFlows() > 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if n := h.router.ActiveFlows(); n != 0 {
		t.Fatalf("closed flow still listed (%d)", n)
	}

	// A full exchange is counted in both directions on the tunnel side.
	resp, err := h.tcp(t, "198.51.100.51:443", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	s := &h.router.Stats
	if s.BytesDirectUp.Load() != int64(len(payload)) {
		t.Fatalf("direct up = %d", s.BytesDirectUp.Load())
	}
	if s.BytesTunnelUp.Load() != 5 || s.BytesTunnelDown.Load() != int64(len(resp)) {
		t.Fatalf("tunnel up/down = %d/%d, resp %d", s.BytesTunnelUp.Load(), s.BytesTunnelDown.Load(), len(resp))
	}
}

func TestTunnelOnlyWinsOverExclusions(t *testing.T) {
	h := newHarness(t, []string{"ru"}, nil)
	h.router.SetEngine(h.tunnel)
	excl, _ := rules.NewSet([]string{"ru"})
	forced, _ := rules.NewTunnelSet([]string{"mail.ru"})
	h.router.SetSettings(Settings{Exclusions: excl, TunnelOnly: forced})
	if resp, _ := h.tcp(t, "198.51.100.60:443", tlsHello("yandex.ru")); path(resp) != "D" {
		t.Fatal("excluded zone must go direct")
	}
	if resp, _ := h.tcp(t, "198.51.100.60:443", tlsHello("e.mail.ru")); path(resp) != "T" {
		t.Fatal("VPN-only domain must use the tunnel despite the exclusion")
	}
	h.cache.Put(netip.MustParseAddr("198.51.100.61"), "cloud.mail.ru", time.Minute)
	if resp, _ := h.tcp(t, "198.51.100.61:9000", []byte("raw")); path(resp) != "T" {
		t.Fatal("VPN-only via DNS cache must use the tunnel")
	}
	// While the tunnel is down VPN-only domains are rejected, not sent direct.
	h.router.SetEngine(nil)
	if _, err := h.tcp(t, "198.51.100.60:443", tlsHello("e.mail.ru")); err == nil {
		t.Fatal("VPN-only domain must be blocked while the tunnel is down")
	}
}

func TestAddressExclusions(t *testing.T) {
	h := newHarness(t, nil, nil)
	h.router.SetEngine(h.tunnel)
	excl, errs := rules.NewSet([]string{"198.51.100.80", "198.51.100.96/28"})
	if errs != nil {
		t.Fatal(errs)
	}
	h.router.SetSettings(Settings{Exclusions: excl})
	ssh := []byte("SSH-2.0-OpenSSH_9.9\r\n")
	if resp, _ := h.tcp(t, "198.51.100.80:22", ssh); path(resp) != "D" {
		t.Fatal("excluded address must go direct")
	}
	if resp, _ := h.tcp(t, "198.51.100.100:22", ssh); path(resp) != "D" {
		t.Fatal("excluded subnet must go direct")
	}
	if resp, _ := h.tcp(t, "198.51.100.81:22", ssh); path(resp) != "T" {
		t.Fatal("other addresses must use the tunnel")
	}
	// The name on the connection does not matter for an excluded address...
	h.cache.Put(netip.MustParseAddr("198.51.100.80"), "vpn-only.example", time.Minute)
	if resp, _ := h.tcp(t, "198.51.100.80:22", ssh); path(resp) != "D" {
		t.Fatal("address exclusion must win over the DNS name")
	}
	// ...and it keeps working while the tunnel is down.
	h.router.SetEngine(nil)
	if resp, _ := h.tcp(t, "198.51.100.80:22", ssh); path(resp) != "D" {
		t.Fatal("excluded address must stay reachable while the tunnel is down")
	}
}

func TestVPNListIncludeMode(t *testing.T) {
	h := newHarness(t, nil, nil)
	h.router.SetEngine(h.tunnel)
	vpn, _ := rules.NewTunnelSet([]string{"youtube.com"})
	h.router.SetSettings(Settings{TunnelOnly: vpn})
	if resp, _ := h.tcp(t, "198.51.100.70:443", tlsHello("www.youtube.com")); path(resp) != "T" {
		t.Fatal("listed domain must use the tunnel")
	}
	if resp, _ := h.tcp(t, "198.51.100.70:443", tlsHello("example.org")); path(resp) != "D" {
		t.Fatal("unlisted domain must go direct")
	}
	if resp, _ := h.tcp(t, "198.51.100.71:9000", []byte("raw")); path(resp) != "D" {
		t.Fatal("unknown destination must go direct in include mode")
	}
	if resp, _ := h.tcp(t, "198.51.100.70:443", tlsHello("api.ipify.org")); path(resp) != "T" {
		t.Fatal("self-check hosts must always use the tunnel")
	}
	// Tunnel down: unlisted sites keep working, listed ones are blocked.
	h.router.SetEngine(nil)
	if resp, _ := h.tcp(t, "198.51.100.70:443", tlsHello("example.org")); path(resp) != "D" {
		t.Fatal("unlisted domain must stay direct while the tunnel is down")
	}
	if _, err := h.tcp(t, "198.51.100.70:443", tlsHello("youtube.com")); err == nil {
		t.Fatal("listed domain must be blocked while the tunnel is down")
	}
}

func TestVPNListWildcard(t *testing.T) {
	h := newHarness(t, nil, nil)
	h.router.SetEngine(h.tunnel)
	excl, _ := rules.NewSet([]string{"vk.com"})
	vpn, _ := rules.NewTunnelSet([]string{"*", "full:vk.com"})
	h.router.SetSettings(Settings{Exclusions: excl, TunnelOnly: vpn})
	if resp, _ := h.tcp(t, "198.51.100.72:443", tlsHello("m.vk.com")); path(resp) != "D" {
		t.Fatal("exclusion must win over *")
	}
	if resp, _ := h.tcp(t, "198.51.100.72:443", tlsHello("vk.com")); path(resp) != "T" {
		t.Fatal("exact VPN rule must win over the suffix exclusion")
	}
	if resp, _ := h.tcp(t, "198.51.100.73:9000", []byte("raw")); path(resp) != "T" {
		t.Fatal("unknown destination must use the tunnel with *")
	}
}
