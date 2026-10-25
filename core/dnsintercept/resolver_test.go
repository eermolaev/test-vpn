package dnsintercept

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eermolaev/test-vpn/core/rules"
	"golang.org/x/net/dns/dnsmessage"
)

// fakeDNS answers every A query with ip. With truncateUDP it sets TC on UDP
// answers, forcing a TCP retry.
type fakeDNS struct {
	ip          [4]byte
	truncateUDP bool
	udp         *net.UDPConn
	tcp         net.Listener
	udpQueries  atomic.Int64
	tcpQueries  atomic.Int64
}

func startFakeDNS(t *testing.T, ip [4]byte, truncate bool) *fakeDNS {
	t.Helper()
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp4", u.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeDNS{ip: ip, truncateUDP: truncate, udp: u, tcp: l}
	t.Cleanup(func() { u.Close(); l.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := u.ReadFromUDP(buf)
			if err != nil {
				return
			}
			f.udpQueries.Add(1)
			u.WriteToUDP(f.answer(buf[:n], f.truncateUDP), addr)
		}
	}()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var lb [2]byte
				if _, err := io.ReadFull(c, lb[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(lb[:]))
				io.ReadFull(c, q)
				f.tcpQueries.Add(1)
				a := f.answer(q, false)
				c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(a))), a...))
			}()
		}
	}()
	return f
}

func (f *fakeDNS) addr() netip.AddrPort { return netip.MustParseAddrPort(f.udp.LocalAddr().String()) }

func (f *fakeDNS) answer(q []byte, tc bool) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil {
		return nil
	}
	qs, _ := p.Question()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Truncated: tc, RecursionAvailable: true})
	b.StartQuestions()
	b.Question(qs)
	b.StartAnswers()
	if !tc && qs.Type == dnsmessage.TypeA {
		b.AResource(dnsmessage.ResourceHeader{Name: qs.Name, Class: dnsmessage.ClassINET, TTL: 300}, dnsmessage.AResource{A: f.ip})
	}
	out, _ := b.Finish()
	return out
}

func query(t *testing.T, name string, id uint16) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func rcodeAndIP(t *testing.T, resp []byte) (dnsmessage.RCode, string) {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		t.Fatal(err)
	}
	ips, _ := answerIPs(resp)
	ip := ""
	if len(ips) > 0 {
		ip = ips[0].String()
	}
	return h.RCode, ip
}

// countingDial dials loopback and counts calls, standing in for the direct
// dialer or the tunnel engine.
func countingDial(n *atomic.Int64) DialFunc {
	return func(ctx context.Context, network string, s netip.AddrPort) (net.Conn, error) {
		n.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, s.String())
	}
}

func TestSplitDNS(t *testing.T) {
	network := startFakeDNS(t, [4]byte{10, 0, 0, 1}, false)
	public := startFakeDNS(t, [4]byte{20, 0, 0, 1}, false)
	excl, _ := rules.NewSet([]string{"bank.example"})
	var directDials, tunnelDials atomic.Int64
	cache := NewCache(0)
	r := NewResolver(cache, countingDial(&directDials), Config{
		Exclusions:    excl,
		TunnelServers: []netip.AddrPort{public.addr()},
		DirectServers: []netip.AddrPort{network.addr()},
	})

	// Tunnel down: non-excluded names get SERVFAIL, excluded still resolve.
	if rc, _ := rcodeAndIP(t, r.Serve(context.Background(), query(t, "news.example", 1))); rc != dnsmessage.RCodeServerFailure {
		t.Fatalf("tunnel down: rcode %v", rc)
	}
	rc, ip := rcodeAndIP(t, r.Serve(context.Background(), query(t, "www.bank.example", 2)))
	if rc != dnsmessage.RCodeSuccess || ip != "10.0.0.1" {
		t.Fatalf("excluded while down: %v %s", rc, ip)
	}
	if cache.Lookup(netip.MustParseAddr("10.0.0.1")) != "www.bank.example" {
		t.Fatal("answer not cached")
	}

	r.SetTunnel(countingDial(&tunnelDials))
	rc, ip = rcodeAndIP(t, r.Serve(context.Background(), query(t, "news.example", 3)))
	if rc != dnsmessage.RCodeSuccess || ip != "20.0.0.1" {
		t.Fatalf("tunnel query: %v %s", rc, ip)
	}
	if network.udpQueries.Load() != 1 || public.udpQueries.Load() != 1 {
		t.Fatalf("queries network=%d public=%d", network.udpQueries.Load(), public.udpQueries.Load())
	}

	// Many concurrent queries with the same client ID share one tunnel conn.
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			q := query(t, "multi.example", 7)
			resp := r.Serve(context.Background(), q)
			if resp[0] != q[0] || resp[1] != q[1] {
				t.Error("ID not restored")
			}
			if rc, ip := rcodeAndIP(t, resp); rc != dnsmessage.RCodeSuccess || ip != "20.0.0.1" {
				t.Errorf("concurrent: %v %s", rc, ip)
			}
		}()
	}
	wg.Wait()
	if tunnelDials.Load() != 1 {
		t.Fatalf("tunnel dials = %d, want 1 (multiplexed)", tunnelDials.Load())
	}
	if r.Stats.Direct.Load() != 1 || r.Stats.Tunnel.Load() != 51 || r.Stats.Failed.Load() != 1 {
		t.Fatalf("stats %d/%d/%d", r.Stats.Direct.Load(), r.Stats.Tunnel.Load(), r.Stats.Failed.Load())
	}
}

func TestPublicModeAndTruncation(t *testing.T) {
	public := startFakeDNS(t, [4]byte{20, 0, 0, 2}, true)
	excl, _ := rules.NewSet([]string{"bank.example"})
	var directDials atomic.Int64
	r := NewResolver(NewCache(0), countingDial(&directDials), Config{
		Exclusions:    excl,
		TunnelServers: []netip.AddrPort{public.addr()},
	})
	// No direct servers: excluded names go to the public resolver, directly.
	rc, ip := rcodeAndIP(t, r.Serve(context.Background(), query(t, "bank.example", 9)))
	if rc != dnsmessage.RCodeSuccess || ip != "20.0.0.2" || public.tcpQueries.Load() != 1 {
		t.Fatalf("truncated retry: %v %s tcp=%d", rc, ip, public.tcpQueries.Load())
	}
	if directDials.Load() != 2 {
		t.Fatalf("direct dials = %d", directDials.Load())
	}
}

func TestFailoverToSecondServer(t *testing.T) {
	good := startFakeDNS(t, [4]byte{20, 0, 0, 3}, false)
	dead := netip.MustParseAddrPort("127.0.0.1:1") // nothing listens
	var n atomic.Int64
	r := NewResolver(NewCache(0), countingDial(&n), Config{TunnelServers: []netip.AddrPort{dead, good.addr()}})
	r.SetTunnel(countingDial(&n))
	start := time.Now()
	if rc, ip := rcodeAndIP(t, r.Serve(context.Background(), query(t, "x.example", 1))); rc != dnsmessage.RCodeSuccess || ip != "20.0.0.3" {
		t.Fatalf("failover: %v %s", rc, ip)
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("failover too slow")
	}
}

func TestMalformed(t *testing.T) {
	r := NewResolver(NewCache(0), nil, Config{})
	if resp := r.Serve(context.Background(), []byte{1, 2, 3}); resp != nil {
		t.Fatal("garbage must produce no reply")
	}
}

func TestCacheLimits(t *testing.T) {
	c := NewCache(3)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		c.Put(netip.AddrFrom4([4]byte{1, 1, 1, byte(i)}), "h", time.Second)
	}
	if c.Len() > 3 {
		t.Fatalf("len %d", c.Len())
	}
	c.Put(netip.MustParseAddr("9.9.9.9"), "nine", time.Second) // clamped to 60s
	now = now.Add(59 * time.Second)
	if c.Lookup(netip.MustParseAddr("9.9.9.9")) != "nine" {
		t.Fatal("min TTL not applied")
	}
	now = now.Add(2 * time.Second)
	if c.Lookup(netip.MustParseAddr("9.9.9.9")) != "" {
		t.Fatal("entry must expire")
	}
}
