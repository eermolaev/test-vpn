// Package flowrouter decides for every captured flow whether it goes through
// the tunnel engine, directly through the physical interface (excluded
// domains, SPLIT-002), or is rejected (kill switch, SEC-KILL-001).
package flowrouter

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eermolaev/test-vpn/core/dnsintercept"
	"github.com/eermolaev/test-vpn/core/engine"
	"github.com/eermolaev/test-vpn/core/netstack"
	"github.com/eermolaev/test-vpn/core/rules"
	"github.com/eermolaev/test-vpn/core/sniff"
)

// Route is the outcome of a routing decision.
type Route int

const (
	Tunnel Route = iota
	Direct
	Reject
)

func (r Route) String() string {
	return [...]string{"tunnel", "direct", "reject"}[r]
}

// Source tells how the destination host was learned.
type Source string

const (
	SourceSNI  Source = "sni"
	SourceHTTP Source = "http"
	SourceQUIC Source = "quic"
	SourceDNS  Source = "dns"
	SourceNone Source = "none"
)

// Decision is a routing decision for one flow.
type Decision struct {
	Route  Route
	Host   string
	Source Source
	Reason string
}

// Settings can be replaced at runtime; they apply to new flows (SPLIT-001).
type Settings struct {
	Exclusions *rules.Set
	// TunnelOnly lists domains that must never be reached directly; they win
	// over exclusions (e.g. exclude "ru" but keep "mail.ru" in the VPN).
	TunnelOnly *rules.Set
	// BlockQUICInTunnel drops QUIC (UDP 443) in the tunnel when the engine does
	// not carry UDP natively, so browsers fall back to TCP (spec 4.2).
	BlockQUICInTunnel bool
}

// Stats counts flows by route.
type Stats struct {
	TCPTunnel, TCPDirect, TCPReject atomic.Int64
	UDPTunnel, UDPDirect, UDPReject atomic.Int64
	DNSQueries                      atomic.Int64
	// Payload bytes of relayed flows; up is app -> internet.
	BytesTunnelUp, BytesTunnelDown atomic.Int64
	BytesDirectUp, BytesDirectDown atomic.Int64
}

const (
	sniffTimeout    = 300 * time.Millisecond
	quicWait        = 50 * time.Millisecond
	dialTimeout     = 10 * time.Second
	udpIdleTimeout  = 60 * time.Second
	dnsIdleTimeout  = 20 * time.Second
	maxDatagram     = 65535
	relayBufferSize = 16 << 10
)

var bufPool = sync.Pool{New: func() any { b := make([]byte, relayBufferSize); return &b }}

type engineRef struct{ e engine.Engine }

// Router implements netstack.Handler.
type Router struct {
	direct   engine.Dialer
	resolver *dnsintercept.Resolver
	cache    *dnsintercept.Cache
	settings atomic.Pointer[Settings]
	eng      atomic.Pointer[engineRef]

	Stats Stats
	flows flowTable
	// OnDecision, if set, is called for every flow (diagnostics, tests).
	OnDecision func(f netstack.Flow, proto string, d Decision)
}

// New creates a router. The engine starts as nil (tunnel down).
func New(direct engine.Dialer, resolver *dnsintercept.Resolver, cache *dnsintercept.Cache, s Settings) *Router {
	r := &Router{direct: direct, resolver: resolver, cache: cache}
	r.settings.Store(&s)
	r.eng.Store(&engineRef{})
	return r
}

// SetSettings replaces the settings for new flows.
func (r *Router) SetSettings(s Settings) { r.settings.Store(&s) }

// Settings returns the current settings.
func (r *Router) Settings() Settings { return *r.settings.Load() }

// SetEngine switches the active engine; nil means the tunnel is down and
// non-excluded flows are rejected. Flows already using the old engine keep it
// until the engine is closed.
func (r *Router) SetEngine(e engine.Engine) {
	r.eng.Store(&engineRef{e: e})
	if e == nil {
		r.resolver.SetTunnel(nil)
		return
	}
	r.resolver.SetTunnel(func(ctx context.Context, network string, s netip.AddrPort) (net.Conn, error) {
		if network == "tcp" {
			return e.DialTCP(ctx, s)
		}
		return e.DialUDP(ctx, s)
	})
}

// Engine returns the active engine or nil.
func (r *Router) Engine() engine.Engine { return r.eng.Load().e }

// Decide routes a flow to dst, given the sniffed host (may be empty).
func (r *Router) Decide(dst netip.AddrPort, host string, src Source) Decision {
	if !dst.Addr().Unmap().Is4() {
		return Decision{Route: Reject, Reason: "ipv6 disabled"}
	}
	s := r.settings.Load()
	d := Decision{Route: Tunnel, Host: host, Source: src}
	direct := func(h string) bool { return s.Exclusions.Match(h) && !s.TunnelOnly.Covers(h) }
	switch {
	case host != "":
		// The sniffed name wins over the DNS cache: two domains may share a
		// CDN address, only the excluded one goes direct.
		if direct(host) {
			d.Route = Direct
		}
	default:
		if h := r.cache.Lookup(dst.Addr()); h != "" {
			d.Host, d.Source = h, SourceDNS
			if direct(h) {
				d.Route = Direct
			}
		} else {
			d.Source = SourceNone
		}
	}
	if d.Route == Tunnel && r.Engine() == nil {
		d.Route, d.Reason = Reject, "tunnel down"
	}
	return d
}

func (r *Router) dialerFor(d Decision) (engine.Dialer, engine.Engine) {
	switch d.Route {
	case Direct:
		return r.direct, nil
	case Tunnel:
		if e := r.Engine(); e != nil {
			return e, e
		}
	}
	return nil, nil
}

func (r *Router) notify(f netstack.Flow, proto string, d Decision) {
	if r.OnDecision != nil {
		r.OnDecision(f, proto, d)
	}
}

// AcceptTCP rejects flows that can never be served before the handshake, so
// the app gets an immediate RST.
func (r *Router) AcceptTCP(f netstack.Flow) bool {
	if !f.Dst.Addr().Unmap().Is4() {
		r.Stats.TCPReject.Add(1)
		r.notify(f, "tcp", Decision{Route: Reject, Reason: "ipv6 disabled"})
		return false
	}
	if r.Engine() == nil && r.settings.Load().Exclusions.Len() == 0 && f.Dst.Port() != 53 {
		r.Stats.TCPReject.Add(1)
		r.notify(f, "tcp", Decision{Route: Reject, Reason: "tunnel down"})
		return false
	}
	return true
}

// HandleTCP sniffs, routes and relays a TCP flow.
func (r *Router) HandleTCP(c *netstack.TCPConn) {
	if c.Flow.Dst.Port() == 53 {
		r.serveDNSOverTCP(c)
		return
	}
	prefix, host, proto := sniffStream(c)
	src := SourceNone
	switch proto {
	case sniff.TLS:
		src = SourceSNI
	case sniff.HTTP:
		src = SourceHTTP
	}
	d := r.Decide(c.Flow.Dst, host, src)
	dialer, _ := r.dialerFor(d)
	if dialer == nil {
		r.Stats.TCPReject.Add(1)
		r.notify(c.Flow, "tcp", d)
		c.Abort()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	out, err := dialer.DialTCP(ctx, c.Flow.Dst)
	cancel()
	if err != nil {
		d.Reason = "dial: " + err.Error()
		r.Stats.TCPReject.Add(1)
		r.notify(c.Flow, "tcp", Decision{Route: Reject, Host: d.Host, Source: d.Source, Reason: d.Reason})
		c.Abort()
		return
	}
	if d.Route == Direct {
		r.Stats.TCPDirect.Add(1)
	} else {
		r.Stats.TCPTunnel.Add(1)
	}
	r.notify(c.Flow, "tcp", d)
	fe := r.track("tcp", c.Flow, d)
	defer r.untrack(fe)
	if len(prefix) > 0 {
		if _, err := out.Write(prefix); err != nil {
			out.Close()
			c.Abort()
			return
		}
		fe.addUp(len(prefix))
	}
	relayTCP(c, out, fe)
}

// sniffStream reads the first bytes of a connection until a host is found,
// the data is not a known protocol, or the timeout expires (server-speaks-
// first protocols send nothing).
func sniffStream(c net.Conn) ([]byte, string, sniff.Protocol) {
	var buf []byte
	tmp := make([]byte, 4096)
	deadline := time.Now().Add(sniffTimeout)
	defer c.SetReadDeadline(time.Time{})
	for len(buf) < sniff.MaxStreamPrefix {
		c.SetReadDeadline(deadline)
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if n > 0 {
			host, proto, serr := sniff.Stream(buf)
			if serr == nil {
				return buf, host, proto
			}
			if !errors.Is(serr, sniff.ErrNeedMore) {
				return buf, "", ""
			}
		}
		if err != nil {
			return buf, "", ""
		}
	}
	return buf, "", ""
}

type closeWriter interface{ CloseWrite() error }

// relayTCP relays between the app side a and the outbound side b.
func relayTCP(a, b net.Conn, fe *flowEntry) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn, add func(int)) {
		defer wg.Done()
		bp := bufPool.Get().(*[]byte)
		err := copyCounting(dst, src, *bp, add)
		bufPool.Put(bp)
		if cw, ok := dst.(closeWriter); ok && err == nil {
			cw.CloseWrite()
		} else {
			dst.Close()
			src.Close()
		}
	}
	wg.Add(2)
	go cp(a, b, fe.addDown)
	go cp(b, a, fe.addUp)
	wg.Wait()
	a.Close()
	b.Close()
}

// AcceptUDP drops IPv6 UDP flows.
func (r *Router) AcceptUDP(f netstack.Flow) bool {
	if !f.Dst.Addr().Unmap().Is4() {
		r.Stats.UDPReject.Add(1)
		r.notify(f, "udp", Decision{Route: Reject, Reason: "ipv6 disabled"})
		return false
	}
	return true
}

// HandleUDP routes and relays a UDP flow. DNS is answered by the resolver.
func (r *Router) HandleUDP(c *netstack.UDPConn) {
	defer c.Close()
	if c.Flow.Dst.Port() == 53 {
		r.serveDNSOverUDP(c)
		return
	}
	first := make([]byte, maxDatagram)
	c.SetReadDeadline(time.Now().Add(udpIdleTimeout))
	n, err := c.Read(first)
	if err != nil {
		return
	}
	pending := [][]byte{append([]byte(nil), first[:n]...)}
	host, isQUIC := "", false
	if looksLikeQUICInitial(pending[0]) {
		isQUIC = true
		var qs sniff.QUICSniffer
		h, serr := qs.Feed(pending[0])
		for errors.Is(serr, sniff.ErrNeedMore) {
			c.SetReadDeadline(time.Now().Add(quicWait))
			n, err := c.Read(first)
			if err != nil {
				break
			}
			pkt := append([]byte(nil), first[:n]...)
			pending = append(pending, pkt)
			h, serr = qs.Feed(pkt)
		}
		if serr == nil {
			host = h
		}
	}
	src := SourceNone
	if host != "" {
		src = SourceQUIC
	}
	d := r.Decide(c.Flow.Dst, host, src)
	dialer, eng := r.dialerFor(d)
	if d.Route == Tunnel && isQUIC && c.Flow.Dst.Port() == 443 && eng != nil && !eng.NativeUDP() && r.settings.Load().BlockQUICInTunnel {
		d = Decision{Route: Reject, Host: d.Host, Source: d.Source, Reason: "quic blocked in tunnel"}
		dialer = nil
	}
	if dialer == nil {
		r.Stats.UDPReject.Add(1)
		r.notify(c.Flow, "udp", d)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	out, err := dialer.DialUDP(ctx, c.Flow.Dst)
	cancel()
	if err != nil {
		r.Stats.UDPReject.Add(1)
		r.notify(c.Flow, "udp", Decision{Route: Reject, Host: d.Host, Source: d.Source, Reason: "dial: " + err.Error()})
		return
	}
	defer out.Close()
	if d.Route == Direct {
		r.Stats.UDPDirect.Add(1)
	} else {
		r.Stats.UDPTunnel.Add(1)
	}
	r.notify(c.Flow, "udp", d)
	proto := "udp"
	if isQUIC {
		proto = "quic"
	}
	fe := r.track(proto, c.Flow, d)
	defer r.untrack(fe)
	for _, p := range pending {
		if _, err := out.Write(p); err != nil {
			return
		}
		fe.addUp(len(p))
	}
	relayUDP(c, out, fe)
}

func looksLikeQUICInitial(b []byte) bool {
	return len(b) >= 1200 && b[0]&0xc0 == 0xc0
}

func relayUDP(app, out net.Conn, fe *flowEntry) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn, add func(int)) {
		buf := make([]byte, maxDatagram)
		for {
			src.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			n, err := src.Read(buf)
			if err != nil {
				break
			}
			if _, err := dst.Write(buf[:n]); err != nil {
				break
			}
			add(n)
		}
		done <- struct{}{}
	}
	go cp(out, app, fe.addUp)
	go cp(app, out, fe.addDown)
	<-done
	app.Close()
	out.Close()
	<-done
}

func (r *Router) serveDNSOverUDP(c *netstack.UDPConn) {
	buf := make([]byte, maxDatagram)
	for {
		c.SetReadDeadline(time.Now().Add(dnsIdleTimeout))
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		r.Stats.DNSQueries.Add(1)
		go func() {
			if resp := r.resolver.Serve(context.Background(), q); resp != nil {
				c.Write(resp)
			}
		}()
	}
}

func (r *Router) serveDNSOverTCP(c *netstack.TCPConn) {
	defer c.Close()
	var lb [2]byte
	for {
		c.SetReadDeadline(time.Now().Add(dnsIdleTimeout))
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		r.Stats.DNSQueries.Add(1)
		resp := r.resolver.Serve(context.Background(), q)
		if resp == nil {
			return
		}
		if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(resp))), resp...)); err != nil {
			return
		}
	}
}
