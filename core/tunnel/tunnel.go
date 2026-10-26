package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/eermolaev/test-vpn/core/direct"
	"github.com/eermolaev/test-vpn/core/dnsintercept"
	"github.com/eermolaev/test-vpn/core/engine"
	"github.com/eermolaev/test-vpn/core/errclass"
	"github.com/eermolaev/test-vpn/core/fallback"
	"github.com/eermolaev/test-vpn/core/flowrouter"
	"github.com/eermolaev/test-vpn/core/netstack"
	"github.com/eermolaev/test-vpn/core/profile"
	"golang.org/x/net/dns/dnsmessage"
)

// Starter starts an engine for a transport. ctx bounds the connection
// attempt (T_fail).
type Starter func(ctx context.Context, t profile.Transport) (engine.Engine, error)

// Deps are injectable dependencies.
type Deps struct {
	Starter  Starter          // default: real engines
	Memory   *fallback.Memory // per-network transport memory (may be nil)
	Logf     func(string)     // receives redacted log lines
	OnStatus func(Status)
	// Direct overrides the direct dialer (tests).
	Direct engine.Dialer
}

// Tunnel is a running client.
type Tunnel struct {
	cfg      Config
	deps     Deps
	direct   *direct.Dialer
	cache    *dnsintercept.Cache
	resolver *dnsintercept.Resolver
	router   *flowrouter.Router
	stack    *netstack.Stack
	redact   func(string) string

	ctx    context.Context
	cancel context.CancelFunc
	wakeCh chan struct{}
	done   chan struct{}

	mu          sync.Mutex
	status      Status
	eng         engine.Engine
	netKey      string
	dnsShown    []string
	dnsAddrs    []netip.AddrPort // tunnel resolvers, also used for health checks
	udpWarned   engine.Engine
	dialFailLog map[string]time.Time
}

// Start validates cfg, starts the stack with the kill switch active, and
// connects in the background.
func Start(pio netstack.PacketIO, cfg Config, deps Deps) (*Tunnel, error) {
	if cfg.Profile == nil {
		return nil, errNoProfile
	}
	if err := cfg.Profile.Validate(); err != nil {
		return nil, errclass.Wrap(errclass.Config, err)
	}
	cfg.defaults()
	comp, err := cfg.Settings.compile()
	if err != nil {
		return nil, err
	}
	if _, err := fallback.NewPlanner(cfg.Profile, cfg.Policy, fallback.Options{Manual: cfg.ManualTransport}); err != nil {
		return nil, errclass.Wrap(errclass.Config, err)
	}
	if deps.Starter == nil {
		deps.Starter = DefaultStarter(deps.Logf)
	}
	if deps.Memory == nil {
		deps.Memory = fallback.NewMemory(nil)
	}
	redactor := profile.NewRedactor(cfg.Profile.Secrets())
	t := &Tunnel{
		cfg:    cfg,
		deps:   deps,
		direct: &direct.Dialer{},
		cache:  dnsintercept.NewCache(0),
		redact: redactor.Redact,
		wakeCh: make(chan struct{}, 1),
		done:   make(chan struct{}),
		netKey: fallback.NetworkKey(cfg.NetworkID),
	}
	t.direct.SetInterface(cfg.InterfaceIndex, cfg.InterfaceName)
	var directDialer engine.Dialer = t.direct
	if deps.Direct != nil {
		directDialer = deps.Direct
	}
	directDNS := func(ctx context.Context, network string, s netip.AddrPort) (net.Conn, error) {
		if network == "tcp" {
			return directDialer.DialTCP(ctx, s)
		}
		return directDialer.DialUDP(ctx, s)
	}
	t.resolver = dnsintercept.NewResolver(t.cache, directDNS, comp.dns)
	t.router = flowrouter.New(directDialer, t.resolver, t.cache, comp.router)
	t.router.OnDecision = t.logDialFailure
	t.dnsShown = serversString(comp.dns.TunnelServers)
	t.dnsAddrs = comp.dns.TunnelServers
	t.status = Status{State: StateConnecting, Since: time.Now(), Exclusions: comp.router.Exclusions.Len(), DNSServers: t.dnsShown}
	so := cfg.Stack
	so.MTU = cfg.MTU
	st, err := netstack.New(pio, t.router, so)
	if err != nil {
		return nil, err
	}
	t.stack = st
	t.ctx, t.cancel = context.WithCancel(context.Background())
	go t.run()
	return t, nil
}

// logDialFailure logs flows that were reset because the outbound connection
// could not be opened, at most once a minute per host and route, so that
// "connection reset" in an app has a visible cause.
func (t *Tunnel) logDialFailure(f netstack.Flow, proto string, d flowrouter.Decision) {
	if d.Route != flowrouter.Reject || !strings.HasPrefix(d.Reason, "dial: ") {
		return
	}
	host := d.Host
	if host == "" {
		host = f.Dst.Addr().String()
	}
	route := "tunnel"
	if p := t.router.Settings().Policy(); p.Direct(d.Host) || p.DirectAddr(f.Dst.Addr(), d.Host) {
		route = "direct"
	}
	key := route + "|" + host
	now := time.Now()
	t.mu.Lock()
	if t.dialFailLog == nil {
		t.dialFailLog = map[string]time.Time{}
	}
	if last, ok := t.dialFailLog[key]; ok && now.Sub(last) < time.Minute {
		t.mu.Unlock()
		return
	}
	if len(t.dialFailLog) > 256 {
		t.dialFailLog = map[string]time.Time{}
	}
	t.dialFailLog[key] = now
	t.mu.Unlock()
	t.logf("%s %s connection to %s (%s) failed: %s", route, proto, host, f.Dst, strings.TrimPrefix(d.Reason, "dial: "))
}

func serversString(s []netip.AddrPort) []string {
	out := make([]string, len(s))
	for i, a := range s {
		if a.Port() == 53 {
			out[i] = a.Addr().String()
		} else {
			out[i] = a.String()
		}
	}
	return out
}

func (t *Tunnel) logf(format string, a ...any) {
	if t.deps.Logf != nil {
		t.deps.Logf(t.redact(fmt.Sprintf(format, a...)))
	}
}

func (t *Tunnel) setStatus(f func(*Status)) {
	t.mu.Lock()
	f(&t.status)
	s := t.snapshotLocked()
	t.mu.Unlock()
	if t.deps.OnStatus != nil {
		t.deps.OnStatus(s)
	}
}

func (t *Tunnel) snapshotLocked() Status {
	s := t.status
	rs := &t.router.Stats
	ds := &t.resolver.Stats
	s.Stats = Stats{
		TCPTunnel: rs.TCPTunnel.Load(), TCPDirect: rs.TCPDirect.Load(), TCPReject: rs.TCPReject.Load(),
		UDPTunnel: rs.UDPTunnel.Load(), UDPDirect: rs.UDPDirect.Load(), UDPReject: rs.UDPReject.Load(),
		DNSQueries: rs.DNSQueries.Load(), DNSDirect: ds.Direct.Load(), DNSTunnel: ds.Tunnel.Load(), DNSFailed: ds.Failed.Load(),
		BytesTunnelUp: rs.BytesTunnelUp.Load(), BytesTunnelDown: rs.BytesTunnelDown.Load(),
		BytesDirectUp: rs.BytesDirectUp.Load(), BytesDirectDown: rs.BytesDirectDown.Load(),
		ActiveFlows: t.router.ActiveFlows(),
	}
	s.DNSServers = append([]string(nil), t.dnsShown...)
	return s
}

// Status returns the current status.
func (t *Tunnel) Status() Status {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.snapshotLocked()
}

// Flows returns up to n active flows, busiest first.
func (t *Tunnel) Flows(n int) []flowrouter.FlowInfo { return t.router.Flows(n) }

// Router exposes the router (diagnostics and tests).
func (t *Tunnel) Router() *flowrouter.Router { return t.router }

func (t *Tunnel) wake() {
	select {
	case t.wakeCh <- struct{}{}:
	default:
	}
}

// Reconnect forces a health check now, and a new connection plan if the
// tunnel has failed.
func (t *Tunnel) Reconnect() { t.wake() }

// NetworkChanged updates the physical interface and network identity
// (SEC-NET-005) and re-checks the tunnel.
func (t *Tunnel) NetworkChanged(networkID string, ifIndex int, ifName string) {
	t.direct.SetInterface(ifIndex, ifName)
	t.mu.Lock()
	t.netKey = fallback.NetworkKey(networkID)
	t.mu.Unlock()
	t.wake()
}

// UpdateSettings applies new settings to new flows without reconnecting.
func (t *Tunnel) UpdateSettings(s Settings) error {
	comp, err := s.compile()
	if err != nil {
		return err
	}
	t.router.SetSettings(comp.router)
	t.resolver.SetConfig(comp.dns)
	t.mu.Lock()
	t.dnsShown = serversString(comp.dns.TunnelServers)
	t.dnsAddrs = comp.dns.TunnelServers
	t.mu.Unlock()
	t.setStatus(func(st *Status) { st.Exclusions = comp.router.Exclusions.Len() })
	return nil
}

// Stop disconnects and releases all resources.
func (t *Tunnel) Stop() {
	t.cancel()
	<-t.done
	t.stack.Close()
	t.setStatus(func(s *Status) { s.State, s.Since = StateStopped, time.Now() })
}

func (t *Tunnel) sleep(d time.Duration) bool {
	if d <= 0 {
		return t.ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-t.ctx.Done():
		return false
	}
}

func (t *Tunnel) run() {
	defer close(t.done)
	defer func() {
		t.mu.Lock()
		e := t.eng
		t.eng = nil
		t.mu.Unlock()
		t.router.SetEngine(nil)
		if e != nil {
			e.Close()
		}
	}()
	for t.ctx.Err() == nil {
		e, err := t.connect()
		if err != nil {
			if t.ctx.Err() != nil {
				return
			}
			c := errclass.Classify(err)
			t.logf("all transports failed: %v", err)
			t.setStatus(func(s *Status) {
				s.State, s.Since, s.ErrorClass, s.ErrorMessage = StateFailed, time.Now(), c, c.Message()
			})
			// Wait for a network change or an explicit retry.
			select {
			case <-t.wakeCh:
				continue
			case <-t.ctx.Done():
				return
			}
		}
		t.monitor(e)
	}
}

// connect walks the fallback plan until an engine passes the health check.
func (t *Tunnel) connect() (engine.Engine, error) {
	t.mu.Lock()
	preferred := t.deps.Memory.Preferred(t.netKey)
	t.mu.Unlock()
	pl, err := fallback.NewPlanner(t.cfg.Profile, t.cfg.Policy, fallback.Options{Manual: t.cfg.ManualTransport, Preferred: preferred})
	if err != nil {
		return nil, errclass.Wrap(errclass.Config, err)
	}
	var lastErr error
	for {
		step, ok := pl.Next(lastErr)
		if !ok {
			if lastErr == nil {
				lastErr = errors.New("no transports")
			}
			return nil, lastErr
		}
		if !t.sleep(step.Delay) {
			return nil, t.ctx.Err()
		}
		tr := t.cfg.Profile.Transports[step.Index]
		t.setStatus(func(s *Status) {
			if s.State != StateReconnecting {
				s.State = StateConnecting
			}
			s.TransportID, s.TransportKind, s.Attempt, s.Round = tr.ID(), string(tr.Kind), step.Attempt, step.Round
		})
		t.logf("connecting via %s (attempt %d, round %d)", tr.ID(), step.Attempt, step.Round)
		e, err := t.attempt(tr)
		if err != nil {
			lastErr = err
			c := errclass.Classify(err)
			t.logf("%s failed: %v", tr.ID(), err)
			t.setStatus(func(s *Status) { s.ErrorClass, s.ErrorMessage = c, c.Message(); s.Failures++ })
			continue
		}
		t.mu.Lock()
		t.eng = e
		key := t.netKey
		t.mu.Unlock()
		t.deps.Memory.Remember(key, tr.ID())
		t.router.SetEngine(e)
		t.setStatus(func(s *Status) {
			s.State, s.Since, s.ErrorClass, s.ErrorMessage = StateConnected, time.Now(), errclass.None, ""
			s.Failures = 0
		})
		t.logf("connected via %s", tr.ID())
		return e, nil
	}
}

func (t *Tunnel) attempt(tr profile.Transport) (engine.Engine, error) {
	ctx, cancel := context.WithTimeout(t.ctx, t.cfg.Policy.FailTimeout)
	defer cancel()
	e, err := t.deps.Starter(ctx, tr)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			err = errclass.Wrap(timeoutClass(tr), err)
		}
		return nil, err
	}
	if err := t.healthCheck(ctx, e); err != nil {
		e.Close()
		return nil, errclass.Wrap(timeoutClass(tr), err)
	}
	return e, nil
}

func timeoutClass(tr profile.Transport) errclass.Class {
	if tr.AWG != nil {
		return errclass.UDPTimeout
	}
	return errclass.TCPTimeout
}

// monitor checks the engine periodically. After HealthFailures consecutive
// failures the engine is dropped; until a new one is up, the router rejects
// tunneled flows and exclusions keep working (SPLIT-004).
func (t *Tunnel) monitor(e engine.Engine) {
	ticker := time.NewTicker(t.cfg.HealthInterval)
	defer ticker.Stop()
	failures := 0
	lastDown := t.router.Stats.BytesTunnelDown.Load()
	for {
		woken := false
		select {
		case <-t.ctx.Done():
			return
		case <-ticker.C:
		case <-t.wakeCh:
			woken = true
		}
		// Data arriving from the tunnel already proves it works; probe only
		// when it is idle or the user asked for a re-check.
		if down := t.router.Stats.BytesTunnelDown.Load(); down != lastDown && !woken {
			lastDown, failures = down, 0
			continue
		}
		ctx, cancel := context.WithTimeout(t.ctx, t.cfg.HealthTimeout)
		err := t.healthCheck(ctx, e)
		cancel()
		if t.ctx.Err() != nil {
			return
		}
		lastDown = t.router.Stats.BytesTunnelDown.Load()
		if err == nil {
			failures = 0
			continue
		}
		failures++
		t.logf("health check failed (%d/%d): %v", failures, t.cfg.HealthFailures, err)
		if failures < t.cfg.HealthFailures {
			continue
		}
		t.router.SetEngine(nil)
		t.mu.Lock()
		t.eng = nil
		t.mu.Unlock()
		e.Close()
		t.setStatus(func(s *Status) {
			s.State, s.Since, s.ErrorClass, s.ErrorMessage = StateReconnecting, time.Now(), errclass.Routing, errclass.Routing.Message()
		})
		return
	}
}

// healthCheck sends DNS queries through the engine to the tunnel resolvers
// over UDP and TCP at once: some VLESS servers do not relay UDP, and TCP-only
// operation is still a working tunnel. All probes share the whole time
// budget (each VLESS probe opens a new connection to the server, which can
// take seconds on a slow path), and the first well-formed answer proves that
// traffic passes the tunnel. Once UDP is known not to work for this engine,
// only TCP is probed.
func (t *Tunnel) healthCheck(ctx context.Context, e engine.Engine) error {
	servers := t.resolverServers()
	if len(servers) == 0 {
		return errors.New("no DNS servers for health check")
	}
	networks := []string{"udp", "tcp"}
	t.mu.Lock()
	if t.udpWarned == e {
		networks = []string{"tcp"}
	}
	t.mu.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan probeResult, len(servers)*len(networks))
	for _, s := range servers {
		for _, network := range networks {
			go func() {
				err := dnsProbe(ctx, e, network, s)
				if err != nil {
					err = fmt.Errorf("dns %s %s: %w", network, s, err)
				}
				results <- probeResult{network, err}
			}()
		}
	}
	var lastErr error
	for i := 0; i < cap(results); i++ {
		r := <-results
		if r.err == nil {
			if r.network == "tcp" && len(networks) == 2 && !t.udpAnswers(results, cap(results)-i-1) {
				t.warnUDPOnce(e)
			}
			return nil
		}
		if lastErr == nil || r.network == "tcp" {
			lastErr = r.err // the TCP error says more about the tunnel
		}
	}
	return errclass.Wrap(errclass.Routing, lastErr)
}

type probeResult struct {
	network string
	err     error
}

// udpAnswers waits briefly for a UDP probe to succeed after TCP did. UDP
// usually answers first; one that is still silent a second later is taken as
// not relayed, and later checks probe TCP only.
func (t *Tunnel) udpAnswers(results <-chan probeResult, pending int) bool {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for ; pending > 0; pending-- {
		select {
		case r := <-results:
			if r.network == "udp" && r.err == nil {
				return true
			}
		case <-timer.C:
			return false
		}
	}
	return false
}

func (t *Tunnel) warnUDPOnce(e engine.Engine) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.udpWarned == e {
		return
	}
	t.udpWarned = e
	t.logf("UDP does not pass through the server (TCP works): DNS uses TCP, UDP apps and QUIC will fail")
}

func (t *Tunnel) resolverServers() []netip.AddrPort {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]netip.AddrPort(nil), t.dnsAddrs...)
}

var probeName = dnsmessage.MustNewName("example.com.")

func dnsProbe(ctx context.Context, e engine.Engine, network string, server netip.AddrPort) error {
	var c net.Conn
	var err error
	if network == "tcp" {
		c, err = e.DialTCP(ctx, server)
	} else {
		c, err = e.DialUDP(ctx, server)
	}
	if err != nil {
		return err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	// Not every engine conn implements deadlines (xray does not); closing
	// the conn unblocks the read.
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	id := uint16(time.Now().UnixNano())
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: probeName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	if network == "tcp" {
		q = append([]byte{byte(len(q) >> 8), byte(len(q))}, q...)
	}
	if _, err := c.Write(q); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	for {
		var msg []byte
		if network == "tcp" {
			var l [2]byte
			if _, err = io.ReadFull(c, l[:]); err == nil {
				msg = make([]byte, int(l[0])<<8|int(l[1]))
				_, err = io.ReadFull(c, msg)
			}
		} else {
			var n int
			n, err = c.Read(buf)
			msg = buf[:n]
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		var p dnsmessage.Parser
		if h, err := p.Start(msg); err == nil && h.ID == id && h.Response {
			return nil
		}
	}
}
