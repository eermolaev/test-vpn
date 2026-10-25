package dnsintercept

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/eermolaev/test-vpn/core/rules"
	"golang.org/x/net/dns/dnsmessage"
)

// Config is the DNS part of the tunnel settings.
type Config struct {
	Exclusions *rules.Set
	// TunnelOnly is the VPN list; names follow the same rules.Policy as flows.
	TunnelOnly *rules.Set
	// TunnelServers are queried through the tunnel (default 8.8.8.8, 8.8.4.4).
	TunnelServers []netip.AddrPort
	// DirectServers resolve excluded domains outside the tunnel. When empty,
	// TunnelServers are queried directly instead (SPLIT-003 "public" mode).
	DirectServers []netip.AddrPort
}

// ErrTunnelDown is returned when a non-excluded query arrives while no engine
// is connected; the client receives SERVFAIL instead of a leaked answer.
var ErrTunnelDown = errors.New("dns: tunnel is down")

// Stats counts answered queries by route.
type Stats struct {
	Direct, Tunnel, Failed atomic.Int64
}

// Resolver answers captured DNS queries.
type Resolver struct {
	cache  *Cache
	direct DialFunc
	Stats  Stats

	mu     sync.Mutex
	cfg    Config
	tunnel DialFunc // nil while the tunnel is down
	muxes  map[netip.AddrPort]*mux
}

// NewResolver creates a resolver. direct dials outside of the tunnel.
func NewResolver(cache *Cache, direct DialFunc, cfg Config) *Resolver {
	return &Resolver{cache: cache, direct: direct, cfg: cfg, muxes: map[netip.AddrPort]*mux{}}
}

// SetConfig replaces the configuration (GEO-010 changes apply live).
func (r *Resolver) SetConfig(cfg Config) {
	r.mu.Lock()
	r.cfg = cfg
	r.resetLocked()
	r.mu.Unlock()
}

// SetTunnel sets the dialer of the active engine, or nil when it is down.
func (r *Resolver) SetTunnel(d DialFunc) {
	r.mu.Lock()
	r.tunnel = d
	r.resetLocked()
	r.mu.Unlock()
}

func (r *Resolver) resetLocked() {
	for k, m := range r.muxes {
		m.reset(nil)
		delete(r.muxes, k)
	}
}

// Serve answers one DNS query. It never returns nil for a well-formed query:
// failures produce SERVFAIL so that applications fail fast.
func (r *Resolver) Serve(ctx context.Context, q []byte) []byte {
	_, name, _, err := question(q)
	if err != nil {
		r.Stats.Failed.Add(1)
		return errorResponse(q, dnsmessage.RCodeFormatError)
	}
	r.mu.Lock()
	cfg, tunnel := r.cfg, r.tunnel
	r.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	var resp []byte
	if (rules.Policy{Exclusions: cfg.Exclusions, VPN: cfg.TunnelOnly}).Direct(name) {
		servers := cfg.DirectServers
		if len(servers) == 0 {
			servers = cfg.TunnelServers
		}
		resp, err = r.try(ctx, servers, func(ctx context.Context, s netip.AddrPort) ([]byte, error) {
			resp, err := exchangeUDP(ctx, r.direct, s, q)
			if err == nil && truncated(resp) {
				return exchangeTCP(ctx, r.direct, s, q)
			}
			return resp, err
		})
		if err == nil {
			r.Stats.Direct.Add(1)
		}
	} else {
		if tunnel == nil {
			err = ErrTunnelDown
		} else {
			resp, err = r.try(ctx, cfg.TunnelServers, func(ctx context.Context, s netip.AddrPort) ([]byte, error) {
				resp, err := r.muxFor(tunnel, s).exchange(ctx, q)
				if err == nil && truncated(resp) {
					return exchangeTCP(ctx, tunnel, s, q)
				}
				return resp, err
			})
		}
		if err == nil {
			r.Stats.Tunnel.Add(1)
		}
	}
	if err != nil {
		r.Stats.Failed.Add(1)
		return errorResponse(q, dnsmessage.RCodeServerFailure)
	}
	if ips, ttl := answerIPs(resp); len(ips) > 0 {
		for _, ip := range ips {
			r.cache.Put(ip, name, ttl)
		}
	}
	return resp
}

func (r *Resolver) try(ctx context.Context, servers []netip.AddrPort, f func(context.Context, netip.AddrPort) ([]byte, error)) ([]byte, error) {
	if len(servers) == 0 {
		return nil, errors.New("dns: no servers configured")
	}
	var lastErr error
	for _, s := range servers {
		sctx, cancel := context.WithTimeout(ctx, serverTimeout)
		resp, err := f(sctx, s)
		cancel()
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

func (r *Resolver) muxFor(dial DialFunc, s netip.AddrPort) *mux {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.muxes[s]
	if !ok {
		m = newMux(dial, s)
		r.muxes[s] = m
	}
	return m
}
