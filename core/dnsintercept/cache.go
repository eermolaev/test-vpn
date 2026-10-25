// Package dnsintercept answers DNS queries captured by the tunnel: queries for
// excluded domains are resolved directly (SPLIT-003), all other queries go
// through the tunnel engine to the selected public resolver (GEO-004).
package dnsintercept

import (
	"net/netip"
	"sync"
	"time"
)

const (
	minTTL       = 60 * time.Second
	maxTTL       = time.Hour
	defaultLimit = 16384
)

// Cache maps IPv4 addresses from DNS answers to the queried names, so that
// connections without SNI can still be matched against exclusions.
type Cache struct {
	mu    sync.Mutex
	m     map[netip.Addr]cacheEntry
	limit int
	now   func() time.Time
}

type cacheEntry struct {
	host string
	exp  time.Time
}

// NewCache returns a cache bounded to limit entries (0 = default).
func NewCache(limit int) *Cache {
	if limit <= 0 {
		limit = defaultLimit
	}
	return &Cache{m: map[netip.Addr]cacheEntry{}, limit: limit, now: time.Now}
}

// Put records that ip belongs to host.
func (c *Cache) Put(ip netip.Addr, host string, ttl time.Duration) {
	ttl = min(max(ttl, minTTL), maxTTL)
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if _, ok := c.m[ip]; !ok && len(c.m) >= c.limit {
		for k, e := range c.m {
			if now.After(e.exp) {
				delete(c.m, k)
			}
		}
		for k := range c.m { // still full: evict an arbitrary entry
			if len(c.m) < c.limit {
				break
			}
			delete(c.m, k)
		}
	}
	c.m[ip.Unmap()] = cacheEntry{host: host, exp: now.Add(ttl)}
}

// Lookup returns the host for ip, or "".
func (c *Cache) Lookup(ip netip.Addr) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[ip.Unmap()]
	if !ok {
		return ""
	}
	if c.now().After(e.exp) {
		delete(c.m, ip.Unmap())
		return ""
	}
	return e.host
}

// Len returns the number of entries.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}
