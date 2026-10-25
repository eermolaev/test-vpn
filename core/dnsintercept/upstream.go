package dnsintercept

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// DialFunc opens a connection to a DNS server ("udp" or "tcp").
type DialFunc func(ctx context.Context, network string, server netip.AddrPort) (net.Conn, error)

const (
	queryTimeout  = 5 * time.Second
	serverTimeout = 2 * time.Second
	maxDNSSize    = 65535
)

var errUpstreamClosed = errors.New("dns: upstream closed")

// exchangeTCP sends a query over DNS-over-TCP (RFC 7766 framing).
func exchangeTCP(ctx context.Context, dial DialFunc, server netip.AddrPort, q []byte) ([]byte, error) {
	c, err := dial(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	msg := binary.BigEndian.AppendUint16(nil, uint16(len(q)))
	if _, err := c.Write(append(msg, q...)); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// exchangeUDP sends one query on a fresh socket (used for direct queries,
// where a socket costs nothing).
func exchangeUDP(ctx context.Context, dial DialFunc, server netip.AddrPort, q []byte) ([]byte, error) {
	c, err := dial(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, maxDNSSize)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if n >= 2 && buf[0] == q[0] && buf[1] == q[1] {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

// mux multiplexes queries over one long-lived datagram conn per server. Over
// VLESS every new UDP conn costs a TLS handshake, so conns are reused; DNS IDs
// are rewritten to avoid collisions between clients.
type mux struct {
	dial   DialFunc
	server netip.AddrPort

	mu      sync.Mutex
	conn    net.Conn
	pending map[uint16]chan []byte
	nextID  uint16
}

func newMux(dial DialFunc, server netip.AddrPort) *mux {
	return &mux{dial: dial, server: server, pending: map[uint16]chan []byte{}}
}

func (m *mux) getConn(ctx context.Context) (net.Conn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.conn != nil {
		return m.conn, nil
	}
	c, err := m.dial(ctx, "udp", m.server)
	if err != nil {
		return nil, err
	}
	m.conn = c
	go m.readLoop(c)
	return c, nil
}

func (m *mux) readLoop(c net.Conn) {
	buf := make([]byte, maxDNSSize)
	for {
		n, err := c.Read(buf)
		if err != nil {
			m.mu.Lock()
			if m.conn == c {
				m.conn = nil
				for id, ch := range m.pending {
					close(ch)
					delete(m.pending, id)
				}
			}
			m.mu.Unlock()
			c.Close()
			return
		}
		if n < 12 {
			continue
		}
		id := binary.BigEndian.Uint16(buf[:2])
		m.mu.Lock()
		ch, ok := m.pending[id]
		delete(m.pending, id)
		m.mu.Unlock()
		if ok {
			ch <- append([]byte(nil), buf[:n]...)
		}
	}
}

func (m *mux) exchange(ctx context.Context, q []byte) ([]byte, error) {
	c, err := m.getConn(ctx)
	if err != nil {
		return nil, err
	}
	origID := binary.BigEndian.Uint16(q[:2])
	ch := make(chan []byte, 1)
	m.mu.Lock()
	var id uint16
	for {
		m.nextID++
		id = m.nextID
		if _, busy := m.pending[id]; !busy {
			break
		}
	}
	m.pending[id] = ch
	m.mu.Unlock()
	if _, err := c.Write(withID(q, id)); err != nil {
		m.drop(id)
		m.reset(c)
		return nil, err
	}
	select {
	case resp, ok := <-ch:
		if !ok {
			return nil, errUpstreamClosed
		}
		return withID(resp, origID), nil
	case <-ctx.Done():
		m.drop(id)
		return nil, ctx.Err()
	}
}

func (m *mux) drop(id uint16) {
	m.mu.Lock()
	delete(m.pending, id)
	m.mu.Unlock()
}

func (m *mux) reset(c net.Conn) {
	m.mu.Lock()
	if c == nil || m.conn == c {
		if m.conn != nil {
			m.conn.Close() // readLoop fails pending queries
		}
		m.conn = nil
	}
	m.mu.Unlock()
}
