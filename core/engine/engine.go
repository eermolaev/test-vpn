// Package engine defines the interface implemented by tunnel engines
// (xray-core for VLESS + REALITY, amneziawg-go for AmneziaWG).
package engine

import (
	"context"
	"net"
	"net/netip"
)

// Dialer opens connections to IPv4 destinations.
type Dialer interface {
	DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
	// DialUDP returns a connected datagram conn: each Write is one datagram.
	DialUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
}

// Engine is a started tunnel engine. Only one engine is active at a time.
type Engine interface {
	Dialer
	// Name is the transport kind, e.g. "amneziawg".
	Name() string
	// NativeUDP reports whether UDP is carried as datagrams (AmneziaWG) rather
	// than over a TCP-based transport (VLESS), which matters for QUIC policy.
	NativeUDP() bool
	Close() error
}
