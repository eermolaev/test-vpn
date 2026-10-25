// Package direct opens connections that bypass the tunnel through the
// physical interface. It is used for excluded domains (SPLIT-002) and for
// resolving them (SPLIT-003). Only IPv4 is allowed (GEO-003).
package direct

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
)

// ErrIPv6 is returned for IPv6 destinations.
var ErrIPv6 = errors.New("direct: IPv6 is disabled")

type iface struct {
	index int
	name  string
}

// Dialer binds sockets to the current physical interface. The host app
// updates the interface when the network changes.
type Dialer struct {
	cur atomic.Pointer[iface]
}

// SetInterface sets the physical interface (index for Darwin, name for Linux).
// index 0 and empty name disable binding.
func (d *Dialer) SetInterface(index int, name string) {
	d.cur.Store(&iface{index: index, name: name})
}

func (d *Dialer) dialer() *net.Dialer {
	nd := &net.Dialer{}
	if ifc := d.cur.Load(); ifc != nil && (ifc.index != 0 || ifc.name != "") {
		nd.Control = func(network, address string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) { serr = bindToInterface(fd, ifc.index, ifc.name) }); err != nil {
				return err
			}
			return serr
		}
	}
	return nd
}

// DialTCP connects to dst outside of the tunnel.
func (d *Dialer) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if !dst.Addr().Unmap().Is4() {
		return nil, ErrIPv6
	}
	return d.dialer().DialContext(ctx, "tcp4", dst.String())
}

// DialUDP returns a connected UDP socket outside of the tunnel.
func (d *Dialer) DialUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if !dst.Addr().Unmap().Is4() {
		return nil, ErrIPv6
	}
	return d.dialer().DialContext(ctx, "udp4", dst.String())
}
