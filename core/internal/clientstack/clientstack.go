// Package clientstack provides a gVisor stack that plays the role of the
// operating system's applications in tests: it sends packets into the tunnel
// stack through a netstack.PipeIO.
package clientstack

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/eermolaev/test-vpn/core/netstack"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// Addr4 and Addr6 are the client's tunnel addresses.
var (
	Addr4 = netip.MustParseAddr("10.10.0.2")
	Addr6 = netip.MustParseAddr("fd00::2")
)

// Client is the "apps" side of the tunnel.
type Client struct {
	S      *stack.Stack
	ep     *channel.Endpoint
	io     *netstack.PipeIO
	cancel context.CancelFunc
}

// New connects a client stack to pio.
func New(pio *netstack.PipeIO) *Client {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(512, 1400, "")
	s.CreateNIC(1, ep)
	s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4(Addr4.As4()).WithPrefix()}, stack.AddressProperties{})
	s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom16(Addr6.As16()).WithPrefix()}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{S: s, ep: ep, io: pio, cancel: cancel}
	go func() { // client -> tunnel
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			var b []byte
			for _, s := range pkt.AsSlices() {
				b = append(b, s...)
			}
			pkt.DecRef()
			pio.WritePacket(b)
		}
	}()
	go func() { // tunnel -> client
		buf := make([]byte, 2000)
		for {
			n, err := pio.ReadPacket(buf)
			if err != nil {
				return
			}
			proto := ipv4.ProtocolNumber
			if buf[0]>>4 == 6 {
				proto = ipv6.ProtocolNumber
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), buf[:n]...))})
			ep.InjectInbound(proto, pkt)
			pkt.DecRef()
		}
	}()
	return c
}

func full(a netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	if a.Addr().Is4() {
		return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(a.Addr().As4()), Port: a.Port()}, ipv4.ProtocolNumber
	}
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom16(a.Addr().As16()), Port: a.Port()}, ipv6.ProtocolNumber
}

// DialTCP connects to dst through the tunnel.
func (c *Client) DialTCP(dst netip.AddrPort, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	fa, proto := full(dst)
	return gonet.DialContextTCP(ctx, c.S, fa, proto)
}

// DialUDP opens a connected UDP socket to dst through the tunnel.
func (c *Client) DialUDP(dst netip.AddrPort) (net.Conn, error) {
	fa, proto := full(dst)
	return gonet.DialUDP(c.S, nil, &fa, proto)
}

// Close stops the client.
func (c *Client) Close() {
	c.cancel()
	c.S.Close()
}
