// Package netstack terminates the TCP and UDP flows captured by the tunnel
// interface in a userspace gVisor stack, so that the router can decide per
// flow whether it goes through the engine or directly (spec 6.2).
package netstack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

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
	"gvisor.dev/gvisor/pkg/waiter"
)

// PacketIO carries raw IP packets between the OS tunnel interface and the
// stack.
type PacketIO interface {
	// ReadPacket reads one IP packet into p.
	ReadPacket(p []byte) (int, error)
	// WritePacket writes one IP packet. It must not retain p.
	WritePacket(p []byte) error
	Close() error
}

// Flow identifies a captured flow.
type Flow struct {
	Src, Dst netip.AddrPort
}

func (f Flow) String() string { return f.Src.String() + "->" + f.Dst.String() }

// TCPConn is an accepted TCP flow. Abort resets it.
type TCPConn struct {
	*gonet.TCPConn
	Flow Flow
	ep   tcpip.Endpoint
}

// Abort closes the connection with RST.
func (c *TCPConn) Abort() { c.ep.Abort() }

// UDPConn is a UDP flow: Read returns datagrams from the app, Write sends
// datagrams back to it.
type UDPConn struct {
	*gonet.UDPConn
	Flow Flow
}

// Handler receives flows from the stack.
type Handler interface {
	// AcceptTCP is called before the handshake; false sends RST.
	AcceptTCP(f Flow) bool
	HandleTCP(c *TCPConn)
	// AcceptUDP is called for a new UDP flow; false drops it.
	AcceptUDP(f Flow) bool
	HandleUDP(c *UDPConn)
}

// Options tune memory use (PLAT-002).
type Options struct {
	MTU int
	// TCPBufferSize is the default and max TCP send/receive buffer.
	TCPBufferSize int
	// MaxInFlight bounds concurrent TCP handshakes.
	MaxInFlight int
	// QueueSize is the outbound packet queue length; packets beyond it are
	// dropped, which TCP sees as loss.
	QueueSize int
	// ModerateReceiveBuffer lets TCP grow its receive window with the
	// application's read rate, up to TCPBufferSize.
	ModerateReceiveBuffer bool
}

func (o *Options) defaults() {
	if o.MTU == 0 {
		o.MTU = 1400
	}
	if o.TCPBufferSize == 0 {
		o.TCPBufferSize = 128 << 10
	}
	if o.MaxInFlight == 0 {
		o.MaxInFlight = 256
	}
	if o.QueueSize == 0 {
		o.QueueSize = 512
	}
}

const nicID = 1

// Stack is a running userspace network stack.
type Stack struct {
	s      *stack.Stack
	ep     *channel.Endpoint
	io     PacketIO
	h      Handler
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once
	mtu    int
}

// New starts a stack that reads packets from pio.
func New(pio PacketIO, h Handler, opts Options) (*Stack, error) {
	opts.defaults()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        false,
	})
	ep := channel.New(opts.QueueSize, uint32(opts.MTU), "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("netstack: create NIC: %v", err)
	}
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("netstack: promiscuous: %v", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("netstack: spoofing: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4096, Default: opts.TCPBufferSize, Max: opts.TCPBufferSize}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcv)
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: 4096, Default: opts.TCPBufferSize, Max: opts.TCPBufferSize}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &snd)
	if opts.ModerateReceiveBuffer {
		mod := tcpip.TCPModerateReceiveBufferOption(true)
		s.SetTransportProtocolOption(tcp.ProtocolNumber, &mod)
	}

	ctx, cancel := context.WithCancel(context.Background())
	st := &Stack{s: s, ep: ep, io: pio, h: h, ctx: ctx, cancel: cancel, mtu: opts.MTU}

	tcpFwd := tcp.NewForwarder(s, 0, opts.MaxInFlight, st.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, st.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	st.wg.Add(2)
	go st.inbound()
	go st.outbound()
	return st, nil
}

func toAddrPort(a tcpip.Address, port uint16) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return netip.AddrPortFrom(ip.Unmap(), port)
}

func flowOf(id stack.TransportEndpointID) Flow {
	return Flow{Src: toAddrPort(id.RemoteAddress, id.RemotePort), Dst: toAddrPort(id.LocalAddress, id.LocalPort)}
}

func (st *Stack) handleTCP(r *tcp.ForwarderRequest) {
	f := flowOf(r.ID())
	if !st.h.AcceptTCP(f) {
		r.Complete(true)
		return
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	ep.SocketOptions().SetKeepAlive(true)
	go st.h.HandleTCP(&TCPConn{TCPConn: gonet.NewTCPConn(&wq, ep), Flow: f, ep: ep})
}

func (st *Stack) handleUDP(r *udp.ForwarderRequest) bool {
	f := flowOf(r.ID())
	if !st.h.AcceptUDP(f) {
		return true // handled: drop silently
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		return false
	}
	go st.h.HandleUDP(&UDPConn{UDPConn: gonet.NewUDPConn(&wq, ep), Flow: f})
	return true
}

func (st *Stack) inbound() {
	defer st.wg.Done()
	buf := make([]byte, st.mtu+64)
	for {
		n, err := st.io.ReadPacket(buf)
		if err != nil {
			st.Close()
			return
		}
		if n == 0 {
			continue
		}
		var proto tcpip.NetworkProtocolNumber
		switch buf[0] >> 4 {
		case 4:
			proto = ipv4.ProtocolNumber
		case 6:
			proto = ipv6.ProtocolNumber
		default:
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), buf[:n]...))})
		st.ep.InjectInbound(proto, pkt)
		pkt.DecRef()
	}
}

func (st *Stack) outbound() {
	defer st.wg.Done()
	out := make([]byte, 0, st.mtu+64)
	for {
		pkt := st.ep.ReadContext(st.ctx)
		if pkt == nil {
			return
		}
		out = out[:0]
		for _, s := range pkt.AsSlices() {
			out = append(out, s...)
		}
		pkt.DecRef()
		if err := st.io.WritePacket(out); err != nil && !errors.Is(err, net.ErrClosed) {
			continue
		}
	}
}

// Close stops the stack and closes the packet I/O.
func (st *Stack) Close() error {
	st.once.Do(func() {
		st.cancel()
		st.io.Close()
		st.ep.Close()
		st.s.Close()
	})
	return nil
}

// Wait blocks until the packet pumps have stopped.
func (st *Stack) Wait() {
	st.wg.Wait()
	st.s.Wait()
}
