package netstack

import (
	"net"
	"sync"
)

// PipeIO is an in-memory PacketIO pair used by tests and by the callback
// bridge: packets written to one end are read from the other.
type PipeIO struct {
	in     <-chan []byte
	out    chan<- []byte
	closed chan struct{}
	once   *sync.Once
}

// NewPipe returns two connected ends.
func NewPipe(queue int) (*PipeIO, *PipeIO) {
	a := make(chan []byte, queue)
	b := make(chan []byte, queue)
	closed := make(chan struct{})
	once := &sync.Once{}
	return &PipeIO{in: a, out: b, closed: closed, once: once}, &PipeIO{in: b, out: a, closed: closed, once: once}
}

func (p *PipeIO) ReadPacket(buf []byte) (int, error) {
	select {
	case pkt := <-p.in:
		return copy(buf, pkt), nil
	case <-p.closed:
		return 0, net.ErrClosed
	}
}

func (p *PipeIO) WritePacket(pkt []byte) error {
	c := append([]byte(nil), pkt...)
	select {
	case p.out <- c:
		return nil
	case <-p.closed:
		return net.ErrClosed
	default:
		return nil // queue full: drop like a real interface
	}
}

func (p *PipeIO) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}
