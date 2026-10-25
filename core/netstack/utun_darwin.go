//go:build darwin

package netstack

import (
	"encoding/binary"
	"os"

	"golang.org/x/sys/unix"
)

// UtunIO reads and writes packets on a Darwin utun file descriptor, which
// prefixes every packet with a 4-byte address family.
type UtunIO struct {
	f   *os.File
	buf []byte
	wb  []byte
}

// NewUtunIO wraps fd. The fd is owned by the system; Close does not close it
// (the packet tunnel provider tears the interface down itself).
func NewUtunIO(fd int, mtu int) *UtunIO {
	return &UtunIO{f: os.NewFile(uintptr(fd), "utun"), buf: make([]byte, mtu+4+64), wb: make([]byte, 0, mtu+4+64)}
}

func (u *UtunIO) ReadPacket(p []byte) (int, error) {
	n, err := u.f.Read(u.buf)
	if err != nil {
		return 0, err
	}
	if n <= 4 {
		return 0, nil
	}
	return copy(p, u.buf[4:n]), nil
}

func (u *UtunIO) WritePacket(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	af := uint32(unix.AF_INET)
	if p[0]>>4 == 6 {
		af = unix.AF_INET6
	}
	u.wb = binary.BigEndian.AppendUint32(u.wb[:0], af)
	u.wb = append(u.wb, p...)
	_, err := u.f.Write(u.wb)
	return err
}

// Close unblocks readers by closing the duplicate file.
func (u *UtunIO) Close() error { return u.f.Close() }
