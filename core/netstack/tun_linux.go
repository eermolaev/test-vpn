//go:build linux

package netstack

import (
	"os"

	"golang.org/x/sys/unix"
)

// TunFileIO reads and writes raw IP packets on a Linux TUN file descriptor
// opened with IFF_NO_PI (no packet information header).
type TunFileIO struct {
	f *os.File
}

// NewTunFileIO takes ownership of fd; Close closes it, which also removes a
// non-persistent interface and unblocks readers.
func NewTunFileIO(fd int) (*TunFileIO, error) {
	// Non-blocking, so that os.File uses the poller and Close interrupts Read.
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}
	return &TunFileIO{f: os.NewFile(uintptr(fd), "tun")}, nil
}

func (t *TunFileIO) ReadPacket(p []byte) (int, error) { return t.f.Read(p) }

func (t *TunFileIO) WritePacket(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	_, err := t.f.Write(p)
	return err
}

func (t *TunFileIO) Close() error { return t.f.Close() }
