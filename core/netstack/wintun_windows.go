//go:build windows

package netstack

import (
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// WintunIO adapts a wireguard-go tun.Device (Wintun on Windows) to PacketIO.
type WintunIO struct {
	dev tun.Device

	rmu   sync.Mutex
	bufs  [][]byte
	sizes []int
	wmu   sync.Mutex
	wbufs [][]byte
}

// NewWintunIO wraps dev; Close closes the device and removes the adapter.
func NewWintunIO(dev tun.Device) *WintunIO {
	return &WintunIO{dev: dev, bufs: make([][]byte, 1), sizes: make([]int, 1), wbufs: make([][]byte, 1)}
}

func (w *WintunIO) ReadPacket(p []byte) (int, error) {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	w.bufs[0] = p
	n, err := w.dev.Read(w.bufs, w.sizes, 0)
	if err != nil || n == 0 {
		return 0, err
	}
	return w.sizes[0], nil
}

func (w *WintunIO) WritePacket(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	w.wmu.Lock()
	defer w.wmu.Unlock()
	w.wbufs[0] = p
	_, err := w.dev.Write(w.wbufs, 0)
	return err
}

func (w *WintunIO) Close() error { return w.dev.Close() }
