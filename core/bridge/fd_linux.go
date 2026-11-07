//go:build linux

package vpncore

import "github.com/eermolaev/test-vpn/core/netstack"

// tunIO wraps the TUN descriptor from Android's VpnService (raw IP packets,
// no header). The core takes ownership: pass ParcelFileDescriptor.detachFd().
func tunIO(fd, _ int) (netstack.PacketIO, error) { return netstack.NewTunFileIO(fd) }

// stackOptions: a phone has memory to spare compared with an iOS network
// extension, and larger buffers avoid window stalls on fast links.
func stackOptions() netstack.Options {
	return netstack.Options{TCPBufferSize: 1 << 20, QueueSize: 2048, ModerateReceiveBuffer: true}
}
