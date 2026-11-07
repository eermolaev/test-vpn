package vpncore

import "github.com/eermolaev/test-vpn/core/netstack"

// tunIO wraps a duplicate of the utun descriptor of the packet tunnel
// provider, which keeps owning the original.
func tunIO(fd, mtu int) (netstack.PacketIO, error) {
	if mtu == 0 {
		mtu = 1400
	}
	return netstack.NewUtunIO(fd, mtu)
}

// stackOptions keeps the memory-saving defaults of the network extension.
func stackOptions() netstack.Options { return netstack.Options{} }
