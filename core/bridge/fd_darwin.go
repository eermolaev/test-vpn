//go:build darwin

package vpncore

import "github.com/eermolaev/test-vpn/core/netstack"

func utunIO(fd, mtu int) (netstack.PacketIO, error) {
	if mtu == 0 {
		mtu = 1400
	}
	return netstack.NewUtunIO(fd, mtu)
}
