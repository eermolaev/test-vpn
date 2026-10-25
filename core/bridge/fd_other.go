//go:build !darwin

package vpncore

import (
	"errors"

	"github.com/eermolaev/test-vpn/core/netstack"
)

func utunIO(int, int) (netstack.PacketIO, error) {
	return nil, errors.New("vpncore: file descriptor mode is only supported on Darwin")
}
