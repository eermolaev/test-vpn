//go:build !darwin && !linux

package vpncore

import (
	"errors"

	"github.com/eermolaev/test-vpn/core/netstack"
)

func tunIO(int, int) (netstack.PacketIO, error) {
	return nil, errors.New("vpncore: file descriptor mode is supported on Darwin and Android")
}

func stackOptions() netstack.Options { return netstack.Options{} }
