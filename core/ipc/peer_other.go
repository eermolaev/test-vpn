//go:build !darwin && !linux

package ipc

import (
	"errors"
	"net"
)

func peerUID(net.Conn) (int, error) { return -1, errors.New("peer credentials not supported") }
