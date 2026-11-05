//go:build windows

package ipc

import (
	"errors"
	"net"
)

// peerUID is not available on Windows; access is controlled by the DACL of
// the socket file (see ListenSID).
func peerUID(net.Conn) (int, error) { return -1, errors.New("peer credentials not supported") }
