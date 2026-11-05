//go:build windows

package direct

import (
	"encoding/binary"

	"golang.org/x/sys/windows"
)

// ipUnicastIf is IP_UNICAST_IF from ws2ipdef.h; for IPv4 the interface
// index is passed in network byte order.
const ipUnicastIf = 31

func bindToInterface(fd uintptr, index int, _ string) error {
	if index == 0 {
		return nil
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(index))
	return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, int(binary.NativeEndian.Uint32(b[:])))
}
