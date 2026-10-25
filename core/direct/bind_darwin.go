//go:build darwin

package direct

import "golang.org/x/sys/unix"

func bindToInterface(fd uintptr, index int, _ string) error {
	if index == 0 {
		return nil
	}
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, index)
}
