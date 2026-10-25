//go:build linux

package direct

import "golang.org/x/sys/unix"

func bindToInterface(fd uintptr, _ int, name string) error {
	if name == "" {
		return nil
	}
	return unix.BindToDevice(int(fd), name)
}
