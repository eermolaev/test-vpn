//go:build linux

package ipc

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

func peerUID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return -1, errors.New("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1, err
	}
	uid := -1
	var serr error
	raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			serr = err
			return
		}
		uid = int(cred.Uid)
	})
	return uid, serr
}
