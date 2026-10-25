//go:build darwin

package daemon

import "golang.org/x/sys/unix"

func bootTime() int64 {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return 0
	}
	return tv.Sec
}
