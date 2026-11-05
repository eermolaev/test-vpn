//go:build !windows

package ipc

import "os"

const installHint = "sudo testvpn install"

func restrictToUID(path string, uid int) error {
	if err := os.Chown(path, uid, -1); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
