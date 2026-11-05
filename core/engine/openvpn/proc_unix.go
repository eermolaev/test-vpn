//go:build !windows

package openvpn

import (
	"os"
	"syscall"
)

// procAttr puts openvpn into its own process group, so that a terminal
// signal to the daemon does not reach it directly.
func procAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setpgid: true} }

// stopProcess asks openvpn to exit; Close kills it after a timeout.
func stopProcess(p *os.Process) { p.Signal(syscall.SIGTERM) }
