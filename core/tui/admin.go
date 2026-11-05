package tui

import "runtime"

// adminCmd is how the user runs a privileged testvpn command.
func adminCmd(cmd string) string {
	if runtime.GOOS == "windows" {
		return "testvpn " + cmd + " (Administrator terminal)"
	}
	return "sudo testvpn " + cmd
}
