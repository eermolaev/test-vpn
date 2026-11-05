package openvpn

import (
	"os"
	"syscall"
)

var candidates = []string{`C:\Program Files\OpenVPN\bin\openvpn.exe`}

const (
	installHint = "install OpenVPN from https://openvpn.net/community-downloads/"
	devType     = "tun"
	deviceRE    = `(?:TUN/TAP|DCO|Wintun) device \[?([^\]]+?)\]? opened`
	unsupported = "the OpenVPN transport is not supported on Windows yet; use AmneziaWG or VLESS"
)

func procAttr() *syscall.SysProcAttr { return nil }

func stopProcess(p *os.Process) { p.Kill() }
