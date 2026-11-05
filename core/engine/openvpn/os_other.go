//go:build !darwin && !linux && !windows

package openvpn

var candidates = []string{"/usr/local/sbin/openvpn", "/usr/sbin/openvpn"}

const (
	installHint = "install openvpn"
	devType     = "tun"
	deviceRE    = `(?:TUN/TAP|DCO) device (\S+) opened`
	unsupported = ""
)
