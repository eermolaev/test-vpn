package openvpn

var candidates = []string{"/opt/homebrew/sbin/openvpn", "/usr/local/sbin/openvpn", "/opt/local/sbin/openvpn", "/usr/sbin/openvpn"}

const (
	installHint = "brew install openvpn"
	devType     = "utun"
	deviceRE    = `Opened utun device (utun\d+)`
	unsupported = ""
)
