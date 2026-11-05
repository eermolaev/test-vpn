package openvpn

var candidates = []string{"/usr/sbin/openvpn", "/usr/local/sbin/openvpn", "/sbin/openvpn"}

const (
	installHint = "apt install openvpn / dnf install openvpn"
	devType     = "tun"
	// "TUN/TAP device tun0 opened", or with data channel offload (2.6+)
	// "DCO device tun0 opened".
	deviceRE    = `(?:TUN/TAP|DCO) device (\S+) opened`
	unsupported = ""
)
