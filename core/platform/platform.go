// Package platform configures the operating system for the standalone
// (non-Network-Extension) client: tunnel interface, routes, DNS and the
// packet-filter kill switch. The macOS implementation runs as root in the
// daemon; Fake records calls for tests.
package platform

import (
	"net/netip"

	"github.com/eermolaev/test-vpn/core/netstack"
)

// Tunnel interface addresses (same as the packet tunnel provider).
var (
	TunAddr4 = netip.MustParseAddr("10.255.0.2")
	TunPeer4 = netip.MustParseAddr("10.255.0.1")
	TunAddr6 = netip.MustParseAddr("fd00:255::2")
)

// DefaultRoute is the physical default route, outside the tunnel.
type DefaultRoute struct {
	Gateway   netip.Addr `json:"gateway"`
	Interface string     `json:"interface"`
	Index     int        `json:"index"`
	// LAN is the IPv4 subnet of the interface (for "allow local network").
	LAN netip.Prefix `json:"lan"`
}

// Valid reports whether there is a usable default route.
func (r DefaultRoute) Valid() bool { return r.Interface != "" && r.Index != 0 }

// KillSwitch configures the packet filter (SEC-KILL-001).
type KillSwitch struct {
	Tun      string       // tunnel interface name, empty while it does not exist
	Servers  []netip.Addr // VPN server addresses, reachable directly
	AllowLAN bool
	LAN      netip.Prefix // local subnet when AllowLAN
}

// Platform is the OS-specific part of the daemon.
type Platform interface {
	// CreateTUN creates the tunnel interface and returns its packet I/O.
	CreateTUN(mtu int) (netstack.PacketIO, string, error)
	// ConfigureTUN assigns addresses and routes all IPv4 and IPv6 traffic
	// into the tunnel (IPv6 only to be dropped by the core).
	ConfigureTUN(name string, mtu int) error
	// DestroyTUN closes the tunnel interface.
	DestroyTUN() error
	// DefaultRoute returns the physical default route.
	DefaultRoute() (DefaultRoute, error)
	// SetServerRoutes routes the VPN servers via the physical gateway,
	// replacing the previous set; nil removes them.
	SetServerRoutes(servers []netip.Addr, via DefaultRoute) error
	// SetDNS points the system resolver to servers (saving the originals).
	SetDNS(servers []netip.Addr) error
	// RestoreDNS restores the saved resolver configuration.
	RestoreDNS() error
	// EnableKillSwitch loads or reloads the filter rules.
	EnableKillSwitch(KillSwitch) error
	// AllowDirect lets traffic to ips bypass the filter (excluded domains);
	// it must return before the connection is opened.
	AllowDirect(ips ...netip.Addr) error
	// DisableKillSwitch removes the filter rules.
	DisableKillSwitch() error
}
