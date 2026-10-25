// Package daemon is the root service of the standalone client: it stores
// profiles and settings, configures the OS through platform.Platform, runs the
// tunnel and serves the TUI over ipc.
package daemon

import (
	"time"

	"github.com/eermolaev/test-vpn/core/flowrouter"
	"github.com/eermolaev/test-vpn/core/platform"
	"github.com/eermolaev/test-vpn/core/profile"
	"github.com/eermolaev/test-vpn/core/tunnel"
)

// IPC commands.
const (
	CmdStatus        = "status"
	CmdFlows         = "flows"
	CmdLogs          = "logs"
	CmdProfiles      = "profiles"
	CmdImport        = "import"
	CmdUpdateProfile = "update_profile"
	CmdDeleteProfile = "delete_profile"
	CmdSelectProfile = "select_profile"
	CmdConnect       = "connect"
	CmdDisconnect    = "disconnect"
	CmdReconnect     = "reconnect"
	CmdGetSettings   = "get_settings"
	CmdSetSettings   = "set_settings"
)

// Settings are the user settings (GEO-010, SPLIT-001/003).
type Settings struct {
	Exclusions []string `json:"exclusions"`
	// VPNOnly domains never go direct (they win over exclusions) and are
	// blocked while the tunnel is down.
	VPNOnly          []string `json:"vpnOnly,omitempty"`
	DNSServers       []string `json:"dnsServers"` // empty: Google 8.8.8.8, 8.8.4.4
	ExclusionDNSMode string   `json:"exclusionDNSMode"`
	BlockQUIC        bool     `json:"blockQUIC"`
	AllowLAN         bool     `json:"allowLAN"`
	// AutoConnect: what to do when the Mac boots (AutoConnect* constants).
	AutoConnect string `json:"autoConnect,omitempty"`
}

// AutoConnect modes.
const (
	AutoConnectLast    = "last"    // always connect to the last selected profile
	AutoConnectRestore = "restore" // connect only if connected before shutdown
	AutoConnectOff     = "off"     // never connect automatically
)

// AutoConnectMode returns the mode, defaulting to AutoConnectLast.
func (s Settings) AutoConnectMode() string {
	if s.AutoConnect == "" {
		return AutoConnectLast
	}
	return s.AutoConnect
}

// DefaultSettings returns the defaults.
func DefaultSettings() Settings {
	return Settings{ExclusionDNSMode: tunnel.ExclusionDNSPublic, BlockQUIC: true, AutoConnect: AutoConnectLast}
}

// ProfileEntry describes a stored profile without secrets.
type ProfileEntry struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	ExpectedCountry string          `json:"expectedCountry,omitempty"`
	ManualTransport string          `json:"manualTransport,omitempty"`
	Summary         profile.Summary `json:"summary"`
	Selected        bool            `json:"selected"`
}

// Status is the daemon status shown by the TUI.
type Status struct {
	Version    string                `json:"version"`
	Build      string                `json:"build"`
	Connected  bool                  `json:"connected"` // desired state
	Profile    *ProfileEntry         `json:"profile,omitempty"`
	Tunnel     *tunnel.Status        `json:"tunnel,omitempty"`
	KillSwitch bool                  `json:"killSwitch"`
	Interface  string                `json:"interface,omitempty"`
	Route      platform.DefaultRoute `json:"route"`
	Since      time.Time             `json:"since,omitzero"`
	LastError  string                `json:"lastError,omitempty"`
	// Warnings are conflicts with other VPNs or firewalls.
	Warnings   []string `json:"warnings,omitempty"`
	DNSServers []string `json:"dnsServers"`
}

// LogLine is a redacted log entry.
type LogLine struct {
	Seq  uint64    `json:"seq"`
	Time time.Time `json:"time"`
	Text string    `json:"text"`
}

// Argument types.
type (
	FlowsArgs  struct{ Limit int }
	LogsArgs   struct{ After uint64 }
	ImportArgs struct {
		Text string `json:"text"`
		Into string `json:"into,omitempty"` // add transports to this profile
	}
	IDArgs        struct{ ID string }
	UpdateProfile struct {
		ID              string  `json:"id"`
		Name            *string `json:"name,omitempty"`
		ExpectedCountry *string `json:"expectedCountry,omitempty"`
		ManualTransport *string `json:"manualTransport,omitempty"`
	}
	ConnectArgs struct {
		ID string `json:"id,omitempty"` // empty: selected profile
	}
)

// FlowList is returned by CmdFlows.
type FlowList struct {
	Flows []flowrouter.FlowInfo `json:"flows"`
}
