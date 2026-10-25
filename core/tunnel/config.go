// Package tunnel runs the whole client: userspace stack, router, DNS, and the
// active engine chosen by the fallback planner, with health checks and the
// kill switch (SEC-KILL-001).
package tunnel

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/eermolaev/test-vpn/core/dnsintercept"
	"github.com/eermolaev/test-vpn/core/errclass"
	"github.com/eermolaev/test-vpn/core/fallback"
	"github.com/eermolaev/test-vpn/core/flowrouter"
	"github.com/eermolaev/test-vpn/core/profile"
	"github.com/eermolaev/test-vpn/core/rules"
)

// Default public resolver (GEO-010).
var DefaultDNS = []string{"8.8.8.8", "8.8.4.4"}

// ExclusionDNS modes (SPLIT-003).
const (
	ExclusionDNSNetwork = "network" // DNS of the current network
	ExclusionDNSPublic  = "public"  // selected public resolver, queried directly
)

// Settings are the user settings that can change while connected.
type Settings struct {
	Exclusions       []string `json:"exclusions"`
	DNSServers       []string `json:"dnsServers"`
	DirectDNSServers []string `json:"directDNSServers"`
	ExclusionDNSMode string   `json:"exclusionDNSMode"`
	// BlockQUIC drops QUIC inside TCP-based tunnels (default true).
	BlockQUIC *bool `json:"blockQUIC,omitempty"`
}

// Config starts a tunnel.
type Config struct {
	Profile         *profile.Profile `json:"profile"`
	ManualTransport string           `json:"manualTransport,omitempty"`
	NetworkID       string           `json:"networkID,omitempty"`
	InterfaceIndex  int              `json:"interfaceIndex,omitempty"`
	InterfaceName   string           `json:"interfaceName,omitempty"`
	MTU             int              `json:"mtu,omitempty"`
	Settings

	Policy         fallback.Policy `json:"-"`
	HealthInterval time.Duration   `json:"-"`
	HealthTimeout  time.Duration   `json:"-"`
	// HealthFailures is how many consecutive failed checks drop the engine.
	HealthFailures int `json:"-"`
}

func (c *Config) defaults() {
	if c.Policy.Attempts == 0 {
		c.Policy = fallback.DefaultPolicy()
	}
	if c.HealthInterval == 0 {
		c.HealthInterval = 30 * time.Second
	}
	if c.HealthTimeout == 0 {
		c.HealthTimeout = 5 * time.Second
	}
	if c.HealthFailures == 0 {
		c.HealthFailures = 2
	}
	if c.MTU == 0 {
		c.MTU = 1400
	}
}

// compiled is the validated form of Settings.
type compiled struct {
	router flowrouter.Settings
	dns    dnsintercept.Config
}

// SettingsError lists all invalid entries.
type SettingsError struct {
	Exclusions []rules.LineError
	Other      []string
}

func (e *SettingsError) Error() string {
	var parts []string
	for _, le := range e.Exclusions {
		parts = append(parts, "exclusions: "+le.Error())
	}
	parts = append(parts, e.Other...)
	return strings.Join(parts, "; ")
}

func parseServers(list []string, field string) ([]netip.AddrPort, error) {
	var out []netip.AddrPort
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ap, err := netip.ParseAddrPort(s); err == nil {
			if !ap.Addr().Is4() {
				return nil, fmt.Errorf("%s: %s: only IPv4 is supported", field, s)
			}
			out = append(out, ap)
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not an IP address", field, s)
		}
		if !a.Is4() {
			return nil, fmt.Errorf("%s: %s: only IPv4 is supported", field, s)
		}
		out = append(out, netip.AddrPortFrom(a, 53))
	}
	if len(out) > 4 {
		return nil, fmt.Errorf("%s: at most 4 servers", field)
	}
	return out, nil
}

// Compile validates settings (GEO-010, SPLIT-001, SPLIT-003).
func (s Settings) compile() (compiled, error) {
	var serr SettingsError
	set, lineErrs := rules.NewSet(s.Exclusions)
	serr.Exclusions = lineErrs
	dnsList := s.DNSServers
	if len(dnsList) == 0 {
		dnsList = DefaultDNS
	}
	tunnelDNS, err := parseServers(dnsList, "dnsServers")
	if err != nil {
		serr.Other = append(serr.Other, err.Error())
	}
	directDNS, err := parseServers(s.DirectDNSServers, "directDNSServers")
	if err != nil {
		serr.Other = append(serr.Other, err.Error())
	}
	switch s.ExclusionDNSMode {
	case "", ExclusionDNSNetwork:
	case ExclusionDNSPublic:
		directDNS = nil
	default:
		serr.Other = append(serr.Other, fmt.Sprintf("exclusionDNSMode: unknown mode %q", s.ExclusionDNSMode))
	}
	if len(serr.Exclusions) > 0 || len(serr.Other) > 0 {
		return compiled{}, errclass.Wrap(errclass.Config, &serr)
	}
	block := true
	if s.BlockQUIC != nil {
		block = *s.BlockQUIC
	}
	return compiled{
		router: flowrouter.Settings{Exclusions: set, BlockQUICInTunnel: block},
		dns:    dnsintercept.Config{Exclusions: set, TunnelServers: tunnelDNS, DirectServers: directDNS},
	}, nil
}

var errNoProfile = errclass.Wrap(errclass.Config, errors.New("tunnel: no profile"))
