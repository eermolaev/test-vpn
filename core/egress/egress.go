package egress

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Severity of a warning.
type Severity string

const (
	Info     Severity = "info"
	Warning  Severity = "warning"
	Critical Severity = "critical"
)

// Finding is a warning shown in diagnostics.
type Finding struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

// Config controls a check.
type Config struct {
	ExpectedCountry string // ISO code of the profile's location, may be empty
	Services        []IPService
	MinSources      int
	IPv6Service     *IPService
	STUNServers     []string
	GeoIP           *GeoIP
	HTTPClient      *http.Client
	IPv6Client      *http.Client
	// BypassClient sends requests bound to the physical interface (GEO-006);
	// nil skips the check.
	BypassClient *http.Client
	TimeZone     string // IANA zone of the device
	Exclusions   int    // active exclusion rules (SPLIT-005 reminder)
	Timeout      time.Duration
}

// Result of a check (GEO-007).
type Result struct {
	CheckedAt       time.Time `json:"checkedAt"`
	ExpectedCountry string    `json:"expectedCountry,omitempty"`
	IPv4            IPResult  `json:"ipv4"`
	Country         Country   `json:"country"`
	CountryMatch    *bool     `json:"countryMatch,omitempty"`
	IPv6            struct {
		Blocked bool   `json:"blocked"`
		IP      string `json:"ip,omitempty"`
	} `json:"ipv6"`
	STUN struct {
		IP    string `json:"ip,omitempty"`
		Error string `json:"error,omitempty"`
	} `json:"stun"`
	Bypass struct {
		Checked bool   `json:"checked"`
		Blocked bool   `json:"blocked"`
		IP      string `json:"ip,omitempty"`
	} `json:"bypass"`
	TimeZone struct {
		Zone    string `json:"zone,omitempty"`
		Country string `json:"country,omitempty"`
	} `json:"timeZone"`
	Exclusions int       `json:"exclusions"`
	Findings   []Finding `json:"findings"`
}

// JSON encodes the result.
func (r Result) JSON() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func (r *Result) add(code string, sev Severity, msg string) {
	r.Findings = append(r.Findings, Finding{Code: code, Severity: sev, Message: msg})
}

func ipv6Client(timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: timeout}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp6", addr)
		},
	}}
}

// Check runs all checks. Network failures of individual services are
// reported in the result, never as an error.
func Check(ctx context.Context, cfg Config) Result {
	if cfg.Timeout == 0 {
		cfg.Timeout = 6 * time.Second
	}
	if cfg.Services == nil {
		cfg.Services = DefaultIPServices
	}
	if cfg.MinSources == 0 {
		cfg.MinSources = 2
	}
	if cfg.IPv6Service == nil {
		cfg.IPv6Service = &IPv6Service
	}
	if cfg.STUNServers == nil {
		cfg.STUNServers = DefaultSTUNServers
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: cfg.Timeout}
	}
	if cfg.IPv6Client == nil {
		cfg.IPv6Client = ipv6Client(cfg.Timeout)
	}
	r := Result{CheckedAt: time.Now().UTC(), ExpectedCountry: strings.ToUpper(cfg.ExpectedCountry), Exclusions: cfg.Exclusions}

	r.IPv4 = ResolveExitIP(ctx, cfg.HTTPClient, cfg.Services, cfg.MinSources, cfg.Timeout)
	exit, _ := netip.ParseAddr(r.IPv4.IP)
	switch {
	case r.IPv4.IP == "":
		r.add("ip_unknown", Warning, "The exit IP could not be determined: no service answered.")
	case !r.IPv4.Confirmed:
		r.add("ip_unconfirmed", Warning, "IP services disagree or too few answered; the exit IP is not confirmed.")
	}

	if cfg.GeoIP != nil && exit.IsValid() {
		r.Country = cfg.GeoIP.Lookup(exit)
		if r.Country.ISO == "" {
			r.add("country_unknown", Warning, "The exit IP is not in the local GeoIP database.")
		}
		if r.ExpectedCountry != "" && r.Country.ISO != "" {
			match := r.Country.ISO == r.ExpectedCountry
			r.CountryMatch = &match
			if !match {
				// GEO-007: never claim the expected country.
				r.add("country_mismatch", Warning, "The exit IP is located in "+r.Country.ISO+", not in "+r.ExpectedCountry+" as the profile says.")
			}
		}
	}

	ctx6, cancel := context.WithTimeout(ctx, cfg.Timeout)
	if ip6, err := fetchIP(ctx6, cfg.IPv6Client, *cfg.IPv6Service); err == nil && ip6.Is6() {
		r.IPv6.IP = ip6.String()
		r.add("ipv6_leak", Critical, "IPv6 traffic reaches the internet although it must be blocked.")
	} else {
		r.IPv6.Blocked = true
	}
	cancel()

	d := &net.Dialer{Timeout: cfg.Timeout}
	for _, s := range cfg.STUNServers {
		sctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
		ap, err := STUNMappedAddress(sctx, d, s)
		cancel()
		if err != nil {
			r.STUN.Error = err.Error()
			continue
		}
		r.STUN.IP, r.STUN.Error = ap.Addr().String(), ""
		break
	}
	if r.STUN.IP != "" && exit.IsValid() && r.STUN.IP != exit.String() {
		r.add("webrtc_leak", Critical, "WebRTC (STUN) reveals a different public IP than the tunnel exit.")
	}

	if cfg.BypassClient != nil && len(cfg.Services) > 0 {
		r.Bypass.Checked = true
		bctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
		ip, err := fetchIP(bctx, cfg.BypassClient, cfg.Services[0])
		cancel()
		if err != nil {
			r.Bypass.Blocked = true
		} else {
			r.Bypass.IP = ip.String()
			r.add("bypass", Critical, "A request bound to the physical interface reached the internet directly.")
		}
	}

	if cfg.TimeZone != "" {
		r.TimeZone.Zone = cfg.TimeZone
		r.TimeZone.Country = TimeZoneCountry(cfg.TimeZone)
		if r.TimeZone.Country != "" && r.Country.ISO != "" && r.TimeZone.Country != r.Country.ISO {
			r.add("timezone_mismatch", Info, "The device time zone ("+cfg.TimeZone+") does not match the exit country; sites may notice.")
		}
	}
	if cfg.Exclusions > 0 {
		r.add("exclusions_active", Info, "Sites in the exclusion list see your real IP address and country.")
	}
	return r
}
