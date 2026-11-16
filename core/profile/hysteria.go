package profile

import (
	"encoding/hex"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// HysteriaConfig is a Hysteria 2 server (QUIC over UDP).
type HysteriaConfig struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	// Ports enables port hopping: "20000-30000" or "443,5000-6000". The
	// client then moves between these ports; Port is the first one.
	Ports string `json:"ports,omitempty"`
	Auth  string `json:"auth"`
	SNI   string `json:"sni,omitempty"`
	// Insecure accepts any server certificate (self-signed without a pin).
	Insecure bool `json:"insecure,omitempty"`
	// PinSHA256 is the SHA-256 of the server (or CA) certificate, hex.
	PinSHA256 string `json:"pinSHA256,omitempty"`
	// ObfsPassword enables Salamander obfuscation.
	ObfsPassword string `json:"obfsPassword,omitempty"`
}

var portsRe = regexp.MustCompile(`^\d+(-\d+)?(,\d+(-\d+)?)*$`)

func (c *HysteriaConfig) validate() error {
	if c.Address == "" {
		return invalid("hysteria2: empty address")
	}
	if c.Ports != "" {
		if !portsRe.MatchString(c.Ports) {
			return invalid("hysteria2: bad port list %q", c.Ports)
		}
		for _, r := range strings.Split(c.Ports, ",") {
			lo, hi, _ := strings.Cut(r, "-")
			a, _ := strconv.Atoi(lo)
			b := a
			if hi != "" {
				b, _ = strconv.Atoi(hi)
			}
			if a <= 0 || b > 65535 || a > b {
				return invalid("hysteria2: bad port range %q", r)
			}
			if c.Port == 0 {
				c.Port = a
			}
		}
	}
	if c.Port == 0 {
		c.Port = 443
	}
	if c.Port < 0 || c.Port > 65535 {
		return invalid("hysteria2: bad port %d", c.Port)
	}
	if c.Auth == "" {
		return invalid("hysteria2: empty password (auth)")
	}
	if c.PinSHA256 != "" {
		pin := strings.ToLower(strings.ReplaceAll(c.PinSHA256, ":", ""))
		if b, err := hex.DecodeString(pin); err != nil || len(b) != 32 {
			return invalid("hysteria2: pinSHA256 must be 64 hex digits")
		}
		c.PinSHA256 = pin
	}
	if c.SNI == "" && net.ParseIP(c.Address) == nil {
		c.SNI = c.Address
	}
	if c.SNI == "" && !c.Insecure && c.PinSHA256 == "" {
		return invalid("hysteria2: a server given by IP needs sni, pinSHA256 or insecure=1")
	}
	return nil
}

// Verified reports whether the server certificate is checked.
func (c *HysteriaConfig) Verified() bool { return !c.Insecure || c.PinSHA256 != "" }

// isHysteriaLink reports whether s is a hysteria2:// or hy2:// link.
func isHysteriaLink(s string) bool {
	return hasPrefixFold(s, "hysteria2://") || hasPrefixFold(s, "hy2://")
}

// multiPortRe matches the official multi-port form host:443,5000-6000.
var multiPortRe = regexp.MustCompile(`^([^/?#]*@)?(\[[^\]]+\]|[^:/?#@]+):(\d+(?:-\d+)?(?:,\d+(?:-\d+)?)+|\d+-\d+)([/?#].*)?$`)

// ParseHysteriaURL parses a Hysteria 2 link:
//
//	hysteria2://auth@host:port/?sni=…&obfs=salamander&obfs-password=…&pinSHA256=…&insecure=1#name
//
// hy2:// is the same. Port hopping is given as host:443,5000-6000 or with
// mport=5000-6000.
func ParseHysteriaURL(s string) (*Transport, string, error) {
	s = strings.TrimSpace(s)
	i := strings.Index(s, "://")
	body := s[i+3:]
	c := &HysteriaConfig{}
	// url.Parse rejects multi-port hosts: cut the ports out first.
	if m := multiPortRe.FindStringSubmatch(body); m != nil {
		c.Ports = m[3]
		body = m[1] + m[2] + m[4]
	}
	u, err := url.Parse("hysteria2://" + body)
	if err != nil {
		return nil, "", invalid("hysteria2: %v", err)
	}
	if u.Path != "" && u.Path != "/" {
		return nil, "", invalid("hysteria2: unexpected path %q", u.Path)
	}
	c.Address = u.Hostname()
	if p := u.Port(); p != "" {
		if c.Port, err = strconv.Atoi(p); err != nil {
			return nil, "", invalid("hysteria2: bad port %q", p)
		}
	}
	if u.User != nil {
		// "user:pass" is the userpass auth of the server, sent as is.
		c.Auth = u.User.Username()
		if pw, ok := u.User.Password(); ok {
			c.Auth += ":" + pw
		}
	}
	q := u.Query()
	if c.Auth == "" {
		c.Auth = q.Get("auth")
	}
	if mp := q.Get("mport"); mp != "" && c.Ports == "" {
		c.Ports = mp
	}
	c.SNI = q.Get("sni")
	c.Insecure = q.Get("insecure") == "1" || strings.EqualFold(q.Get("insecure"), "true")
	c.PinSHA256 = q.Get("pinSHA256")
	switch obfs := strings.ToLower(q.Get("obfs")); obfs {
	case "", "none":
	case "salamander":
		c.ObfsPassword = q.Get("obfs-password")
		if c.ObfsPassword == "" {
			return nil, "", invalid("hysteria2: salamander without obfs-password")
		}
	default:
		return nil, "", unsupported("hysteria2: obfs %q", obfs)
	}
	name, _ := url.PathUnescape(u.Fragment)
	t := &Transport{Hysteria: c, Label: name}
	if err := t.Validate(); err != nil {
		return nil, "", err
	}
	return t, name, nil
}
