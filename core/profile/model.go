// Package profile parses connection profiles (vless:// links, AmneziaWG
// configs, Amnezia vpn:// keys and xray JSON) into one validated model.
package profile

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Kind identifies a transport protocol.
type Kind string

const (
	KindAmneziaWG    Kind = "amneziawg"
	KindWireGuard    Kind = "wireguard" // AmneziaWG config without obfuscation
	KindVLESSReality Kind = "vless-reality"
	KindVLESSTLS     Kind = "vless-tls"
	KindVLESSPlain   Kind = "vless-plain"
)

// Policy says how a transport may be used (spec 4.1).
type Policy string

const (
	PolicyPrimary    Policy = "primary"
	PolicyFallback   Policy = "fallback"
	PolicyManualOnly Policy = "manual-only" // never selected automatically
	PolicyForbidden  Policy = "forbidden"   // cannot be used at all
)

// Strength orders transports by resistance to DPI; automatic fallback never
// moves to a lower strength than PolicyFallback allows (SEC-NET-003).
func (p Policy) Automatic() bool { return p == PolicyPrimary || p == PolicyFallback }

// Profile is a server profile with one or more transports (SEC-NET-001).
type Profile struct {
	Name       string      `json:"name"`
	Transports []Transport `json:"transports"`
	// DNS servers suggested by the server; informational only (GEO-010).
	ServerDNS []string `json:"serverDNS,omitempty"`
}

// Transport is one way to connect to the server.
type Transport struct {
	Kind   Kind         `json:"kind"`
	Policy Policy       `json:"policy"`
	Label  string       `json:"label,omitempty"`
	AWG    *AWGConfig   `json:"awg,omitempty"`
	VLESS  *VLESSConfig `json:"vless,omitempty"`
}

// ID returns a stable identifier used to remember the working transport for a
// network (SEC-NET-005). It contains no secrets.
func (t Transport) ID() string {
	switch {
	case t.AWG != nil:
		return string(t.Kind) + ":" + t.AWG.Peer.Endpoint
	case t.VLESS != nil:
		return string(t.Kind) + ":" + net.JoinHostPort(t.VLESS.Address, strconv.Itoa(t.VLESS.Port)) + ":" + t.VLESS.Network
	}
	return string(t.Kind)
}

// ServerHost returns the host of the VPN server for this transport.
func (t Transport) ServerHost() string {
	switch {
	case t.AWG != nil:
		h, _, _ := net.SplitHostPort(t.AWG.Peer.Endpoint)
		return h
	case t.VLESS != nil:
		return t.VLESS.Address
	}
	return ""
}

// AWGConfig is an AmneziaWG interface with a single peer.
type AWGConfig struct {
	PrivateKey string         `json:"privateKey"` // base64
	Addresses  []netip.Prefix `json:"addresses"`
	DNS        []netip.Addr   `json:"dns,omitempty"`
	MTU        int            `json:"mtu,omitempty"`

	Jc   int `json:"jc,omitempty"`
	Jmin int `json:"jmin,omitempty"`
	Jmax int `json:"jmax,omitempty"`
	S1   int `json:"s1,omitempty"`
	S2   int `json:"s2,omitempty"`
	S3   int `json:"s3,omitempty"`
	S4   int `json:"s4,omitempty"`
	// H1..H4 are magic headers: a number or a range "min-max".
	H1 string `json:"h1,omitempty"`
	H2 string `json:"h2,omitempty"`
	H3 string `json:"h3,omitempty"`
	H4 string `json:"h4,omitempty"`
	// I1..I5 are signature packet templates, e.g. "<b 0xc700><r 16>".
	I1 string `json:"i1,omitempty"`
	I2 string `json:"i2,omitempty"`
	I3 string `json:"i3,omitempty"`
	I4 string `json:"i4,omitempty"`
	I5 string `json:"i5,omitempty"`

	// AmneziaWG 3 parameters. HeaderProtectionKey is base64 and must match
	// the server; the others are numbers or ranges "min-max".
	HeaderProtectionKey    string `json:"headerProtectionKey,omitempty"`
	ContentPaddingAddition string `json:"contentPaddingAddition,omitempty"`
	RekeyAfterTime         string `json:"rekeyAfterTime,omitempty"`
	RekeyTimeout           string `json:"rekeyTimeout,omitempty"`
	RejectAfterTime        string `json:"rejectAfterTime,omitempty"`
	KeepaliveTimeout       string `json:"keepaliveTimeout,omitempty"`
	MaxHandshakeAttempts   string `json:"maxHandshakeAttempts,omitempty"`
	RandomTrailers         bool   `json:"randomTrailers,omitempty"`
	DisableCookies         bool   `json:"disableCookies,omitempty"`

	Peer AWGPeer `json:"peer"`
}

// AWGPeer is the server side of an AmneziaWG config.
type AWGPeer struct {
	PublicKey    string         `json:"publicKey"`
	PresharedKey string         `json:"presharedKey,omitempty"`
	Endpoint     string         `json:"endpoint"` // host:port
	AllowedIPs   []netip.Prefix `json:"allowedIPs"`
	Keepalive    int            `json:"keepalive,omitempty"`
	// KeepaliveRange is a randomized interval "min-max" (AmneziaWG 3).
	KeepaliveRange string `json:"keepaliveRange,omitempty"`
}

// Obfuscated reports whether any AmneziaWG obfuscation is configured. Without
// it the transport is plain WireGuard and easy to fingerprint.
func (c *AWGConfig) Obfuscated() bool {
	if c.Jc > 0 || c.S1 > 0 || c.S2 > 0 || c.S3 > 0 || c.S4 > 0 {
		return true
	}
	if c.I1 != "" || c.I2 != "" || c.I3 != "" || c.I4 != "" || c.I5 != "" {
		return true
	}
	for i, h := range []string{c.H1, c.H2, c.H3, c.H4} {
		if h != "" && h != strconv.Itoa(i+1) {
			return true
		}
	}
	return false
}

// VLESSConfig is a VLESS outbound.
type VLESSConfig struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	UUID     string `json:"uuid"`
	Flow     string `json:"flow,omitempty"` // xtls-rprx-vision
	Security string `json:"security"`       // reality | tls | none
	Network  string `json:"network"`        // raw | xhttp | grpc | ws
	// TLS / REALITY.
	SNI         string   `json:"sni,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	PublicKey   string   `json:"publicKey,omitempty"` // REALITY password (x25519 public key)
	ShortID     string   `json:"shortId,omitempty"`
	SpiderX     string   `json:"spiderX,omitempty"`
	// Mldsa65Verify is the optional post-quantum REALITY verification key.
	Mldsa65Verify string `json:"mldsa65Verify,omitempty"`
	// Transport specific.
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	Mode        string `json:"mode,omitempty"` // xhttp mode
	ServiceName string `json:"serviceName,omitempty"`
}

// DefaultFingerprint is the uTLS fingerprint used when the profile has none.
const DefaultFingerprint = "chrome"

var (
	ErrUnknownFormat = errors.New("unknown profile format")
	ErrInvalid       = errors.New("invalid profile")
	ErrUnsupported   = errors.New("unsupported profile feature")
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

func unsupported(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrUnsupported, fmt.Sprintf(format, a...))
}

// classify assigns Kind and Policy according to spec 4.1.
func (t *Transport) classify() {
	switch {
	case t.AWG != nil:
		if t.AWG.Obfuscated() {
			t.Kind, t.Policy = KindAmneziaWG, PolicyPrimary
		} else {
			t.Kind, t.Policy = KindWireGuard, PolicyManualOnly
		}
	case t.VLESS != nil:
		switch t.VLESS.Security {
		case "reality":
			t.Kind = KindVLESSReality
			if t.VLESS.Network == "raw" && t.VLESS.Flow == "xtls-rprx-vision" {
				t.Policy = PolicyPrimary
			} else {
				t.Policy = PolicyFallback
			}
		case "tls":
			t.Kind, t.Policy = KindVLESSTLS, PolicyManualOnly
		default:
			t.Kind, t.Policy = KindVLESSPlain, PolicyForbidden
		}
	}
}

// Validate checks the transport and fills defaults.
func (t *Transport) Validate() error {
	switch {
	case t.AWG != nil && t.VLESS == nil:
		if err := t.AWG.validate(); err != nil {
			return err
		}
	case t.VLESS != nil && t.AWG == nil:
		if err := t.VLESS.validate(); err != nil {
			return err
		}
	default:
		return invalid("transport must have exactly one of awg or vless")
	}
	t.classify()
	return nil
}

func (p *Profile) Validate() error {
	if len(p.Transports) == 0 {
		return invalid("profile has no transports")
	}
	for i := range p.Transports {
		if err := p.Transports[i].Validate(); err != nil {
			return fmt.Errorf("transport %d: %w", i+1, err)
		}
	}
	if p.Name == "" {
		p.Name = p.Transports[0].ServerHost()
	}
	return nil
}

// Merge appends the transports of other to p (SEC-NET-001: one profile, many
// transports), skipping transports with the same ID.
func (p *Profile) Merge(other *Profile) {
	seen := map[string]bool{}
	for _, t := range p.Transports {
		seen[t.ID()] = true
	}
	for _, t := range other.Transports {
		if !seen[t.ID()] {
			p.Transports = append(p.Transports, t)
			seen[t.ID()] = true
		}
	}
}

func validHostPort(hp string) bool {
	h, p, err := net.SplitHostPort(hp)
	if err != nil || h == "" {
		return false
	}
	n, err := strconv.Atoi(p)
	return err == nil && n > 0 && n < 65536
}

func (c *AWGConfig) validate() error {
	if !isKey(c.PrivateKey) {
		return invalid("awg: bad private key")
	}
	if !isKey(c.Peer.PublicKey) {
		return invalid("awg: bad peer public key")
	}
	if c.Peer.PresharedKey != "" && !isKey(c.Peer.PresharedKey) {
		return invalid("awg: bad preshared key")
	}
	if !validHostPort(c.Peer.Endpoint) {
		return invalid("awg: bad endpoint %q", c.Peer.Endpoint)
	}
	if len(c.Addresses) == 0 {
		return invalid("awg: no interface address")
	}
	if c.Jc < 0 || c.Jmin < 0 || c.Jmax < 0 || c.S1 < 0 || c.S2 < 0 || c.S3 < 0 || c.S4 < 0 {
		return invalid("awg: negative obfuscation parameter")
	}
	if c.Jc > 0 && (c.Jmin <= 0 || c.Jmax < c.Jmin) {
		return invalid("awg: Jmin/Jmax must satisfy 0 < Jmin <= Jmax")
	}
	for i, h := range []string{c.H1, c.H2, c.H3, c.H4} {
		if h != "" && !validMagicHeader(h) {
			return invalid("awg: bad H%d %q", i+1, h)
		}
	}
	for _, r := range []struct{ name, v string }{
		{"ContentPaddingAddition", c.ContentPaddingAddition}, {"RekeyAfterTime", c.RekeyAfterTime},
		{"RekeyTimeout", c.RekeyTimeout}, {"RejectAfterTime", c.RejectAfterTime},
		{"KeepaliveTimeout", c.KeepaliveTimeout}, {"MaxHandshakeAttempts", c.MaxHandshakeAttempts},
		{"PersistentKeepalive", c.Peer.KeepaliveRange},
	} {
		if r.v != "" && !validMagicHeader(r.v) {
			return invalid("awg: bad %s %q", r.name, r.v)
		}
	}
	if c.HeaderProtectionKey != "" {
		if k, err := base64.StdEncoding.DecodeString(c.HeaderProtectionKey); err != nil || len(k) != 32 {
			return invalid("awg: HeaderProtectionKey must be a base64 32-byte key")
		}
	}
	if c.MTU != 0 && (c.MTU < 1280 || c.MTU > 1500) {
		return invalid("awg: MTU %d out of range 1280..1500", c.MTU)
	}
	if len(c.Peer.AllowedIPs) == 0 {
		c.Peer.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	}
	return nil
}

func validMagicHeader(h string) bool {
	parts := strings.Split(h, "-")
	if len(parts) > 2 {
		return false
	}
	var vals []uint64
	for _, p := range parts {
		v, err := strconv.ParseUint(strings.TrimSpace(p), 10, 32)
		if err != nil {
			return false
		}
		vals = append(vals, v)
	}
	return len(vals) == 1 || vals[0] <= vals[1]
}

func (c *VLESSConfig) validate() error {
	if c.Address == "" {
		return invalid("vless: empty address")
	}
	if c.Port <= 0 || c.Port > 65535 {
		return invalid("vless: bad port %d", c.Port)
	}
	if !isUUID(c.UUID) {
		return invalid("vless: bad uuid")
	}
	switch c.Network {
	case "", "tcp", "raw":
		c.Network = "raw"
	case "xhttp", "splithttp":
		c.Network = "xhttp"
	case "grpc", "ws":
	default:
		return unsupported("vless: network %q", c.Network)
	}
	switch c.Flow {
	case "", "xtls-rprx-vision":
	case "xtls-rprx-vision-udp443":
		c.Flow = "xtls-rprx-vision"
	default:
		return unsupported("vless: flow %q", c.Flow)
	}
	if c.Flow != "" && c.Network != "raw" {
		return invalid("vless: flow %s requires raw/tcp transport", c.Flow)
	}
	if c.Security == "" {
		c.Security = "none"
	}
	switch c.Security {
	case "reality":
		if c.PublicKey == "" {
			return invalid("vless: reality public key is missing")
		}
		if c.SNI == "" {
			return invalid("vless: reality server name is missing")
		}
		if len(c.ShortID) > 16 || len(c.ShortID)%2 != 0 || !isHex(c.ShortID) {
			return invalid("vless: bad reality shortId")
		}
		if c.Fingerprint == "" {
			c.Fingerprint = DefaultFingerprint
		}
	case "tls":
		if c.Fingerprint == "" {
			c.Fingerprint = DefaultFingerprint
		}
	case "none":
	default:
		return unsupported("vless: security %q", c.Security)
	}
	return nil
}
