package profile

import (
	"encoding/base64"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// ProxyProtocol is the protocol of a proxy transport.
type ProxyProtocol string

const (
	ProxySOCKS       ProxyProtocol = "socks"
	ProxyHTTP        ProxyProtocol = "http"
	ProxyShadowsocks ProxyProtocol = "shadowsocks"
)

// ProxyConfig is a SOCKS5, HTTP(S) CONNECT or Shadowsocks server.
type ProxyConfig struct {
	Protocol ProxyProtocol `json:"protocol"`
	Address  string        `json:"address"`
	Port     int           `json:"port"`
	Username string        `json:"username,omitempty"`
	Password string        `json:"password,omitempty"`
	// TLS wraps an HTTP proxy connection in TLS (https://).
	TLS bool   `json:"tls,omitempty"`
	SNI string `json:"sni,omitempty"`
	// Method is the Shadowsocks cipher.
	Method string `json:"method,omitempty"`
}

// ShadowsocksMethods are the AEAD ciphers xray supports.
var ShadowsocksMethods = []string{
	"aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "xchacha20-poly1305",
	"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
}

func (c *ProxyConfig) validate() error {
	if c.Address == "" {
		return invalid("proxy: empty address")
	}
	if c.Port <= 0 || c.Port > 65535 {
		return invalid("proxy: bad port %d", c.Port)
	}
	switch c.Protocol {
	case ProxySOCKS, ProxyHTTP:
		if c.Password != "" && c.Username == "" {
			return invalid("proxy: password without user name")
		}
	case ProxyShadowsocks:
		if c.Method == "chacha20-ietf-poly1305" {
			c.Method = "chacha20-poly1305"
		}
		if !slices.Contains(ShadowsocksMethods, c.Method) {
			return unsupported("shadowsocks: cipher %q (supported: %s)", c.Method, strings.Join(ShadowsocksMethods, ", "))
		}
		if c.Password == "" {
			return invalid("shadowsocks: empty password")
		}
	default:
		return unsupported("proxy: protocol %q", c.Protocol)
	}
	return nil
}

// proxySchemes maps link schemes to proxy protocols.
var proxySchemes = map[string]ProxyProtocol{
	"socks": ProxySOCKS, "socks5": ProxySOCKS, "socks5h": ProxySOCKS,
	"http": ProxyHTTP, "https": ProxyHTTP,
	"ss": ProxyShadowsocks,
}

// isProxyLink reports whether s starts with a proxy link scheme.
func isProxyLink(s string) bool {
	i := strings.Index(s, "://")
	if i <= 0 {
		return false
	}
	_, ok := proxySchemes[strings.ToLower(s[:i])]
	return ok
}

// ParseProxyURL parses a proxy link:
//
//	socks5://user:pass@host:port#name
//	http://user:pass@host:port, https://host:port?sni=name
//	ss://BASE64(method:password)@host:port#name (SIP002)
//	ss://BASE64(method:password@host:port)#name (legacy)
func ParseProxyURL(s string) (*Transport, string, error) {
	s = strings.TrimSpace(s)
	scheme := strings.ToLower(s[:max(strings.Index(s, "://"), 0)])
	proto, ok := proxySchemes[scheme]
	if !ok {
		return nil, "", invalid("proxy: scheme %q", scheme)
	}
	if proto == ProxyShadowsocks {
		s = expandLegacySS(s)
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, "", invalid("proxy: %v", err)
	}
	if u.Path != "" && u.Path != "/" {
		return nil, "", invalid("proxy: %s://… with a path %q is a web address, not a proxy", scheme, u.Path)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, "", invalid("proxy: bad port in %s://…", scheme)
	}
	c := &ProxyConfig{Protocol: proto, Address: u.Hostname(), Port: port}
	q := u.Query()
	switch proto {
	case ProxyShadowsocks:
		if q.Get("plugin") != "" {
			return nil, "", unsupported("shadowsocks: plugin %q", q.Get("plugin"))
		}
		c.Method, c.Password, err = ssUserInfo(u.User)
		if err != nil {
			return nil, "", err
		}
	default:
		if u.User != nil {
			c.Username = u.User.Username()
			c.Password, _ = u.User.Password()
		}
		c.TLS = scheme == "https"
		c.SNI = q.Get("sni")
	}
	name, _ := url.PathUnescape(u.Fragment)
	t := &Transport{Proxy: c, Label: name}
	if err := t.Validate(); err != nil {
		return nil, "", err
	}
	return t, name, nil
}

// expandLegacySS turns ss://BASE64(method:password@host:port)#name into the
// SIP002 form.
func expandLegacySS(s string) string {
	body, frag, _ := strings.Cut(strings.TrimPrefix(s[len("ss://"):], "//"), "#")
	if strings.Contains(body, "@") {
		return s
	}
	dec, err := decodeB64(body)
	if err != nil || !strings.Contains(dec, "@") {
		return s
	}
	i := strings.LastIndex(dec, "@")
	out := "ss://" + base64.RawURLEncoding.EncodeToString([]byte(dec[:i])) + "@" + dec[i+1:]
	if frag != "" {
		out += "#" + frag
	}
	return out
}

// ssUserInfo decodes "method:password", either base64 or, for 2022
// ciphers, percent-encoded.
func ssUserInfo(ui *url.Userinfo) (method, password string, err error) {
	if ui == nil {
		return "", "", invalid("shadowsocks: missing method and password")
	}
	if p, ok := ui.Password(); ok {
		return ui.Username(), p, nil
	}
	dec, err := decodeB64(ui.Username())
	if err != nil {
		return "", "", invalid("shadowsocks: user info is neither method:password nor base64")
	}
	method, password, ok := strings.Cut(dec, ":")
	if !ok {
		return "", "", invalid("shadowsocks: user info lacks a password")
	}
	return method, password, nil
}

func decodeB64(s string) (string, error) {
	s = strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), nil
		}
	}
	return "", invalid("bad base64")
}
