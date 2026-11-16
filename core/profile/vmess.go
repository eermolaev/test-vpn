package profile

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

// ParseTrojanURL parses a trojan:// share link:
//
//	trojan://password@host:port?security=tls&sni=…&type=ws&path=…#name
//
// security defaults to tls; the old peer= parameter is the SNI.
func ParseTrojanURL(s string) (*Transport, string, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return nil, "", invalid("trojan: %v", err)
	}
	if !strings.EqualFold(u.Scheme, "trojan") {
		return nil, "", invalid("trojan: scheme %q", u.Scheme)
	}
	port := 443
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil {
			return nil, "", invalid("trojan: bad port")
		}
	}
	c := &VLESSConfig{Protocol: "trojan", Address: u.Hostname(), Port: port}
	if u.User != nil {
		c.Password = u.User.Username()
	}
	q := u.Query()
	if err := c.streamFromQuery(q); err != nil {
		return nil, "", err
	}
	if c.Security == "" {
		c.Security = "tls"
	}
	if c.SNI == "" {
		c.SNI = q.Get("peer")
	}
	if c.Flow = q.Get("flow"); c.Flow != "" {
		return nil, "", unsupported("trojan: flow %q", c.Flow)
	}
	name, _ := url.PathUnescape(u.Fragment)
	t := &Transport{VLESS: c, Label: name}
	if err := t.Validate(); err != nil {
		return nil, "", err
	}
	return t, name, nil
}

// vmessLink is the v2rayN vmess:// JSON. Numbers may be strings.
type vmessLink struct {
	Name     string  `json:"ps"`
	Address  string  `json:"add"`
	Port     flexInt `json:"port"`
	ID       string  `json:"id"`
	AlterID  flexInt `json:"aid"`
	Cipher   string  `json:"scy"`
	Network  string  `json:"net"`
	Header   string  `json:"type"`
	Host     string  `json:"host"`
	Path     string  `json:"path"`
	Security string  `json:"tls"`
	SNI      string  `json:"sni"`
	ALPN     string  `json:"alpn"`
	FP       string  `json:"fp"`
	// REALITY, written by some clients.
	PublicKey string `json:"pbk"`
	ShortID   string `json:"sid"`
	SpiderX   string `json:"spx"`
}

// ParseVMessURL parses a vmess:// link: base64 of the v2rayN JSON.
func ParseVMessURL(s string) (*Transport, string, error) {
	body := strings.TrimSpace(s)[len("vmess://"):]
	if i := strings.IndexAny(body, "#?"); i >= 0 {
		body = body[:i]
	}
	dec, err := decodeB64(strings.TrimSpace(body))
	if err != nil {
		return nil, "", invalid("vmess: the link is not base64 JSON")
	}
	var l vmessLink
	if err := json.Unmarshal([]byte(dec), &l); err != nil {
		return nil, "", invalid("vmess: %v", err)
	}
	if l.AlterID != 0 {
		return nil, "", unsupported("vmess: alterId %d (only AEAD, alterId 0, is supported)", l.AlterID)
	}
	if l.Header != "" && l.Header != "none" {
		return nil, "", unsupported("vmess: header type %q", l.Header)
	}
	c := &VLESSConfig{
		Protocol: "vmess", Address: l.Address, Port: int(l.Port), UUID: l.ID, Cipher: l.Cipher,
		Network: l.Network, Security: l.Security, SNI: l.SNI, Fingerprint: l.FP,
		Host: l.Host, Path: l.Path, PublicKey: l.PublicKey, ShortID: l.ShortID, SpiderX: l.SpiderX,
	}
	if l.ALPN != "" {
		c.ALPN = splitList(l.ALPN)
	}
	if c.Network == "grpc" {
		c.ServiceName, c.Path = l.Path, ""
	}
	if c.Security == "tls" && c.SNI == "" {
		c.SNI = l.Host
	}
	t := &Transport{VLESS: c, Label: l.Name}
	if err := t.Validate(); err != nil {
		return nil, "", err
	}
	return t, l.Name, nil
}
