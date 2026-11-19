package profile

import (
	"net/url"
	"strconv"
	"strings"
)

// ParseVLESSURL parses a vless:// share link:
//
//	vless://UUID@host:port?type=tcp&security=reality&pbk=..&sid=..&sni=..&fp=chrome&flow=xtls-rprx-vision#name
func ParseVLESSURL(s string) (*Transport, string, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return nil, "", invalid("vless: %v", err)
	}
	if !strings.EqualFold(u.Scheme, "vless") {
		return nil, "", invalid("vless: scheme %q", u.Scheme)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, "", invalid("vless: bad port")
	}
	q := u.Query()
	c := &VLESSConfig{Address: u.Hostname(), Port: port, UUID: u.User.Username(), Flow: q.Get("flow")}
	if err := c.streamFromQuery(q); err != nil {
		return nil, "", err
	}
	if e := q.Get("encryption"); e != "" && e != "none" {
		return nil, "", unsupported("vless: encryption %q", e)
	}
	t := &Transport{VLESS: c}
	if err := t.Validate(); err != nil {
		return nil, "", err
	}
	name, _ := url.PathUnescape(u.Fragment)
	t.Label = name
	return t, name, nil
}

// streamFromQuery reads the stream settings of a vless:// or trojan:// link.
func (c *VLESSConfig) streamFromQuery(q url.Values) error {
	c.Security = q.Get("security")
	c.Network = q.Get("type")
	c.SNI = q.Get("sni")
	c.Fingerprint = q.Get("fp")
	c.PublicKey = q.Get("pbk")
	c.ShortID = q.Get("sid")
	c.SpiderX = q.Get("spx")
	c.Mldsa65Verify = q.Get("pqv")
	c.Path = q.Get("path")
	c.Host = q.Get("host")
	c.Mode = q.Get("mode")
	c.ServiceName = q.Get("serviceName")
	if a := q.Get("alpn"); a != "" {
		c.ALPN = splitList(a)
	}
	if hdr := q.Get("headerType"); hdr != "" && hdr != "none" {
		return unsupported("%s: headerType %q", c.Proto(), hdr)
	}
	if m := q.Get("mux"); m != "" {
		n, err := strconv.Atoi(m)
		if err != nil {
			return invalid("%s: mux must be a number, got %q", c.Proto(), m)
		}
		c.Mux = n
	}
	return nil
}

// FormatVLESSURL renders the transport as a share link.
func FormatVLESSURL(c *VLESSConfig, name string) string {
	q := url.Values{}
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	q.Set("encryption", "none")
	set("type", map[string]string{"raw": "tcp"}[c.Network])
	if q.Get("type") == "" {
		set("type", c.Network)
	}
	set("security", c.Security)
	set("flow", c.Flow)
	set("sni", c.SNI)
	set("fp", c.Fingerprint)
	set("pbk", c.PublicKey)
	set("sid", c.ShortID)
	set("spx", c.SpiderX)
	set("pqv", c.Mldsa65Verify)
	set("path", c.Path)
	set("host", c.Host)
	set("mode", c.Mode)
	set("serviceName", c.ServiceName)
	set("alpn", strings.Join(c.ALPN, ","))
	if c.Mux > 0 {
		q.Set("mux", strconv.Itoa(c.Mux))
	}
	u := url.URL{
		Scheme:   "vless",
		User:     url.User(c.UUID),
		Host:     joinHostPort(c.Address, c.Port),
		RawQuery: q.Encode(),
		Fragment: name,
	}
	return u.String()
}

func joinHostPort(h string, p int) string {
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	return h + ":" + strconv.Itoa(p)
}
