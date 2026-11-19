package profile

import (
	"encoding/json"
	"strconv"
)

type xrayConfig struct {
	Outbounds []xrayOutbound `json:"outbounds"`
	Remarks   string         `json:"remarks"`
}

type xrayOutbound struct {
	Protocol       string          `json:"protocol"`
	Tag            string          `json:"tag"`
	Settings       json.RawMessage `json:"settings"`
	StreamSettings *xrayStream     `json:"streamSettings"`
	Mux            *struct {
		Enabled     bool    `json:"enabled"`
		Concurrency flexInt `json:"concurrency"`
	} `json:"mux"`
}

type xrayUser struct {
	ID         string  `json:"id"`
	Flow       string  `json:"flow"`
	Encryption string  `json:"encryption"`
	Security   string  `json:"security"` // VMess cipher
	AlterID    flexInt `json:"alterId"`  // VMess, must be 0
	Password   string  `json:"password"` // Trojan
}

type xrayVLESSSettings struct {
	Vnext []struct {
		Address string     `json:"address"`
		Port    flexInt    `json:"port"`
		Users   []xrayUser `json:"users"`
	} `json:"vnext"`
	// Trojan servers.
	Servers []struct {
		Address  string  `json:"address"`
		Port     flexInt `json:"port"`
		Password string  `json:"password"`
		Flow     string  `json:"flow"`
	} `json:"servers"`
	// Simplified single-server form.
	Address string  `json:"address"`
	Port    flexInt `json:"port"`
	xrayUser
}

type xrayStream struct {
	Network  string `json:"network"`
	Security string `json:"security"`
	Reality  *struct {
		ServerName  string `json:"serverName"`
		Fingerprint string `json:"fingerprint"`
		PublicKey   string `json:"publicKey"`
		Password    string `json:"password"`
		ShortID     string `json:"shortId"`
		SpiderX     string `json:"spiderX"`
		Mldsa65     string `json:"mldsa65Verify"`
	} `json:"realitySettings"`
	TLS *struct {
		ServerName  string   `json:"serverName"`
		Fingerprint string   `json:"fingerprint"`
		ALPN        []string `json:"alpn"`
	} `json:"tlsSettings"`
	XHTTP *struct {
		Path string `json:"path"`
		Host string `json:"host"`
		Mode string `json:"mode"`
	} `json:"xhttpSettings"`
	SplitHTTP *struct {
		Path string `json:"path"`
		Host string `json:"host"`
		Mode string `json:"mode"`
	} `json:"splithttpSettings"`
	GRPC *struct {
		ServiceName string `json:"serviceName"`
	} `json:"grpcSettings"`
	WS *struct {
		Path    string            `json:"path"`
		Host    string            `json:"host"`
		Headers map[string]string `json:"headers"`
	} `json:"wsSettings"`
}

// flexInt accepts both 443 and "443".
type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	var n int
	if err := json.Unmarshal(b, &n); err == nil {
		*f = flexInt(n)
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	n, err := strconv.Atoi(s)
	*f = flexInt(n)
	return err
}

// ParseXrayJSON extracts all VLESS, VMess and Trojan outbounds from an xray client config. Other
// outbounds (freedom, blackhole, dns, ...) are ignored: routing is done by the
// app, not by the imported config.
func ParseXrayJSON(data []byte) (*Profile, error) {
	var cfg xrayConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, invalid("xray json: %v", err)
	}
	p := &Profile{Name: cfg.Remarks}
	var other []string
	for _, ob := range cfg.Outbounds {
		switch ob.Protocol {
		case "vless", "vmess", "trojan":
		case "freedom", "blackhole", "dns", "loopback":
			continue
		default:
			other = append(other, ob.Protocol)
			continue
		}
		t, err := xrayOutboundToTransport(ob)
		if err != nil {
			return nil, err
		}
		p.Transports = append(p.Transports, *t)
	}
	if len(p.Transports) == 0 {
		if len(other) > 0 {
			return nil, unsupported("xray json: no vless, vmess or trojan outbounds (found %v)", other)
		}
		return nil, invalid("xray json: no vless, vmess or trojan outbounds")
	}
	return p, p.Validate()
}

func xrayOutboundToTransport(ob xrayOutbound) (*Transport, error) {
	var s xrayVLESSSettings
	if err := json.Unmarshal(ob.Settings, &s); err != nil {
		return nil, invalid("xray json: %s settings: %v", ob.Protocol, err)
	}
	c := &VLESSConfig{Protocol: ob.Protocol}
	user := s.xrayUser
	switch {
	case len(s.Servers) > 0:
		if len(s.Servers) > 1 {
			return nil, unsupported("xray json: multiple servers in one outbound")
		}
		v := s.Servers[0]
		c.Address, c.Port = v.Address, int(v.Port)
		user = xrayUser{Password: v.Password, Flow: v.Flow}
	case len(s.Vnext) > 0:
		if len(s.Vnext) > 1 || len(s.Vnext[0].Users) != 1 {
			return nil, unsupported("xray json: multiple servers or users in one outbound")
		}
		v := s.Vnext[0]
		c.Address, c.Port = v.Address, int(v.Port)
		user = v.Users[0]
	default:
		c.Address, c.Port = s.Address, int(s.Port)
	}
	c.UUID, c.Flow, c.Password = user.ID, user.Flow, user.Password
	// xray ignores mux with flow; so do we rather than reject the config.
	if m := ob.Mux; m != nil && m.Enabled && m.Concurrency >= 0 && c.Flow == "" {
		c.Mux = int(m.Concurrency)
		if c.Mux == 0 {
			c.Mux = DefaultMux // xray's default concurrency
		}
	}
	switch ob.Protocol {
	case "vless":
		if e := user.Encryption; e != "" && e != "none" {
			return nil, unsupported("xray json: vless encryption %q", e)
		}
	case "vmess":
		if user.AlterID != 0 {
			return nil, unsupported("xray json: vmess alterId %d (only AEAD, alterId 0, is supported)", user.AlterID)
		}
		c.Cipher = user.Security
	}
	if st := ob.StreamSettings; st != nil {
		c.Network, c.Security = st.Network, st.Security
		if r := st.Reality; r != nil {
			c.SNI, c.Fingerprint, c.ShortID, c.SpiderX, c.Mldsa65Verify = r.ServerName, r.Fingerprint, r.ShortID, r.SpiderX, r.Mldsa65
			c.PublicKey = r.PublicKey
			if c.PublicKey == "" {
				c.PublicKey = r.Password
			}
		}
		if t := st.TLS; t != nil {
			c.SNI, c.Fingerprint, c.ALPN = t.ServerName, t.Fingerprint, t.ALPN
		}
		x := st.XHTTP
		if x == nil {
			x = st.SplitHTTP
		}
		if x != nil {
			c.Path, c.Host, c.Mode = x.Path, x.Host, x.Mode
		}
		if g := st.GRPC; g != nil {
			c.ServiceName = g.ServiceName
		}
		if w := st.WS; w != nil {
			c.Path, c.Host = w.Path, w.Host
			if c.Host == "" {
				c.Host = w.Headers["Host"]
			}
		}
	}
	t := &Transport{VLESS: c, Label: ob.Tag}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return t, nil
}
