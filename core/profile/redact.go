package profile

import (
	"encoding/json"
	"strings"
)

// Secrets returns all secret values of the profile, for log redaction
// (SEC-LOG-001).
func (p *Profile) Secrets() []string {
	var out []string
	add := func(v ...string) {
		for _, s := range v {
			if len(s) >= 4 {
				out = append(out, s)
			}
		}
	}
	for _, t := range p.Transports {
		if c := t.AWG; c != nil {
			add(c.PrivateKey, c.Peer.PublicKey, c.Peer.PresharedKey, c.Peer.Endpoint, c.I1, c.I2, c.I3, c.I4, c.I5)
			add(c.H1, c.H2, c.H3, c.H4)
			if h := t.ServerHost(); h != "" {
				add(h)
			}
		}
		if c := t.VLESS; c != nil {
			add(c.UUID, c.Password, c.PublicKey, c.ShortID, c.Address, c.Path)
		}
		if c := t.OpenVPN; c != nil {
			add(c.Host)
		}
		if c := t.Proxy; c != nil {
			add(c.Address, c.Username, c.Password)
		}
		if c := t.SSH; c != nil {
			add(c.Address, c.Username, c.Password, c.PrivateKey)
		}
		if c := t.Hysteria; c != nil {
			add(c.Address, c.Auth, c.ObfsPassword, c.SNI)
		}
	}
	return out
}

// Redactor replaces secret values in text.
type Redactor struct{ r *strings.Replacer }

// NewRedactor builds a redactor for the given secrets.
func NewRedactor(secrets []string) *Redactor {
	var pairs []string
	for _, s := range secrets {
		pairs = append(pairs, s, "[REDACTED]")
	}
	return &Redactor{r: strings.NewReplacer(pairs...)}
}

// Redact returns s with all secrets replaced.
func (r *Redactor) Redact(s string) string {
	if r == nil || r.r == nil {
		return s
	}
	return r.r.Replace(s)
}

// Summary is a secret-free description of a profile for UI and diagnostics.
type Summary struct {
	Name       string             `json:"name"`
	Transports []TransportSummary `json:"transports"`
}

type TransportSummary struct {
	ID     string `json:"id"` // contains the server endpoint; redact before logging
	Kind   Kind   `json:"kind"`
	Policy Policy `json:"policy"`
	Label  string `json:"label,omitempty"`
	Detail string `json:"detail"` // e.g. "raw+vision", "xhttp"
}

// Summarize returns a summary for display.
func (p *Profile) Summarize() Summary {
	s := Summary{Name: p.Name}
	for _, t := range p.Transports {
		ts := TransportSummary{ID: t.ID(), Kind: t.Kind, Policy: t.Policy, Label: t.Label}
		if v := t.VLESS; v != nil {
			ts.Detail = v.Network
			if v.Flow != "" {
				ts.Detail += "+vision"
			}
			if v.Proto() != "vless" {
				ts.Detail += "+" + v.Security
			}
		}
		if t.AWG != nil {
			ts.Detail = "udp"
		}
		if c := t.OpenVPN; c != nil {
			ts.Detail = c.Proto
		}
		if c := t.Proxy; c != nil {
			switch {
			case c.Method != "":
				ts.Detail = c.Method
			case c.TLS:
				ts.Detail = "tls"
			}
		}
		if c := t.SSH; c != nil {
			ts.Detail = "password"
			if c.PrivateKey != "" {
				ts.Detail = "key"
			}
		}
		if c := t.Hysteria; c != nil {
			var d []string
			if c.ObfsPassword != "" {
				d = append(d, "salamander")
			}
			if c.Ports != "" {
				d = append(d, "port hopping")
			}
			if !c.Verified() {
				d = append(d, "insecure")
			}
			ts.Detail = strings.Join(d, ", ")
		}
		s.Transports = append(s.Transports, ts)
	}
	return s
}

// MarshalSummary is a convenience for the bridge.
func (s Summary) JSON() string {
	b, _ := json.Marshal(s)
	return string(b)
}
