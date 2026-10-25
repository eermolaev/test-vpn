package profile

import (
	"bufio"
	"net/netip"
	"strconv"
	"strings"
)

// wg-quick keys that only make sense for the Linux tool and are ignored.
var ignoredAWGKeys = map[string]bool{
	"postup": true, "postdown": true, "preup": true, "predown": true,
	"table": true, "saveconfig": true, "fwmark": true, "listenport": true,
}

// ParseAWGConf parses an AmneziaWG (wg-quick style) config. Unknown keys are
// rejected rather than silently ignored (spec 4.2), except wg-quick hooks.
func ParseAWGConf(text string) (*Transport, error) {
	cfg := &AWGConfig{}
	section := ""
	peers := 0
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	ln := 0
	for sc.Scan() {
		ln++
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(line, "#;"); i == 0 {
			continue
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch section {
			case "interface":
			case "peer":
				peers++
				if peers > 1 {
					return nil, unsupported("awg: more than one [Peer]")
				}
			default:
				return nil, invalid("awg line %d: unknown section [%s]", ln, section)
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, invalid("awg line %d: expected key = value", ln)
		}
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		var err error
		switch section {
		case "interface":
			err = cfg.setInterface(key, val)
		case "peer":
			err = cfg.Peer.set(key, val)
		default:
			return nil, invalid("awg line %d: key outside of a section", ln)
		}
		if err != nil {
			return nil, invalid("awg line %d (%s): %v", ln, strings.TrimSpace(k), err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, invalid("awg: %v", err)
	}
	if peers == 0 {
		return nil, invalid("awg: no [Peer] section")
	}
	t := &Transport{AWG: cfg}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return t, nil
}

type errText string

func (e errText) Error() string { return string(e) }

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parsePrefixes(v string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, p := range splitList(v) {
		if !strings.Contains(p, "/") {
			a, err := netip.ParseAddr(p)
			if err != nil {
				return nil, err
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		pr, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, err
		}
		out = append(out, pr)
	}
	return out, nil
}

func atoi(v string) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, errText("not a number")
	}
	return n, nil
}

func (c *AWGConfig) setInterface(key, val string) error {
	var err error
	switch key {
	case "privatekey":
		c.PrivateKey = val
	case "address":
		c.Addresses, err = parsePrefixes(val)
	case "dns":
		for _, d := range splitList(val) {
			a, e := netip.ParseAddr(d)
			if e != nil {
				continue // search domains are allowed in wg-quick; ignore them
			}
			c.DNS = append(c.DNS, a)
		}
	case "mtu":
		c.MTU, err = atoi(val)
	case "jc":
		c.Jc, err = atoi(val)
	case "jmin":
		c.Jmin, err = atoi(val)
	case "jmax":
		c.Jmax, err = atoi(val)
	case "s1":
		c.S1, err = atoi(val)
	case "s2":
		c.S2, err = atoi(val)
	case "s3":
		c.S3, err = atoi(val)
	case "s4":
		c.S4, err = atoi(val)
	case "h1":
		c.H1 = val
	case "h2":
		c.H2 = val
	case "h3":
		c.H3 = val
	case "h4":
		c.H4 = val
	case "i1":
		c.I1 = val
	case "i2":
		c.I2 = val
	case "i3":
		c.I3 = val
	case "i4":
		c.I4 = val
	case "i5":
		c.I5 = val
	default:
		if !ignoredAWGKeys[key] {
			return errText("unknown parameter")
		}
	}
	return err
}

func (p *AWGPeer) set(key, val string) error {
	var err error
	switch key {
	case "publickey":
		p.PublicKey = val
	case "presharedkey":
		p.PresharedKey = val
	case "endpoint":
		p.Endpoint = val
	case "allowedips":
		p.AllowedIPs, err = parsePrefixes(val)
	case "persistentkeepalive":
		p.Keepalive, err = atoi(val)
	default:
		return errText("unknown parameter")
	}
	return err
}

// FormatAWGConf renders the config in wg-quick format (used for export and
// for passing configs between processes).
func FormatAWGConf(c *AWGConfig) string {
	var b strings.Builder
	w := func(k, v string) {
		if v != "" && v != "0" {
			b.WriteString(k + " = " + v + "\n")
		}
	}
	join := func(ps []netip.Prefix) string {
		s := make([]string, len(ps))
		for i, p := range ps {
			s[i] = p.String()
		}
		return strings.Join(s, ", ")
	}
	b.WriteString("[Interface]\n")
	w("PrivateKey", c.PrivateKey)
	w("Address", join(c.Addresses))
	if len(c.DNS) > 0 {
		s := make([]string, len(c.DNS))
		for i, a := range c.DNS {
			s[i] = a.String()
		}
		w("DNS", strings.Join(s, ", "))
	}
	w("MTU", strconv.Itoa(c.MTU))
	for _, kv := range []struct {
		k string
		v int
	}{{"Jc", c.Jc}, {"Jmin", c.Jmin}, {"Jmax", c.Jmax}, {"S1", c.S1}, {"S2", c.S2}, {"S3", c.S3}, {"S4", c.S4}} {
		w(kv.k, strconv.Itoa(kv.v))
	}
	for _, kv := range [][2]string{{"H1", c.H1}, {"H2", c.H2}, {"H3", c.H3}, {"H4", c.H4}, {"I1", c.I1}, {"I2", c.I2}, {"I3", c.I3}, {"I4", c.I4}, {"I5", c.I5}} {
		w(kv[0], kv[1])
	}
	b.WriteString("\n[Peer]\n")
	w("PublicKey", c.Peer.PublicKey)
	w("PresharedKey", c.Peer.PresharedKey)
	w("Endpoint", c.Peer.Endpoint)
	w("AllowedIPs", join(c.Peer.AllowedIPs))
	w("PersistentKeepalive", strconv.Itoa(c.Peer.Keepalive))
	return b.String()
}
