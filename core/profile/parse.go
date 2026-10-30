package profile

import (
	"bytes"
	"strings"
)

// Parse detects the format of input (pasted text, file contents or a decoded
// QR code) and parses it. Several links (vless://, ss://, socks5://, http://)
// separated by newlines become one profile with several transports.
func Parse(input string) (*Profile, error) {
	s := strings.TrimSpace(strings.TrimPrefix(input, "\xef\xbb\xbf"))
	switch {
	case s == "":
		return nil, invalid("empty input")
	case hasPrefixFold(s, amneziaScheme):
		return ParseAmneziaKey(s)
	case hasPrefixFold(s, "vless://") || isProxyLink(s):
		p := &Profile{}
		for _, line := range strings.Split(s, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var t *Transport
			var name string
			var err error
			if hasPrefixFold(line, "vless://") {
				t, name, err = ParseVLESSURL(line)
			} else {
				t, name, err = ParseProxyURL(line)
			}
			if err != nil {
				return nil, err
			}
			if p.Name == "" {
				p.Name = name
			}
			p.Merge(&Profile{Transports: []Transport{*t}})
		}
		return p, p.Validate()
	case isOpenVPNConfig(s):
		return ParseOpenVPN(s)
	case strings.HasPrefix(s, "{"):
		return ParseXrayJSON([]byte(s))
	case bytes.Contains(bytes.ToLower([]byte(s)), []byte("[interface]")):
		t, err := ParseAWGConf(s)
		if err != nil {
			return nil, err
		}
		p := &Profile{Transports: []Transport{*t}}
		return p, p.Validate()
	}
	return nil, ErrUnknownFormat
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}
