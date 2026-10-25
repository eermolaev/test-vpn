package profile

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
)

const amneziaScheme = "vpn://"

// maxKeySize bounds the decompressed size of a vpn:// key.
const maxKeySize = 1 << 20

type amneziaKey struct {
	Containers       []map[string]json.RawMessage `json:"containers"`
	DefaultContainer string                       `json:"defaultContainer"`
	Description      string                       `json:"description"`
	DNS1             string                       `json:"dns1"`
	DNS2             string                       `json:"dns2"`
	HostName         string                       `json:"hostName"`
	// Subscription keys (Amnezia Premium / Free) carry no server config,
	// only credentials for the Amnezia gateway.
	ConfigVersion int             `json:"config_version"`
	AuthData      json.RawMessage `json:"auth_data"`
	APIEndpoint   string          `json:"api_endpoint"`
}

// amneziaSubscriptionHelp explains why subscription keys cannot be imported.
const amneziaSubscriptionHelp = "amnezia: this is a subscription key (Amnezia Premium/Free): it holds no server settings, " +
	"only credentials for Amnezia's gateway, which only the official app can use. " +
	"In AmneziaVPN open the server → \"Configuration files\" (\"For router setup or the AmneziaWG app\"), " +
	"download the .conf for a location and import that file"

type amneziaProto struct {
	LastConfig string `json:"last_config"`
}

// ParseAmneziaKey parses a key exported by Amnezia VPN:
// "vpn://" + base64url(qCompress(json)), where qCompress is a 4-byte
// big-endian length followed by a zlib stream.
func ParseAmneziaKey(s string) (*Profile, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(strings.ToLower(s), amneziaScheme) {
		return nil, invalid("amnezia: missing vpn:// prefix")
	}
	raw, err := decodeBase64Any(s[len(amneziaScheme):])
	if err != nil {
		return nil, invalid("amnezia: base64: %v", err)
	}
	data, err := qUncompress(raw)
	if err != nil {
		return nil, err
	}
	var key amneziaKey
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, invalid("amnezia: json: %v", err)
	}
	if len(key.Containers) == 0 && (key.ConfigVersion != 0 || len(key.AuthData) > 0 || key.APIEndpoint != "") {
		return nil, unsupported(amneziaSubscriptionHelp)
	}
	p := &Profile{Name: key.Description}
	for _, d := range []string{key.DNS1, key.DNS2} {
		if d != "" {
			p.ServerDNS = append(p.ServerDNS, d)
		}
	}
	// Default container first, so that it becomes the preferred transport.
	containers := key.Containers
	for i, c := range containers {
		if containerName(c) == key.DefaultContainer && i > 0 {
			containers = append([]map[string]json.RawMessage{c}, append(containers[:i:i], containers[i+1:]...)...)
			break
		}
	}
	var skipped []string
	for _, c := range containers {
		name := containerName(c)
		found := false
		for k, v := range c {
			if k == "container" {
				continue
			}
			var proto amneziaProto
			if json.Unmarshal(v, &proto) != nil || proto.LastConfig == "" {
				continue
			}
			found = true
			sub, err := parseAmneziaLastConfig(proto.LastConfig, key)
			if err != nil {
				return nil, err
			}
			p.Merge(sub)
		}
		if !found {
			skipped = append(skipped, name)
		}
	}
	if len(p.Transports) == 0 {
		return nil, unsupported("amnezia: no supported containers (found %v)", skipped)
	}
	return p, p.Validate()
}

func containerName(c map[string]json.RawMessage) string {
	var n string
	_ = json.Unmarshal(c["container"], &n)
	return n
}

func qUncompress(b []byte) ([]byte, error) {
	if len(b) < 4 {
		return nil, invalid("amnezia: key too short")
	}
	n := binary.BigEndian.Uint32(b[:4])
	if n > maxKeySize {
		return nil, invalid("amnezia: key too large")
	}
	zr, err := zlib.NewReader(bytes.NewReader(b[4:]))
	if err != nil {
		// Some tools export uncompressed JSON.
		if json.Valid(b) {
			return b, nil
		}
		return nil, invalid("amnezia: zlib: %v", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, maxKeySize+1))
	if err != nil {
		return nil, invalid("amnezia: zlib: %v", err)
	}
	if len(out) > maxKeySize {
		return nil, invalid("amnezia: key too large")
	}
	return out, nil
}

func parseAmneziaLastConfig(lc string, key amneziaKey) (*Profile, error) {
	text := lc
	var obj map[string]json.RawMessage
	if json.Unmarshal([]byte(lc), &obj) == nil {
		if _, ok := obj["outbounds"]; ok {
			return ParseXrayJSON([]byte(lc))
		}
		var cfg string
		if json.Unmarshal(obj["config"], &cfg) == nil && cfg != "" {
			text = cfg
		}
	}
	if !strings.Contains(text, "[Interface]") {
		if strings.Contains(text, "outbounds") {
			return ParseXrayJSON([]byte(text))
		}
		return nil, unsupported("amnezia: container config is neither AmneziaWG nor xray")
	}
	text = strings.NewReplacer("$PRIMARY_DNS", key.DNS1, "$SECONDARY_DNS", key.DNS2).Replace(text)
	t, err := ParseAWGConf(text)
	if err != nil {
		return nil, err
	}
	return &Profile{Transports: []Transport{*t}}, nil
}
