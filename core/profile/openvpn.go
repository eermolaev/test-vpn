package profile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// OpenVPNConfig is one remote of an OpenVPN client config. The engine runs
// the openvpn binary with Config and points it at Host:Port over Proto.
type OpenVPNConfig struct {
	// Config is the .ovpn text without remotes, without directives that run
	// programs or change routes and DNS, and with every file inlined.
	Config string `json:"config"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Proto  string `json:"proto"` // udp | tcp
}

// ErrOpenVPNCredentials means the config asks for a user name and password
// that it does not contain.
var ErrOpenVPNCredentials = errors.New("openvpn: the server asks for a user name and password: import with testvpn import --user NAME FILE")

func (c *OpenVPNConfig) validate() error {
	if c.Host == "" {
		return invalid("openvpn: empty remote")
	}
	if c.Port <= 0 || c.Port > 65535 {
		return invalid("openvpn: bad port %d", c.Port)
	}
	if c.Proto != "udp" && c.Proto != "tcp" {
		return unsupported("openvpn: proto %q", c.Proto)
	}
	if !strings.Contains(c.Config, "<ca>") && !hasDirective(c.Config, "pkcs12") {
		return invalid("openvpn: no CA certificate (<ca> block)")
	}
	return nil
}

// isOpenVPNConfig recognises an .ovpn file by its client directives.
func isOpenVPNConfig(s string) bool {
	return hasDirective(s, "remote") && (hasDirective(s, "client") || hasDirective(s, "tls-client") || strings.Contains(s, "<ca>"))
}

func hasDirective(s, name string) bool {
	for _, line := range strings.Split(s, "\n") {
		if f := strings.Fields(line); len(f) > 0 && strings.EqualFold(f[0], name) {
			return true
		}
	}
	return false
}

// openVPNDropped are directives the client never passes to openvpn: they run
// programs, write files, or change routes, DNS or the interface, all of which
// the daemon controls (kill switch, DNS, exclusions).
var openVPNDropped = map[string]bool{
	"up": true, "down": true, "route-up": true, "route-pre-down": true, "ipchange": true,
	"tls-verify": true, "plugin": true, "auth-user-pass-verify": true, "learn-address": true,
	"client-connect": true, "client-disconnect": true, "iproute": true, "script-security": true,
	"up-delay": true, "down-pre": true, "up-restart": true, "setenv-safe": true,
	"config": true, "cd": true, "chroot": true, "daemon": true, "user": true, "group": true,
	"log": true, "log-append": true, "status": true, "writepid": true, "syslog": true,
	"management": true, "management-hold": true, "management-query-passwords": true,
	"management-client-auth": true, "management-signal": true, "tls-export-cert": true,
	"route": true, "route-ipv6": true, "redirect-gateway": true, "redirect-private": true,
	"route-gateway": true, "route-delay": true, "route-method": true, "route-metric": true,
	"route-nopull": true, "route-noexec": true, "dhcp-option": true, "block-outside-dns": true,
	"register-dns": true, "ip-win32": true, "dev": true, "dev-type": true, "dev-node": true,
	"remote": true, "proto": true, "port": true, "rport": true, "remote-random": true,
	"remote-random-hostname": true, "resolv-retry": true, "connect-retry-max": true,
	"verb": true, "mute": true, "askpass": true, "auth-user-pass": true, "service": true,
	"pull-filter": true, "persist-tun": true, "auth-nocache": true,
}

// openVPNFiles are directives whose argument is a file that may be inlined
// as <name>…</name>.
var openVPNFiles = map[string]bool{
	"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true,
	"tls-crypt-v2": true, "extra-certs": true, "pkcs12": true, "secret": true,
	"crl-verify": true, "auth-user-pass": true, "http-proxy-user-pass": true, "dh": true,
}

// ParseOpenVPN parses an .ovpn client config. Each remote becomes one
// transport, in the order of the file. Files must be inlined (see
// InlineOpenVPNFiles).
func ParseOpenVPN(s string) (*Profile, error) {
	var keep []string
	var remotes []OpenVPNConfig
	defPort, defProto := 1194, "udp"
	needAuth, haveAuth := false, false
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if tag, ok := openTag(line); ok {
			end := "</" + tag + ">"
			j := i + 1
			for j < len(lines) && strings.TrimSpace(lines[j]) != end {
				j++
			}
			if j == len(lines) {
				return nil, invalid("openvpn: <%s> is not closed", tag)
			}
			switch {
			case tag == "connection":
				return nil, unsupported("openvpn: <connection> blocks; use remote lines")
			case tag == "auth-user-pass":
				haveAuth = j-i-1 >= 2
			case !openVPNFiles[tag]:
				return nil, unsupported("openvpn: inline <%s>", tag)
			}
			for ; i <= j; i++ {
				keep = append(keep, strings.TrimRight(lines[i], " \t\r"))
			}
			i = j
			continue
		}
		f := strings.Fields(line)
		name := strings.ToLower(strings.TrimPrefix(f[0], "--"))
		args := f[1:]
		switch name {
		case "remote":
			if len(args) == 0 {
				return nil, invalid("openvpn: remote without a host")
			}
			r := OpenVPNConfig{Host: args[0]}
			if len(args) > 1 {
				p, err := strconv.Atoi(args[1])
				if err != nil {
					return nil, invalid("openvpn: bad port %q", args[1])
				}
				r.Port = p
			}
			if len(args) > 2 {
				r.Proto = args[2]
			}
			remotes = append(remotes, r)
			continue
		case "port", "rport":
			if len(args) == 1 {
				p, err := strconv.Atoi(args[0])
				if err != nil {
					return nil, invalid("openvpn: bad port %q", args[0])
				}
				defPort = p
			}
			continue
		case "proto":
			if len(args) == 1 {
				defProto = args[0]
			}
			continue
		case "auth-user-pass":
			needAuth = true
			if len(args) > 0 && args[0] != "[inline]" {
				return nil, invalid("openvpn: auth-user-pass refers to file %q; import the .ovpn file from disk so it can be embedded", args[0])
			}
			continue
		}
		if openVPNFiles[name] && len(args) > 0 && args[0] != "[inline]" {
			return nil, invalid("openvpn: %s refers to file %q; import the .ovpn file from disk so it can be embedded, or paste it as <%s>…</%s>", name, args[0], name, name)
		}
		if openVPNDropped[name] {
			continue
		}
		keep = append(keep, line)
	}
	if len(remotes) == 0 {
		return nil, invalid("openvpn: no remote")
	}
	if needAuth && !haveAuth {
		return nil, ErrOpenVPNCredentials
	}
	cfg := strings.Join(keep, "\n") + "\n"
	if haveAuth {
		cfg += "auth-user-pass\n"
	}
	p := &Profile{}
	for _, r := range remotes {
		if r.Port == 0 {
			r.Port = defPort
		}
		if r.Proto == "" {
			r.Proto = defProto
		}
		proto, err := openVPNProto(r.Proto)
		if err != nil {
			return nil, err
		}
		r.Proto, r.Config = proto, cfg
		p.Merge(&Profile{Transports: []Transport{{OpenVPN: &r}}})
	}
	return p, p.Validate()
}

func openVPNProto(p string) (string, error) {
	switch strings.ToLower(p) {
	case "udp", "udp4", "udp6":
		return "udp", nil
	case "tcp", "tcp4", "tcp6", "tcp-client", "tcp4-client", "tcp6-client":
		return "tcp", nil
	}
	return "", unsupported("openvpn: proto %q", p)
}

// openTag reports whether line is "<name>" and returns the name.
func openTag(line string) (string, bool) {
	if len(line) < 3 || line[0] != '<' || line[1] == '/' || line[len(line)-1] != '>' {
		return "", false
	}
	return strings.ToLower(line[1 : len(line)-1]), true
}

// InlineOpenVPNFiles replaces file references in an .ovpn config (ca, cert,
// key, tls-auth, auth-user-pass, …) with inline blocks, resolving relative
// paths against dir. It runs where the file was read, before the text is
// sent to the daemon, which cannot see the user's files.
func InlineOpenVPNFiles(s, dir string) (string, error) {
	if !isOpenVPNConfig(s) {
		return s, nil
	}
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			out = append(out, line)
			continue
		}
		name := strings.ToLower(strings.TrimPrefix(f[0], "--"))
		if !openVPNFiles[name] || f[1] == "[inline]" {
			out = append(out, line)
			continue
		}
		path := strings.Trim(f[1], `"'`)
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, path)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("openvpn: %s: %w", name, err)
		}
		if name == "tls-auth" && len(f) > 2 {
			out = append(out, "key-direction "+f[2])
		}
		if name == "auth-user-pass" {
			out = append(out, "auth-user-pass")
		}
		out = append(out, "<"+name+">", strings.TrimRight(string(b), "\n"), "</"+name+">")
	}
	return strings.Join(out, "\n"), nil
}

// WithOpenVPNCredentials adds an inline user name and password to an .ovpn
// config that asks for them.
func WithOpenVPNCredentials(s, user, password string) string {
	return strings.TrimRight(s, "\n") + "\n<auth-user-pass>\n" + user + "\n" + password + "\n</auth-user-pass>\n"
}
