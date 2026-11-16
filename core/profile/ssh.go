package profile

import (
	"errors"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SSHConfig is an SSH server used as a tunnel: TCP connections are opened
// through it as direct-tcpip channels (like ssh -D). UDP is not carried; DNS
// goes over TCP.
type SSHConfig struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	// Password authenticates the user; with an encrypted PrivateKey it is
	// also the key passphrase.
	Password string `json:"password,omitempty"`
	// PrivateKey is an OpenSSH or PEM private key.
	PrivateKey string `json:"privateKey,omitempty"`
	// HostKey pins the server key as a SHA256 fingerprint ("SHA256:…").
	// Empty means trust on first use: the key seen first is remembered.
	HostKey string `json:"hostKey,omitempty"`
}

func (c *SSHConfig) validate() error {
	if c.Address == "" {
		return invalid("ssh: empty address")
	}
	if c.Port == 0 {
		c.Port = 22
	}
	if c.Port < 0 || c.Port > 65535 {
		return invalid("ssh: bad port %d", c.Port)
	}
	if c.Username == "" {
		return invalid("ssh: empty user name")
	}
	if c.Password == "" && c.PrivateKey == "" {
		return invalid("ssh: neither password nor private key")
	}
	if c.PrivateKey != "" {
		if _, err := c.Signer(); err != nil {
			return err
		}
	}
	if c.HostKey != "" {
		fp, err := NormalizeHostKey(c.HostKey)
		if err != nil {
			return err
		}
		c.HostKey = fp
	}
	return nil
}

// Signer parses the private key, using Password as the passphrase when the
// key is encrypted.
func (c *SSHConfig) Signer() (ssh.Signer, error) {
	key := []byte(strings.TrimSpace(c.PrivateKey) + "\n")
	s, err := ssh.ParsePrivateKey(key)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if c.Password == "" {
			return nil, invalid("ssh: the private key is encrypted; put its passphrase in the password")
		}
		s, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(c.Password))
	}
	if err != nil {
		return nil, invalid("ssh: private key: %v", err)
	}
	return s, nil
}

// NormalizeHostKey turns a host key given as "SHA256:…" or as a public key
// line ("ssh-ed25519 AAAA…", as in known_hosts) into its SHA256 fingerprint.
func NormalizeHostKey(s string) (string, error) {
	s = strings.TrimSpace(s)
	if rest, ok := strings.CutPrefix(s, "SHA256:"); ok {
		// Query strings turn "+" into a space.
		rest = strings.TrimRight(strings.ReplaceAll(rest, " ", "+"), "=")
		if len(rest) != 43 {
			return "", invalid("ssh: bad host key fingerprint")
		}
		return "SHA256:" + rest, nil
	}
	// known_hosts lines start with the host names.
	fields := strings.Fields(s)
	for i := range fields {
		if k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.Join(fields[i:], " "))); err == nil {
			return ssh.FingerprintSHA256(k), nil
		}
	}
	return "", invalid("ssh: host key is neither SHA256:… nor a public key")
}

// ParseSSHURL parses an SSH link:
//
//	ssh://user:password@host:port?hostkey=SHA256:…&pk=BASE64(private key)#name
//
// The port defaults to 22. pk is the private key file, base64 (standard or
// URL alphabet); with pk the password is the key passphrase.
func ParseSSHURL(s string) (*Transport, string, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return nil, "", invalid("ssh: %v", err)
	}
	if !strings.EqualFold(u.Scheme, "ssh") {
		return nil, "", invalid("ssh: scheme %q", u.Scheme)
	}
	if u.Path != "" && u.Path != "/" {
		return nil, "", invalid("ssh: unexpected path %q", u.Path)
	}
	c := &SSHConfig{Address: u.Hostname()}
	if p := u.Port(); p != "" {
		if c.Port, err = strconv.Atoi(p); err != nil {
			return nil, "", invalid("ssh: bad port %q", p)
		}
	}
	if u.User != nil {
		c.Username = u.User.Username()
		c.Password, _ = u.User.Password()
	}
	q := u.Query()
	c.HostKey = q.Get("hostkey")
	if pk := q.Get("pk"); pk != "" {
		key, err := decodeB64(strings.ReplaceAll(pk, " ", "+"))
		if err != nil {
			return nil, "", invalid("ssh: pk is not base64")
		}
		c.PrivateKey = key
	}
	name, _ := url.PathUnescape(u.Fragment)
	t := &Transport{SSH: c, Label: name}
	if err := t.Validate(); err != nil {
		return nil, "", err
	}
	return t, name, nil
}
