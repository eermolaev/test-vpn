package profile

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

const testHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

func TestParseSSHLink(t *testing.T) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testHostKey))
	if err != nil {
		t.Fatal(err)
	}
	fp := ssh.FingerprintSHA256(pk)
	p, err := Parse("ssh://user:p%40ss@example.com:2222?hostkey=" + url.QueryEscape(fp) + "#My%20SSH")
	if err != nil {
		t.Fatal(err)
	}
	tr := p.Transports[0]
	c := tr.SSH
	if p.Name != "My SSH" || tr.Kind != KindSSH || tr.Policy != PolicyManualOnly {
		t.Fatalf("profile %+v", p)
	}
	if c.Address != "example.com" || c.Port != 2222 || c.Username != "user" || c.Password != "p@ss" || c.HostKey != fp {
		t.Fatalf("config %+v", c)
	}
	// An unescaped "+" in the query arrives as a space.
	raw := "ssh://u:p@h?hostkey=" + fp
	if !strings.Contains(fp, "+") {
		raw = "ssh://u:p@h?hostkey=" + strings.Replace(fp, fp[10:11], "+", 1)
	}
	if _, _, err := ParseSSHURL(raw); err != nil {
		t.Fatalf("plus in fingerprint: %v", err)
	}
	// Default port and a known_hosts line as the host key.
	tr2, _, err := ParseSSHURL("ssh://u:p@h?hostkey=" + url.QueryEscape("h.example "+testHostKey))
	if err != nil || tr2.SSH.Port != 22 || tr2.SSH.HostKey != fp {
		t.Fatalf("%v %+v", err, tr2)
	}
}

func TestParseSSHKey(t *testing.T) {
	key := `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBZG6Wn/RMBn3QYRzqLEdq5kjpGRo8Iih2qp1vh2V/6WgAAAJhKC5V6SguV
egAAAAtzc2gtZWQyNTUxOQAAACBZG6Wn/RMBn3QYRzqLEdq5kjpGRo8Iih2qp1vh2V/6Wg
AAAEDiVIbsTB/hGVv7YZpe7gUs16MbvrMH6sBO16ojZzrZu1kbpaf9EwGfdBhHOosR2rmS
OkZGjwiKHaqnW+HZX/paAAAAEHRlc3RAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----`
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding} {
		tr, _, err := ParseSSHURL("ssh://root@1.2.3.4?pk=" + enc.EncodeToString([]byte(key)))
		if err != nil {
			t.Fatal(err)
		}
		if tr.SSH.PrivateKey == "" || tr.SSH.Password != "" {
			t.Fatalf("%+v", tr.SSH)
		}
		p := &Profile{Transports: []Transport{*tr}}
		if s := p.Summarize().Transports[0].Detail; s != "key" {
			t.Fatalf("detail %q", s)
		}
		if !contains(p.Secrets(), tr.SSH.PrivateKey) {
			t.Fatal("private key is not redacted")
		}
	}
}

func TestParseSSHErrors(t *testing.T) {
	for _, s := range []string{
		"ssh://h",                        // no user
		"ssh://u@h",                      // no password or key
		"ssh://u:p@h:99999",              // port
		"ssh://u:p@h?hostkey=SHA256:abc", // short fingerprint
		"ssh://u@h?pk=bm90IGEga2V5",      // "not a key"
		"ssh://u:p@h/path",
	} {
		if _, err := Parse(s); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", s, err)
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
