// Package rules implements the domain exclusion list (SPLIT-001) and the set
// of protected hosts that must always go through the tunnel (SPLIT-005).
package rules

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// MaxRules is the maximum number of entries in one exclusion list.
const MaxRules = 1000

// Kind is the matching mode of a rule.
type Kind int

const (
	// Suffix matches the domain itself and all of its subdomains.
	Suffix Kind = iota
	// Full matches only the exact domain.
	Full
	// Wildcard ("*") matches every host; only allowed in the VPN list.
	Wildcard
)

const fullPrefix = "full:"

// Rule is a single normalized exclusion entry.
type Rule struct {
	Kind   Kind
	Domain string // lower-case ASCII (punycode), no trailing dot
}

// String returns the canonical textual form of the rule.
func (r Rule) String() string {
	switch r.Kind {
	case Full:
		return fullPrefix + r.Domain
	case Wildcard:
		return "*"
	}
	return r.Domain
}

// Matches reports whether the normalized host is covered by the rule.
func (r Rule) Matches(host string) bool {
	switch r.Kind {
	case Full:
		return host == r.Domain
	case Wildcard:
		return true
	}
	return host == r.Domain || strings.HasSuffix(host, "."+r.Domain)
}

var (
	ErrEmpty     = errors.New("empty rule")
	ErrIPAddress = errors.New("IP addresses are not supported, use a domain name")
	ErrInvalid   = errors.New("invalid domain name")
	ErrProtected = errors.New("domain is used for VPN self-checks and cannot be excluded")
	ErrTooMany   = fmt.Errorf("too many rules (maximum %d)", MaxRules)
	ErrDuplicate = errors.New("duplicate rule")
	ErrWildcard  = errors.New(`"*" is only allowed in the VPN list`)
)

var profile = idna.New(
	idna.MapForLookup(),
	idna.Transitional(false),
	idna.StrictDomainName(true),
)

// NormalizeHost converts a host name to the form used for matching:
// lower-case punycode without a trailing dot. It returns "" if the host is not
// a valid domain name.
func NormalizeHost(host string) string {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		return ""
	}
	ascii, err := profile.ToASCII(host)
	if err != nil {
		return ""
	}
	return strings.ToLower(ascii)
}

// ParseRule parses one user-entered rule. Accepted forms:
//
//	example.com        domain and all subdomains
//	*.example.com      same as above
//	full:example.com   exact domain only
func ParseRule(s string) (Rule, error) {
	if strings.TrimSpace(s) == "*" {
		return Rule{}, ErrWildcard
	}
	r, err := parseRule(s)
	if err == nil && IsProtectedRule(r) {
		return Rule{}, fmt.Errorf("%w: %s", ErrProtected, r.Domain)
	}
	return r, err
}

// ParseTunnelRule parses a rule for the VPN-only list. Self-check hosts may
// be covered: forcing them into the tunnel is what they need anyway.
func ParseTunnelRule(s string) (Rule, error) {
	if strings.TrimSpace(s) == "*" {
		return Rule{Kind: Wildcard}, nil
	}
	return parseRule(s)
}

func parseRule(s string) (Rule, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Rule{}, ErrEmpty
	}
	kind := Suffix
	if len(s) >= len(fullPrefix) && strings.EqualFold(s[:len(fullPrefix)], fullPrefix) {
		kind = Full
		s = strings.TrimSpace(s[len(fullPrefix):])
	} else if strings.HasPrefix(s, "*.") {
		s = s[2:]
	}
	if _, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return Rule{}, ErrIPAddress
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return Rule{}, ErrIPAddress
	}
	d := NormalizeHost(s)
	if d == "" || !strings.Contains(d, ".") && kind == Full {
		return Rule{}, fmt.Errorf("%w: %q", ErrInvalid, s)
	}
	return Rule{Kind: kind, Domain: d}, nil
}

// Set is an immutable, validated exclusion list.
type Set struct {
	full     map[string]struct{}
	suffix   map[string]struct{}
	wildcard bool
	rules    []Rule
}

// LineError describes an invalid line of an imported list.
type LineError struct {
	Line int // 1-based
	Text string
	Err  error
}

func (e LineError) Error() string { return fmt.Sprintf("line %d (%q): %v", e.Line, e.Text, e.Err) }
func (e LineError) Unwrap() error { return e.Err }

// NewSet validates the given entries. Blank lines and lines starting with '#'
// are ignored. If any entry is invalid, the set is not created and all errors
// are returned, so that the user can fix the list in one pass.
func NewSet(entries []string) (*Set, []LineError) { return newSet(entries, ParseRule) }

// NewTunnelSet validates a VPN-only list (domains that must never be reached
// directly). It uses the same format as exclusions.
func NewTunnelSet(entries []string) (*Set, []LineError) { return newSet(entries, ParseTunnelRule) }

// ParseTunnelList parses a newline-separated VPN-only list.
func ParseTunnelList(text string) (*Set, []LineError) {
	return NewTunnelSet(strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n"))
}

func newSet(entries []string, parse func(string) (Rule, error)) (*Set, []LineError) {
	s := &Set{full: map[string]struct{}{}, suffix: map[string]struct{}{}}
	var errs []LineError
	for i, raw := range entries {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r, err := parse(line)
		if err == nil && s.has(r) {
			err = ErrDuplicate
		}
		if err == nil && len(s.rules) >= MaxRules {
			err = ErrTooMany
		}
		if err != nil {
			errs = append(errs, LineError{Line: i + 1, Text: line, Err: err})
			continue
		}
		s.add(r)
	}
	if len(errs) > 0 {
		return nil, errs
	}
	return s, nil
}

// ParseList parses a newline-separated list (SPLIT-006 import format).
func ParseList(text string) (*Set, []LineError) {
	return NewSet(strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n"))
}

func (s *Set) has(r Rule) bool {
	if r.Kind == Wildcard {
		return s.wildcard
	}
	if r.Kind == Full {
		_, ok := s.full[r.Domain]
		return ok
	}
	_, ok := s.suffix[r.Domain]
	return ok
}

func (s *Set) add(r Rule) {
	if r.Kind == Wildcard {
		s.wildcard = true
	} else if r.Kind == Full {
		s.full[r.Domain] = struct{}{}
	} else {
		s.suffix[r.Domain] = struct{}{}
	}
	s.rules = append(s.rules, r)
}

// Len returns the number of rules.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.rules)
}

// Rules returns a copy of the rules in input order.
func (s *Set) Rules() []Rule {
	if s == nil {
		return nil
	}
	return append([]Rule(nil), s.rules...)
}

// Export returns the list in the text format accepted by ParseList.
func (s *Set) Export() string {
	var b strings.Builder
	for _, r := range s.Rules() {
		b.WriteString(r.String())
		b.WriteByte('\n')
	}
	return b.String()
}

// Match reports whether host must bypass the tunnel. Protected hosts never
// match, even if a broader rule (for example "google.com") covers them.
func (s *Set) Match(host string) bool {
	h := NormalizeHost(host)
	if h == "" || IsProtectedHost(h) {
		return false
	}
	return s.matchNormalized(h)
}

// Covers reports whether a rule covers host (no protected-host exception);
// used for the VPN-only list.
func (s *Set) Covers(host string) bool {
	h := NormalizeHost(host)
	return h != "" && s.matchNormalized(h)
}

func (s *Set) matchNormalized(h string) bool {
	_, ok := s.specificity(h)
	return ok
}

// Specificity of the most specific rule covering a normalized host: the
// wildcard is 0, a suffix rule counts its labels, an exact rule beats any
// suffix rule.
func (s *Set) specificity(h string) (int, bool) {
	if s == nil || len(s.rules) == 0 {
		return 0, false
	}
	if _, ok := s.full[h]; ok {
		return 1000, true
	}
	for d := h; ; {
		if _, ok := s.suffix[d]; ok {
			return strings.Count(d, ".") + 1, true
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			break
		}
		d = d[i+1:]
	}
	if s.wildcard {
		return 0, true
	}
	return 0, false
}

// FullTunnel reports whether the VPN list sends everything through the
// tunnel: it is empty or contains "*".
func (s *Set) FullTunnel() bool { return s == nil || len(s.rules) == 0 || s.wildcard }
