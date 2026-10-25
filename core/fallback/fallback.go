// Package fallback decides which transport to try next (SEC-NET-002/003/005).
package fallback

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/eermolaev/test-vpn/core/errclass"
	"github.com/eermolaev/test-vpn/core/profile"
)

// Policy holds the retry limits.
type Policy struct {
	Attempts    int           // attempts per transport per round (N)
	FailTimeout time.Duration // time to confirm a failed attempt (T_fail)
	BackoffBase time.Duration // delay before the 2nd attempt, doubled after
	BackoffMax  time.Duration // cap for attempt delays and the delay between rounds
	MaxRounds   int           // full passes over all transports before giving up
}

// DefaultPolicy matches the defaults of the spec: N=3, T_fail=10s, 3 rounds.
// Delays between attempts total 1.5s, so switching to the next transport takes
// at most N*T_fail + 5s.
func DefaultPolicy() Policy {
	return Policy{Attempts: 3, FailTimeout: 10 * time.Second, BackoffBase: 500 * time.Millisecond, BackoffMax: 8 * time.Second, MaxRounds: 3}
}

// Candidate is a transport selected for connection attempts.
type Candidate struct {
	Index int // index in Profile.Transports
	ID    string
	Kind  profile.Kind
}

// Step is the next connection attempt.
type Step struct {
	Candidate
	Attempt int           // 1-based within the round
	Round   int           // 1-based
	Delay   time.Duration // wait before this attempt
}

var (
	ErrNoAutomaticTransport = errors.New("profile has no transport that can be used automatically")
	ErrForbidden            = errors.New("transport is forbidden")
	ErrUnknownTransport     = errors.New("transport not found in profile")
)

// Options select manual or preferred transports.
type Options struct {
	// Manual pins one transport (may be manual-only). No fallback happens.
	Manual string
	// Preferred is tried first if it is allowed automatically (SEC-NET-005).
	Preferred string
}

// Planner produces the sequence of attempts. It is not safe for concurrent use.
type Planner struct {
	pol    Policy
	cands  []Candidate
	round  int
	ci     int
	att    int
	done   bool
	manual bool
}

// NewPlanner builds a plan for profile p. Automatic plans include only
// transports with a primary or fallback policy, so a failure never leads to
// plain WireGuard or unprotected VLESS (SEC-NET-003).
func NewPlanner(p *profile.Profile, pol Policy, opts Options) (*Planner, error) {
	if pol.Attempts <= 0 || pol.MaxRounds <= 0 {
		return nil, errors.New("fallback: invalid policy")
	}
	pl := &Planner{pol: pol, round: 1}
	if opts.Manual != "" {
		for i, t := range p.Transports {
			if t.ID() == opts.Manual {
				if t.Policy == profile.PolicyForbidden {
					return nil, ErrForbidden
				}
				pl.cands = []Candidate{{Index: i, ID: t.ID(), Kind: t.Kind}}
				pl.manual = true
				return pl, nil
			}
		}
		return nil, ErrUnknownTransport
	}
	var primary, fb []Candidate
	var pref *Candidate
	for i, t := range p.Transports {
		c := Candidate{Index: i, ID: t.ID(), Kind: t.Kind}
		switch {
		case !t.Policy.Automatic():
			continue
		case t.ID() == opts.Preferred:
			pref = &c
		case t.Policy == profile.PolicyPrimary:
			primary = append(primary, c)
		default:
			fb = append(fb, c)
		}
	}
	if pref != nil {
		pl.cands = append(pl.cands, *pref)
	}
	pl.cands = append(append(pl.cands, primary...), fb...)
	if len(pl.cands) == 0 {
		return nil, ErrNoAutomaticTransport
	}
	return pl, nil
}

// Candidates returns the ordered candidates.
func (pl *Planner) Candidates() []Candidate { return append([]Candidate(nil), pl.cands...) }

// Next returns the next attempt given the error of the previous one (nil for
// the first call). ok is false when all attempts are exhausted.
func (pl *Planner) Next(lastErr error) (step Step, ok bool) {
	if pl.done {
		return Step{}, false
	}
	if errclass.Classify(lastErr) == errclass.Canceled {
		pl.done = true
		return Step{}, false
	}
	var delay time.Duration
	switch {
	case pl.att == 0:
		// first call
	case errclass.Classify(lastErr).SkipTransport() || pl.att >= pl.pol.Attempts:
		pl.ci++
		pl.att = 0
		if pl.ci >= len(pl.cands) {
			pl.ci = 0
			pl.round++
			if pl.round > pl.pol.MaxRounds {
				pl.done = true
				return Step{}, false
			}
			delay = pl.pol.BackoffMax
		}
	default:
		delay = pl.backoff(pl.att)
	}
	pl.att++
	return Step{Candidate: pl.cands[pl.ci], Attempt: pl.att, Round: pl.round, Delay: delay}, true
}

func (pl *Planner) backoff(prevAttempts int) time.Duration {
	d := pl.pol.BackoffBase << (prevAttempts - 1)
	if d > pl.pol.BackoffMax || d <= 0 {
		d = pl.pol.BackoffMax
	}
	return d
}

// Store persists the per-network memory.
type Store interface {
	Load() map[string]string
	Save(map[string]string)
}

// Memory remembers the last working transport per network (SEC-NET-005).
// Network identifiers are stored only as hashes.
type Memory struct {
	mu    sync.Mutex
	m     map[string]string
	order []string
	store Store
}

const memoryLimit = 100

// NewMemory loads memory from store (may be nil).
func NewMemory(store Store) *Memory {
	mem := &Memory{m: map[string]string{}, store: store}
	if store != nil {
		for k, v := range store.Load() {
			mem.m[k] = v
			mem.order = append(mem.order, k)
		}
	}
	return mem
}

// NetworkKey hashes a raw network identifier (SSID + gateway, etc.).
func NetworkKey(raw string) string {
	if raw == "" {
		return ""
	}
	h := sha256.Sum256([]byte("vpn-network:" + raw))
	return hex.EncodeToString(h[:8])
}

// Preferred returns the remembered transport ID for the network.
func (mem *Memory) Preferred(netKey string) string {
	mem.mu.Lock()
	defer mem.mu.Unlock()
	return mem.m[netKey]
}

// Remember stores a successful transport for the network.
func (mem *Memory) Remember(netKey, transportID string) {
	if netKey == "" {
		return
	}
	mem.mu.Lock()
	if _, ok := mem.m[netKey]; !ok {
		mem.order = append(mem.order, netKey)
		if len(mem.order) > memoryLimit {
			delete(mem.m, mem.order[0])
			mem.order = mem.order[1:]
		}
	}
	mem.m[netKey] = transportID
	snapshot := make(map[string]string, len(mem.m))
	for k, v := range mem.m {
		snapshot[k] = v
	}
	mem.mu.Unlock()
	if mem.store != nil {
		mem.store.Save(snapshot)
	}
}
