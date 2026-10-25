package fallback

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/eermolaev/test-vpn/core/errclass"
	"github.com/eermolaev/test-vpn/core/profile"
)

func tr(kind profile.Kind, pol profile.Policy, host string) profile.Transport {
	return profile.Transport{Kind: kind, Policy: pol, VLESS: &profile.VLESSConfig{Address: host, Port: 443, Network: "raw"}}
}

func testProfile() *profile.Profile {
	return &profile.Profile{Transports: []profile.Transport{
		tr(profile.KindWireGuard, profile.PolicyManualOnly, "wg"),
		tr(profile.KindVLESSReality, profile.PolicyFallback, "xhttp"),
		tr(profile.KindAmneziaWG, profile.PolicyPrimary, "awg"),
		tr(profile.KindVLESSPlain, profile.PolicyForbidden, "plain"),
		tr(profile.KindVLESSReality, profile.PolicyPrimary, "vision"),
	}}
}

var timeout = errclass.Wrap(errclass.UDPTimeout, errors.New("timeout"))

func collect(pl *Planner, errFor func(Step) error) []Step {
	var steps []Step
	var last error
	for {
		s, ok := pl.Next(last)
		if !ok {
			return steps
		}
		steps = append(steps, s)
		last = errFor(s)
	}
}

func TestOrderAndNoDowngrade(t *testing.T) {
	pl, err := NewPlanner(testProfile(), DefaultPolicy(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, c := range pl.Candidates() {
		ids = append(ids, c.ID)
	}
	want := fmt.Sprint([]string{"amneziawg:awg:443:raw", "vless-reality:vision:443:raw", "vless-reality:xhttp:443:raw"})
	if fmt.Sprint(ids) != want {
		t.Fatalf("order = %v, want %v", ids, want)
	}
	steps := collect(pl, func(Step) error { return timeout })
	if len(steps) != 3*3*3 {
		t.Fatalf("steps = %d, want 27", len(steps))
	}
	for _, s := range steps {
		if s.Kind == profile.KindWireGuard || s.Kind == profile.KindVLESSPlain {
			t.Fatalf("downgrade to %s", s.Kind)
		}
	}
}

func TestSwitchTimeBudget(t *testing.T) {
	pol := DefaultPolicy()
	pl, _ := NewPlanner(testProfile(), pol, Options{})
	var elapsed time.Duration
	var last error
	for {
		s, ok := pl.Next(last)
		if !ok || s.Index != 2 {
			if s.Index == 4 { // switched to the second transport
				break
			}
			t.Fatal("unexpected sequence")
		}
		elapsed += s.Delay + pol.FailTimeout
		last = timeout
	}
	if limit := time.Duration(pol.Attempts)*pol.FailTimeout + 5*time.Second; elapsed > limit {
		t.Fatalf("switch takes %v, limit %v", elapsed, limit)
	}
}

func TestSkipOnConfigError(t *testing.T) {
	pl, _ := NewPlanner(testProfile(), DefaultPolicy(), Options{})
	cfgErr := errclass.Wrap(errclass.AWGMismatch, errors.New("bad header"))
	s1, _ := pl.Next(nil)
	s2, _ := pl.Next(cfgErr)
	if s1.Index == s2.Index || s2.Attempt != 1 {
		t.Fatalf("mismatch must skip transport: %+v -> %+v", s1, s2)
	}
}

func TestCancelStops(t *testing.T) {
	pl, _ := NewPlanner(testProfile(), DefaultPolicy(), Options{})
	pl.Next(nil)
	if _, ok := pl.Next(errclass.Wrap(errclass.Canceled, errors.New("stop"))); ok {
		t.Fatal("cancel must stop the plan")
	}
}

func TestManualAndPreferred(t *testing.T) {
	p := testProfile()
	pl, err := NewPlanner(p, DefaultPolicy(), Options{Manual: p.Transports[0].ID()})
	if err != nil {
		t.Fatal(err)
	}
	if c := pl.Candidates(); len(c) != 1 || c[0].Kind != profile.KindWireGuard {
		t.Fatalf("manual pin: %+v", c)
	}
	if _, err := NewPlanner(p, DefaultPolicy(), Options{Manual: p.Transports[3].ID()}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("forbidden manual: %v", err)
	}
	pl, _ = NewPlanner(p, DefaultPolicy(), Options{Preferred: p.Transports[1].ID()})
	if pl.Candidates()[0].Index != 1 {
		t.Fatal("preferred must be first")
	}
	// A remembered manual-only transport is not used automatically.
	pl, _ = NewPlanner(p, DefaultPolicy(), Options{Preferred: p.Transports[0].ID()})
	if pl.Candidates()[0].Index != 2 {
		t.Fatal("manual-only preferred must be ignored")
	}
	if _, err := NewPlanner(&profile.Profile{Transports: p.Transports[:1]}, DefaultPolicy(), Options{}); !errors.Is(err, ErrNoAutomaticTransport) {
		t.Fatal(err)
	}
}

type memStore struct{ saved map[string]string }

func (m *memStore) Load() map[string]string  { return map[string]string{"k": "v"} }
func (m *memStore) Save(s map[string]string) { m.saved = s }

func TestMemory(t *testing.T) {
	st := &memStore{}
	mem := NewMemory(st)
	if mem.Preferred("k") != "v" {
		t.Fatal("load")
	}
	key := NetworkKey("HomeWiFi|192.168.1.1")
	if key == "" || key == "HomeWiFi|192.168.1.1" || len(key) != 16 {
		t.Fatalf("key = %q", key)
	}
	mem.Remember(key, "awg:x")
	if mem.Preferred(key) != "awg:x" || st.saved[key] != "awg:x" {
		t.Fatal("remember")
	}
	for i := 0; i < memoryLimit+10; i++ {
		mem.Remember(NetworkKey(fmt.Sprint(i)), "t")
	}
	if len(st.saved) > memoryLimit {
		t.Fatalf("memory not bounded: %d", len(st.saved))
	}
}
