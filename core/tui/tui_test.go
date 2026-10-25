package tui

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/eermolaev/test-vpn/core/daemon"
	"github.com/eermolaev/test-vpn/core/egress"
	"github.com/eermolaev/test-vpn/core/flowrouter"
	"github.com/eermolaev/test-vpn/core/platform"
	"github.com/eermolaev/test-vpn/core/profile"
	"github.com/eermolaev/test-vpn/core/tunnel"
)

type fakeBackend struct {
	st        daemon.Status
	flows     []flowrouter.FlowInfo
	settings  daemon.Settings
	profiles  []daemon.ProfileEntry
	calls     []string
	imported  string
	statusErr error
}

func (f *fakeBackend) Status() (daemon.Status, error)           { return f.st, f.statusErr }
func (f *fakeBackend) Flows(int) ([]flowrouter.FlowInfo, error) { return f.flows, nil }
func (f *fakeBackend) Logs(after uint64) ([]daemon.LogLine, error) {
	if after > 0 {
		return nil, nil
	}
	return []daemon.LogLine{{Seq: 1, Time: time.Unix(0, 0), Text: "connected via vless-reality:[REDACTED]"}}, nil
}
func (f *fakeBackend) Profiles() ([]daemon.ProfileEntry, error) { return f.profiles, nil }
func (f *fakeBackend) Import(text, into string) (daemon.ProfileEntry, error) {
	f.imported = text
	f.calls = append(f.calls, "import:"+into)
	return daemon.ProfileEntry{}, nil
}
func (f *fakeBackend) UpdateProfile(u daemon.UpdateProfile) error {
	f.calls = append(f.calls, "update")
	if u.ManualTransport != nil {
		f.profiles[0].ManualTransport = *u.ManualTransport
	}
	return nil
}
func (f *fakeBackend) DeleteProfile(string) error         { f.calls = append(f.calls, "delete"); return nil }
func (f *fakeBackend) SelectProfile(string) error         { f.calls = append(f.calls, "select"); return nil }
func (f *fakeBackend) Connect() error                     { f.calls = append(f.calls, "connect"); return nil }
func (f *fakeBackend) Disconnect() error                  { f.calls = append(f.calls, "disconnect"); return nil }
func (f *fakeBackend) Reconnect() error                   { f.calls = append(f.calls, "reconnect"); return nil }
func (f *fakeBackend) Settings() (daemon.Settings, error) { return f.settings, nil }
func (f *fakeBackend) SetSettings(s daemon.Settings) error {
	if len(s.Exclusions) > 0 && s.Exclusions[0] == "fail.example" {
		return errors.New("rejected")
	}
	f.settings = s
	f.calls = append(f.calls, "settings")
	return nil
}
func (f *fakeBackend) Check(context.Context, daemon.Status, int) egress.Result {
	match := false
	r := egress.Result{ExpectedCountry: "DE", CountryMatch: &match}
	r.IPv4.IP, r.IPv4.Confirmed = "203.0.113.7", true
	r.Country.ISO, r.Country.Name = "NL", "Netherlands"
	r.IPv6.Blocked = true
	r.Findings = []egress.Finding{{Code: "country_mismatch", Severity: egress.Warning, Message: "The exit IP is located in NL, not in DE"}}
	return r
}

func connectedBackend() *fakeBackend {
	summary := profile.Summary{Name: "Frankfurt", Transports: []profile.TransportSummary{
		{ID: "amneziawg:1.2.3.4:51820", Kind: profile.KindAmneziaWG, Policy: profile.PolicyPrimary, Detail: "udp"},
		{ID: "vless-reality:1.2.3.4:443:raw", Kind: profile.KindVLESSReality, Policy: profile.PolicyPrimary, Detail: "raw+vision"},
	}}
	pe := daemon.ProfileEntry{ID: "p1", Name: "Frankfurt", ExpectedCountry: "DE", Summary: summary, Selected: true}
	ts := tunnel.Status{State: tunnel.StateConnected, TransportID: "vless-reality:1.2.3.4:443:raw", TransportKind: "vless-reality", Since: time.Now().Add(-90 * time.Second)}
	ts.Stats.BytesTunnelDown, ts.Stats.BytesTunnelUp, ts.Stats.ActiveFlows = 5<<20, 1<<20, 2
	return &fakeBackend{
		st: daemon.Status{Connected: true, KillSwitch: true, Profile: &pe, Tunnel: &ts, Interface: "utun5", DNSServers: []string{"8.8.8.8", "8.8.4.4"},
			Route: platform.DefaultRoute{Interface: "en0", Index: 4, Gateway: netip.MustParseAddr("192.168.1.1")}},
		flows: []flowrouter.FlowInfo{
			{ID: 1, Proto: "tcp", Dst: "142.250.1.1:443", Host: "www.youtube.com", Route: "tunnel", Start: time.Now().Add(-2 * time.Minute), Down: 45 << 20, Up: 1 << 20},
			{ID: 2, Proto: "quic", Dst: "203.0.113.50:443", Host: "online.bank.example", Route: "direct", Start: time.Now(), Down: 1 << 20},
		},
		settings: daemon.Settings{Exclusions: []string{"bank.example"}, BlockQUIC: true},
		profiles: []daemon.ProfileEntry{pe},
	}
}

// run feeds a message and executes the resulting commands synchronously
// (except ticks), like the Bubble Tea runtime would.
func run(m *Model, msg tea.Msg) {
	_, cmd := m.Update(msg)
	exec(m, cmd, 0)
}

func exec(m *Model, cmd tea.Cmd, depth int) {
	if cmd == nil || depth > 5 {
		return
	}
	done := make(chan tea.Msg, 1)
	go func() { done <- cmd() }()
	var msg tea.Msg
	select {
	case msg = <-done:
	case <-time.After(100 * time.Millisecond):
		return // a tick: skip
	}
	switch msg := msg.(type) {
	case nil:
	case tea.BatchMsg:
		for _, c := range msg {
			exec(m, c, depth+1)
		}
	case tickMsg:
	default:
		_, next := m.Update(msg)
		exec(m, next, depth+1)
	}
}

func key(s string) tea.Msg {
	switch s {
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "down":
		return tea.KeyPressMsg{Code: tea.KeyDown}
	case "right":
		return tea.KeyPressMsg{Code: tea.KeyRight}
	case "ctrl+s":
		return tea.KeyPressMsg{Code: 's', Mod: tea.ModCtrl}
	}
	r := []rune(s)[0]
	return tea.KeyPressMsg{Code: r, Text: s}
}

func typeText(m *Model, s string) {
	for _, r := range s {
		if r == '\n' {
			run(m, tea.KeyPressMsg{Code: tea.KeyEnter})
			continue
		}
		run(m, tea.KeyPressMsg{Code: r, Text: string(r)})
	}
}

func checkGeometry(t *testing.T, m *Model, w, h int) string {
	t.Helper()
	run(m, tea.WindowSizeMsg{Width: w, Height: h})
	out := m.render()
	lines := strings.Split(out, "\n")
	if len(lines) != h {
		t.Fatalf("%dx%d: %d lines", w, h, len(lines))
	}
	for i, l := range lines {
		if lw := ansi.StringWidth(l); lw != w {
			t.Fatalf("%dx%d: line %d width %d: %q", w, h, i, lw, ansi.Strip(l))
		}
	}
	return ansi.Strip(out)
}

func TestDashboardLayout(t *testing.T) {
	be := connectedBackend()
	m := New(be)
	exec(m, m.Init(), 0)
	// Two samples to get a traffic rate.
	be.st.Tunnel.Stats.BytesTunnelDown += 2 << 20
	m.lastSample = m.lastSample.Add(-time.Second)
	exec(m, m.refresh(false), 0)
	for _, size := range [][2]int{{160, 48}, {120, 40}, {100, 30}, {80, 34}, {60, 24}} {
		text := checkGeometry(t, m, size[0], size[1])
		for _, want := range []string{"CONNECTED", "Frankfurt"} {
			if !strings.Contains(text, want) {
				t.Errorf("%v: missing %q", size, want)
			}
		}
		if size[0] >= 100 {
			for _, want := range []string{"youtube.com", "bank.example", "kill switch", "traffic", "connections", "profile", "raw+vision", "↷ bank.example", "8.8.8.8"} {
				if !strings.Contains(text, want) {
					t.Errorf("%v: missing %q\n%s", size, want, text)
				}
			}
		}
	}
	if len(m.down) == 0 || m.down[len(m.down)-1] <= 0 {
		t.Fatalf("no traffic rate sampled: %v", m.down)
	}
}

func TestKeysAndCheck(t *testing.T) {
	be := connectedBackend()
	m := New(be)
	exec(m, m.Init(), 0)
	run(m, key("c"))
	run(m, key("r"))
	if strings.Join(be.calls, ",") != "disconnect,reconnect" {
		t.Fatalf("calls %v", be.calls)
	}
	run(m, key("x"))
	text := checkGeometry(t, m, 120, 40)
	if !strings.Contains(text, "NL Netherlands ≠ DE") || !strings.Contains(text, "203.0.113.7") {
		t.Fatalf("check result not shown:\n%s", text)
	}
	run(m, key("?"))
	if !strings.Contains(checkGeometry(t, m, 120, 40), "sudo testvpn unblock") {
		t.Fatal("help not shown")
	}
	run(m, key("z"))
	if m.dialog != nil {
		t.Fatal("help must close on any key")
	}
	if _, cmd := m.Update(key("q")); cmd == nil {
		t.Fatal("q must quit")
	}
}

func TestExclusionsDialog(t *testing.T) {
	be := connectedBackend()
	m := New(be)
	exec(m, m.Init(), 0)
	run(m, key("e"))
	typeText(m, "\nExample.COM\nfull:a.b.c")
	text := checkGeometry(t, m, 120, 40)
	if !strings.Contains(text, "✓ valid") {
		t.Fatalf("validation:\n%s", text)
	}
	run(m, key("ctrl+s"))
	if m.dialog != nil {
		t.Fatal("dialog must close after save")
	}
	if got := strings.Join(be.settings.Exclusions, ","); got != "bank.example,example.com,full:a.b.c" {
		t.Fatalf("saved %q", got)
	}
	// Invalid entries keep the dialog open with an error.
	run(m, key("e"))
	typeText(m, "\n1.2.3.4")
	run(m, key("ctrl+s"))
	if m.dialog == nil || !strings.Contains(checkGeometry(t, m, 120, 40), "IP addresses are not supported") {
		t.Fatal("invalid list must not be saved")
	}
	run(m, key("esc"))
}

func TestSettingsDialog(t *testing.T) {
	be := connectedBackend()
	m := New(be)
	exec(m, m.Init(), 0)
	run(m, key("s"))
	run(m, key("right")) // Google -> Cloudflare
	run(m, key("down"))  // -> QUIC
	run(m, key("enter")) // toggle off
	run(m, key("down"))  // -> LAN
	run(m, key("down"))  // -> connect on startup
	run(m, key("right")) // last -> restore
	if !strings.Contains(checkGeometry(t, m, 120, 40), "restore previous state") {
		t.Fatal("auto-connect row not shown")
	}
	run(m, key("ctrl+s"))
	if got := strings.Join(be.settings.DNSServers, ","); got != "1.1.1.1,1.0.0.1" || be.settings.BlockQUIC || be.settings.AutoConnect != daemon.AutoConnectRestore {
		t.Fatalf("settings %+v", be.settings)
	}
	// Custom DNS with validation.
	run(m, key("s"))
	run(m, key("right"))
	run(m, key("right")) // Quad9 -> Custom
	run(m, key("down"))  // custom field
	typeText(m, "9.9.9.9 8.8.8.8")
	run(m, key("ctrl+s"))
	if got := strings.Join(be.settings.DNSServers, ","); got != "9.9.9.9,8.8.8.8" {
		t.Fatalf("custom dns %q", got)
	}
}

func TestProfilesDialog(t *testing.T) {
	be := connectedBackend()
	m := New(be)
	exec(m, m.Init(), 0)
	run(m, key("p"))
	if !strings.Contains(checkGeometry(t, m, 120, 40), "raw+vision") {
		t.Fatal("profiles not listed")
	}
	run(m, key("t")) // pin first transport
	if be.profiles[0].ManualTransport != "amneziawg:1.2.3.4:51820" {
		t.Fatalf("pin: %q", be.profiles[0].ManualTransport)
	}
	run(m, key("a")) // add transports to this profile
	typeText(m, "vless://x")
	run(m, key("ctrl+s"))
	if be.imported != "vless://x" || be.calls[len(be.calls)-1] != "import:p1" {
		t.Fatalf("import: %q %v", be.imported, be.calls)
	}
	run(m, key("enter"))
	if m.dialog != nil || be.calls[len(be.calls)-1] != "select" {
		t.Fatalf("select: %v", be.calls)
	}
}

func TestServiceDown(t *testing.T) {
	be := connectedBackend()
	be.statusErr = errors.New("dial unix /var/run/testvpn.sock: no such file")
	m := New(be)
	exec(m, m.Init(), 0)
	if !strings.Contains(checkGeometry(t, m, 100, 30), "sudo testvpn install") {
		t.Fatal("service down hint missing")
	}
}
