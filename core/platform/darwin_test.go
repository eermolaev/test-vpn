//go:build darwin

package platform

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRunner emulates scutil and pfctl and records commands.
type fakeRunner struct {
	cmds   []string
	dns    map[string]string // key -> scutil show output
	rules  string
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{dns: map[string]string{
		"State:/Network/Service/SVC/DNS": scutilShow,
	}}
}

func (f *fakeRunner) run(stdin, name string, args ...string) (string, error) {
	cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.cmds = append(f.cmds, cmd)
	switch {
	case name == "scutil" && strings.HasPrefix(stdin, "show State:/Network/Global/IPv4"):
		return "<dictionary> {\n  PrimaryService : SVC\n}\n", nil
	case name == "scutil" && strings.HasPrefix(stdin, "show "):
		key := strings.TrimSpace(strings.TrimPrefix(strings.SplitN(stdin, "\n", 2)[0], "show "))
		if out, ok := f.dns[key]; ok {
			return out, nil
		}
		return "  No such key\n", nil
	case name == "scutil" && strings.Contains(stdin, "\nset "):
		key := strings.TrimSpace(strings.SplitN(strings.SplitN(stdin, "\nset ", 2)[1], "\n", 2)[0])
		var addrs []string
		for _, l := range strings.Split(stdin, "\n") {
			if v, ok := strings.CutPrefix(l, "d.add ServerAddresses * "); ok {
				addrs = strings.Fields(v)
			}
		}
		out := "<dictionary> {\n  ServerAddresses : <array> {\n"
		for i, a := range addrs {
			out += "    " + string(rune('0'+i)) + " : " + a + "\n"
		}
		f.dns[key] = out + "  }\n}\n"
		f.cmds[len(f.cmds)-1] += " <" + strings.Join(addrs, ",") + ">"
	case name == "pfctl" && len(args) > 0 && args[0] == "-sr":
		return `anchor "com.apple/*" all`, nil
	case name == "pfctl" && len(args) > 0 && args[0] == "-E":
		return "pf enabled\nToken : 42\n", nil
	case name == "pfctl" && strings.Contains(cmd, "-f -"):
		f.rules = stdin
	}
	return "", nil
}

func TestDarwinLifecycle(t *testing.T) {
	r := newFakeRunner()
	path := filepath.Join(t.TempDir(), "state.json")
	d := NewDarwin(path, r.run)
	dns := []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.4.4")}
	if err := d.EnableKillSwitch(KillSwitch{Servers: []netip.Addr{netip.MustParseAddr("203.0.113.10")}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.rules, "block drop out quick all") {
		t.Fatal("rules not loaded")
	}
	d.AllowDirect(netip.MustParseAddr("198.51.100.7"))
	d.AllowDirect(netip.MustParseAddr("198.51.100.7")) // deduplicated
	if err := d.SetDNS(dns); err != nil {
		t.Fatal(err)
	}
	if err := d.SetDNS(dns); err != nil { // idempotent
		t.Fatal(err)
	}
	if err := d.SetServerRoutes([]netip.Addr{netip.MustParseAddr("203.0.113.10")}, DefaultRoute{Gateway: netip.MustParseAddr("192.168.1.1")}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.cmds, "\n")
	if strings.Count(joined, "-T add 198.51.100.7") != 1 {
		t.Fatalf("direct add:\n%s", joined)
	}
	if strings.Count(joined, "<8.8.8.8,8.8.4.4>") != 1 {
		t.Fatalf("dns set must happen once:\n%s", joined)
	}
	// A crash leaves state on disk; Unblock restores everything.
	r.cmds = nil
	if err := Unblock(path, r.run); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(r.cmds, "\n")
	for _, want := range []string{"pfctl -a " + Anchor + " -F all", "pfctl -X 42", "<192.168.1.1,fe80::1%en0>", "route -q -n delete -inet -host 203.0.113.10"} {
		if !strings.Contains(joined, want) {
			t.Errorf("unblock missing %q:\n%s", want, joined)
		}
	}
}
