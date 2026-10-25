package platform

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/eermolaev/test-vpn/core/netstack"
)

// Fake is an in-memory Platform for tests. The "apps" side of the tunnel is
// available through AppEnd after CreateTUN.
type Fake struct {
	mu       sync.Mutex
	events   []string
	appEnd   *netstack.PipeIO
	Route    DefaultRoute
	ks       *KillSwitch
	allowed  map[netip.Addr]bool
	dns      []netip.Addr
	servers  []netip.Addr
	OnCreate func(app *netstack.PipeIO) // called when the tunnel is created
	// ConflictList is returned by Conflicts.
	ConflictList []string
}

// NewFake returns a fake with a default route on en0.
func NewFake() *Fake {
	return &Fake{
		Route:   DefaultRoute{Gateway: netip.MustParseAddr("192.168.1.1"), Interface: "en0", Index: 4, LAN: netip.MustParsePrefix("192.168.1.0/24")},
		allowed: map[netip.Addr]bool{},
	}
}

func (f *Fake) log(format string, a ...any) {
	f.events = append(f.events, fmt.Sprintf(format, a...))
}

// Events returns the recorded calls in order.
func (f *Fake) Events() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

// EventIndex returns the index of the first event with the prefix, or -1.
func (f *Fake) EventIndex(prefix string) int {
	for i, e := range f.Events() {
		if strings.HasPrefix(e, prefix) {
			return i
		}
	}
	return -1
}

func (f *Fake) CreateTUN(mtu int) (netstack.PacketIO, string, error) {
	tun, app := netstack.NewPipe(1024)
	f.mu.Lock()
	f.appEnd = app
	f.log("create-tun")
	cb := f.OnCreate
	f.mu.Unlock()
	if cb != nil {
		cb(app)
	}
	return tun, "utun9", nil
}

func (f *Fake) ConfigureTUN(name string, mtu int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log("configure-tun %s", name)
	return nil
}

func (f *Fake) DestroyTUN() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log("destroy-tun")
	if f.appEnd != nil {
		f.appEnd.Close()
	}
	return nil
}

func (f *Fake) DefaultRoute() (DefaultRoute, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Route, nil
}

func (f *Fake) SetServerRoutes(servers []netip.Addr, via DefaultRoute) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.servers = servers
	f.log("server-routes %v", servers)
	return nil
}

func (f *Fake) SetDNS(servers []netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dns = servers
	f.log("set-dns %v", servers)
	return nil
}

func (f *Fake) RestoreDNS() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dns = nil
	f.log("restore-dns")
	return nil
}

func (f *Fake) EnableKillSwitch(k KillSwitch) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ks = &k
	f.log("killswitch-on tun=%s", k.Tun)
	return nil
}

func (f *Fake) AllowDirect(ips ...netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ip := range ips {
		f.allowed[ip] = true
	}
	return nil
}

func (f *Fake) DisableKillSwitch() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ks = nil
	f.allowed = map[netip.Addr]bool{}
	f.log("killswitch-off")
	return nil
}

// KillSwitchActive reports whether filter rules are loaded.
func (f *Fake) KillSwitchActive() (KillSwitch, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ks == nil {
		return KillSwitch{}, false
	}
	return *f.ks, true
}

// Allowed reports whether ip was allowed through the filter.
func (f *Fake) Allowed(ip netip.Addr) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.allowed[ip]
}

// DNS returns the configured resolver override.
func (f *Fake) DNS() []netip.Addr {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]netip.Addr(nil), f.dns...)
}

func (f *Fake) Conflicts(string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ConflictList...)
}
