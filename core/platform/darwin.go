//go:build darwin

package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/eermolaev/test-vpn/core/netstack"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// Runner executes a command with optional stdin and returns combined output.
type Runner func(stdin string, name string, args ...string) (string, error)

// ExecRunner runs commands with os/exec.
func ExecRunner(stdin string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// state survives daemon crashes so that `testvpn unblock` can undo changes.
type state struct {
	PFToken      string     `json:"pfToken,omitempty"`
	DNSService   string     `json:"dnsService,omitempty"`
	OrigDNS      *DNSConfig `json:"origDNS,omitempty"`
	ServerRoutes []string   `json:"serverRoutes,omitempty"`
}

// Darwin implements Platform on macOS. It must run as root.
type Darwin struct {
	run       Runner
	statePath string

	mu     sync.Mutex
	st     state
	fd     int
	tun    *netstack.UtunIO
	dns    []netip.Addr
	direct map[netip.Addr]bool
	ksOn   bool
}

// NewDarwin loads persisted state from statePath.
func NewDarwin(statePath string, run Runner) *Darwin {
	if run == nil {
		run = ExecRunner
	}
	d := &Darwin{run: run, statePath: statePath, fd: -1, direct: map[netip.Addr]bool{}}
	if b, err := os.ReadFile(statePath); err == nil {
		json.Unmarshal(b, &d.st)
	}
	return d
}

func (d *Darwin) saveLocked() {
	b, _ := json.MarshalIndent(d.st, "", "  ")
	tmp := d.statePath + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		os.Rename(tmp, d.statePath)
	}
}

const (
	sysprotoControl = 2
	utunOptIfname   = 2
)

// CreateTUN creates a utun interface through the kernel control socket; no
// Network Extension is involved, so this needs root.
func (d *Darwin) CreateTUN(mtu int) (netstack.PacketIO, string, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, "", fmt.Errorf("utun socket: %w", err)
	}
	info := &unix.CtlInfo{}
	copy(info.Name[:], "com.apple.net.utun_control")
	if err := unix.IoctlCtlInfo(fd, info); err != nil {
		unix.Close(fd)
		return nil, "", fmt.Errorf("utun ctlinfo: %w", err)
	}
	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: 0}); err != nil {
		unix.Close(fd)
		return nil, "", fmt.Errorf("utun connect: %w", err)
	}
	name, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
	if err != nil {
		unix.Close(fd)
		return nil, "", fmt.Errorf("utun name: %w", err)
	}
	name = strings.TrimRight(name, "\x00")
	io, err := netstack.NewUtunIO(fd, mtu)
	if err != nil {
		unix.Close(fd)
		return nil, "", err
	}
	d.mu.Lock()
	d.fd, d.tun = fd, io
	d.mu.Unlock()
	return io, name, nil
}

func (d *Darwin) runAll(cmds [][]string) error {
	for _, c := range cmds {
		if _, err := d.run("", c[0], c[1:]...); err != nil {
			return err
		}
	}
	return nil
}

func (d *Darwin) ConfigureTUN(name string, mtu int) error {
	return d.runAll(TunCommands(name, mtu))
}

// DestroyTUN closes the interface; its routes disappear with it.
func (d *Darwin) DestroyTUN() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.tun != nil {
		d.tun.Close()
		d.tun = nil
	}
	if d.fd >= 0 {
		unix.Close(d.fd)
		d.fd = -1
	}
	return nil
}

// DefaultRoute reads the routing table and returns the unscoped IPv4 default
// route that does not point into a utun interface.
func (d *Darwin) DefaultRoute() (DefaultRoute, error) {
	rib, err := route.FetchRIB(unix.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return DefaultRoute{}, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return DefaultRoute{}, err
	}
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&unix.RTF_GATEWAY == 0 || rm.Flags&unix.RTF_IFSCOPE != 0 || len(rm.Addrs) <= unix.RTAX_NETMASK {
			continue
		}
		dst, ok := rm.Addrs[unix.RTAX_DST].(*route.Inet4Addr)
		if !ok || dst.IP != [4]byte{} {
			continue
		}
		if mask, ok := rm.Addrs[unix.RTAX_NETMASK].(*route.Inet4Addr); ok && mask.IP != [4]byte{} {
			continue
		}
		gw, ok := rm.Addrs[unix.RTAX_GATEWAY].(*route.Inet4Addr)
		if !ok {
			continue
		}
		ifc, err := net.InterfaceByIndex(rm.Index)
		if err != nil || strings.HasPrefix(ifc.Name, "utun") {
			continue
		}
		r := DefaultRoute{Gateway: netip.AddrFrom4(gw.IP), Interface: ifc.Name, Index: ifc.Index}
		if addrs, err := ifc.Addrs(); err == nil {
			for _, a := range addrs {
				if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() {
					r.LAN = p.Masked()
					break
				}
			}
		}
		return r, nil
	}
	return DefaultRoute{}, errors.New("no default route")
}

func (d *Darwin) SetServerRoutes(servers []netip.Addr, via DefaultRoute) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, s := range d.st.ServerRoutes {
		if a, err := netip.ParseAddr(s); err == nil {
			d.run("", "route", ServerRouteCommand(false, a, netip.Addr{})[1:]...)
		}
	}
	d.st.ServerRoutes = nil
	var firstErr error
	for _, s := range servers {
		if !s.Is4() || !via.Gateway.IsValid() {
			continue
		}
		if _, err := d.run("", "route", ServerRouteCommand(true, s, via.Gateway)[1:]...); err != nil && firstErr == nil {
			firstErr = err
			continue
		}
		d.st.ServerRoutes = append(d.st.ServerRoutes, s.String())
	}
	d.saveLocked()
	return firstErr
}

func (d *Darwin) scutil(script string) (string, error) { return d.run(script, "scutil") }

func (d *Darwin) primaryService() (string, error) {
	out, err := d.scutil("show State:/Network/Global/IPv4\nquit\n")
	if err != nil {
		return "", err
	}
	if s := ParsePrimaryService(out); s != "" {
		return s, nil
	}
	return "", errors.New("no primary network service")
}

// SetDNS overrides the resolver of the primary network service. It is
// idempotent and re-applies the override if the service changed or DHCP
// rewrote it.
func (d *Darwin) SetDNS(servers []netip.Addr) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	svc, err := d.primaryService()
	if err != nil {
		return err
	}
	if d.st.DNSService != "" && d.st.DNSService != svc {
		d.restoreDNSLocked()
	}
	key := ServiceDNSKey(svc)
	out, _ := d.scutil("show " + key + "\nquit\n")
	cur := ParseScutilDNS(out)
	want := make([]string, len(servers))
	for i, s := range servers {
		want[i] = s.String()
	}
	if d.st.DNSService == svc && strings.Join(cur.ServerAddresses, " ") == strings.Join(want, " ") {
		return nil
	}
	if d.st.DNSService != svc {
		orig := cur
		d.st.DNSService, d.st.OrigDNS = svc, &orig
		d.saveLocked()
	}
	cfg := DNSConfig{ServerAddresses: want, SearchDomains: d.st.OrigDNS.SearchDomains, DomainName: d.st.OrigDNS.DomainName}
	if _, err := d.scutil(ScutilSetDNS(key, cfg)); err != nil {
		return err
	}
	d.dns = servers
	d.flushDNS()
	return nil
}

func (d *Darwin) flushDNS() {
	d.run("", "dscacheutil", "-flushcache")
	d.run("", "killall", "-HUP", "mDNSResponder")
}

func (d *Darwin) RestoreDNS() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.restoreDNSLocked()
}

func (d *Darwin) restoreDNSLocked() error {
	if d.st.DNSService == "" || d.st.OrigDNS == nil {
		return nil
	}
	key := ServiceDNSKey(d.st.DNSService)
	var err error
	if d.st.OrigDNS.Present {
		_, err = d.scutil(ScutilSetDNS(key, *d.st.OrigDNS))
	} else {
		_, err = d.scutil(ScutilRemove(key))
	}
	d.st.DNSService, d.st.OrigDNS = "", nil
	d.dns = nil
	d.saveLocked()
	d.flushDNS()
	return err
}

// EnableKillSwitch loads the anchor rules and enables pf with a reference
// token. Rules stay in place if the daemon dies (fail closed).
func (d *Darwin) EnableKillSwitch(k KillSwitch) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	// The anchor is only evaluated if the main ruleset references com.apple/*,
	// which the default /etc/pf.conf does.
	if out, err := d.run("", "pfctl", "-sr"); err != nil || !strings.Contains(out, `anchor "com.apple/*"`) {
		if _, err := d.run("", "pfctl", "-f", "/etc/pf.conf"); err != nil {
			return err
		}
	}
	if _, err := d.run(PFRules(k), "pfctl", "-a", Anchor, "-f", "-"); err != nil {
		return err
	}
	if d.st.PFToken == "" {
		out, err := d.run("", "pfctl", "-E")
		if err != nil {
			return err
		}
		d.st.PFToken = ParsePFToken(out)
		d.saveLocked()
	}
	d.ksOn = true
	// Reloading the anchor resets its tables: restore known direct addresses.
	if len(d.direct) > 0 {
		ips := make([]netip.Addr, 0, len(d.direct))
		for ip := range d.direct {
			ips = append(ips, ip)
		}
		return d.addDirectLocked(ips)
	}
	return nil
}

func (d *Darwin) AllowDirect(ips ...netip.Addr) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	var add []netip.Addr
	for _, ip := range ips {
		ip = ip.Unmap()
		if ip.Is4() && !d.direct[ip] {
			add = append(add, ip)
		}
	}
	if len(add) == 0 {
		return nil
	}
	if err := d.addDirectLocked(add); err != nil {
		return err
	}
	for _, ip := range add {
		d.direct[ip] = true
	}
	return nil
}

func (d *Darwin) addDirectLocked(ips []netip.Addr) error {
	args := []string{"-a", Anchor, "-t", "direct", "-T", "add"}
	for _, ip := range ips {
		args = append(args, ip.String())
	}
	_, err := d.run("", "pfctl", args...)
	return err
}

func (d *Darwin) DisableKillSwitch() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.direct = map[netip.Addr]bool{}
	d.ksOn = false
	return unblockLocked(d.run, &d.st, d.saveLocked)
}

func unblockLocked(run Runner, st *state, save func()) error {
	_, err := run("", "pfctl", "-a", Anchor, "-F", "all")
	if st.PFToken != "" {
		run("", "pfctl", "-X", st.PFToken)
		st.PFToken = ""
	}
	save()
	return err
}

// Unblock undoes all changes recorded in statePath: filter rules, DNS
// override and server routes. It is used by `testvpn unblock` when the
// daemon is not running.
func Unblock(statePath string, run Runner) error {
	d := NewDarwin(statePath, run)
	d.mu.Lock()
	defer d.mu.Unlock()
	err := unblockLocked(d.run, &d.st, d.saveLocked)
	if derr := d.restoreDNSLocked(); err == nil {
		err = derr
	}
	for _, s := range d.st.ServerRoutes {
		if a, perr := netip.ParseAddr(s); perr == nil {
			d.run("", "route", ServerRouteCommand(false, a, netip.Addr{})[1:]...)
		}
	}
	d.st.ServerRoutes = nil
	d.saveLocked()
	return err
}
