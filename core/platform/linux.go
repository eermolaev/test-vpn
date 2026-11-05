//go:build linux

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
	"golang.org/x/sys/unix"
)

// linuxState survives daemon crashes so that `testvpn unblock` can undo
// changes. The tunnel interface, its routes and per-link DNS of
// systemd-resolved disappear with the daemon process and are not recorded.
type linuxState struct {
	Nft          bool         `json:"nft,omitempty"`
	ResolvConf   *savedResolv `json:"resolvConf,omitempty"`
	ServerRoutes []string     `json:"serverRoutes,omitempty"`
}

// savedResolv is the original /etc/resolv.conf.
type savedResolv struct {
	Symlink string `json:"symlink,omitempty"` // target when it was a symlink
	Content string `json:"content,omitempty"`
	Missing bool   `json:"missing,omitempty"`
}

// Linux implements Platform with /dev/net/tun, iproute2, nftables and
// systemd-resolved (or /etc/resolv.conf). It must run as root.
type Linux struct {
	run        Runner
	statePath  string
	resolvPath string
	procRoute  string

	mu      sync.Mutex
	st      linuxState
	tun     *netstack.TunFileIO
	tunName string
	dnsLink string // link configured through resolvectl
	dns     []netip.Addr
	direct  map[netip.Addr]bool
	ksOn    bool
	ks      KillSwitch
	engTun  string
}

// NewLinux loads persisted state from statePath.
func NewLinux(statePath string, run Runner) *Linux {
	if run == nil {
		run = ExecRunner
	}
	l := &Linux{run: run, statePath: statePath, resolvPath: "/etc/resolv.conf", procRoute: "/proc/net/route", direct: map[netip.Addr]bool{}}
	if b, err := os.ReadFile(statePath); err == nil {
		json.Unmarshal(b, &l.st)
	}
	return l
}

func (l *Linux) saveLocked() {
	b, _ := json.MarshalIndent(l.st, "", "  ")
	tmp := l.statePath + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		os.Rename(tmp, l.statePath)
	}
}

// CreateTUN opens a non-persistent TUN interface; it is removed when the
// descriptor is closed, including when the daemon dies.
func (l *Linux) CreateTUN(mtu int) (netstack.PacketIO, string, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", fmt.Errorf("open /dev/net/tun (is the tun module loaded? try: modprobe tun): %w", err)
	}
	ifr, err := unix.NewIfreq(LinuxTunPrefix + "%d")
	if err != nil {
		unix.Close(fd)
		return nil, "", err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, "", fmt.Errorf("create tun interface: %w", err)
	}
	name := ifr.Name()
	io, err := netstack.NewTunFileIO(fd)
	if err != nil {
		unix.Close(fd)
		return nil, "", err
	}
	l.mu.Lock()
	l.tun, l.tunName = io, name
	l.mu.Unlock()
	return io, name, nil
}

func (l *Linux) ConfigureTUN(name string, mtu int) error {
	v4, v6 := LinuxTunCommands(name, mtu)
	for _, c := range v4 {
		if _, err := l.run("", c[0], c[1:]...); err != nil {
			return err
		}
	}
	// IPv6 may be disabled on the host; then there is nothing to capture.
	for _, c := range v6 {
		l.run("", c[0], c[1:]...)
	}
	return nil
}

// DestroyTUN closes the interface; its routes and resolved link settings
// disappear with it.
func (l *Linux) DestroyTUN() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.tun != nil {
		l.tun.Close()
		l.tun = nil
	}
	l.tunName, l.dnsLink = "", ""
	return nil
}

func (l *Linux) routes() []ProcRoute {
	b, err := os.ReadFile(l.procRoute)
	if err != nil {
		return nil
	}
	return ParseProcRoute(string(b))
}

// DefaultRoute returns the IPv4 default route via a gateway with the lowest
// metric that does not point into a tunnel of the daemon.
func (l *Linux) DefaultRoute() (DefaultRoute, error) {
	r, ok := PickDefaultRoute(l.routes(), func(ifc string) bool { return strings.HasPrefix(ifc, LinuxTunPrefix) })
	if !ok {
		return DefaultRoute{}, errors.New("no default route")
	}
	ifc, err := net.InterfaceByName(r.Iface)
	if err != nil {
		return DefaultRoute{}, err
	}
	dr := DefaultRoute{Gateway: r.Gateway, Interface: ifc.Name, Index: ifc.Index}
	if addrs, err := ifc.Addrs(); err == nil {
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() {
				dr.LAN = p.Masked()
				break
			}
		}
	}
	return dr, nil
}

// SetServerRoutes routes the servers via the physical gateway. No scoped
// default route is needed: SO_BINDTODEVICE restricts the route lookup to the
// physical interface, where the default route stays.
func (l *Linux) SetServerRoutes(servers []netip.Addr, via DefaultRoute) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.st.ServerRoutes {
		if a, err := netip.ParseAddr(s); err == nil {
			c := LinuxServerRoute(false, a, netip.Addr{}, "")
			l.run("", c[0], c[1:]...)
		}
	}
	l.st.ServerRoutes = nil
	var firstErr error
	for _, s := range servers {
		if !s.Is4() || !via.Gateway.IsValid() || via.Interface == "" {
			continue
		}
		c := LinuxServerRoute(true, s, via.Gateway, via.Interface)
		if _, err := l.run("", c[0], c[1:]...); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		l.st.ServerRoutes = append(l.st.ServerRoutes, s.String())
	}
	l.saveLocked()
	return firstErr
}

// RepairRoutes re-adds server routes that disappeared (for example when
// NetworkManager reconfigured the interface).
func (l *Linux) RepairRoutes(servers []netip.Addr, via DefaultRoute) []string {
	if !via.Valid() || !via.Gateway.IsValid() {
		return nil
	}
	hosts := HostRoutes(l.routes())
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, s := range servers {
		if s.Is4() && !hosts[s] {
			c := LinuxServerRoute(true, s, via.Gateway, via.Interface)
			if _, err := l.run("", c[0], c[1:]...); err == nil {
				n++
			}
		}
	}
	if n == 0 {
		return nil
	}
	return []string{fmt.Sprintf("%d server route(s)", n)}
}

// SetDNS points the system resolver to servers. With the systemd-resolved
// stub in /etc/resolv.conf the tunnel link gets the servers and the "~."
// routing domain; otherwise /etc/resolv.conf is rewritten (the original is
// saved). It is idempotent, so the daemon can call it to re-apply settings
// that NetworkManager or DHCP overwrote.
func (l *Linux) SetDNS(servers []netip.Addr) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	cur, _ := os.ReadFile(l.resolvPath)
	if UsesResolvedStub(string(cur)) && l.st.ResolvConf == nil {
		if _, err := exec.LookPath("resolvectl"); err == nil {
			if l.tunName == "" {
				return nil // applied to the link once the tunnel exists
			}
			return l.setResolvedLocked(servers)
		}
	}
	return l.setResolvConfLocked(servers, string(cur))
}

func sameAddrs(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (l *Linux) setResolvedLocked(servers []netip.Addr) error {
	if l.dnsLink == l.tunName && sameAddrs(l.dns, servers) {
		return nil
	}
	args := []string{"dns", l.tunName}
	for _, s := range servers {
		args = append(args, s.String())
	}
	if _, err := l.run("", "resolvectl", args...); err != nil {
		return err
	}
	if _, err := l.run("", "resolvectl", "domain", l.tunName, "~."); err != nil {
		return err
	}
	l.run("", "resolvectl", "default-route", l.tunName, "true") // absent in old versions
	l.run("", "resolvectl", "flush-caches")
	l.dnsLink, l.dns = l.tunName, servers
	return nil
}

func (l *Linux) setResolvConfLocked(servers []netip.Addr, cur string) error {
	if l.st.ResolvConf == nil {
		orig := &savedResolv{Content: cur}
		if fi, err := os.Lstat(l.resolvPath); err != nil {
			orig.Missing = true
		} else if fi.Mode()&os.ModeSymlink != 0 {
			orig.Symlink, _ = os.Readlink(l.resolvPath)
		}
		if strings.HasPrefix(cur, ResolvConfHeader) {
			// Left over from a crash without saved state: keep its options.
			orig = &savedResolv{Content: cur}
		}
		l.st.ResolvConf = orig
		l.saveLocked()
	}
	want := RenderResolvConf(l.st.ResolvConf.Content, servers)
	if fi, err := os.Lstat(l.resolvPath); err == nil && fi.Mode()&os.ModeSymlink == 0 && cur == want {
		return nil
	}
	if err := writeFileAtomic(l.resolvPath, want, 0o644); err != nil {
		return err
	}
	l.dns = servers
	return nil
}

// writeFileAtomic replaces path (also when it is a symlink) with content.
func writeFileAtomic(path, content string, mode os.FileMode) error {
	tmp := path + ".testvpn.tmp"
	if err := os.WriteFile(tmp, []byte(content), mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		// In containers resolv.conf is a bind mount that cannot be replaced,
		// only rewritten in place.
		if errors.Is(err, unix.EBUSY) {
			return os.WriteFile(path, []byte(content), mode)
		}
		return err
	}
	return nil
}

func (l *Linux) RestoreDNS() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.restoreDNSLocked()
}

func (l *Linux) restoreDNSLocked() error {
	if l.dnsLink != "" {
		l.run("", "resolvectl", "revert", l.dnsLink)
		l.dnsLink = ""
	}
	l.dns = nil
	o := l.st.ResolvConf
	if o == nil {
		return nil
	}
	var err error
	switch {
	case o.Symlink != "":
		tmp := l.resolvPath + ".testvpn.tmp"
		os.Remove(tmp)
		if err = os.Symlink(o.Symlink, tmp); err == nil {
			err = os.Rename(tmp, l.resolvPath)
		}
	case o.Missing:
		err = os.Remove(l.resolvPath)
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
	default:
		err = writeFileAtomic(l.resolvPath, o.Content, 0o644)
	}
	if err != nil {
		return fmt.Errorf("restore %s: %w", l.resolvPath, err)
	}
	l.st.ResolvConf = nil
	l.saveLocked()
	return nil
}

// EnableKillSwitch replaces the nftables table. Rules stay in place if the
// daemon dies (fail closed).
func (l *Linux) EnableKillSwitch(k KillSwitch) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ks = k
	return l.enableKillSwitchLocked()
}

func (l *Linux) AllowEngineInterface(name string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.engTun == name {
		return nil
	}
	l.engTun = name
	if !l.ksOn {
		return nil
	}
	return l.enableKillSwitchLocked()
}

func (l *Linux) enableKillSwitchLocked() error {
	k := l.ks
	k.EngineTun = l.engTun
	if _, err := exec.LookPath("nft"); err != nil {
		return errors.New("nft is not installed: the kill switch needs nftables (apt install nftables / dnf install nftables)")
	}
	if !l.st.Nft {
		l.st.Nft = true
		l.saveLocked()
	}
	if _, err := l.run(NftRules(k), "nft", "-f", "-"); err != nil {
		return err
	}
	l.ksOn = true
	// Replacing the table empties @direct: restore known direct addresses.
	if len(l.direct) > 0 {
		ips := make([]netip.Addr, 0, len(l.direct))
		for ip := range l.direct {
			ips = append(ips, ip)
		}
		return l.addDirectLocked(ips)
	}
	return nil
}

func (l *Linux) AllowDirect(ips ...netip.Addr) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var add []netip.Addr
	for _, ip := range ips {
		ip = ip.Unmap()
		if ip.Is4() && !l.direct[ip] {
			add = append(add, ip)
		}
	}
	if len(add) == 0 {
		return nil
	}
	if l.ksOn {
		if err := l.addDirectLocked(add); err != nil {
			return err
		}
	}
	for _, ip := range add {
		l.direct[ip] = true
	}
	return nil
}

func (l *Linux) addDirectLocked(ips []netip.Addr) error {
	_, err := l.run("", "nft", NftAddDirect(ips)...)
	return err
}

func (l *Linux) DisableKillSwitch() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.direct = map[netip.Addr]bool{}
	l.ksOn, l.engTun = false, ""
	return linuxUnblockLocked(l.run, &l.st, l.saveLocked)
}

func linuxUnblockLocked(run Runner, st *linuxState, save func()) error {
	if !st.Nft {
		return nil
	}
	out, err := run("", "nft", "delete", "table", "inet", NftTable)
	if err != nil && (strings.Contains(out, "No such file") || errors.Is(err, exec.ErrNotFound)) {
		err = nil
	}
	if err == nil {
		st.Nft = false
		save()
	}
	return err
}

// Unblock undoes all changes recorded in statePath: filter rules, the
// resolv.conf override and server routes. It is used by `testvpn unblock`
// when the daemon is not running.
func Unblock(statePath string, run Runner) error {
	l := NewLinux(statePath, run)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.st.Nft = true // remove the table even if the state file was lost
	err := linuxUnblockLocked(l.run, &l.st, l.saveLocked)
	if derr := l.restoreDNSLocked(); err == nil {
		err = derr
	}
	for _, s := range l.st.ServerRoutes {
		if a, perr := netip.ParseAddr(s); perr == nil {
			c := LinuxServerRoute(false, a, netip.Addr{}, "")
			l.run("", c[0], c[1:]...)
		}
	}
	l.st.ServerRoutes = nil
	l.saveLocked()
	return err
}

// Conflicts reports other VPNs and firewalls that would capture or block the
// daemon's traffic.
func (l *Linux) Conflicts(ownTun string) []string {
	var out []string
	for _, ifc := range ForeignTunnels(l.routes(), ownTun) {
		out = append(out, "another tunnel ("+ifc+") routes traffic; disconnect other VPNs")
	}
	if rules, err := l.run("", "ip", "-4", "rule", "show"); err == nil {
		for _, r := range ForeignPolicyRules(rules) {
			out = append(out, fmt.Sprintf("policy routing rule %q may send traffic past the tunnel (another VPN such as wg-quick?)", r))
		}
	}
	return out
}
