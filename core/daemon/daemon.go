package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eermolaev/test-vpn/core/direct"
	"github.com/eermolaev/test-vpn/core/engine"
	"github.com/eermolaev/test-vpn/core/fallback"
	"github.com/eermolaev/test-vpn/core/platform"
	"github.com/eermolaev/test-vpn/core/profile"
	"github.com/eermolaev/test-vpn/core/tunnel"
)

// Version of the daemon.
const Version = "0.1.0"

// Options configure the daemon.
type Options struct {
	Dir      string // state directory (root-only)
	Platform platform.Platform
	MTU      int
	// MonitorInterval is how often the network is checked (default 2s).
	MonitorInterval time.Duration
	// NoBind disables binding direct sockets to the physical interface (tests).
	NoBind bool
	// DirectDialer overrides the dialer for direct connections (tests).
	DirectDialer engine.Dialer
	// LogWriter also receives log lines (the launchd log file).
	LogWriter io.Writer
	// Tunnel overrides tunnel timing (tests).
	TunePolicy func(*tunnel.Config)
}

// Daemon is the running service.
type Daemon struct {
	opts Options
	plat platform.Platform
	st   *store
	logs logRing
	mem  *fallback.Memory
	dial *direct.Dialer

	mu        sync.Mutex
	tun       *tunnel.Tunnel
	tunName   string
	servers   []netip.Addr
	route     platform.DefaultRoute
	since     time.Time
	lastErr   string
	ksOn      bool
	stopMon   context.CancelFunc
	profileID string
	warnings  []string
	// directBroken is set when sockets bound to the physical interface
	// cannot reach the network; excluded domains then use the tunnel.
	directBroken error
}

// New opens the state directory.
func New(opts Options) (*Daemon, error) {
	if opts.MTU == 0 {
		opts.MTU = 1400
	}
	if opts.MonitorInterval == 0 {
		opts.MonitorInterval = 2 * time.Second
	}
	st, err := openStore(opts.Dir)
	if err != nil {
		return nil, err
	}
	d := &Daemon{opts: opts, plat: opts.Platform, st: st, dial: &direct.Dialer{}}
	d.mem = fallback.NewMemory(memoryStore{st})
	return d, nil
}

func (d *Daemon) logf(format string, a ...any) { d.log(fmt.Sprintf(format, a...)) }

// log records a (redacted) line in the ring shown by the dashboard and, if
// configured, in the service log file.
func (d *Daemon) log(line string) {
	d.logs.add(line)
	if w := d.opts.LogWriter; w != nil {
		fmt.Fprintf(w, "%s %s\n", time.Now().Format("2006-01-02 15:04:05"), line)
	}
}

// Start restores the desired state after a (re)start: reconnect if the user
// was connected — the kill switch from a crash stays active meanwhile — or
// clean up leftovers otherwise.
func (d *Daemon) Start() {
	if d.st.view().Connected {
		d.logf("restoring connection after restart")
		if err := d.Connect(""); err != nil {
			d.logf("reconnect failed: %v", err)
		}
		return
	}
	d.plat.RestoreDNS()
	d.plat.SetServerRoutes(nil, platform.DefaultRoute{})
	d.plat.DisableKillSwitch()
}

// Shutdown is called when the daemon is stopped by launchd (not a crash):
// the desired state is kept, so the tunnel comes back on the next start, but
// the system is left unblocked if the user had disconnected.
func (d *Daemon) Shutdown() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.tun != nil {
		d.teardownLocked(!d.st.view().Connected)
	}
}

func (d *Daemon) profileByID(id string) (storedProfile, bool) {
	v := d.st.view()
	if id == "" {
		id = v.Selected
	}
	for _, p := range v.Profiles {
		if p.ID == id {
			return p, true
		}
	}
	return storedProfile{}, false
}

func dnsServers(s Settings) []string {
	if len(s.DNSServers) == 0 {
		return tunnel.DefaultDNS
	}
	return s.DNSServers
}

func toAddrs(list []string) []netip.Addr {
	var out []netip.Addr
	for _, s := range list {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		} else if ap, err := netip.ParseAddrPort(s); err == nil {
			out = append(out, ap.Addr())
		}
	}
	return out
}

func tunnelSettings(s Settings) tunnel.Settings {
	block := s.BlockQUIC
	return tunnel.Settings{
		Exclusions:       s.Exclusions,
		DNSServers:       dnsServers(s),
		ExclusionDNSMode: s.ExclusionDNSMode,
		BlockQUIC:        &block,
	}
}

// allowDialer opens the kill switch for a destination before dialing it
// directly (excluded domains and their DNS).
type allowDialer struct {
	plat platform.Platform
	d    engine.Dialer
}

func (a allowDialer) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if err := a.plat.AllowDirect(dst.Addr()); err != nil {
		return nil, err
	}
	return a.d.DialTCP(ctx, dst)
}

func (a allowDialer) DialUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if err := a.plat.AllowDirect(dst.Addr()); err != nil {
		return nil, err
	}
	return a.d.DialUDP(ctx, dst)
}

// pinServers resolves server names directly and rewrites the profile copy to
// use IP addresses, so that routes and filter rules cover them.
func (d *Daemon) pinServers(p *profile.Profile, s Settings) ([]netip.Addr, error) {
	var dns []netip.AddrPort
	for _, a := range toAddrs(dnsServers(s)) {
		dns = append(dns, netip.AddrPortFrom(a, 53))
	}
	resolver := allowDialer{plat: d.plat, d: d.directDialer()}
	seen := map[netip.Addr]bool{}
	var servers []netip.Addr
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for i := range p.Transports {
		t := &p.Transports[i]
		host := t.ServerHost()
		ip, err := resolveDirect(ctx, resolver, dns, host)
		if err != nil {
			return nil, err
		}
		switch {
		case t.AWG != nil:
			_, port, _ := net.SplitHostPort(t.AWG.Peer.Endpoint)
			t.AWG.Peer.Endpoint = net.JoinHostPort(ip.String(), port)
		case t.VLESS != nil:
			t.VLESS.Address = ip.String()
		}
		if !seen[ip] {
			seen[ip] = true
			servers = append(servers, ip)
		}
	}
	return servers, nil
}

func cloneProfile(p *profile.Profile) (*profile.Profile, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var c profile.Profile
	return &c, json.Unmarshal(b, &c)
}

// Connect brings the tunnel up. Order: kill switch, tunnel interface, routes,
// DNS, engine; nothing leaks while a step is in progress.
func (d *Daemon) Connect(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.tun != nil {
		d.teardownLocked(false)
	}
	sp, ok := d.profileByID(id)
	if !ok {
		return errors.New("no profile selected; import one first")
	}
	settings := d.st.view().Settings
	d.st.update(func(s *storeData) error { s.Connected, s.Selected = true, sp.ID; return nil })
	err := d.connectLocked(sp, settings)
	if err != nil {
		// Fail closed: the kill switch stays until the user disconnects.
		d.plat.DestroyTUN()
		d.lastErr = err.Error()
		d.logf("connect failed: %v", err)
	}
	return err
}

func (d *Daemon) connectLocked(sp storedProfile, s Settings) error {
	d.checkConflictsLocked("")
	route, err := d.plat.DefaultRoute()
	if err != nil {
		route = platform.DefaultRoute{}
	}
	d.route = route
	if !d.opts.NoBind {
		d.dial.SetInterface(route.Index, route.Interface)
	}
	// Block first: from here on only the VPN servers and excluded domains
	// can be reached directly.
	ks := platform.KillSwitch{AllowLAN: s.AllowLAN, LAN: route.LAN}
	if err := d.plat.EnableKillSwitch(ks); err != nil {
		return fmt.Errorf("kill switch: %w", err)
	}
	d.ksOn = true
	prof, err := cloneProfile(sp.Profile)
	if err != nil {
		return err
	}
	servers, err := d.pinServers(prof, s)
	if err != nil {
		return err
	}
	d.servers = servers
	ks.Servers = servers
	if err := d.plat.EnableKillSwitch(ks); err != nil {
		return fmt.Errorf("kill switch: %w", err)
	}
	pio, name, err := d.plat.CreateTUN(d.opts.MTU)
	if err != nil {
		return fmt.Errorf("tunnel interface: %w", err)
	}
	d.tunName = name
	ks.Tun = name
	if err := d.plat.EnableKillSwitch(ks); err != nil {
		return fmt.Errorf("kill switch: %w", err)
	}
	if err := d.plat.ConfigureTUN(name, d.opts.MTU); err != nil {
		return fmt.Errorf("tunnel interface: %w", err)
	}
	if err := d.plat.SetServerRoutes(servers, route); err != nil {
		d.logf("server routes: %v", err)
	}
	if err := d.plat.SetDNS(toAddrs(dnsServers(s))); err != nil {
		d.logf("dns: %v", err)
	}
	cfg := tunnel.Config{
		Profile:         prof,
		ManualTransport: sp.ManualTransport,
		NetworkID:       route.Interface + "|" + route.Gateway.String(),
		InterfaceIndex:  route.Index,
		InterfaceName:   route.Interface,
		MTU:             d.opts.MTU,
		Settings:        tunnelSettings(s),
	}
	if d.opts.TunePolicy != nil {
		d.opts.TunePolicy(&cfg)
	}
	t, err := tunnel.Start(pio, cfg, tunnel.Deps{
		Memory: d.mem,
		Logf:   d.log,
		Direct: allowDialer{plat: d.plat, d: d.directDialer()},
	})
	if err != nil {
		pio.Close()
		return err
	}
	d.tun, d.profileID, d.since, d.lastErr = t, sp.ID, time.Now(), ""
	ctx, cancel := context.WithCancel(context.Background())
	d.stopMon = cancel
	go d.monitor(ctx, s)
	d.logf("tunnel started on %s", name)
	d.checkDirectLocked(s)
	return nil
}

// Disconnect stops the tunnel and removes all system changes.
func (d *Daemon) Disconnect() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.st.update(func(s *storeData) error { s.Connected = false; return nil })
	d.teardownLocked(true)
	d.logf("disconnected")
	return nil
}

func (d *Daemon) teardownLocked(unblock bool) {
	d.directBroken = nil
	if d.stopMon != nil {
		d.stopMon()
		d.stopMon = nil
	}
	if d.tun != nil {
		d.tun.Stop()
		d.tun = nil
	}
	d.plat.DestroyTUN()
	d.tunName = ""
	if unblock {
		d.plat.RestoreDNS()
		d.plat.SetServerRoutes(nil, platform.DefaultRoute{})
		d.plat.DisableKillSwitch()
		d.ksOn = false
	}
}

func (d *Daemon) directDialer() engine.Dialer {
	if d.opts.DirectDialer != nil {
		return d.opts.DirectDialer
	}
	return d.dial
}

// effectiveSettings are the tunnel settings, with exclusions moved into the
// tunnel while the direct path is broken.
func (d *Daemon) effectiveSettings(s Settings) tunnel.Settings {
	ts := tunnelSettings(s)
	if d.directBroken != nil {
		ts.Exclusions = nil
	}
	return ts
}

// checkDirectLocked verifies that sockets bound to the physical interface can
// reach a VPN server (a routing check: a UDP connect does a route lookup and
// sends nothing). If they cannot, excluded domains would be reset, so they
// go through the tunnel until the direct path works again.
func (d *Daemon) checkDirectLocked(s Settings) {
	if d.tun == nil || len(d.servers) == 0 {
		return
	}
	var err error
	if len(s.Exclusions) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		var c net.Conn
		c, err = d.directDialer().DialUDP(ctx, netip.AddrPortFrom(d.servers[0], 443))
		cancel()
		if c != nil {
			c.Close()
		}
	}
	was := d.directBroken
	d.directBroken = err
	switch {
	case err != nil && was == nil:
		d.logf("warning: excluded domains cannot be reached directly (%v); sending them through the VPN for now", err)
	case err == nil && was != nil:
		d.logf("direct path works again; excluded domains bypass the VPN")
	default:
		return
	}
	if uerr := d.tun.UpdateSettings(d.effectiveSettings(s)); uerr != nil {
		d.logf("apply settings: %v", uerr)
	}
}

// checkConflictsLocked records and logs other VPNs/firewalls. Another VPN
// that is connected captures the daemon's own traffic to the servers, so
// connections time out; this is the most common cause of failures.
func (d *Daemon) checkConflictsLocked(ownTun string) {
	w := d.plat.Conflicts(ownTun)
	if strings.Join(w, "\n") != strings.Join(d.warnings, "\n") {
		for _, x := range w {
			d.logf("warning: %s", x)
		}
	}
	d.warnings = w
}

// monitor follows network changes (SEC-NET-005) and keeps the DNS override.
func (d *Daemon) monitor(ctx context.Context, s Settings) {
	t := time.NewTicker(d.opts.MonitorInterval)
	defer t.Stop()
	ticks := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		route, err := d.plat.DefaultRoute()
		if err != nil || !route.Valid() {
			continue
		}
		d.mu.Lock()
		if d.tun == nil || ctx.Err() != nil {
			d.mu.Unlock()
			return
		}
		cur := d.st.view().Settings
		if route != d.route {
			d.logf("network changed: %s via %s", route.Interface, route.Gateway)
			d.route = route
			if !d.opts.NoBind {
				d.dial.SetInterface(route.Index, route.Interface)
			}
			d.plat.SetServerRoutes(d.servers, route)
			d.plat.EnableKillSwitch(platform.KillSwitch{Tun: d.tunName, Servers: d.servers, AllowLAN: cur.AllowLAN, LAN: route.LAN})
			d.tun.NetworkChanged(route.Interface+"|"+route.Gateway.String(), route.Index, route.Interface)
			d.checkDirectLocked(cur)
		}
		d.plat.SetDNS(toAddrs(dnsServers(cur)))
		if ticks++; ticks%15 == 0 {
			d.checkConflictsLocked(d.tunName)
			if d.directBroken != nil {
				d.checkDirectLocked(cur)
			}
		}
		d.mu.Unlock()
	}
}

// Reconnect re-checks the tunnel now.
func (d *Daemon) Reconnect() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.tun == nil {
		return errors.New("not connected")
	}
	d.tun.Reconnect()
	return nil
}

// SetSettings validates and stores settings; a running tunnel applies them
// without reconnecting.
func (d *Daemon) SetSettings(s Settings) error {
	if s.ExclusionDNSMode == "" {
		s.ExclusionDNSMode = tunnel.ExclusionDNSPublic
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.tun != nil {
		if err := d.tun.UpdateSettings(d.effectiveSettings(s)); err != nil {
			return err
		}
		old := d.st.view().Settings
		if old.AllowLAN != s.AllowLAN {
			d.plat.EnableKillSwitch(platform.KillSwitch{Tun: d.tunName, Servers: d.servers, AllowLAN: s.AllowLAN, LAN: d.route.LAN})
		}
		d.plat.SetDNS(toAddrs(dnsServers(s)))
	} else if err := tunnelSettings(s).Validate(); err != nil {
		return err
	}
	return d.st.update(func(sd *storeData) error { sd.Settings = s; return nil })
}

func entry(p storedProfile, selected string) ProfileEntry {
	return ProfileEntry{ID: p.ID, Name: p.Name, ExpectedCountry: p.ExpectedCountry, ManualTransport: p.ManualTransport, Summary: p.Profile.Summarize(), Selected: p.ID == selected}
}

// Status returns the current status.
func (d *Daemon) Status() Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	v := d.st.view()
	st := Status{Version: Version, Build: Build(), Connected: v.Connected, KillSwitch: d.ksOn, Interface: d.tunName, Route: d.route, Since: d.since, LastError: d.lastErr, DNSServers: dnsServers(v.Settings), Warnings: d.warnings}
	if sp, ok := d.profileByID(""); ok {
		e := entry(sp, v.Selected)
		st.Profile = &e
	}
	if d.tun != nil {
		ts := d.tun.Status()
		st.Tunnel = &ts
	}
	if d.directBroken != nil {
		st.Warnings = append(append([]string(nil), st.Warnings...), "excluded domains go through the VPN: the direct path is unreachable ("+d.directBroken.Error()+")")
	}
	return st
}

// Profiles lists stored profiles.
func (d *Daemon) Profiles() []ProfileEntry {
	v := d.st.view()
	out := []ProfileEntry{}
	for _, p := range v.Profiles {
		out = append(out, entry(p, v.Selected))
	}
	return out
}

// Import parses and stores a profile, or adds its transports to an existing one.
func (d *Daemon) Import(a ImportArgs) (ProfileEntry, error) {
	p, err := profile.Parse(a.Text)
	if err != nil {
		return ProfileEntry{}, err
	}
	var out storedProfile
	err = d.st.update(func(s *storeData) error {
		if a.Into != "" {
			for i := range s.Profiles {
				if s.Profiles[i].ID == a.Into {
					s.Profiles[i].Profile.Merge(p)
					out = s.Profiles[i]
					return nil
				}
			}
			return errors.New("profile not found")
		}
		out = storedProfile{ID: newID(), Name: p.Name, Profile: p}
		if out.Name == "" {
			out.Name = "Server " + strconv.Itoa(len(s.Profiles)+1)
		}
		s.Profiles = append(s.Profiles, out)
		if s.Selected == "" {
			s.Selected = out.ID
		}
		return nil
	})
	if err != nil {
		return ProfileEntry{}, err
	}
	d.logf("imported profile %q (%d transports)", out.Name, len(out.Profile.Transports))
	return entry(out, d.st.view().Selected), nil
}

// UpdateProfile changes profile metadata.
func (d *Daemon) UpdateProfile(u UpdateProfile) error {
	return d.st.update(func(s *storeData) error {
		for i := range s.Profiles {
			p := &s.Profiles[i]
			if p.ID != u.ID {
				continue
			}
			if u.Name != nil {
				p.Name = *u.Name
			}
			if u.ExpectedCountry != nil {
				p.ExpectedCountry = *u.ExpectedCountry
			}
			if u.ManualTransport != nil {
				if *u.ManualTransport != "" {
					if _, err := fallback.NewPlanner(p.Profile, fallback.DefaultPolicy(), fallback.Options{Manual: *u.ManualTransport}); err != nil {
						return err
					}
				}
				p.ManualTransport = *u.ManualTransport
			}
			return nil
		}
		return errors.New("profile not found")
	})
}

// DeleteProfile removes a profile (not the connected one).
func (d *Daemon) DeleteProfile(id string) error {
	d.mu.Lock()
	connected := d.tun != nil && d.profileID == id
	d.mu.Unlock()
	if connected {
		return errors.New("disconnect before deleting the active profile")
	}
	return d.st.update(func(s *storeData) error {
		for i, p := range s.Profiles {
			if p.ID == id {
				s.Profiles = append(s.Profiles[:i], s.Profiles[i+1:]...)
				if s.Selected == id {
					s.Selected = ""
					if len(s.Profiles) > 0 {
						s.Selected = s.Profiles[0].ID
					}
				}
				return nil
			}
		}
		return errors.New("profile not found")
	})
}

// SelectProfile sets the profile used by Connect.
func (d *Daemon) SelectProfile(id string) error {
	if _, ok := d.profileByID(id); !ok {
		return errors.New("profile not found")
	}
	return d.st.update(func(s *storeData) error { s.Selected = id; return nil })
}

// Handle serves IPC requests.
func (d *Daemon) Handle(cmd string, args json.RawMessage) (any, error) {
	decode := func(v any) error {
		if len(args) == 0 {
			return nil
		}
		return json.Unmarshal(args, v)
	}
	switch cmd {
	case CmdStatus:
		return d.Status(), nil
	case CmdFlows:
		var a FlowsArgs
		decode(&a)
		d.mu.Lock()
		t := d.tun
		d.mu.Unlock()
		fl := FlowList{Flows: nil}
		if t != nil {
			fl.Flows = t.Flows(a.Limit)
		}
		return fl, nil
	case CmdLogs:
		var a LogsArgs
		decode(&a)
		return d.logs.after(a.After), nil
	case CmdProfiles:
		return d.Profiles(), nil
	case CmdImport:
		var a ImportArgs
		if err := decode(&a); err != nil {
			return nil, err
		}
		return d.Import(a)
	case CmdUpdateProfile:
		var a UpdateProfile
		if err := decode(&a); err != nil {
			return nil, err
		}
		return nil, d.UpdateProfile(a)
	case CmdDeleteProfile:
		var a IDArgs
		decode(&a)
		return nil, d.DeleteProfile(a.ID)
	case CmdSelectProfile:
		var a IDArgs
		decode(&a)
		return nil, d.SelectProfile(a.ID)
	case CmdConnect:
		var a ConnectArgs
		decode(&a)
		return nil, d.Connect(a.ID)
	case CmdDisconnect:
		return nil, d.Disconnect()
	case CmdReconnect:
		return nil, d.Reconnect()
	case CmdGetSettings:
		return d.st.view().Settings, nil
	case CmdSetSettings:
		var s Settings
		if err := decode(&s); err != nil {
			return nil, err
		}
		return nil, d.SetSettings(s)
	}
	return nil, fmt.Errorf("unknown command %q", cmd)
}
