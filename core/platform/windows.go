//go:build windows

package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/eermolaev/test-vpn/core/netstack"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/firewall"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// WindowsTunName is the name of the Wintun adapter.
const WindowsTunName = "TestVPN"

// tunGUID is fixed so that Windows reuses the adapter's network profile
// instead of creating "Network 2", "Network 3", ... on every connect.
var tunGUID = &windows.GUID{Data1: 0x5e3c1a7d, Data2: 0x2b4f, Data3: 0x4c1e, Data4: [8]byte{0x9a, 0x61, 0x7e, 0x0d, 0x54, 0x3b, 0x21, 0xc8}}

// winRoute is a server route on the physical interface.
type winRoute struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Index   uint32 `json:"index"`
}

// windowsState survives daemon crashes so that `testvpn unblock` can undo
// changes. The firewall rules live in a dynamic WFP session and the DNS
// servers on the Wintun adapter, so both disappear with the daemon.
type windowsState struct {
	ServerRoutes []winRoute `json:"serverRoutes,omitempty"`
}

// Windows implements Platform with Wintun, the IP Helper API and the Windows
// Filtering Platform. It must run elevated (as a service under LocalSystem).
type Windows struct {
	statePath string

	mu     sync.Mutex
	st     windowsState
	dev    tun.Device
	luid   winipcfg.LUID
	dns    []netip.Addr
	fwOn   bool
	fwLUID uint64
}

// NewWindows loads persisted state from statePath.
func NewWindows(statePath string) *Windows {
	w := &Windows{statePath: statePath}
	if b, err := os.ReadFile(statePath); err == nil {
		json.Unmarshal(b, &w.st)
	}
	return w
}

func (w *Windows) saveLocked() {
	b, _ := json.MarshalIndent(w.st, "", "  ")
	tmp := w.statePath + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		os.Rename(tmp, w.statePath)
	}
}

// CreateTUN creates the Wintun adapter. wintun.dll must be next to the
// executable or in System32.
func (w *Windows) CreateTUN(mtu int) (netstack.PacketIO, string, error) {
	tun.WintunTunnelType = "TestVPN"
	dev, err := tun.CreateTUNWithRequestedGUID(WindowsTunName, tunGUID, mtu)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "wintun") || errors.Is(err, windows.ERROR_MOD_NOT_FOUND) {
			return nil, "", fmt.Errorf("create Wintun adapter (is wintun.dll next to testvpn.exe? get it from https://www.wintun.net): %w", err)
		}
		return nil, "", fmt.Errorf("create Wintun adapter: %w", err)
	}
	nt, ok := dev.(*tun.NativeTun)
	if !ok {
		dev.Close()
		return nil, "", errors.New("unexpected tun device type")
	}
	name, err := dev.Name()
	if err != nil {
		name = WindowsTunName
	}
	w.mu.Lock()
	w.dev, w.luid = dev, winipcfg.LUID(nt.LUID())
	w.mu.Unlock()
	return netstack.NewWintunIO(dev), name, nil
}

// ConfigureTUN assigns the addresses, captures all traffic with split
// default routes and gives the adapter the lowest metric, so that its DNS
// servers are preferred.
func (w *Windows) ConfigureTUN(name string, mtu int) error {
	w.mu.Lock()
	luid, ok := w.luid, w.dev != nil
	w.mu.Unlock()
	if !ok {
		return errors.New("the tunnel adapter does not exist")
	}
	if err := luid.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{netip.PrefixFrom(TunAddr4, 32)}); err != nil {
		return fmt.Errorf("set address: %w", err)
	}
	any4 := netip.IPv4Unspecified()
	if err := luid.SetRoutesForFamily(windows.AF_INET, []*winipcfg.RouteData{
		{Destination: netip.MustParsePrefix("0.0.0.0/1"), NextHop: any4},
		{Destination: netip.MustParsePrefix("128.0.0.0/1"), NextHop: any4},
	}); err != nil {
		return fmt.Errorf("set routes: %w", err)
	}
	if err := setInterfaceParams(luid, windows.AF_INET, mtu); err != nil {
		return fmt.Errorf("set interface parameters: %w", err)
	}
	// IPv6 may be disabled; then there is nothing to capture.
	if luid.SetIPAddressesForFamily(windows.AF_INET6, []netip.Prefix{netip.PrefixFrom(TunAddr6, 128)}) == nil {
		any6 := netip.IPv6Unspecified()
		luid.SetRoutesForFamily(windows.AF_INET6, []*winipcfg.RouteData{
			{Destination: netip.MustParsePrefix("::/1"), NextHop: any6},
			{Destination: netip.MustParsePrefix("8000::/1"), NextHop: any6},
		})
		setInterfaceParams(luid, windows.AF_INET6, mtu)
	}
	return nil
}

func setInterfaceParams(luid winipcfg.LUID, family winipcfg.AddressFamily, mtu int) error {
	ipif, err := luid.IPInterface(family)
	if err != nil {
		return err
	}
	ipif.UseAutomaticMetric = false
	ipif.Metric = 0
	ipif.NLMTU = uint32(mtu)
	ipif.DadTransmits = 0
	ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	return ipif.Set()
}

// DestroyTUN closes the adapter; its routes and DNS servers go with it.
func (w *Windows) DestroyTUN() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dev != nil {
		w.dev.Close()
		w.dev, w.luid, w.dns = nil, 0, nil
	}
	return nil
}

// DefaultRoute returns the IPv4 default route via a gateway with the lowest
// effective metric (route metric plus interface metric), outside the tunnel.
func (w *Windows) DefaultRoute() (DefaultRoute, error) {
	w.mu.Lock()
	own := w.luid
	w.mu.Unlock()
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return DefaultRoute{}, err
	}
	ifMetric := map[winipcfg.LUID]uint32{}
	if ifs, err := winipcfg.GetIPInterfaceTable(windows.AF_INET); err == nil {
		for _, i := range ifs {
			if i.Connected {
				ifMetric[i.InterfaceLUID] = i.Metric
			}
		}
	}
	var best *winipcfg.MibIPforwardRow2
	bestMetric := ^uint64(0)
	for i := range rows {
		r := &rows[i]
		if r.InterfaceLUID == own || r.DestinationPrefix.Prefix() != netip.PrefixFrom(netip.IPv4Unspecified(), 0) {
			continue
		}
		gw := r.NextHop.Addr()
		if !gw.Is4() || gw.IsUnspecified() {
			continue
		}
		im, ok := ifMetric[r.InterfaceLUID]
		if !ok {
			continue // interface is down
		}
		if m := uint64(r.Metric) + uint64(im); m < bestMetric {
			best, bestMetric = r, m
		}
	}
	if best == nil {
		return DefaultRoute{}, errors.New("no default route")
	}
	ifc, err := net.InterfaceByIndex(int(best.InterfaceIndex))
	if err != nil {
		return DefaultRoute{}, err
	}
	dr := DefaultRoute{Gateway: best.NextHop.Addr(), Interface: ifc.Name, Index: ifc.Index}
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

func addRoute(r winRoute) error {
	luid, err := winipcfg.LUIDFromIndex(r.Index)
	if err != nil {
		return err
	}
	dst, err := netip.ParsePrefix(r.Dst)
	if err != nil {
		return err
	}
	gw, err := netip.ParseAddr(r.Gateway)
	if err != nil {
		return err
	}
	if err := luid.AddRoute(dst, gw, 0); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return fmt.Errorf("add route %s via %s: %w", dst, gw, err)
	}
	return nil
}

func deleteRoute(r winRoute) {
	luid, err := winipcfg.LUIDFromIndex(r.Index)
	if err != nil {
		return
	}
	dst, err1 := netip.ParsePrefix(r.Dst)
	gw, err2 := netip.ParseAddr(r.Gateway)
	if err1 == nil && err2 == nil {
		luid.DeleteRoute(dst, gw)
	}
}

func serverRoute(s netip.Addr, via DefaultRoute) winRoute {
	return winRoute{Dst: netip.PrefixFrom(s, 32).String(), Gateway: via.Gateway.String(), Index: uint32(via.Index)}
}

// SetServerRoutes routes the servers via the physical gateway. Sockets bound
// with IP_UNICAST_IF use the physical default route, so nothing else is
// needed for direct connections.
func (w *Windows) SetServerRoutes(servers []netip.Addr, via DefaultRoute) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, r := range w.st.ServerRoutes {
		deleteRoute(r)
	}
	w.st.ServerRoutes = nil
	var firstErr error
	for _, s := range servers {
		if !s.Is4() || !via.Valid() || !via.Gateway.IsValid() {
			continue
		}
		r := serverRoute(s, via)
		if err := addRoute(r); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		w.st.ServerRoutes = append(w.st.ServerRoutes, r)
	}
	w.saveLocked()
	return firstErr
}

// RepairRoutes re-adds server routes that disappeared.
func (w *Windows) RepairRoutes(servers []netip.Addr, via DefaultRoute) []string {
	if !via.Valid() || !via.Gateway.IsValid() {
		return nil
	}
	luid, err := winipcfg.LUIDFromIndex(uint32(via.Index))
	if err != nil {
		return nil
	}
	n := 0
	for _, s := range servers {
		if !s.Is4() {
			continue
		}
		if _, err := luid.Route(netip.PrefixFrom(s, 32), via.Gateway); err == nil {
			continue
		}
		if addRoute(serverRoute(s, via)) == nil {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	return []string{fmt.Sprintf("%d server route(s)", n)}
}

var procDnsFlushResolverCache = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")

func flushDNSCache() {
	if procDnsFlushResolverCache.Find() == nil {
		procDnsFlushResolverCache.Call()
	}
}

// SetDNS sets the DNS servers of the tunnel adapter. Its metric is the
// lowest, so Windows asks them first; queries sent to other servers by other
// programs are routed into the tunnel as well.
func (w *Windows) SetDNS(servers []netip.Addr) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dev == nil {
		return nil
	}
	if sameAddrsWin(w.dns, servers) {
		return nil
	}
	var v4 []netip.Addr
	for _, s := range servers {
		if s.Is4() {
			v4 = append(v4, s)
		}
	}
	if err := w.luid.SetDNS(windows.AF_INET, v4, nil); err != nil {
		return err
	}
	w.luid.SetDNS(windows.AF_INET6, nil, nil)
	w.dns = servers
	flushDNSCache()
	return nil
}

func sameAddrsWin(a, b []netip.Addr) bool {
	if len(a) != len(b) || a == nil {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (w *Windows) RestoreDNS() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dev != nil {
		w.luid.FlushDNS(windows.AF_INET)
	}
	w.dns = nil
	flushDNSCache()
	return nil
}

// EnableKillSwitch installs WFP filters that block all traffic except the
// tunnel adapter, loopback, DHCP, neighbor discovery and this process (the
// daemon reaches the servers and excluded domains itself). The filters live
// in a dynamic session: if the daemon dies they are removed and the service
// manager restarts it. "Allow local network" is not supported on Windows.
func (w *Windows) EnableKillSwitch(k KillSwitch) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	var luid uint64
	if k.Tun != "" && w.dev != nil {
		luid = uint64(w.luid)
	}
	if w.fwOn && w.fwLUID == luid {
		return nil
	}
	if w.fwOn {
		firewall.DisableFirewall()
		w.fwOn = false
	}
	if err := firewall.EnableFirewall(luid, false, nil); err != nil {
		return err
	}
	w.fwOn, w.fwLUID = true, luid
	return nil
}

// AllowDirect is a no-op: the daemon's own traffic is permitted, and other
// programs reach excluded domains through the tunnel.
func (w *Windows) AllowDirect(...netip.Addr) error { return nil }

// AllowEngineInterface is a no-op: engines with their own tunnel are not
// supported on Windows.
func (w *Windows) AllowEngineInterface(string) error { return nil }

func (w *Windows) DisableKillSwitch() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fwOn {
		firewall.DisableFirewall()
		w.fwOn, w.fwLUID = false, 0
	}
	return nil
}

// Conflicts reports other tunnels that capture all IPv4 traffic.
func (w *Windows) Conflicts(string) []string {
	w.mu.Lock()
	own := w.luid
	w.mu.Unlock()
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return nil
	}
	split := map[netip.Prefix]bool{netip.MustParsePrefix("0.0.0.0/1"): true, netip.MustParsePrefix("128.0.0.0/1"): true}
	seen := map[uint32]bool{}
	var out []string
	for i := range rows {
		r := &rows[i]
		if r.InterfaceLUID == own || seen[r.InterfaceIndex] || !split[r.DestinationPrefix.Prefix()] {
			continue
		}
		seen[r.InterfaceIndex] = true
		name := fmt.Sprint(r.InterfaceIndex)
		if ifc, err := net.InterfaceByIndex(int(r.InterfaceIndex)); err == nil {
			name = ifc.Name
		}
		out = append(out, "another tunnel ("+name+") routes traffic; disconnect other VPN apps")
	}
	return out
}

// Unblock undoes the changes recorded in statePath (server routes) and
// removes a Wintun adapter left over by a crashed daemon. It is used by
// `testvpn unblock` when the daemon is not running.
func Unblock(statePath string, _ Runner) error {
	w := NewWindows(statePath)
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, r := range w.st.ServerRoutes {
		deleteRoute(r)
	}
	w.st.ServerRoutes = nil
	w.saveLocked()
	if a, err := wintun.OpenAdapter(WindowsTunName); err == nil {
		a.Close()
	}
	return nil
}
