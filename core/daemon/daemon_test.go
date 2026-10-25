package daemon

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eermolaev/test-vpn/core/engine"
	"github.com/eermolaev/test-vpn/core/fallback"
	"github.com/eermolaev/test-vpn/core/internal/clientstack"
	"github.com/eermolaev/test-vpn/core/internal/quictest"
	"github.com/eermolaev/test-vpn/core/internal/testenv"
	"github.com/eermolaev/test-vpn/core/ipc"
	"github.com/eermolaev/test-vpn/core/netstack"
	"github.com/eermolaev/test-vpn/core/platform"
	"github.com/eermolaev/test-vpn/core/profile"
	"github.com/eermolaev/test-vpn/core/tunnel"
)

type env struct {
	d      *Daemon
	plat   *platform.Fake
	cl     *ipc.Client
	client chan *clientstack.Client
	dir    string
}

func startDaemon(t *testing.T, dir string) *env {
	return startDaemonWith(t, dir, nil)
}

func startDaemonWith(t *testing.T, dir string, directDialer engine.Dialer) *env {
	return startDaemonBoot(t, dir, directDialer, nil)
}

func startDaemonBoot(t *testing.T, dir string, directDialer engine.Dialer, boot func() int64) *env {
	t.Helper()
	plat := platform.NewFake()
	e := &env{plat: plat, client: make(chan *clientstack.Client, 4), dir: dir}
	plat.OnCreate = func(app *netstack.PipeIO) { e.client <- clientstack.New(app) }
	d, err := New(Options{
		Dir: dir, Platform: plat, NoBind: true, MonitorInterval: 50 * time.Millisecond, DirectDialer: directDialer, BootTime: boot,
		TunePolicy: func(c *tunnel.Config) {
			c.Policy = fallback.Policy{Attempts: 1, FailTimeout: 3 * time.Second, BackoffBase: 10 * time.Millisecond, BackoffMax: 50 * time.Millisecond, MaxRounds: 1}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.d = d
	sock := filepath.Join(dir, "d.sock")
	srv, err := ipc.Listen(sock, -1, d.Handle)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := ipc.Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	e.cl = cl
	t.Cleanup(func() { cl.Close(); srv.Close(); d.Shutdown() })
	return e
}

func (e *env) waitConnected(t *testing.T) Status {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var st Status
	for time.Now().Before(deadline) {
		if err := e.cl.Call(CmdStatus, nil, &st); err != nil {
			t.Fatal(err)
		}
		if st.Tunnel != nil && st.Tunnel.State == tunnel.StateConnected {
			return st
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("not connected: %+v (tunnel %+v)", st, st.Tunnel)
	return st
}

func exchange(t *testing.T, c *clientstack.Client, dst netip.AddrPort, payload []byte) string {
	t.Helper()
	conn, err := c.DialTCP(dst, 3*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", dst, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write(payload)
	buf := make([]byte, 32<<10)
	n, _ := io.ReadAtLeast(conn, buf, len(payload))
	return string(buf[:n])
}

func TestDaemonEndToEnd(t *testing.T) {
	host := testenv.HostIP(t)
	directEcho := testenv.StartEchoOn(t, host, "direct:")
	srv := testenv.StartAWG(t, testenv.Obfuscation(), [4]byte{1, 2, 3, 4})
	e := startDaemon(t, t.TempDir())

	var pe ProfileEntry
	if err := e.cl.Call(CmdImport, ImportArgs{Text: profile.FormatAWGConf(srv.Client)}, &pe); err != nil {
		t.Fatal(err)
	}
	if !pe.Selected || len(pe.Summary.Transports) != 1 {
		t.Fatalf("import: %+v", pe)
	}
	settings := Settings{Exclusions: []string{"bank.example"}, DNSServers: []string{testenv.AWGServerIP.String()}, BlockQUIC: true}
	if err := e.cl.Call(CmdSetSettings, settings, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.cl.Call(CmdSetSettings, Settings{Exclusions: []string{"1.2.3.4"}}, nil); err == nil {
		t.Fatal("invalid settings must be rejected")
	}
	if err := e.cl.Call(CmdConnect, nil, nil); err != nil {
		t.Fatal(err)
	}
	st := e.waitConnected(t)
	if !st.KillSwitch || st.Interface != "utun9" || st.Profile == nil {
		t.Fatalf("status: %+v", st)
	}
	// Order: kill switch before the tunnel interface, DNS after it.
	p := e.plat
	if !(p.EventIndex("killswitch-on") < p.EventIndex("create-tun") && p.EventIndex("create-tun") < p.EventIndex("set-dns")) {
		t.Fatalf("wrong order: %v", p.Events())
	}
	ks, _ := p.KillSwitchActive()
	if ks.Tun != "utun9" || len(ks.Servers) != 1 || ks.Servers[0].String() != "127.0.0.1" {
		t.Fatalf("kill switch: %+v", ks)
	}

	c := <-e.client
	if got := exchange(t, c, netip.AddrPortFrom(testenv.AWGServerIP, 7), []byte("hi")); got != "awg:hi" {
		t.Fatalf("tunnel flow: %q", got)
	}
	ch := quictest.ClientHello("www.bank.example")
	tls := append([]byte{0x16, 3, 1, byte(len(ch) >> 8), byte(len(ch))}, ch...)
	if got := exchange(t, c, directEcho.TCP, tls); !strings.HasPrefix(got, "direct:") {
		t.Fatalf("excluded flow failed")
	}
	if !p.Allowed(host) {
		t.Fatal("direct destination must be allowed in the kill switch before dialing")
	}

	var fl FlowList
	e.cl.Call(CmdFlows, FlowsArgs{Limit: 10}, &fl)
	var logs []LogLine
	e.cl.Call(CmdLogs, LogsArgs{}, &logs)
	if len(logs) == 0 || !strings.Contains(logs[len(logs)-1].Text+logs[0].Text, "") {
		t.Fatal("no logs")
	}
	for _, l := range logs {
		if strings.Contains(l.Text, srv.Client.PrivateKey) {
			t.Fatal("secret in logs")
		}
	}
	e.cl.Call(CmdStatus, nil, &st)
	if st.Tunnel.Stats.BytesTunnelUp == 0 || st.Tunnel.Stats.BytesDirectUp == 0 {
		t.Fatalf("byte counters: %+v", st.Tunnel.Stats)
	}

	if err := e.cl.Call(CmdDisconnect, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, on := p.KillSwitchActive(); on {
		t.Fatal("kill switch must be removed after disconnect")
	}
	if p.EventIndex("destroy-tun") > p.EventIndex("killswitch-off") || p.EventIndex("restore-dns") < 0 {
		t.Fatalf("teardown order: %v", p.Events())
	}
}

func TestDaemonRestoresAfterRestart(t *testing.T) {
	srv := testenv.StartAWG(t, testenv.Obfuscation(), [4]byte{1, 2, 3, 4})
	dir := t.TempDir()
	e := startDaemon(t, dir)
	e.cl.Call(CmdImport, ImportArgs{Text: profile.FormatAWGConf(srv.Client)}, nil)
	e.cl.Call(CmdSetSettings, Settings{DNSServers: []string{testenv.AWGServerIP.String()}}, nil)
	if err := e.cl.Call(CmdConnect, nil, nil); err != nil {
		t.Fatal(err)
	}
	e.waitConnected(t)

	// A new daemon process (after a crash or reboot) reconnects by itself.
	e2 := startDaemon(t, dir)
	e2.d.Start()
	e2.waitConnected(t)
	if _, on := e2.plat.KillSwitchActive(); !on {
		t.Fatal("kill switch must be active")
	}

	// After an explicit disconnect, a restart leaves the system unblocked.
	e2.cl.Call(CmdDisconnect, nil, nil)
	e3 := startDaemon(t, dir)
	e3.d.Start()
	var st Status
	e3.cl.Call(CmdStatus, nil, &st)
	if st.Connected || st.Tunnel != nil || e3.plat.EventIndex("killswitch-off") < 0 {
		t.Fatalf("restart after disconnect: %+v %v", st, e3.plat.Events())
	}
}

func TestProfileManagement(t *testing.T) {
	e := startDaemon(t, t.TempDir())
	link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.10:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=www.microsoft.com&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba8#One"
	var a, b ProfileEntry
	e.cl.Call(CmdImport, ImportArgs{Text: link}, &a)
	e.cl.Call(CmdImport, ImportArgs{Text: strings.Replace(link, "#One", "#Two", 1)}, &b)
	xhttp := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.10:8443?type=xhttp&path=/x&security=reality&sni=www.microsoft.com&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba8"
	var merged ProfileEntry
	if err := e.cl.Call(CmdImport, ImportArgs{Text: xhttp, Into: a.ID}, &merged); err != nil || len(merged.Summary.Transports) != 2 {
		t.Fatalf("merge: %+v %v", merged, err)
	}
	name, country, bad := "Renamed", "DE", "nope"
	if err := e.cl.Call(CmdUpdateProfile, UpdateProfile{ID: a.ID, Name: &name, ExpectedCountry: &country}, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.cl.Call(CmdUpdateProfile, UpdateProfile{ID: a.ID, ManualTransport: &bad}, nil); err == nil {
		t.Fatal("unknown transport must be rejected")
	}
	e.cl.Call(CmdSelectProfile, IDArgs{ID: b.ID}, nil)
	var list []ProfileEntry
	e.cl.Call(CmdProfiles, nil, &list)
	if len(list) != 2 || list[0].Name != "Renamed" || list[0].ExpectedCountry != "DE" || !list[1].Selected {
		t.Fatalf("list: %+v", list)
	}
	e.cl.Call(CmdDeleteProfile, IDArgs{ID: b.ID}, nil)
	e.cl.Call(CmdProfiles, nil, &list)
	if len(list) != 1 || !list[0].Selected {
		t.Fatalf("after delete: %+v", list)
	}
}

func TestConflictWarnings(t *testing.T) {
	srv := testenv.StartAWG(t, testenv.Obfuscation(), [4]byte{1, 2, 3, 4})
	e := startDaemon(t, t.TempDir())
	e.plat.ConflictList = []string{`VPN "AmneziaVPN" is connected`}
	e.cl.Call(CmdImport, ImportArgs{Text: profile.FormatAWGConf(srv.Client)}, nil)
	e.cl.Call(CmdSetSettings, Settings{DNSServers: []string{testenv.AWGServerIP.String()}}, nil)
	if err := e.cl.Call(CmdConnect, nil, nil); err != nil {
		t.Fatal(err)
	}
	var st Status
	e.cl.Call(CmdStatus, nil, &st)
	if len(st.Warnings) != 1 || !strings.Contains(st.Warnings[0], "AmneziaVPN") {
		t.Fatalf("warnings: %v", st.Warnings)
	}
	var logs []LogLine
	e.cl.Call(CmdLogs, LogsArgs{}, &logs)
	found := false
	for _, l := range logs {
		found = found || strings.Contains(l.Text, "warning: VPN \"AmneziaVPN\"")
	}
	if !found {
		t.Fatal("conflict not logged")
	}
}

type unreachableDialer struct{}

func (unreachableDialer) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("connect: network is unreachable")
}
func (unreachableDialer) DialUDP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("connect: network is unreachable")
}

// If the direct path does not work, excluded domains must keep working
// through the tunnel instead of being reset.
func TestBrokenDirectPathFallsBackToTunnel(t *testing.T) {
	srv := testenv.StartAWG(t, testenv.Obfuscation(), [4]byte{1, 2, 3, 4})
	e := startDaemonWith(t, t.TempDir(), unreachableDialer{})
	e.cl.Call(CmdImport, ImportArgs{Text: profile.FormatAWGConf(srv.Client)}, nil)
	e.cl.Call(CmdSetSettings, Settings{Exclusions: []string{"bank.example"}, DNSServers: []string{testenv.AWGServerIP.String()}}, nil)
	if err := e.cl.Call(CmdConnect, nil, nil); err != nil {
		t.Fatal(err)
	}
	st := e.waitConnected(t)
	found := false
	for _, w := range st.Warnings {
		found = found || strings.Contains(w, "direct path is unreachable")
	}
	if !found {
		t.Fatalf("warnings: %v", st.Warnings)
	}
	c := <-e.client
	ch := quictest.ClientHello("www.bank.example")
	tls := append([]byte{0x16, 3, 1, byte(len(ch) >> 8), byte(len(ch))}, ch...)
	got := exchange(t, c, netip.AddrPortFrom(testenv.AWGServerIP, 7), tls)
	if !strings.HasPrefix(got, "awg:") {
		t.Fatal("excluded domain must go through the tunnel while the direct path is broken")
	}
}

func TestAutoConnectOnStartup(t *testing.T) {
	bootA := func() int64 { return 1000 }
	bootB := func() int64 { return 2000 } // after a reboot

	setup := func(t *testing.T, mode string, connected bool) string {
		// A fresh server per case: daemons of earlier cases keep running
		// with the same peer key until the test ends.
		srv := testenv.StartAWG(t, testenv.Obfuscation(), [4]byte{1, 2, 3, 4})
		dir := t.TempDir()
		e := startDaemonBoot(t, dir, nil, bootA)
		e.cl.Call(CmdImport, ImportArgs{Text: profile.FormatAWGConf(srv.Client)}, nil)
		if err := e.cl.Call(CmdSetSettings, Settings{DNSServers: []string{testenv.AWGServerIP.String()}, AutoConnect: mode}, nil); err != nil {
			t.Fatal(err)
		}
		e.cl.Call(CmdConnect, nil, nil)
		e.waitConnected(t)
		if !connected {
			e.cl.Call(CmdDisconnect, nil, nil)
		}
		e.d.Shutdown()
		return dir
	}
	started := func(t *testing.T, dir string, boot func() int64) bool {
		e := startDaemonBoot(t, dir, nil, boot)
		e.d.Start()
		var st Status
		e.cl.Call(CmdStatus, nil, &st)
		_, ks := e.plat.KillSwitchActive()
		return st.Connected && st.Tunnel != nil && ks
	}

	cases := []struct {
		mode      string
		connected bool
		boot      func() int64
		want      bool
	}{
		{AutoConnectLast, false, bootB, true},     // reboot: always connect
		{AutoConnectRestore, false, bootB, false}, // reboot: was disconnected
		{AutoConnectRestore, true, bootB, true},   // reboot: was connected
		{AutoConnectOff, true, bootB, false},      // reboot: never
		{AutoConnectOff, true, bootA, true},       // crash/restart: restore, fail closed
		{AutoConnectLast, false, bootA, false},    // restart after manual disconnect
	}
	for _, c := range cases {
		dir := setup(t, c.mode, c.connected)
		if got := started(t, dir, c.boot); got != c.want {
			t.Errorf("mode=%s connected=%v reboot=%v: connected=%v, want %v", c.mode, c.connected, c.boot() != 1000, got, c.want)
		}
	}
}

func TestAutoConnectValidation(t *testing.T) {
	e := startDaemon(t, t.TempDir())
	if err := e.cl.Call(CmdSetSettings, Settings{AutoConnect: "sometimes"}, nil); err == nil {
		t.Fatal("unknown mode must be rejected")
	}
	var s Settings
	e.cl.Call(CmdGetSettings, nil, &s)
	if s.AutoConnectMode() != AutoConnectLast {
		t.Fatalf("default %q", s.AutoConnectMode())
	}
}

func TestFailoverToNextProfile(t *testing.T) {
	good := testenv.StartAWG(t, testenv.Obfuscation(), [4]byte{1, 2, 3, 4})
	dead := *good.Client
	dead.Peer.Endpoint = "127.0.0.1:9" // nothing answers there
	e := startDaemon(t, t.TempDir())
	var deadEntry, goodEntry ProfileEntry
	if err := e.cl.Call(CmdImport, ImportArgs{Text: profile.FormatAWGConf(&dead)}, &deadEntry); err != nil {
		t.Fatal(err)
	}
	if err := e.cl.Call(CmdImport, ImportArgs{Text: profile.FormatAWGConf(good.Client)}, &goodEntry); err != nil {
		t.Fatal(err)
	}
	name := "good"
	e.cl.Call(CmdUpdateProfile, UpdateProfile{ID: goodEntry.ID, Name: &name}, nil)
	if err := e.cl.Call(CmdSetSettings, Settings{DNSServers: []string{testenv.AWGServerIP.String()}, FailoverAttempts: 1}, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.cl.Call(CmdSelectProfile, IDArgs{ID: deadEntry.ID}, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.cl.Call(CmdConnect, nil, nil); err != nil {
		t.Fatal(err)
	}
	st := e.waitConnected(t)
	if st.Profile == nil || st.Profile.ID != goodEntry.ID {
		t.Fatalf("expected failover to the good profile: %+v", st.Profile)
	}
	if _, ks := e.plat.KillSwitchActive(); !ks {
		t.Fatal("kill switch must stay on")
	}
	var logs []LogLine
	e.cl.Call(CmdLogs, LogsArgs{}, &logs)
	found := false
	for _, l := range logs {
		found = found || strings.Contains(l.Text, "switching to good")
	}
	if !found {
		t.Fatal("failover must be logged")
	}
}

func TestFailoverSettings(t *testing.T) {
	if (Settings{}).Failover() != DefaultFailoverAttempts || (Settings{FailoverAttempts: -1}).Failover() != 0 || (Settings{FailoverAttempts: 3}).Failover() != 3 {
		t.Fatal("Failover()")
	}
}
