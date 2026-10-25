package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/eermolaev/test-vpn/core/daemon"
	"github.com/eermolaev/test-vpn/core/direct"
	"github.com/eermolaev/test-vpn/core/egress"
	"github.com/eermolaev/test-vpn/core/flowrouter"
	"github.com/eermolaev/test-vpn/core/ipc"
)

// Backend is what the TUI needs from the daemon (and from the local process
// for the exit check).
type Backend interface {
	Status() (daemon.Status, error)
	Flows(limit int) ([]flowrouter.FlowInfo, error)
	Logs(after uint64) ([]daemon.LogLine, error)
	Profiles() ([]daemon.ProfileEntry, error)
	Import(text, into string) (daemon.ProfileEntry, error)
	UpdateProfile(daemon.UpdateProfile) error
	DeleteProfile(id string) error
	SelectProfile(id string) error
	Connect() error
	Disconnect() error
	Reconnect() error
	Settings() (daemon.Settings, error)
	SetSettings(daemon.Settings) error
	// Check verifies the exit from this (unprivileged) process, so that the
	// kill switch is tested as any other app would experience it.
	Check(ctx context.Context, st daemon.Status, exclusions int) egress.Result
}

// IPCBackend talks to the daemon over its socket.
type IPCBackend struct {
	C        *ipc.Client
	GeoIPDir string // per-user directory for the GeoIP database
}

func (b *IPCBackend) Status() (s daemon.Status, err error) {
	err = b.C.Call(daemon.CmdStatus, nil, &s)
	return
}

func (b *IPCBackend) Flows(limit int) ([]flowrouter.FlowInfo, error) {
	var fl daemon.FlowList
	err := b.C.Call(daemon.CmdFlows, daemon.FlowsArgs{Limit: limit}, &fl)
	return fl.Flows, err
}

func (b *IPCBackend) Logs(after uint64) (l []daemon.LogLine, err error) {
	err = b.C.Call(daemon.CmdLogs, daemon.LogsArgs{After: after}, &l)
	return
}

func (b *IPCBackend) Profiles() (p []daemon.ProfileEntry, err error) {
	err = b.C.Call(daemon.CmdProfiles, nil, &p)
	return
}

func (b *IPCBackend) Import(text, into string) (p daemon.ProfileEntry, err error) {
	err = b.C.Call(daemon.CmdImport, daemon.ImportArgs{Text: text, Into: into}, &p)
	return
}

func (b *IPCBackend) UpdateProfile(u daemon.UpdateProfile) error {
	return b.C.Call(daemon.CmdUpdateProfile, u, nil)
}
func (b *IPCBackend) DeleteProfile(id string) error {
	return b.C.Call(daemon.CmdDeleteProfile, daemon.IDArgs{ID: id}, nil)
}
func (b *IPCBackend) SelectProfile(id string) error {
	return b.C.Call(daemon.CmdSelectProfile, daemon.IDArgs{ID: id}, nil)
}
func (b *IPCBackend) Connect() error    { return b.C.Call(daemon.CmdConnect, nil, nil) }
func (b *IPCBackend) Disconnect() error { return b.C.Call(daemon.CmdDisconnect, nil, nil) }
func (b *IPCBackend) Reconnect() error  { return b.C.Call(daemon.CmdReconnect, nil, nil) }

func (b *IPCBackend) Settings() (s daemon.Settings, err error) {
	err = b.C.Call(daemon.CmdGetSettings, nil, &s)
	return
}
func (b *IPCBackend) SetSettings(s daemon.Settings) error {
	return b.C.Call(daemon.CmdSetSettings, s, nil)
}

func (b *IPCBackend) Check(ctx context.Context, st daemon.Status, exclusions int) egress.Result {
	cfg := egress.Config{Exclusions: exclusions, TimeZone: LocalTimeZone()}
	if st.Profile != nil {
		cfg.ExpectedCountry = st.Profile.ExpectedCountry
	}
	if b.GeoIPDir != "" {
		os.MkdirAll(b.GeoIPDir, 0o755)
		path := filepath.Join(b.GeoIPDir, egress.GeoIPFileName)
		if fi, err := os.Stat(path); err != nil || time.Since(fi.ModTime()) > 31*24*time.Hour {
			egress.UpdateGeoIP(ctx, nil, "", b.GeoIPDir, time.Now())
		}
		if g, err := egress.OpenGeoIP(path); err == nil {
			defer g.Close()
			cfg.GeoIP = g
		}
	}
	if st.Route.Index != 0 {
		d := &direct.Dialer{}
		d.SetInterface(st.Route.Index, st.Route.Interface)
		cfg.BypassClient = egress.BoundClient(d)
	}
	return egress.Check(ctx, cfg)
}

// LocalTimeZone returns the IANA name of the system time zone.
func LocalTimeZone() string {
	if tz := os.Getenv("TZ"); tz != "" {
		return tz
	}
	if p, err := os.Readlink("/etc/localtime"); err == nil {
		if i := strings.Index(p, "zoneinfo/"); i >= 0 {
			return p[i+len("zoneinfo/"):]
		}
	}
	return ""
}
