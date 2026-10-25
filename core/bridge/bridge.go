// Package vpncore is the API exposed to Swift through gomobile. All complex
// values cross the boundary as JSON strings.
package vpncore

import (
	"context"
	"encoding/json"
	"errors"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/eermolaev/test-vpn/core/direct"
	"github.com/eermolaev/test-vpn/core/egress"

	"github.com/eermolaev/test-vpn/core/errclass"
	"github.com/eermolaev/test-vpn/core/fallback"
	"github.com/eermolaev/test-vpn/core/netstack"
	"github.com/eermolaev/test-vpn/core/profile"
	"github.com/eermolaev/test-vpn/core/rules"
	"github.com/eermolaev/test-vpn/core/tunnel"
)

// Version of the core.
const Version = "0.1.0"

// StatusListener receives status updates as JSON (tunnel.Status).
type StatusListener interface {
	OnStatus(statusJSON string)
}

// Logger receives redacted log lines.
type Logger interface {
	Log(line string)
}

// Store persists small values (per-network transport memory) in the App Group.
type Store interface {
	Load(key string) string
	Save(key, value string)
}

// PacketWriter receives packets from the core in callback mode; Swift writes
// them to NEPacketTunnelFlow.
type PacketWriter interface {
	WritePacket(packet []byte)
}

// Tunnel is a running tunnel.
type Tunnel struct {
	t  *tunnel.Tunnel
	cb *callbackIO
}

const memoryKey = "transport-memory"

type storeAdapter struct{ s Store }

func (a storeAdapter) Load() map[string]string {
	m := map[string]string{}
	if a.s != nil {
		_ = json.Unmarshal([]byte(a.s.Load(memoryKey)), &m)
	}
	return m
}

func (a storeAdapter) Save(m map[string]string) {
	if a.s != nil {
		b, _ := json.Marshal(m)
		a.s.Save(memoryKey, string(b))
	}
}

func deps(listener StatusListener, logger Logger, store Store) tunnel.Deps {
	d := tunnel.Deps{Memory: fallback.NewMemory(storeAdapter{store})}
	if listener != nil {
		d.OnStatus = func(s tunnel.Status) { listener.OnStatus(s.JSON()) }
	}
	if logger != nil {
		d.Logf = logger.Log
	}
	return d
}

func parseConfig(configJSON string) (tunnel.Config, error) {
	var cfg tunnel.Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return cfg, errclass.Wrap(errclass.Config, err)
	}
	return cfg, nil
}

// StartWithFD starts the tunnel on a utun file descriptor (Darwin).
func StartWithFD(configJSON string, fd int32, listener StatusListener, logger Logger, store Store) (*Tunnel, error) {
	cfg, err := parseConfig(configJSON)
	if err != nil {
		return nil, err
	}
	pio, err := utunIO(int(fd), cfg.MTU)
	if err != nil {
		return nil, err
	}
	t, err := tunnel.Start(pio, cfg, deps(listener, logger, store))
	if err != nil {
		pio.Close()
		return nil, err
	}
	return &Tunnel{t: t}, nil
}

// StartWithCallbacks starts the tunnel in callback mode: Swift passes packets
// read from NEPacketTunnelFlow to InputPacket and writes packets it receives
// through writer.
func StartWithCallbacks(configJSON string, writer PacketWriter, listener StatusListener, logger Logger, store Store) (*Tunnel, error) {
	if writer == nil {
		return nil, errors.New("vpncore: nil packet writer")
	}
	cfg, err := parseConfig(configJSON)
	if err != nil {
		return nil, err
	}
	cb := newCallbackIO(writer)
	t, err := tunnel.Start(cb, cfg, deps(listener, logger, store))
	if err != nil {
		cb.Close()
		return nil, err
	}
	return &Tunnel{t: t, cb: cb}, nil
}

// InputPacket passes one packet from the OS to the core (callback mode).
func (t *Tunnel) InputPacket(packet []byte) {
	if t.cb != nil {
		t.cb.input(packet)
	}
}

// UpdateSettings applies settings JSON (tunnel.Settings) without reconnecting.
func (t *Tunnel) UpdateSettings(settingsJSON string) error {
	var s tunnel.Settings
	if err := json.Unmarshal([]byte(settingsJSON), &s); err != nil {
		return err
	}
	return t.t.UpdateSettings(s)
}

// NetworkChanged reports a new physical network.
func (t *Tunnel) NetworkChanged(networkID string, interfaceIndex int32, interfaceName string) {
	t.t.NetworkChanged(networkID, int(interfaceIndex), interfaceName)
}

// Reconnect re-checks the tunnel and retries after a failure.
func (t *Tunnel) Reconnect() { t.t.Reconnect() }

// Status returns the current status JSON.
func (t *Tunnel) Status() string { return t.t.Status().JSON() }

// Stop disconnects.
func (t *Tunnel) Stop() {
	t.t.Stop()
	if t.cb != nil {
		t.cb.Close()
	}
}

// ParseProfile parses a pasted link, file contents or decoded QR code and
// returns the profile JSON (with secrets: store it in the Keychain).
func ParseProfile(input string) (string, error) {
	p, err := profile.Parse(input)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(p)
	return string(b), err
}

func loadProfile(profileJSON string) (*profile.Profile, error) {
	var p profile.Profile
	if err := json.Unmarshal([]byte(profileJSON), &p); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// SummarizeProfile returns a secret-free summary JSON for the UI.
func SummarizeProfile(profileJSON string) (string, error) {
	p, err := loadProfile(profileJSON)
	if err != nil {
		return "", err
	}
	return p.Summarize().JSON(), nil
}

// MergeProfiles adds the transports of b to a (SEC-NET-001).
func MergeProfiles(aJSON, bJSON string) (string, error) {
	a, err := loadProfile(aJSON)
	if err != nil {
		return "", err
	}
	b, err := loadProfile(bJSON)
	if err != nil {
		return "", err
	}
	a.Merge(b)
	out, err := json.Marshal(a)
	return string(out), err
}

type lineErr struct {
	Line  int    `json:"line"`
	Text  string `json:"text"`
	Error string `json:"error"`
}

// ValidateExclusions checks an exclusion list (one rule per line) and
// returns JSON {"rules": n, "normalized": "...", "errors": [...]}.
func ValidateExclusions(text string) string {
	set, errs := rules.ParseList(text)
	out := struct {
		Rules      int       `json:"rules"`
		Normalized string    `json:"normalized"`
		Errors     []lineErr `json:"errors"`
	}{Errors: []lineErr{}}
	for _, e := range errs {
		out.Errors = append(out.Errors, lineErr{Line: e.Line, Text: e.Text, Error: e.Err.Error()})
	}
	if set != nil {
		out.Rules = set.Len()
		out.Normalized = set.Export()
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// ProtectedHosts returns the hosts that always go through the tunnel, one per
// line (SPLIT-005).
func ProtectedHosts() string { return strings.Join(rules.ProtectedHosts(), "\n") }

// ErrorClass returns the error class code of err (SEC-NET-004).
func ErrorClass(err error) string { return string(errclass.Classify(err)) }

// ErrorMessage returns the user-facing message for an error class code.
func ErrorMessage(class string) string { return errclass.Class(class).Message() }

// SetMemoryLimit sets the Go soft memory limit (PLAT-002).
func SetMemoryLimit(bytes int64) { debug.SetMemoryLimit(bytes) }

// FreeMemory returns memory to the OS (call on memory warnings).
func FreeMemory() { debug.FreeOSMemory() }

// callbackIO adapts gomobile callbacks to netstack.PacketIO.
type callbackIO struct {
	w      PacketWriter
	in     chan []byte
	closed chan struct{}
	once   sync.Once
}

var _ netstack.PacketIO = (*callbackIO)(nil)

func newCallbackIO(w PacketWriter) *callbackIO {
	return &callbackIO{w: w, in: make(chan []byte, 1024), closed: make(chan struct{})}
}

func (c *callbackIO) input(p []byte) {
	cp := append([]byte(nil), p...)
	select {
	case c.in <- cp:
	case <-c.closed:
	default: // queue full: drop like an interface would
	}
}

func (c *callbackIO) ReadPacket(p []byte) (int, error) {
	select {
	case pkt := <-c.in:
		return copy(p, pkt), nil
	case <-c.closed:
		return 0, errors.New("closed")
	}
}

func (c *callbackIO) WritePacket(p []byte) error {
	select {
	case <-c.closed:
		return errors.New("closed")
	default:
	}
	c.w.WritePacket(append([]byte(nil), p...))
	return nil
}

func (c *callbackIO) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

// EgressConfig is the JSON accepted by RunEgressCheck.
type egressConfig struct {
	ExpectedCountry string `json:"expectedCountry"`
	GeoIPPath       string `json:"geoipPath"`
	InterfaceIndex  int    `json:"interfaceIndex"`
	InterfaceName   string `json:"interfaceName"`
	TimeZone        string `json:"timeZone"`
	Exclusions      int    `json:"exclusions"`
}

// RunEgressCheck verifies the exit IP, country and leaks (GEO-001…009) and
// returns the result JSON. Call it from the app process while connected.
func RunEgressCheck(configJSON string) (string, error) {
	var cfg egressConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return "", err
	}
	ec := egress.Config{ExpectedCountry: cfg.ExpectedCountry, TimeZone: cfg.TimeZone, Exclusions: cfg.Exclusions}
	if cfg.GeoIPPath != "" {
		g, err := egress.OpenGeoIP(cfg.GeoIPPath)
		if err == nil {
			defer g.Close()
			ec.GeoIP = g
		}
	}
	if cfg.InterfaceIndex != 0 || cfg.InterfaceName != "" {
		d := &direct.Dialer{}
		d.SetInterface(cfg.InterfaceIndex, cfg.InterfaceName)
		ec.BypassClient = egress.BoundClient(d)
	}
	return egress.Check(context.Background(), ec).JSON(), nil
}

// UpdateGeoIP downloads the DB-IP Lite Country database into dir and returns
// the file path (GEO-008).
func UpdateGeoIP(dir string) (string, error) {
	return egress.UpdateGeoIP(context.Background(), nil, "", dir, time.Now())
}
