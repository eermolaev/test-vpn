// Package openvpn runs the openvpn binary as an engine. openvpn opens its own
// utun interface but is told not to touch routes or DNS; the engine reaches
// the tunnel by binding sockets to that interface, so the daemon keeps
// control of routing, the kill switch and exclusions.
package openvpn

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/eermolaev/test-vpn/core/direct"
	"github.com/eermolaev/test-vpn/core/errclass"
	"github.com/eermolaev/test-vpn/core/profile"
)

// Candidates are the usual install locations; the daemon runs under launchd
// with a minimal PATH.
var Candidates = []string{"/opt/homebrew/sbin/openvpn", "/usr/local/sbin/openvpn", "/opt/local/sbin/openvpn", "/usr/sbin/openvpn"}

// ErrNotInstalled means no openvpn binary was found.
var ErrNotInstalled = errors.New("openvpn is not installed (brew install openvpn)")

// Find returns the path of the openvpn binary.
func Find() (string, error) {
	if p, err := exec.LookPath("openvpn"); err == nil {
		return p, nil
	}
	for _, p := range Candidates {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", ErrNotInstalled
}

// Options configure Start.
type Options struct {
	Binary string // default: Find()
	// Dir holds the generated config; default os.TempDir(). The config
	// contains keys, so it is written with mode 0600 into a fresh 0700 dir.
	Dir  string
	Logf func(string)
}

// Engine is a running openvpn process.
type Engine struct {
	cmd    *exec.Cmd
	dir    string
	ifName string
	dial   direct.Dialer
	exited chan struct{}
	once   sync.Once
}

// Args returns the openvpn command line for config file cfg and transport c.
// Options after --config override the file: the daemon owns routes and DNS.
func Args(cfg string, c *profile.OpenVPNConfig) []string {
	proto := "udp4"
	if c.Proto == "tcp" {
		proto = "tcp4-client"
	}
	return []string{
		"--config", cfg,
		"--remote", c.Host, strconv.Itoa(c.Port), proto,
		"--dev", "utun",
		"--route-noexec", "--route-nopull",
		"--script-security", "1",
		"--persist-tun", "--auth-nocache",
		"--connect-retry-max", "1",
		"--verb", "1", "--suppress-timestamps",
	}
}

var (
	reDevice = regexp.MustCompile(`Opened utun device (utun\d+)`)
	reReady  = regexp.MustCompile(`Initialization Sequence Completed`)
)

// classify maps an openvpn log line to an error, or nil for ordinary lines.
func classify(line string) error {
	switch {
	case strings.Contains(line, "AUTH_FAILED"):
		return errclass.Wrap(errclass.Config, errors.New("the server rejected the user name or password"))
	case strings.Contains(line, "Options error"):
		return errclass.Wrap(errclass.Config, errors.New(line))
	case strings.Contains(line, "VERIFY ERROR"), strings.Contains(line, "TLS Error"), strings.Contains(line, "TLS handshake failed"), strings.Contains(line, "OpenSSL: error"):
		return errclass.Wrap(errclass.TLS, errors.New(line))
	case strings.Contains(line, "Connection refused"), strings.Contains(line, "Connection reset"):
		return errclass.Wrap(errclass.TCPReset, errors.New(line))
	}
	return nil
}

// Start runs openvpn and waits until the tunnel is up or ctx ends.
func Start(ctx context.Context, c *profile.OpenVPNConfig, o Options) (*Engine, error) {
	bin := o.Binary
	if bin == "" {
		var err error
		if bin, err = Find(); err != nil {
			return nil, errclass.Wrap(errclass.Config, err)
		}
	}
	if st, err := os.Stat(bin); err == nil && st.Mode()&0o022 != 0 {
		return nil, errclass.Wrap(errclass.Config, fmt.Errorf("%s is writable by other users; refusing to run it as root", bin))
	}
	logf := o.Logf
	if logf == nil {
		logf = func(string) {}
	}
	dir, err := os.MkdirTemp(o.Dir, "openvpn-")
	if err != nil {
		return nil, err
	}
	cfg := filepath.Join(dir, "client.ovpn")
	if err := os.WriteFile(cfg, []byte(c.Config), 0o600); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	cmd := exec.Command(bin, Args(cfg, c)...)
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		os.RemoveAll(dir)
		return nil, errclass.Wrap(errclass.Config, fmt.Errorf("openvpn: %w", err))
	}
	e := &Engine{cmd: cmd, dir: dir, exited: make(chan struct{})}
	go func() {
		cmd.Wait()
		pw.Close()
		close(e.exited)
	}()

	type event struct {
		dev string
		err error
		up  bool
	}
	// The reader keeps draining output for the life of the process (openvpn
	// blocks on a full pipe); events after startup are dropped. events is
	// closed once openvpn has exited and its output is read.
	events := make(chan event, 64)
	go func() {
		defer close(events)
		send := func(ev event) {
			select {
			case events <- ev:
			default:
			}
		}
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			logf("openvpn: " + line)
			switch {
			case reDevice.MatchString(line):
				send(event{dev: reDevice.FindStringSubmatch(line)[1]})
			case reReady.MatchString(line):
				send(event{up: true})
			default:
				if err := classify(line); err != nil {
					send(event{err: err})
				}
			}
		}
		io.Copy(io.Discard, pr)
	}()

	var lastErr error
	for {
		select {
		case ev, ok := <-events:
			switch {
			case !ok:
				if lastErr == nil {
					<-e.exited
					lastErr = fmt.Errorf("openvpn exited: %v", cmd.ProcessState)
				}
				e.Close()
				return nil, lastErr
			case ev.dev != "":
				e.ifName = ev.dev
			case ev.err != nil:
				lastErr = ev.err
				if errclass.Classify(ev.err) == errclass.Config {
					e.Close()
					return nil, ev.err
				}
			case ev.up:
				if e.ifName == "" {
					e.Close()
					return nil, errors.New("openvpn: tunnel is up, but its interface name was not reported")
				}
				ifc, err := net.InterfaceByName(e.ifName)
				if err != nil {
					e.Close()
					return nil, fmt.Errorf("openvpn: %w", err)
				}
				e.dial.SetInterface(ifc.Index, ifc.Name)
				return e, nil
			}
		case <-ctx.Done():
			e.Close()
			if lastErr != nil {
				return nil, fmt.Errorf("%w (%w)", lastErr, ctx.Err())
			}
			return nil, fmt.Errorf("openvpn: no connection to the server: %w", ctx.Err())
		}
	}
}

// Interface is the utun interface opened by openvpn.
func (e *Engine) Interface() string { return e.ifName }

// DialTCP connects to dst through the OpenVPN tunnel.
func (e *Engine) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return e.dial.DialTCP(ctx, dst)
}

// DialUDP opens a UDP socket through the OpenVPN tunnel.
func (e *Engine) DialUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return e.dial.DialUDP(ctx, dst)
}

func (e *Engine) Name() string    { return string(profile.KindOpenVPN) }
func (e *Engine) NativeUDP() bool { return true }

// Close stops openvpn (SIGTERM, then SIGKILL after 3 s) and removes its config.
func (e *Engine) Close() error {
	e.once.Do(func() {
		if e.cmd.Process != nil {
			e.cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-e.exited:
			case <-time.After(3 * time.Second):
				e.cmd.Process.Kill()
				<-e.exited
			}
		}
		os.RemoveAll(e.dir)
	})
	return nil
}
