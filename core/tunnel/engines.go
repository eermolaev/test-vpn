package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/eermolaev/test-vpn/core/engine"
	"github.com/eermolaev/test-vpn/core/engine/awg"
	"github.com/eermolaev/test-vpn/core/engine/openvpn"
	sshengine "github.com/eermolaev/test-vpn/core/engine/ssh"
	"github.com/eermolaev/test-vpn/core/engine/xray"
	"github.com/eermolaev/test-vpn/core/errclass"
	"github.com/eermolaev/test-vpn/core/fallback"
	"github.com/eermolaev/test-vpn/core/profile"
)

// DefaultStarter starts the real engines without persistent memory: SSH
// server keys are then trusted on first use only within the process.
func DefaultStarter(logf func(string)) Starter { return NewStarter(logf, nil) }

// NewStarter starts the real engines; mem keeps SSH server keys seen on
// first use (may be nil).
func NewStarter(logf func(string), mem *fallback.Memory) Starter {
	if mem == nil {
		mem = fallback.NewMemory(nil)
	}
	keys := hostKeys{mem}
	return func(ctx context.Context, t profile.Transport) (engine.Engine, error) {
		switch {
		case t.Policy == profile.PolicyForbidden:
			return nil, errclass.Wrap(errclass.Config, errors.New("transport is forbidden"))
		case t.AWG != nil:
			timeout := 10 * time.Second
			if dl, ok := ctx.Deadline(); ok {
				timeout = time.Until(dl)
			}
			return awg.Start(ctx, t.AWG, awg.Options{HandshakeTimeout: timeout, Logf: logf})
		case t.VLESS != nil:
			// xray connects lazily, so check TCP reachability first: then a
			// later failure points at REALITY/UUID rather than the network.
			if err := tcpReachable(ctx, t.VLESS.Address, t.VLESS.Port); err != nil {
				return nil, err
			}
			return xray.Start(t.VLESS, logf)
		case t.Proxy != nil:
			if err := tcpReachable(ctx, t.Proxy.Address, t.Proxy.Port); err != nil {
				return nil, err
			}
			return xray.StartProxy(t.Proxy, t.Kind, logf)
		case t.OpenVPN != nil:
			return openvpn.Start(ctx, t.OpenVPN, openvpn.Options{Logf: logf})
		case t.Hysteria != nil:
			return xray.StartHysteria(t.Hysteria, logf)
		case t.SSH != nil:
			return sshengine.Start(ctx, t.SSH, sshengine.Options{Logf: logf, HostKeys: keys})
		}
		return nil, errclass.Wrap(errclass.Config, errors.New("empty transport"))
	}
}

// tcpReachable opens and closes a TCP connection to the server.
func tcpReachable(ctx context.Context, host string, port int) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		c := errclass.Classify(err)
		if c != errclass.TCPReset && c != errclass.NoNetwork && c != errclass.DNS {
			c = errclass.TCPTimeout
		}
		return errclass.Wrap(c, fmt.Errorf("server %s is not reachable over TCP: %w", net.JoinHostPort(host, strconv.Itoa(port)), err))
	}
	c.Close()
	return nil
}

// hostKeys stores SSH server keys in the transport memory.
type hostKeys struct{ mem *fallback.Memory }

func (h hostKeys) Get(key string) string       { return h.mem.Preferred(key) }
func (h hostKeys) Set(key, fingerprint string) { h.mem.Remember(key, fingerprint) }
