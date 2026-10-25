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
	"github.com/eermolaev/test-vpn/core/engine/xray"
	"github.com/eermolaev/test-vpn/core/errclass"
	"github.com/eermolaev/test-vpn/core/profile"
)

// DefaultStarter starts the real engines.
func DefaultStarter(logf func(string)) Starter {
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
