package tunnel

import (
	"context"
	"errors"
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
			return xray.Start(t.VLESS, logf)
		}
		return nil, errclass.Wrap(errclass.Config, errors.New("empty transport"))
	}
}
