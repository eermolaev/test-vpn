// Package ssh tunnels TCP connections through an SSH server as direct-tcpip
// channels, like "ssh -D". UDP is not carried: DNS falls back to TCP.
package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eermolaev/test-vpn/core/errclass"
	"github.com/eermolaev/test-vpn/core/profile"
	"golang.org/x/crypto/ssh"
)

// HostKeys remembers server keys for trust on first use.
type HostKeys interface {
	Get(key string) string
	Set(key, fingerprint string)
}

// Options configure the engine.
type Options struct {
	Logf     func(string)
	HostKeys HostKeys // nil: an unpinned key is accepted every time
	// KeepAlive is the interval of keepalive requests (default 15 s).
	KeepAlive time.Duration
}

// ErrUDP is returned by DialUDP.
var ErrUDP = errors.New("ssh: UDP is not carried over SSH")

// Engine is a connected SSH client.
type Engine struct {
	client *ssh.Client
	done   chan struct{}
	once   sync.Once
}

// Start connects and authenticates. ctx bounds the connection attempt.
func Start(ctx context.Context, c *profile.SSHConfig, opts Options) (*Engine, error) {
	logf := opts.Logf
	if logf == nil {
		logf = func(string) {}
	}
	auth, err := authMethods(c)
	if err != nil {
		return nil, errclass.Wrap(errclass.Config, err)
	}
	addr := net.JoinHostPort(c.Address, strconv.Itoa(c.Port))
	var keyErr error
	cfg := &ssh.ClientConfig{
		User: c.Username,
		Auth: auth,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			keyErr = checkHostKey(c, addr, key, opts.HostKeys, logf)
			return keyErr
		},
		// OpenSSH order: the key users pin (from known_hosts or
		// ssh_host_ed25519_key.pub) is then the one the server presents.
		HostKeyAlgorithms: []string{
			ssh.KeyAlgoED25519,
			ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
			ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
		},
		ClientVersion: "SSH-2.0-OpenSSH_9.6",
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp4", addr)
	if err != nil {
		return nil, errclass.Wrap(dialClass(err), fmt.Errorf("ssh: connect %s: %w", addr, err))
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	// Closing the connection aborts the handshake when ctx ends first.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	stop()
	if err != nil {
		conn.Close()
		return nil, handshakeError(ctx, err, keyErr)
	}
	conn.SetDeadline(time.Time{})

	e := &Engine{client: ssh.NewClient(sc, chans, reqs), done: make(chan struct{})}
	go func() {
		err := e.client.Wait()
		e.close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			logf("ssh: connection closed: " + err.Error())
		}
	}()
	interval := opts.KeepAlive
	if interval <= 0 {
		interval = 15 * time.Second
	}
	go e.keepAlive(interval, logf)
	return e, nil
}

func authMethods(c *profile.SSHConfig) ([]ssh.AuthMethod, error) {
	var auth []ssh.AuthMethod
	if c.PrivateKey != "" {
		s, err := c.Signer()
		if err != nil {
			return nil, err
		}
		auth = append(auth, ssh.PublicKeys(s))
	} else if c.Password != "" {
		auth = append(auth,
			ssh.Password(c.Password),
			// Servers with PasswordAuthentication off often still ask for
			// the password through keyboard-interactive.
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = c.Password
				}
				return answers, nil
			}),
		)
	}
	if len(auth) == 0 {
		return nil, errors.New("ssh: no credentials")
	}
	return auth, nil
}

func hostKeyID(addr string) string { return "ssh-hostkey|" + addr }

// checkHostKey compares the server key with the pinned fingerprint or, when
// none is pinned, with the one remembered on first use.
func checkHostKey(c *profile.SSHConfig, addr string, key ssh.PublicKey, store HostKeys, logf func(string)) error {
	fp := ssh.FingerprintSHA256(key)
	if c.HostKey != "" {
		if fp != c.HostKey {
			return fmt.Errorf("ssh: server key %s does not match the pinned %s", fp, c.HostKey)
		}
		return nil
	}
	if store == nil {
		logf("ssh: server key " + fp + " is not pinned (add hostkey=" + fp + " to the link)")
		return nil
	}
	switch known := store.Get(hostKeyID(addr)); known {
	case "":
		store.Set(hostKeyID(addr), fp)
		logf("ssh: trusting server key " + fp + " on first use")
		return nil
	case fp:
		return nil
	default:
		return fmt.Errorf("ssh: server key %s differs from the remembered %s", fp, known)
	}
}

func dialClass(err error) errclass.Class {
	c := errclass.Classify(err)
	if c != errclass.TCPReset && c != errclass.NoNetwork && c != errclass.DNS {
		c = errclass.TCPTimeout
	}
	return c
}

func handshakeError(ctx context.Context, err, keyErr error) error {
	switch {
	case keyErr != nil:
		return errclass.Wrap(errclass.HostKey, keyErr)
	case strings.Contains(err.Error(), "unable to authenticate"):
		return errclass.Wrap(errclass.Auth, fmt.Errorf("ssh: the server rejected the login: %w", err))
	case ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || isTimeout(err):
		return errclass.Wrap(errclass.TLSTimeout, fmt.Errorf("ssh: no handshake answer: %w", err))
	}
	return errclass.Wrap(errclass.TCPReset, fmt.Errorf("ssh: handshake: %w", err))
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// keepAlive drops a connection the server no longer answers on, so the
// health check fails fast and the tunnel reconnects.
func (e *Engine) keepAlive(interval time.Duration, logf func(string)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-t.C:
		}
		res := make(chan error, 1)
		go func() {
			_, _, err := e.client.SendRequest("keepalive@openssh.com", true, nil)
			res <- err
		}()
		select {
		case <-e.done:
			return
		case err := <-res:
			if err == nil {
				continue
			}
			logf("ssh: keepalive failed: " + err.Error())
		case <-time.After(2 * interval):
			logf("ssh: the server stopped answering keepalives")
		}
		e.close()
		return
	}
}

// DialTCP opens a direct-tcpip channel to dst.
func (e *Engine) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	select {
	case <-e.done:
		return nil, errclass.Wrap(errclass.ServerClosed, errors.New("ssh: connection closed"))
	default:
	}
	c, err := e.client.DialContext(ctx, "tcp", dst.String())
	if err != nil {
		var oe *ssh.OpenChannelError
		if errors.As(err, &oe) {
			// The server refused the forward: AllowTcpForwarding no, or
			// the destination is unreachable from the server.
			return nil, fmt.Errorf("ssh: server refused %s: %s", dst, oe.Message)
		}
		return nil, err
	}
	return c, nil
}

// DialUDP always fails: SSH has no datagram channels.
func (e *Engine) DialUDP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, ErrUDP
}

func (e *Engine) Name() string    { return string(profile.KindSSH) }
func (e *Engine) NativeUDP() bool { return false }

func (e *Engine) close() {
	e.once.Do(func() {
		close(e.done)
		e.client.Close()
	})
}

// Close disconnects.
func (e *Engine) Close() error {
	e.close()
	return nil
}
