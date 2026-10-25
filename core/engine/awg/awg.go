// Package awg runs amneziawg-go as the AmneziaWG engine. The device works in
// netstack mode: flows are dialed through a userspace stack, so the router can
// send some flows directly (spec 6.2).
package awg

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/eermolaev/test-vpn/core/errclass"
	"github.com/eermolaev/test-vpn/core/profile"
)

// DefaultMTU is used when the profile has none: the WireGuard default,
// minus AmneziaWG transport padding (S4) so packets still fit in 1500.
const DefaultMTU = 1420

// Options configure the engine.
type Options struct {
	// Resolve resolves the endpoint host. It must not go through the tunnel.
	Resolve func(ctx context.Context, host string) (netip.Addr, error)
	// HandshakeTimeout is T_fail for the first handshake (SEC-NET-002).
	HandshakeTimeout time.Duration
	// Bind overrides the UDP transport (tests).
	Bind conn.Bind
	Logf func(string)
}

// Engine is a running AmneziaWG device.
type Engine struct {
	dev  *device.Device
	tnet *netstack.Net
	once sync.Once
}

func keyHex(b64 string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) != 32 {
		return "", errors.New("bad key")
	}
	return hex.EncodeToString(b), nil
}

// UAPI renders the device configuration in the UAPI text format.
func UAPI(c *profile.AWGConfig, endpoint netip.AddrPort) (string, error) {
	priv, err := keyHex(c.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	pub, err := keyHex(c.Peer.PublicKey)
	if err != nil {
		return "", fmt.Errorf("public key: %w", err)
	}
	var b strings.Builder
	kv := func(k, v string) { b.WriteString(k + "=" + v + "\n") }
	kvi := func(k string, v int) {
		if v != 0 {
			kv(k, strconv.Itoa(v))
		}
	}
	kv("private_key", priv)
	kvi("jc", c.Jc)
	kvi("jmin", c.Jmin)
	kvi("jmax", c.Jmax)
	kvi("s1", c.S1)
	kvi("s2", c.S2)
	kvi("s3", c.S3)
	kvi("s4", c.S4)
	for _, h := range [][2]string{{"h1", c.H1}, {"h2", c.H2}, {"h3", c.H3}, {"h4", c.H4}, {"i1", c.I1}, {"i2", c.I2}, {"i3", c.I3}, {"i4", c.I4}, {"i5", c.I5}} {
		if h[1] != "" {
			kv(h[0], h[1])
		}
	}
	if c.HeaderProtectionKey != "" {
		hp, err := keyHex(c.HeaderProtectionKey)
		if err != nil {
			return "", fmt.Errorf("header protection key: %w", err)
		}
		kv("header_protection_key", hp)
	}
	for _, r := range [][2]string{
		{"content_padding_addition", c.ContentPaddingAddition}, {"rekey_after_time", c.RekeyAfterTime},
		{"rekey_timeout", c.RekeyTimeout}, {"reject_after_time", c.RejectAfterTime},
		{"keepalive_timeout", c.KeepaliveTimeout}, {"max_handshake_attempts", c.MaxHandshakeAttempts},
	} {
		if r[1] != "" {
			kv(r[0], r[1])
		}
	}
	if c.RandomTrailers {
		kv("random_trailers", "true")
	}
	if c.DisableCookies {
		kv("disable_cookies", "true")
	}
	kv("replace_peers", "true")
	kv("public_key", pub)
	if c.Peer.PresharedKey != "" {
		psk, err := keyHex(c.Peer.PresharedKey)
		if err != nil {
			return "", fmt.Errorf("preshared key: %w", err)
		}
		kv("preshared_key", psk)
	}
	kv("endpoint", endpoint.String())
	keepalive := c.Peer.Keepalive
	if keepalive == 0 {
		keepalive = 25 // keeps NAT mappings and lets us notice dead servers
	}
	if c.Peer.KeepaliveRange != "" {
		kv("persistent_keepalive_interval", c.Peer.KeepaliveRange)
	} else {
		kvi("persistent_keepalive_interval", keepalive)
	}
	kv("replace_allowed_ips", "true")
	for _, p := range c.Peer.AllowedIPs {
		if p.Addr().Is4() {
			kv("allowed_ip", p.String())
		}
	}
	return b.String(), nil
}

// Start brings the device up and waits for the first handshake.
func Start(ctx context.Context, c *profile.AWGConfig, opts Options) (*Engine, error) {
	host, portStr, err := net.SplitHostPort(c.Peer.Endpoint)
	if err != nil {
		return nil, errclass.Wrap(errclass.Config, err)
	}
	port, _ := strconv.Atoi(portStr)
	addr, err := netip.ParseAddr(host)
	if err != nil {
		resolve := opts.Resolve
		if resolve == nil {
			resolve = defaultResolve
		}
		addr, err = resolve(ctx, host)
		if err != nil {
			return nil, errclass.Wrap(errclass.DNS, err)
		}
	}
	if !addr.Unmap().Is4() {
		return nil, errclass.Wrap(errclass.Config, errors.New("awg: IPv6 endpoints are not supported"))
	}
	endpoint := netip.AddrPortFrom(addr.Unmap(), uint16(port))

	var local []netip.Addr
	for _, p := range c.Addresses {
		if p.Addr().Is4() {
			local = append(local, p.Addr())
		}
	}
	if len(local) == 0 {
		return nil, errclass.Wrap(errclass.Config, errors.New("awg: no IPv4 interface address"))
	}
	mtu := c.MTU
	if mtu == 0 {
		mtu = max(DefaultMTU-c.S4, 1280)
	}
	tunDev, tnet, err := netstack.CreateNetTUN(local, nil, mtu)
	if err != nil {
		return nil, errclass.Wrap(errclass.Config, err)
	}
	uapi, err := UAPI(c, endpoint)
	if err != nil {
		tunDev.Close()
		return nil, errclass.Wrap(errclass.Config, err)
	}
	bind := opts.Bind
	if bind == nil {
		bind = conn.NewDefaultBind()
	}
	logger := device.NewLogger(device.LogLevelSilent, "")
	if opts.Logf != nil {
		logger = &device.Logger{
			Verbosef: func(string, ...any) {},
			Errorf:   func(f string, a ...any) { opts.Logf("awg: " + fmt.Sprintf(f, a...)) },
		}
	}
	dev := device.NewDevice(tunDev, bind, logger)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, errclass.Wrap(errclass.Config, fmt.Errorf("awg config: %w", err))
	}
	FlushReader(tnet)
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, errclass.Wrap(errclass.NoNetwork, err)
	}
	e := &Engine{dev: dev, tnet: tnet}
	timeout := opts.HandshakeTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	if err := e.waitHandshake(ctx, timeout); err != nil {
		e.Close()
		return nil, err
	}
	return e, nil
}

// FlushReader works around a race in amneziawg-go v3: the device's TUN
// reader loads the transport padding (S4) before it blocks waiting for a
// packet, and the netstack TUN is up before the config is applied. The
// first packet would then go out without padding and the server would drop
// it. One throwaway datagram (to TEST-NET-1, dropped by the server) makes
// the reader loop once and pick up the configured padding.
func FlushReader(tnet *netstack.Net) {
	c, err := tnet.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("192.0.2.1:9"))
	if err != nil {
		return
	}
	c.Write([]byte{0})
	c.Close()
}

func defaultResolve(ctx context.Context, host string) (netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(addrs) == 0 {
		return netip.Addr{}, &net.DNSError{Err: "no IPv4 address", Name: host}
	}
	return addrs[0], nil
}

// LastHandshake returns the time of the latest handshake with the server.
func (e *Engine) LastHandshake() time.Time {
	s, err := e.dev.IpcGet()
	if err != nil {
		return time.Time{}
	}
	var sec, nsec int64
	for _, line := range strings.Split(s, "\n") {
		k, v, _ := strings.Cut(line, "=")
		switch k {
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	if sec == 0 && nsec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, nsec)
}

func (e *Engine) waitHandshake(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// A handshake is only initiated when there is traffic; send a datagram to
	// a discard address inside the tunnel to trigger it.
	if c, err := e.tnet.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("192.0.2.1:9")); err == nil {
		c.Write([]byte{0})
		c.Close()
	}
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
	for {
		if !e.LastHandshake().IsZero() {
			return nil
		}
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.Canceled) {
				return errclass.Wrap(errclass.Canceled, ctx.Err())
			}
			// Either UDP is filtered or the obfuscation parameters differ;
			// the server cannot tell us which (SEC-NET-004).
			return errclass.Wrap(errclass.UDPTimeout, errors.New("awg: no handshake response"))
		case <-t.C:
		}
	}
}

// DialTCP opens a TCP connection through the tunnel.
func (e *Engine) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return e.tnet.DialContextTCPAddrPort(ctx, dst)
}

// DialUDP opens a connected UDP socket through the tunnel.
func (e *Engine) DialUDP(_ context.Context, dst netip.AddrPort) (net.Conn, error) {
	return e.tnet.DialUDPAddrPort(netip.AddrPort{}, dst)
}

func (e *Engine) Name() string    { return string(profile.KindAmneziaWG) }
func (e *Engine) NativeUDP() bool { return true }

// Close shuts the device down.
func (e *Engine) Close() error {
	e.once.Do(func() { e.dev.Close() })
	return nil
}
