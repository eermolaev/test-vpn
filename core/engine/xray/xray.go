// Package xray runs xray-core as the VLESS + REALITY engine. Only the
// features needed by the client are linked in, to keep the iOS extension
// within its memory budget (PLAT-002).
package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/eermolaev/test-vpn/core/errclass"
	"github.com/eermolaev/test-vpn/core/profile"
	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/policy"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/http"
	_ "github.com/xtls/xray-core/proxy/shadowsocks"
	_ "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	_ "github.com/xtls/xray-core/proxy/socks"
	_ "github.com/xtls/xray-core/proxy/trojan"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/proxy/vmess/outbound"
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/websocket"
)

// Engine is a running xray-core instance with a single outbound: VLESS or a
// proxy (SOCKS5, HTTP, Shadowsocks).
type Engine struct {
	inst   *core.Instance
	ctx    context.Context
	cancel context.CancelFunc
	name   string
	cfg    *profile.VLESSConfig    // set for VLESS
	proxy  *profile.ProxyConfig    // set for proxies
	hy     *profile.HysteriaConfig // set for Hysteria 2
	once   sync.Once
}

// BuildConfig renders the xray JSON config for a VLESS, VMess or Trojan
// transport.
func BuildConfig(c *profile.VLESSConfig) ([]byte, error) {
	stream := map[string]any{"network": c.Network, "security": c.Security}
	switch c.Security {
	case "reality":
		r := map[string]any{
			"serverName":  c.SNI,
			"fingerprint": c.Fingerprint,
			"publicKey":   c.PublicKey,
			"shortId":     c.ShortID,
			"spiderX":     c.SpiderX,
		}
		if c.Mldsa65Verify != "" {
			r["mldsa65Verify"] = c.Mldsa65Verify
		}
		stream["realitySettings"] = r
	case "tls":
		t := map[string]any{"serverName": c.SNI, "fingerprint": c.Fingerprint}
		if len(c.ALPN) > 0 {
			t["alpn"] = c.ALPN
		}
		stream["tlsSettings"] = t
	case "none":
		// VMess encrypts by itself; VLESS and Trojan would send the
		// traffic and credentials in the clear.
		if c.Proto() != "vmess" {
			return nil, errclass.Wrap(errclass.Config, fmt.Errorf("xray: %s without TLS/REALITY is forbidden", c.Proto()))
		}
	}
	switch c.Network {
	case "xhttp":
		x := map[string]any{"path": c.Path}
		if c.Host != "" {
			x["host"] = c.Host
		}
		if c.Mode != "" {
			x["mode"] = c.Mode
		}
		stream["xhttpSettings"] = x
	case "grpc":
		stream["grpcSettings"] = map[string]any{"serviceName": c.ServiceName}
	case "ws":
		stream["wsSettings"] = map[string]any{"path": c.Path, "host": c.Host}
	}
	var extra []any
	if c.Fragment > 0 && c.Fragment < len(Fragments) {
		stream["sockopt"] = map[string]any{"dialerProxy": "fragment"}
		extra = append(extra, Fragments[c.Fragment].outbound("fragment"))
	}
	var settings map[string]any
	switch c.Proto() {
	case "trojan":
		settings = map[string]any{"servers": []any{map[string]any{
			"address": c.Address, "port": c.Port, "password": c.Password,
		}}}
	default:
		user := map[string]any{"id": c.UUID}
		if c.Proto() == "vmess" {
			user["security"] = c.Cipher
		} else {
			user["encryption"] = "none"
			if c.Flow != "" {
				user["flow"] = c.Flow
			}
		}
		settings = map[string]any{"vnext": []any{map[string]any{
			"address": c.Address, "port": c.Port, "users": []any{user},
		}}}
	}
	out := map[string]any{
		"tag":            "proxy",
		"protocol":       c.Proto(),
		"settings":       settings,
		"streamSettings": stream,
	}
	if c.Mux > 0 {
		// UDP goes over the same connections (XUDP); QUIC to port 443
		// keeps its own connection, as browsers expect.
		out["mux"] = map[string]any{
			"enabled": true, "concurrency": c.Mux,
			"xudpConcurrency": c.Mux, "xudpProxyUDP443": "skip",
		}
	}
	return withOutbound(out, extra...)
}

// BuildProxyConfig renders the xray JSON config for a SOCKS5, HTTP(S) or
// Shadowsocks server.
func BuildProxyConfig(c *profile.ProxyConfig) ([]byte, error) {
	out := map[string]any{"tag": "proxy"}
	settings := map[string]any{"address": c.Address, "port": c.Port}
	switch c.Protocol {
	case profile.ProxySOCKS, profile.ProxyHTTP:
		out["protocol"] = string(c.Protocol)
		if c.Username != "" {
			settings["user"], settings["pass"] = c.Username, c.Password
		}
		if c.TLS {
			sni := c.SNI
			if sni == "" {
				sni = c.Address
			}
			out["streamSettings"] = map[string]any{"network": "raw", "security": "tls", "tlsSettings": map[string]any{"serverName": sni, "fingerprint": profile.DefaultFingerprint}}
		}
	case profile.ProxyShadowsocks:
		out["protocol"] = "shadowsocks"
		settings["method"], settings["password"] = c.Method, c.Password
	default:
		return nil, errclass.Wrap(errclass.Config, fmt.Errorf("xray: proxy protocol %q", c.Protocol))
	}
	out["settings"] = settings
	return withOutbound(out)
}

func withOutbound(out map[string]any, extra ...any) ([]byte, error) {
	return json.Marshal(map[string]any{
		"log": map[string]any{"loglevel": "warning", "access": "none"},
		"policy": map[string]any{
			"levels": map[string]any{"0": map[string]any{"handshake": 8, "connIdle": 300, "uplinkOnly": 2, "downlinkOnly": 5, "bufferSize": 16}},
		},
		"outbounds": append([]any{out}, extra...),
	})
}

// Start starts xray-core for the transport. The VLESS connection itself is
// established lazily on the first dial; the tunnel health check verifies it.
func Start(c *profile.VLESSConfig, logf func(string)) (*Engine, error) {
	js, err := BuildConfig(c)
	if err != nil {
		return nil, err
	}
	name := profile.KindVLESSReality
	switch {
	case c.Proto() == "vmess":
		name = profile.KindVMess
	case c.Proto() == "trojan":
		name = profile.KindTrojan
	case c.Security == "tls":
		name = profile.KindVLESSTLS
	}
	e, err := start(js, name, logf)
	if err != nil {
		return nil, err
	}
	e.cfg = c
	return e, nil
}

// StartProxy starts xray-core with a SOCKS5, HTTP(S) or Shadowsocks outbound.
func StartProxy(c *profile.ProxyConfig, kind profile.Kind, logf func(string)) (*Engine, error) {
	js, err := BuildProxyConfig(c)
	if err != nil {
		return nil, err
	}
	e, err := start(js, kind, logf)
	if err != nil {
		return nil, err
	}
	e.proxy = c
	return e, nil
}

func start(js []byte, kind profile.Kind, logf func(string)) (*Engine, error) {
	return startPatched(js, kind, logf, nil)
}

// startPatched starts xray-core; patch, if set, adjusts the built config.
func startPatched(js []byte, kind profile.Kind, logf func(string), patch func(*core.Config) error) (*Engine, error) {
	var jc conf.Config
	if err := json.Unmarshal(js, &jc); err != nil {
		return nil, errclass.Wrap(errclass.Config, err)
	}
	pb, err := jc.Build()
	if err != nil {
		return nil, errclass.Wrap(errclass.Config, fmt.Errorf("xray config: %w", err))
	}
	if patch != nil {
		if err := patch(pb); err != nil {
			return nil, errclass.Wrap(errclass.Config, fmt.Errorf("xray config: %w", err))
		}
	}
	if logf != nil {
		log.RegisterHandler(logHandler(logf))
	}
	inst, err := core.New(pb)
	if err != nil {
		return nil, errclass.Wrap(errclass.Config, fmt.Errorf("xray: %w", err))
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		return nil, errclass.Wrap(errclass.Config, fmt.Errorf("xray start: %w", err))
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Engine{inst: inst, ctx: ctx, cancel: cancel, name: string(kind)}, nil
}

type logHandler func(string)

// Handle forwards errors and warnings, plus informational messages about
// failures (dial errors are logged at info level). Debug output and the
// per-connection chatter are dropped.
func (h logHandler) Handle(msg log.Message) {
	text := msg.String()
	if gm, ok := msg.(*log.GeneralMessage); ok {
		switch {
		case gm.Severity == log.Severity_Debug:
			return
		case gm.Severity == log.Severity_Info:
			l := strings.ToLower(text)
			if !strings.Contains(l, "fail") && !strings.Contains(l, "error") && !strings.Contains(l, "reality") {
				return
			}
		}
	}
	h("xray: " + text)
}

func dest(network xnet.Network, dst netip.AddrPort) xnet.Destination {
	return xnet.Destination{
		Network: network,
		Address: xnet.IPAddress(dst.Addr().Unmap().AsSlice()),
		Port:    xnet.Port(dst.Port()),
	}
}

// conn cancels the per-connection context when closed. xray ties the
// lifetime of a dispatched link to its context, so the dial context of the
// caller (which has a timeout) cannot be used.
type conn struct {
	net.Conn
	cancel context.CancelFunc
	addr   net.Addr
}

func (c *conn) Close() error {
	err := c.Conn.Close()
	c.cancel()
	return err
}

func (c *conn) RemoteAddr() net.Addr { return c.addr }

func (e *Engine) dial(network xnet.Network, dst netip.AddrPort) (net.Conn, error) {
	ctx, cancel := context.WithCancel(e.ctx)
	c, err := core.Dial(ctx, e.inst, dest(network, dst))
	if err != nil {
		cancel()
		return nil, err
	}
	var addr net.Addr
	if network == xnet.Network_TCP {
		addr = net.TCPAddrFromAddrPort(dst)
	} else {
		addr = net.UDPAddrFromAddrPort(dst)
	}
	return &conn{Conn: c, cancel: cancel, addr: addr}, nil
}

// DialTCP opens a TCP stream through the VLESS server.
func (e *Engine) DialTCP(_ context.Context, dst netip.AddrPort) (net.Conn, error) {
	return e.dial(xnet.Network_TCP, dst)
}

// DialUDP opens a UDP association through the VLESS server (XUDP).
func (e *Engine) DialUDP(_ context.Context, dst netip.AddrPort) (net.Conn, error) {
	return e.dial(xnet.Network_UDP, dst)
}

func (e *Engine) Name() string { return e.name }

// NativeUDP is true for Hysteria 2, which carries UDP as QUIC datagrams.
func (e *Engine) NativeUDP() bool { return e.hy != nil }

// Close stops xray-core and all connections.
func (e *Engine) Close() error {
	var err error
	e.once.Do(func() {
		e.cancel()
		err = e.inst.Close()
	})
	return err
}

// Diagnose checks the server stage by stage (see the package function).
// For proxies only the TCP connection is checked.
func (e *Engine) Diagnose(ctx context.Context, dns netip.AddrPort) error {
	if e.proxy != nil {
		return diagnoseProxy(ctx, e.proxy)
	}
	if e.hy != nil {
		return diagnoseHysteria(ctx, e.hy)
	}
	return Diagnose(ctx, e.cfg, dns)
}
