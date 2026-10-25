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
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/websocket"
)

// Engine is a running xray-core instance with a single VLESS outbound.
type Engine struct {
	inst   *core.Instance
	ctx    context.Context
	cancel context.CancelFunc
	name   string
	once   sync.Once
}

// BuildConfig renders the xray JSON config for a VLESS transport.
func BuildConfig(c *profile.VLESSConfig) ([]byte, error) {
	user := map[string]any{"id": c.UUID, "encryption": "none"}
	if c.Flow != "" {
		user["flow"] = c.Flow
	}
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
		return nil, errclass.Wrap(errclass.Config, fmt.Errorf("xray: VLESS without TLS/REALITY is forbidden"))
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
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning", "access": "none"},
		"policy": map[string]any{
			"levels": map[string]any{"0": map[string]any{"handshake": 8, "connIdle": 300, "uplinkOnly": 2, "downlinkOnly": 5, "bufferSize": 16}},
		},
		"outbounds": []any{map[string]any{
			"tag":      "proxy",
			"protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": c.Address,
				"port":    c.Port,
				"users":   []any{user},
			}}},
			"streamSettings": stream,
		}},
	}
	return json.Marshal(cfg)
}

// Start starts xray-core for the transport. The VLESS connection itself is
// established lazily on the first dial; the tunnel health check verifies it.
func Start(c *profile.VLESSConfig, logf func(string)) (*Engine, error) {
	js, err := BuildConfig(c)
	if err != nil {
		return nil, err
	}
	var jc conf.Config
	if err := json.Unmarshal(js, &jc); err != nil {
		return nil, errclass.Wrap(errclass.Config, err)
	}
	pb, err := jc.Build()
	if err != nil {
		return nil, errclass.Wrap(errclass.Config, fmt.Errorf("xray config: %w", err))
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
	name := string(profile.KindVLESSReality)
	if c.Security == "tls" {
		name = string(profile.KindVLESSTLS)
	}
	return &Engine{inst: inst, ctx: ctx, cancel: cancel, name: name}, nil
}

type logHandler func(string)

func (h logHandler) Handle(msg log.Message) { h(msg.String()) }

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

func (e *Engine) Name() string    { return e.name }
func (e *Engine) NativeUDP() bool { return false }

// Close stops xray-core and all connections.
func (e *Engine) Close() error {
	var err error
	e.once.Do(func() {
		e.cancel()
		err = e.inst.Close()
	})
	return err
}
