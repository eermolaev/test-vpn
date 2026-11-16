package xray

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/eermolaev/test-vpn/core/errclass"
	"github.com/eermolaev/test-vpn/core/profile"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet/tls"

	_ "github.com/xtls/xray-core/proxy/hysteria"
	_ "github.com/xtls/xray-core/transport/internet/finalmask/salamander"
	_ "github.com/xtls/xray-core/transport/internet/hysteria"
)

// BuildHysteriaConfig renders the xray JSON config for a Hysteria 2 server.
func BuildHysteriaConfig(c *profile.HysteriaConfig) ([]byte, error) {
	// Hysteria 2 servers accept only HTTP/3; xray does not set the ALPN.
	tlsSettings := map[string]any{"alpn": []string{"h3"}}
	if c.SNI != "" {
		tlsSettings["serverName"] = c.SNI
	}
	if c.PinSHA256 != "" {
		tlsSettings["pinnedPeerCertSha256"] = c.PinSHA256
	}
	stream := map[string]any{
		"network":          "hysteria",
		"security":         "tls",
		"tlsSettings":      tlsSettings,
		"hysteriaSettings": map[string]any{"version": 2, "auth": c.Auth},
	}
	mask := map[string]any{}
	if c.ObfsPassword != "" {
		mask["udp"] = []any{map[string]any{"type": "salamander", "settings": map[string]any{"password": c.ObfsPassword}}}
	}
	if c.Ports != "" {
		mask["quicParams"] = map[string]any{"udpHop": map[string]any{"ports": c.Ports}}
	}
	if len(mask) > 0 {
		stream["finalmask"] = mask
	}
	return withOutbound(map[string]any{
		"tag":            "proxy",
		"protocol":       "hysteria",
		"settings":       map[string]any{"version": 2, "address": c.Address, "port": c.Port},
		"streamSettings": stream,
	})
}

// StartHysteria starts xray-core with a Hysteria 2 outbound. Like VLESS, the
// QUIC connection is made on the first dial; the health check verifies it.
func StartHysteria(c *profile.HysteriaConfig, logf func(string)) (*Engine, error) {
	js, err := BuildHysteriaConfig(c)
	if err != nil {
		return nil, err
	}
	var patch func(*core.Config) error
	if !c.Verified() {
		// xray dropped allowInsecure from its JSON config, but the TLS
		// settings still honour it.
		patch = allowInsecure
		if logf != nil {
			logf("hysteria2: the server certificate is not checked (insecure=1); add pinSHA256 to the link to pin it")
		}
	}
	evictHysteriaClient(net.JoinHostPort(c.Address, strconv.Itoa(c.Port)))
	e, err := startPatched(js, profile.KindHysteria2, logf, patch)
	if err != nil {
		return nil, err
	}
	e.hy = c
	return e, nil
}

// allowInsecure turns off certificate checks in the outbound TLS settings.
func allowInsecure(pb *core.Config) error {
	for _, ob := range pb.Outbound {
		inst, err := ob.SenderSettings.GetInstance()
		if err != nil {
			return err
		}
		sender, ok := inst.(*proxyman.SenderConfig)
		if !ok || sender.StreamSettings == nil {
			continue
		}
		for i, tm := range sender.StreamSettings.SecuritySettings {
			v, err := tm.GetInstance()
			if err != nil {
				return err
			}
			if tc, ok := v.(*tls.Config); ok {
				tc.AllowInsecure = true
				sender.StreamSettings.SecuritySettings[i] = serial.ToTypedMessage(tc)
			}
		}
		ob.SenderSettings = serial.ToTypedMessage(sender)
	}
	return nil
}

// diagnoseHysteria explains a failed health check: QUIC gives no cheap way
// to tell the stages apart, so the likely causes are named.
func diagnoseHysteria(_ context.Context, c *profile.HysteriaConfig) error {
	addr := net.JoinHostPort(c.Address, strconv.Itoa(c.Port))
	return errclass.Wrap(errclass.UDPTimeout, fmt.Errorf("nothing passes through the Hysteria 2 server %s: UDP may be filtered or slowed on this network, or the password, obfs password or certificate do not match", addr))
}
