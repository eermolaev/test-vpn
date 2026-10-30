package testenv

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/eermolaev/test-vpn/core/profile"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	_ "github.com/xtls/xray-core/proxy/http"
	_ "github.com/xtls/xray-core/proxy/shadowsocks"
	_ "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	_ "github.com/xtls/xray-core/proxy/socks"
)

// ProxyServers are in-process SOCKS5, HTTP and Shadowsocks servers whose
// freedom outbound reaches loopback services.
type ProxyServers struct {
	SOCKS, HTTP, SS, SS2022 *profile.ProxyConfig
}

// StartProxies starts the proxy servers with password authentication.
func StartProxies(t testing.TB) *ProxyServers {
	t.Helper()
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	s := &ProxyServers{
		SOCKS:  &profile.ProxyConfig{Protocol: profile.ProxySOCKS, Address: "127.0.0.1", Port: freePort(t), Username: "alice", Password: "socks-pw"},
		HTTP:   &profile.ProxyConfig{Protocol: profile.ProxyHTTP, Address: "127.0.0.1", Port: freePort(t), Username: "bob", Password: "http-pw"},
		SS:     &profile.ProxyConfig{Protocol: profile.ProxyShadowsocks, Address: "127.0.0.1", Port: freePort(t), Method: "aes-256-gcm", Password: "ss-pw"},
		SS2022: &profile.ProxyConfig{Protocol: profile.ProxyShadowsocks, Address: "127.0.0.1", Port: freePort(t), Method: "2022-blake3-aes-256-gcm", Password: key},
	}
	in := func(c *profile.ProxyConfig, protocol string, settings map[string]any) map[string]any {
		return map[string]any{"listen": "127.0.0.1", "port": c.Port, "protocol": protocol, "settings": settings}
	}
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"inbounds": []any{
			in(s.SOCKS, "socks", map[string]any{"auth": "password", "udp": true, "ip": "127.0.0.1", "accounts": []any{map[string]any{"user": "alice", "pass": "socks-pw"}}}),
			in(s.HTTP, "http", map[string]any{"accounts": []any{map[string]any{"user": "bob", "pass": "http-pw"}}}),
			in(s.SS, "shadowsocks", map[string]any{"method": "aes-256-gcm", "password": "ss-pw", "network": "tcp,udp"}),
			in(s.SS2022, "shadowsocks", map[string]any{"method": "2022-blake3-aes-256-gcm", "password": key, "network": "tcp,udp"}),
		},
		"outbounds": []any{map[string]any{"protocol": "freedom"}},
	}
	js, _ := json.Marshal(cfg)
	var jc conf.Config
	if err := json.Unmarshal(js, &jc); err != nil {
		t.Fatal(err)
	}
	pb, err := jc.Build()
	if err != nil {
		t.Fatal(err)
	}
	inst, err := core.New(pb)
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inst.Close() })
	return s
}
