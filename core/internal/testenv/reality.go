package testenv

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"testing"

	"github.com/eermolaev/test-vpn/core/profile"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/trojan"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/proxy/vmess/inbound"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/websocket"
)

// RealityServer is an in-process xray server with VLESS + REALITY inbounds
// (RAW + Vision and XHTTP), Trojan + REALITY, and VMess over bare TCP and
// WebSocket. Its freedom outbound reaches loopback services.
type RealityServer struct {
	Vision *profile.VLESSConfig
	// Plain is VLESS over REALITY without flow (mux works there).
	Plain   *profile.VLESSConfig
	XHTTP   *profile.VLESSConfig
	Trojan  *profile.VLESSConfig
	VMess   *profile.VLESSConfig
	VMessWS *profile.VLESSConfig
	inst    *core.Instance
}

const realitySNI = "reality.test"

func freePort(t testing.TB) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// StartReality starts the server.
func StartReality(t testing.TB) *RealityServer {
	t.Helper()
	site := StartTLSSite(t, realitySNI)
	priv, pub := X25519()
	uuid := "b831381d-6324-4d53-ad4f-8cda48b30811"
	sid := hex.EncodeToString([]byte{0xab, 0xcd, 0xef, 0x01})
	visionPort, xhttpPort := freePort(t), freePort(t)
	trojanPort, vmessPort, vmessWSPort := freePort(t), freePort(t), freePort(t)
	plainPort := freePort(t)
	reality := map[string]any{
		"target":      site.String(),
		"serverNames": []string{realitySNI},
		"privateKey":  b64url(priv),
		"shortIds":    []string{sid},
	}
	inbound := func(port int, network, flow string, extra map[string]any) map[string]any {
		client := map[string]any{"id": uuid}
		if flow != "" {
			client["flow"] = flow
		}
		stream := map[string]any{"network": network, "security": "reality", "realitySettings": reality}
		for k, v := range extra {
			stream[k] = v
		}
		return map[string]any{
			"listen":         "127.0.0.1",
			"port":           port,
			"protocol":       "vless",
			"settings":       map[string]any{"clients": []any{client}, "decryption": "none"},
			"streamSettings": stream,
		}
	}
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"inbounds": []any{
			inbound(visionPort, "raw", "xtls-rprx-vision", nil),
			inbound(plainPort, "raw", "", nil),
			inbound(xhttpPort, "xhttp", "", map[string]any{"xhttpSettings": map[string]any{"path": "/x"}}),
			map[string]any{
				"listen": "127.0.0.1", "port": trojanPort, "protocol": "trojan",
				"settings":       map[string]any{"clients": []any{map[string]any{"password": "trojan-pw"}}},
				"streamSettings": map[string]any{"network": "raw", "security": "reality", "realitySettings": reality},
			},
			map[string]any{
				"listen": "127.0.0.1", "port": vmessPort, "protocol": "vmess",
				"settings": map[string]any{"clients": []any{map[string]any{"id": uuid}}},
			},
			map[string]any{
				"listen": "127.0.0.1", "port": vmessWSPort, "protocol": "vmess",
				"settings":       map[string]any{"clients": []any{map[string]any{"id": uuid}}},
				"streamSettings": map[string]any{"network": "ws", "wsSettings": map[string]any{"path": "/vm"}},
			},
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
		t.Fatal(fmt.Errorf("reality server config: %w", err))
	}
	inst, err := core.New(pb)
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inst.Close() })
	base := profile.VLESSConfig{
		Address: "127.0.0.1", UUID: uuid, Security: "reality",
		SNI: realitySNI, Fingerprint: "chrome", PublicKey: b64url(pub), ShortID: sid,
	}
	vision, xh, plain := base, base, base
	plain.Port, plain.Network = plainPort, "raw"
	vision.Port, vision.Network, vision.Flow = visionPort, "raw", "xtls-rprx-vision"
	xh.Port, xh.Network, xh.Path = xhttpPort, "xhttp", "/x"
	trojan := base
	trojan.Protocol, trojan.UUID, trojan.Password, trojan.Port, trojan.Network = "trojan", "", "trojan-pw", trojanPort, "raw"
	vm := profile.VLESSConfig{Protocol: "vmess", Address: "127.0.0.1", Port: vmessPort, UUID: uuid, Cipher: "auto", Network: "raw", Security: "none"}
	vmws := vm
	vmws.Port, vmws.Network, vmws.Path = vmessWSPort, "ws", "/vm"
	return &RealityServer{Vision: &vision, Plain: &plain, XHTTP: &xh, Trojan: &trojan, VMess: &vm, VMessWS: &vmws, inst: inst}
}

// Vision2ID returns the transport ID of the Vision inbound.
func (s *RealityServer) Vision2ID() string {
	t := profile.Transport{VLESS: s.Vision}
	t.Validate()
	return t.ID()
}
