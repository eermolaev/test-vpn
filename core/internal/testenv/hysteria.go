package testenv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/eermolaev/test-vpn/core/profile"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/hysteria"
	_ "github.com/xtls/xray-core/transport/internet/finalmask/salamander"
	_ "github.com/xtls/xray-core/transport/internet/hysteria"
)

// HysteriaServer is an in-process Hysteria 2 server (xray) with a
// self-signed certificate for SNI "hy.test".
type HysteriaServer struct {
	// Config is a client profile with the certificate pinned.
	Config *profile.HysteriaConfig
	// CertSHA256 is the hex SHA-256 of the server certificate.
	CertSHA256 string
}

// StartHysteria starts the server on 127.0.0.1; obfs enables Salamander.
func StartHysteria(t testing.TB, obfs string) *HysteriaServer {
	t.Helper()
	certPEM, keyPEM, der := selfSigned(t, "hy.test")
	sum := sha256.Sum256(der)
	port := freeUDPPort(t)
	stream := map[string]any{
		"network":  "hysteria",
		"security": "tls",
		"tlsSettings": map[string]any{"alpn": []string{"h3"}, "certificates": []any{map[string]any{
			"certificate": strings.Split(strings.TrimSpace(certPEM), "\n"),
			"key":         strings.Split(strings.TrimSpace(keyPEM), "\n"),
		}}},
		"hysteriaSettings": map[string]any{"version": 2},
	}
	if obfs != "" {
		stream["finalmask"] = map[string]any{"udp": []any{map[string]any{"type": "salamander", "settings": map[string]any{"password": obfs}}}}
	}
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": port, "protocol": "hysteria",
			"settings":       map[string]any{"version": 2, "clients": []any{map[string]any{"auth": "hy-pass"}}},
			"streamSettings": stream,
		}},
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
	return &HysteriaServer{
		Config: &profile.HysteriaConfig{
			Address: "127.0.0.1", Port: port, Auth: "hy-pass", SNI: "hy.test",
			PinSHA256: hex.EncodeToString(sum[:]), ObfsPassword: obfs,
		},
		CertSHA256: hex.EncodeToString(sum[:]),
	}
}

func selfSigned(t testing.TB, name string) (certPEM, keyPEM string, der []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
	return certPEM, keyPEM, der
}
