package testenv

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
	"github.com/eermolaev/test-vpn/core/profile"
)

// AWG tunnel addresses.
var (
	AWGServerIP = netip.MustParseAddr("10.8.0.1")
	AWGClientIP = netip.MustParseAddr("10.8.0.2")
)

// AWGServer is an in-process AmneziaWG server whose tunnel side runs echo
// services on AWGServerIP:7 (TCP and UDP) and DNS on AWGServerIP:53.
type AWGServer struct {
	Client *profile.AWGConfig // ready-to-use client config
	Port   int
	dev    *device.Device
}

// Obfuscation returns AmneziaWG 2.0 style parameters for tests.
func Obfuscation() profile.AWGConfig {
	return profile.AWGConfig{
		Jc: 3, Jmin: 30, Jmax: 60, S1: 15, S2: 40, S3: 12, S4: 6,
		H1: "100000-100999", H2: "200000-200999", H3: "300000-300999", H4: "400000-400999",
		I1: "<b 0xc6000000><r 16>",
	}
}

// StartAWG starts a server with the given obfuscation parameters.
func StartAWG(t testing.TB, obf profile.AWGConfig, dnsAnswer [4]byte) *AWGServer {
	t.Helper()
	srvPriv, srvPub := X25519()
	cliPriv, cliPub := X25519()
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{AWGServerIP}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	var b strings.Builder
	w := func(k, v string) { b.WriteString(k + "=" + v + "\n") }
	w("private_key", hexKey(srvPriv))
	port := freeUDPPort(t)
	w("listen_port", strconv.Itoa(port))
	for _, kv := range [][2]string{
		{"jc", itoa(obf.Jc)}, {"jmin", itoa(obf.Jmin)}, {"jmax", itoa(obf.Jmax)},
		{"s1", itoa(obf.S1)}, {"s2", itoa(obf.S2)}, {"s3", itoa(obf.S3)}, {"s4", itoa(obf.S4)},
		{"h1", obf.H1}, {"h2", obf.H2}, {"h3", obf.H3}, {"h4", obf.H4}, {"i1", obf.I1},
	} {
		if kv[1] != "" && kv[1] != "0" {
			w(kv[0], kv[1])
		}
	}
	w("public_key", hexKey(cliPub))
	w("allowed_ip", AWGClientIP.String()+"/32")
	if err := dev.IpcSet(b.String()); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)
	tl, err := tnet.ListenTCPAddrPort(netip.AddrPortFrom(AWGServerIP, 7))
	if err != nil {
		t.Fatal(err)
	}
	ul, err := tnet.ListenUDPAddrPort(netip.AddrPortFrom(AWGServerIP, 7))
	if err != nil {
		t.Fatal(err)
	}
	ServeEcho(t, tl, ul, "awg:")
	dl, err := tnet.ListenUDPAddrPort(netip.AddrPortFrom(AWGServerIP, 53))
	if err != nil {
		t.Fatal(err)
	}
	go ServeDNS(dl, dnsAnswer)

	client := obf
	client.PrivateKey = b64(cliPriv)
	client.Addresses = []netip.Prefix{netip.PrefixFrom(AWGClientIP, 32)}
	client.Peer = profile.AWGPeer{
		PublicKey:  b64(srvPub),
		Endpoint:   "127.0.0.1:" + strconv.Itoa(port),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
	}
	return &AWGServer{Client: &client, Port: port, dev: dev}
}

func freeUDPPort(t testing.TB) int {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func hexKey(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 64)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

func itoa(n int) string { return strconv.Itoa(n) }

// Close stops the server (simulates a dead or blocked server).
func (s *AWGServer) Close() { s.dev.Close() }
