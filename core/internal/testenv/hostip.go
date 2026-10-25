package testenv

import (
	"net"
	"net/netip"
	"testing"
)

// HostIP returns a non-loopback IPv4 address of this machine. Flows to it
// leave the client test stack (gVisor does not route 127/8 over a NIC) and
// can be reached by the direct dialer and by the VPN servers.
func HostIP(t testing.TB) netip.Addr {
	t.Helper()
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() && !p.Addr().IsLoopback() {
			return p.Addr()
		}
	}
	t.Skip("no non-loopback IPv4 address")
	return netip.Addr{}
}

// StartEchoOn starts echo servers on ip.
func StartEchoOn(t testing.TB, ip netip.Addr, prefix string) Echo {
	t.Helper()
	tl, err := net.Listen("tcp4", netip.AddrPortFrom(ip, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	ul, err := net.ListenPacket("udp4", netip.AddrPortFrom(ip, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tl.Close(); ul.Close() })
	ServeEcho(t, tl, ul, prefix)
	return Echo{TCP: netip.MustParseAddrPort(tl.Addr().String()), UDP: netip.MustParseAddrPort(ul.LocalAddr().String())}
}

// StartDNSOn starts a DNS server on ip answering A queries with answer.
func StartDNSOn(t testing.TB, ip netip.Addr, answer [4]byte) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp4", netip.AddrPortFrom(ip, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go ServeDNS(pc, answer)
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}
