package testenv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ServeEcho answers each TCP connection's data with prefix+data and each UDP
// datagram likewise.
func ServeEcho(t testing.TB, tl net.Listener, ul net.PacketConn, prefix string) {
	t.Helper()
	if tl != nil {
		go func() {
			for {
				c, err := tl.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					buf := make([]byte, 32<<10)
					for {
						n, err := c.Read(buf)
						if err != nil {
							return
						}
						if _, err := c.Write(append([]byte(prefix), buf[:n]...)); err != nil {
							return
						}
					}
				}()
			}
		}()
	}
	if ul != nil {
		go func() {
			buf := make([]byte, 65535)
			for {
				n, a, err := ul.ReadFrom(buf)
				if err != nil {
					return
				}
				ul.WriteTo(append([]byte(prefix), buf[:n]...), a)
			}
		}()
	}
}

// Echo is a pair of loopback echo servers.
type Echo struct {
	TCP, UDP netip.AddrPort
}

// StartEcho starts loopback echo servers replying with prefix+data.
func StartEcho(t testing.TB, prefix string) Echo {
	t.Helper()
	tl, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ul, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tl.Close(); ul.Close() })
	ServeEcho(t, tl, ul, prefix)
	return Echo{TCP: netip.MustParseAddrPort(tl.Addr().String()), UDP: netip.MustParseAddrPort(ul.LocalAddr().String())}
}

// ServeDNS answers every A query on pc with ip.
func ServeDNS(pc net.PacketConn, ip [4]byte) {
	buf := make([]byte, 1500)
	for {
		n, a, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		var p dnsmessage.Parser
		h, err := p.Start(buf[:n])
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil {
			continue
		}
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true})
		b.StartQuestions()
		b.Question(q)
		b.StartAnswers()
		if q.Type == dnsmessage.TypeA {
			b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 120}, dnsmessage.AResource{A: ip})
		}
		out, _ := b.Finish()
		pc.WriteTo(out, a)
	}
}

// StartDNS starts a loopback DNS server answering A queries with ip.
func StartDNS(t testing.TB, ip [4]byte) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go ServeDNS(pc, ip)
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

// StartTLSSite starts a TLS 1.3 + h2 server that REALITY can borrow
// handshakes from (its "dest"/"target").
func StartTLSSite(t testing.TB, name string) netip.AddrPort {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	l, err := tls.Listen("tcp4", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				if tc, ok := c.(*tls.Conn); ok {
					tc.Handshake()
				}
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
			}()
		}
	}()
	return netip.MustParseAddrPort(l.Addr().String())
}
