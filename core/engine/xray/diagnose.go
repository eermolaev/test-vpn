package xray

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/reality"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/eermolaev/test-vpn/core/errclass"
	"github.com/eermolaev/test-vpn/core/profile"
)

// Diagnose explains why traffic does not pass through a VLESS server by
// repeating the connection one stage at a time, without xray's dispatcher:
// TCP connect, the TLS/REALITY handshake and, for the raw transport, one DNS
// query to dns sent as a bare VLESS UDP request. The error names the first
// stage that failed; nil means every checked stage worked.
func Diagnose(ctx context.Context, c *profile.VLESSConfig, dns netip.AddrPort) error {
	addr := net.JoinHostPort(c.Address, strconv.Itoa(c.Port))
	start := time.Now()
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp4", addr)
	if err != nil {
		cl := errclass.Classify(err)
		if cl != errclass.TCPReset && cl != errclass.NoNetwork && cl != errclass.DNS {
			cl = errclass.TCPTimeout
		}
		return errclass.Wrap(cl, fmt.Errorf("server %s is not reachable over TCP: %w", addr, err))
	}
	defer raw.Close()
	tcpTime := time.Since(start)
	if dl, ok := ctx.Deadline(); ok {
		raw.SetDeadline(dl)
	}
	// The handshake may be stuck in a read that ignores ctx.
	stop := context.AfterFunc(ctx, func() { raw.SetDeadline(time.Now()) })
	defer stop()

	start = time.Now()
	sec, err := handshake(ctx, raw, c)
	if err != nil {
		return handshakeError(c, tcpTime, time.Since(start), err)
	}
	hsTime := time.Since(start)
	ok := fmt.Sprintf("TCP %s, %s handshake %s", ms(tcpTime), strings.ToUpper(c.Security), ms(hsTime))
	if c.Network != "raw" && c.Network != "tcp" && c.Network != "" {
		return errclass.Wrap(errclass.Routing, fmt.Errorf("%s; the %s transport over it was not checked", ok, c.Network))
	}

	start = time.Now()
	err = vlessDNS(sec, c.UUID, dns)
	switch {
	case err == nil:
		return nil
	case isTimeout(err):
		return errclass.Wrap(errclass.ServerSilent, fmt.Errorf("%s; a DNS query to %s through the server got no answer in %s", ok, dns, ms(time.Since(start))))
	case isClosed(err):
		return errclass.Wrap(errclass.ServerClosed, fmt.Errorf("%s; the server closed the connection after the VLESS request (%v): it does not accept user ID %s…, or does not relay UDP", ok, err, short(c.UUID)))
	}
	return errclass.Wrap(errclass.Routing, fmt.Errorf("%s; VLESS request: %w", ok, err))
}

// diagnoseProxy checks that the proxy accepts TCP connections. The proxy
// protocol itself is not repeated: its errors reach the log through xray.
func diagnoseProxy(ctx context.Context, c *profile.ProxyConfig) error {
	addr := net.JoinHostPort(c.Address, strconv.Itoa(c.Port))
	start := time.Now()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp4", addr)
	if err != nil {
		cl := errclass.Classify(err)
		if cl != errclass.TCPReset && cl != errclass.NoNetwork && cl != errclass.DNS {
			cl = errclass.TCPTimeout
		}
		return errclass.Wrap(cl, fmt.Errorf("proxy %s is not reachable over TCP: %w", addr, err))
	}
	conn.Close()
	return errclass.Wrap(errclass.ServerSilent, fmt.Errorf("proxy accepts TCP in %s, but nothing passes through it: check the user name, password or cipher", ms(time.Since(start))))
}

func handshake(ctx context.Context, raw net.Conn, c *profile.VLESSConfig) (net.Conn, error) {
	fp := c.Fingerprint
	if fp == "" {
		fp = profile.DefaultFingerprint
	}
	switch c.Security {
	case "reality":
		rc := conf.REALITYConfig{Fingerprint: fp, ServerName: c.SNI, PublicKey: c.PublicKey, ShortId: c.ShortID, SpiderX: c.SpiderX, Mldsa65Verify: c.Mldsa65Verify}
		pb, err := rc.Build()
		if err != nil {
			return nil, errclass.Wrap(errclass.Config, err)
		}
		return reality.UClient(raw, pb.(*reality.Config), ctx, xnet.TCPDestination(xnet.ParseAddress(c.Address), xnet.Port(c.Port)))
	case "tls":
		id := xtls.GetFingerprint(fp)
		if id == nil {
			return nil, errclass.Wrap(errclass.Config, fmt.Errorf("unknown fingerprint %q", fp))
		}
		sni := c.SNI
		if sni == "" {
			sni = c.Address
		}
		uc := utls.UClient(raw, &utls.Config{ServerName: sni, NextProtos: c.ALPN}, *id)
		if err := uc.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return uc, nil
	}
	return nil, errclass.Wrap(errclass.Config, fmt.Errorf("security %q cannot be checked", c.Security))
}

func handshakeError(c *profile.VLESSConfig, tcpTime, hsTime time.Duration, err error) error {
	pre := fmt.Sprintf("TCP %s, then the %s handshake", ms(tcpTime), strings.ToUpper(c.Security))
	switch {
	case errclass.Classify(err) == errclass.Config:
		return err
	case c.Security == "reality" && (strings.Contains(err.Error(), "processed invalid connection") || strings.Contains(err.Error(), "x509:")):
		// A REALITY server that does not recognise the client relays the
		// handshake to the real site, whose certificate xray then rejects
		// or, when it is valid, browses as a decoy.
		return errclass.Wrap(errclass.TLS, fmt.Errorf("%s: the server answered with an ordinary certificate for %s instead of REALITY's, so it did not accept the public key or short ID (or the connection was redirected)", pre, c.SNI))
	case isTimeout(err):
		return errclass.Wrap(errclass.TLSTimeout, fmt.Errorf("%s got no answer in %s", pre, ms(hsTime)))
	case isClosed(err):
		return errclass.Wrap(errclass.TCPReset, fmt.Errorf("%s was cut off after %s: %v", pre, ms(hsTime), err))
	}
	return errclass.Wrap(errclass.TLS, fmt.Errorf("%s failed: %w", pre, err))
}

// vlessDNS sends one DNS query as a VLESS UDP request (flow "", which
// Vision accounts accept for UDP) and waits for the answer.
func vlessDNS(c net.Conn, id string, server netip.AddrPort) error {
	u, err := uuid.ParseString(id)
	if err != nil {
		return errclass.Wrap(errclass.Config, fmt.Errorf("user ID: %w", err))
	}
	q, err := dnsQuery()
	if err != nil {
		return err
	}
	ip := server.Addr().Unmap().As4()
	req := []byte{0}
	req = append(req, u.Bytes()...)
	req = append(req, 0, 2) // no addons, command UDP
	req = binary.BigEndian.AppendUint16(req, server.Port())
	req = append(req, 1) // IPv4
	req = append(req, ip[:]...)
	req = binary.BigEndian.AppendUint16(req, uint16(len(q)))
	req = append(req, q...)
	if _, err := c.Write(req); err != nil {
		return err
	}
	// Response: version, addons, then length-prefixed datagrams.
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return err
	}
	if _, err := io.CopyN(io.Discard, c, int64(hdr[1])); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, hdr); err != nil {
		return err
	}
	resp := make([]byte, binary.BigEndian.Uint16(hdr))
	if _, err := io.ReadFull(c, resp); err != nil {
		return err
	}
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil || !h.Response || h.ID != binary.BigEndian.Uint16(q) {
		return fmt.Errorf("malformed DNS answer from %s", server)
	}
	return nil
}

func dnsQuery() ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: uint16(time.Now().UnixNano()), RecursionDesired: true})
	b.StartQuestions()
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return b.Finish()
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || errors.As(err, &ne) && ne.Timeout()
}

func isClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errclass.Classify(err) == errclass.TCPReset
}

func ms(d time.Duration) string { return d.Round(time.Millisecond).String() }

// short keeps the start of a user ID: enough to recognise it in a server
// panel without writing the whole secret to the log.
func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
