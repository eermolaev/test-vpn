package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/eermolaev/test-vpn/core/engine"
	"golang.org/x/net/dns/dnsmessage"
)

// resolveDirect resolves a VPN server name with an A query sent directly
// (outside the tunnel, through the kill switch), because the system resolver
// may already point into the tunnel or be blocked.
func resolveDirect(ctx context.Context, d engine.Dialer, servers []netip.AddrPort, host string) (netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap(), nil
	}
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return netip.Addr{}, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: uint16(time.Now().UnixNano()), RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	var lastErr error = errors.New("no DNS servers")
	for _, s := range servers {
		ip, err := queryA(ctx, d, s, q)
		if err == nil {
			return ip, nil
		}
		lastErr = err
	}
	return netip.Addr{}, fmt.Errorf("resolve %s: %w", host, lastErr)
}

func queryA(ctx context.Context, d engine.Dialer, server netip.AddrPort, q []byte) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	c, err := d.DialUDP(ctx, server)
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	dl, _ := ctx.Deadline()
	c.SetDeadline(dl)
	if _, err := c.Write(q); err != nil {
		return netip.Addr{}, err
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return netip.Addr{}, err
	}
	var p dnsmessage.Parser
	if _, err := p.Start(buf[:n]); err != nil {
		return netip.Addr{}, err
	}
	p.SkipAllQuestions()
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			return netip.Addr{}, errors.New("no A record")
		}
		if h.Type == dnsmessage.TypeA {
			r, err := p.AResource()
			if err != nil {
				return netip.Addr{}, err
			}
			return netip.AddrFrom4(r.A), nil
		}
		p.SkipAnswer()
	}
}
