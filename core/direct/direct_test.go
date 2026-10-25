package direct

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestDirect(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Write([]byte("ok"))
			c.Close()
		}
	}()
	var d Dialer
	c, err := d.DialTCP(context.Background(), netip.MustParseAddrPort(ln.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := c.Read(buf); err != nil || string(buf) != "ok" {
		t.Fatalf("%q %v", buf, err)
	}
	c.Close()
	if _, err := d.DialTCP(context.Background(), netip.MustParseAddrPort("[2001:db8::1]:443")); !errors.Is(err, ErrIPv6) {
		t.Fatal("IPv6 must be refused")
	}
	if _, err := d.DialUDP(context.Background(), netip.MustParseAddrPort("[2001:db8::1]:53")); !errors.Is(err, ErrIPv6) {
		t.Fatal("IPv6 must be refused")
	}
}
