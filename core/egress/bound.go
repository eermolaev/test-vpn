package egress

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/eermolaev/test-vpn/core/direct"
)

// BoundClient sends HTTP requests through sockets bound to the physical
// interface. With a working kill switch they must fail (GEO-006).
func BoundClient(d *direct.Dialer) *http.Client {
	return &http.Client{Timeout: 6 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("resolve %s: %v", host, err)
			}
			p, _ := strconv.Atoi(port)
			return d.DialTCP(ctx, netip.AddrPortFrom(ips[0], uint16(p)))
		},
	}}
}
