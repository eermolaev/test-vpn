package platform

import (
	"net"
	"net/netip"
	"os"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func rmsg(flags, index int, dst, mask [4]byte) *route.RouteMessage {
	addrs := make([]route.Addr, unix.RTAX_NETMASK+1)
	addrs[unix.RTAX_DST] = &route.Inet4Addr{IP: dst}
	addrs[unix.RTAX_NETMASK] = &route.Inet4Addr{IP: mask}
	return &route.RouteMessage{Flags: flags, Index: index, Addrs: addrs}
}

func TestPresentRoutes(t *testing.T) {
	msgs := []route.Message{
		rmsg(unix.RTF_UP|unix.RTF_GATEWAY, 4, [4]byte{}, [4]byte{}),                               // global default
		rmsg(unix.RTF_UP|unix.RTF_GATEWAY|unix.RTF_IFSCOPE, 9, [4]byte{}, [4]byte{}),              // scoped, other interface
		rmsg(unix.RTF_UP|unix.RTF_GATEWAY|unix.RTF_HOST, 4, [4]byte{31, 172, 77, 119}, [4]byte{}), // server
		rmsg(unix.RTF_UP|unix.RTF_GATEWAY|unix.RTF_IFSCOPE, 4, [4]byte{}, [4]byte{128, 0, 0, 0}),  // not a default
	}
	scoped, hosts := presentRoutes(msgs, 4)
	if scoped || !hosts[netip.MustParseAddr("31.172.77.119")] {
		t.Fatalf("scoped=%v hosts=%v", scoped, hosts)
	}
	msgs = append(msgs, rmsg(unix.RTF_UP|unix.RTF_GATEWAY|unix.RTF_IFSCOPE, 4, [4]byte{}, [4]byte{}))
	if scoped, _ := presentRoutes(msgs, 4); !scoped {
		t.Fatal("scoped default on interface 4 not found")
	}
}

// TestPresentRoutesLive prints what presentRoutes sees in this machine's
// table for PLATFORM_IF (set PLATFORM_LIVE=1); compare with netstat -rn.
func TestPresentRoutesLive(t *testing.T) {
	if os.Getenv("PLATFORM_LIVE") == "" {
		t.Skip("PLATFORM_LIVE not set")
	}
	ifc, err := net.InterfaceByName(os.Getenv("PLATFORM_IF"))
	if err != nil {
		t.Fatal(err)
	}
	rib, _ := route.FetchRIB(unix.AF_INET, route.RIBTypeRoute, 0)
	msgs, _ := route.ParseRIB(route.RIBTypeRoute, rib)
	scoped, hosts := presentRoutes(msgs, ifc.Index)
	t.Logf("%s: scoped default %v, %d host routes", ifc.Name, scoped, len(hosts))
}
