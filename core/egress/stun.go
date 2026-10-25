package egress

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
)

// DefaultSTUNServers are public STUN servers (GEO-005).
var DefaultSTUNServers = []string{"stun.l.google.com:19302", "stun.cloudflare.com:3478"}

const stunMagic = 0x2112A442

// STUNMappedAddress sends a STUN Binding Request (RFC 5389) and returns the
// reflexive address, i.e. the public address WebRTC would expose.
func STUNMappedAddress(ctx context.Context, d *net.Dialer, server string) (netip.AddrPort, error) {
	c, err := d.DialContext(ctx, "udp4", server)
	if err != nil {
		return netip.AddrPort{}, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:], 0x0001) // Binding Request
	binary.BigEndian.PutUint32(req[4:], stunMagic)
	tid := req[8:20]
	if _, err := rand.Read(tid); err != nil {
		return netip.AddrPort{}, err
	}
	if _, err := c.Write(req); err != nil {
		return netip.AddrPort{}, err
	}
	buf := make([]byte, 1500)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return netip.AddrPort{}, err
		}
		if ap, ok := parseBindingResponse(buf[:n], tid); ok {
			return ap, nil
		}
	}
}

func parseBindingResponse(b []byte, tid []byte) (netip.AddrPort, bool) {
	if len(b) < 20 || binary.BigEndian.Uint16(b[0:]) != 0x0101 || binary.BigEndian.Uint32(b[4:]) != stunMagic || string(b[8:20]) != string(tid) {
		return netip.AddrPort{}, false
	}
	attrs := b[20:]
	if l := int(binary.BigEndian.Uint16(b[2:])); l <= len(attrs) {
		attrs = attrs[:l]
	}
	var mapped netip.AddrPort
	for len(attrs) >= 4 {
		typ := binary.BigEndian.Uint16(attrs[0:])
		l := int(binary.BigEndian.Uint16(attrs[2:]))
		if 4+l > len(attrs) {
			break
		}
		v := attrs[4 : 4+l]
		switch typ {
		case 0x0020: // XOR-MAPPED-ADDRESS
			if ap, err := decodeAddr(v, true); err == nil {
				return ap, true
			}
		case 0x0001: // MAPPED-ADDRESS (RFC 3489 servers)
			if ap, err := decodeAddr(v, false); err == nil {
				mapped = ap
			}
		}
		attrs = attrs[4+(l+3)&^3:]
	}
	return mapped, mapped.IsValid()
}

func decodeAddr(v []byte, xor bool) (netip.AddrPort, error) {
	if len(v) < 8 || v[1] != 0x01 { // IPv4 only
		return netip.AddrPort{}, errors.New("unsupported address")
	}
	port := binary.BigEndian.Uint16(v[2:])
	var ip [4]byte
	copy(ip[:], v[4:8])
	if xor {
		port ^= stunMagic >> 16
		m := binary.BigEndian.Uint32(ip[:]) ^ stunMagic
		binary.BigEndian.PutUint32(ip[:], m)
	}
	return netip.AddrPortFrom(netip.AddrFrom4(ip), port), nil
}
