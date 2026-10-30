package xray

import (
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"time"
)

// Fragment splits the TLS ClientHello so that DPI matching it in one TCP
// segment (SNI, fingerprint) does not see it whole.
type Fragment struct {
	Name string
	// Packets is "tlshello" (split the ClientHello into several TLS records,
	// each in its own TCP segment) or "1-3" (split the first writes into
	// small TCP segments).
	Packets  string
	Length   [2]int // bytes per piece
	Interval [2]int // ms between pieces
}

// Fragments are the presets the tunnel walks through when failures look like
// DPI; index 0 sends the ClientHello unchanged.
var Fragments = []Fragment{
	{Name: "none"},
	{Name: "tlshello 100-200", Packets: "tlshello", Length: [2]int{100, 200}, Interval: [2]int{10, 20}},
	{Name: "tlshello 10-30", Packets: "tlshello", Length: [2]int{10, 30}, Interval: [2]int{5, 15}},
	{Name: "tcp 1-5", Packets: "1-3", Length: [2]int{1, 5}, Interval: [2]int{1, 3}},
}

// outbound returns the freedom outbound that applies f, for dialerProxy.
func (f Fragment) outbound(tag string) map[string]any {
	r := func(v [2]int) string { return fmt.Sprintf("%d-%d", v[0], v[1]) }
	return map[string]any{
		"tag":      tag,
		"protocol": "freedom",
		"settings": map[string]any{"fragment": map[string]any{"packets": f.Packets, "length": r(f.Length), "interval": r(f.Interval)}},
	}
}

// fragmentConn applies a Fragment to the writes of a connection, the same way
// xray's freedom outbound does; Diagnose uses it so that it checks the
// connection exactly as the engine makes it.
type fragmentConn struct {
	net.Conn
	f     Fragment
	count int
}

func between(v [2]int) int { return v[0] + rand.IntN(v[1]-v[0]+1) }

func (c *fragmentConn) pause() { time.Sleep(time.Duration(between(c.f.Interval)) * time.Millisecond) }

func (c *fragmentConn) Write(b []byte) (int, error) {
	c.count++
	if c.f.Packets == "tlshello" {
		if c.count != 1 || len(b) <= 5 || b[0] != 22 {
			return c.Conn.Write(b)
		}
		end := 5 + (int(b[3])<<8 | int(b[4]))
		if len(b) < end {
			return c.Conn.Write(b)
		}
		data := b[5:end]
		for from := 0; from < len(data); {
			to := min(from+between(c.f.Length), len(data))
			rec := append([]byte{b[0], b[1], b[2], byte((to - from) >> 8), byte(to - from)}, data[from:to]...)
			if _, err := c.Conn.Write(rec); err != nil {
				return 0, err
			}
			from = to
			c.pause()
		}
		if len(b) > end {
			n, err := c.Conn.Write(b[end:])
			return end + n, err
		}
		return len(b), nil
	}
	if c.count > 3 {
		return c.Conn.Write(b)
	}
	from := 0
	for from < len(b) {
		to := min(from+between(c.f.Length), len(b))
		n, err := c.Conn.Write(b[from:to])
		from += n
		if err != nil {
			return from, err
		}
		c.pause()
	}
	return from, nil
}

var _ io.Writer = (*fragmentConn)(nil)
