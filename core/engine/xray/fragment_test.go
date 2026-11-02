package xray

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/eermolaev/test-vpn/core/internal/testenv"
)

func TestFragmentPresetsConnect(t *testing.T) {
	srv := testenv.StartReality(t)
	echo := testenv.StartEcho(t, "echo:")
	dns := testenv.StartDNS(t, [4]byte{1, 2, 3, 4})
	for k := 1; k < len(Fragments); k++ {
		c := *srv.Vision
		c.Fragment = k
		js, _ := BuildConfig(&c)
		if !strings.Contains(string(js), `"dialerProxy":"fragment"`) {
			t.Fatalf("%s: no dialerProxy in %s", Fragments[k].Name, js)
		}
		e, err := Start(&c, nil)
		if err != nil {
			t.Fatal(err)
		}
		tcpRoundTrip(t, e, echo)
		e.Close()
		if err := diagnose(t, &c, dns, 20*time.Second); err != nil {
			t.Fatalf("%s: %v", Fragments[k].Name, err)
		}
	}
}

// recConn records each Write as one segment.
type recConn struct {
	net.Conn
	segs [][]byte
}

func (r *recConn) Write(b []byte) (int, error) {
	r.segs = append(r.segs, append([]byte(nil), b...))
	return len(b), nil
}

func TestFragmentTLSHello(t *testing.T) {
	body := bytes.Repeat([]byte{7}, 300)
	hello := append([]byte{22, 3, 1, 1, 44}, body...)
	for _, k := range []int{2, 3} {
		f := Fragments[k]
		r := &recConn{}
		fc := &fragmentConn{Conn: r, f: f}
		if n, err := fc.Write(append(hello, 9, 9)); err != nil || n != len(hello)+2 {
			t.Fatal(f.Name, n, err)
		}
		recs := r.segs[:len(r.segs)-1]
		if f.Interval[1] == 0 {
			if len(recs) != 1 {
				t.Fatalf("%s: records must go out in one write, got %d", f.Name, len(recs))
			}
		} else if len(recs) < 10 {
			t.Fatalf("%s: each record must be its own write, got %d", f.Name, len(recs))
		}
		var got []byte
		rest := bytes.Join(recs, nil)
		for len(rest) > 0 {
			l := int(rest[3])<<8 | int(rest[4])
			if rest[0] != 22 || l > 30 || 5+l > len(rest) {
				t.Fatalf("%s: not a small TLS record: %v", f.Name, rest[:5])
			}
			got = append(got, rest[5:5+l]...)
			rest = rest[5+l:]
		}
		if !bytes.Equal(got, body) || !bytes.Equal(r.segs[len(r.segs)-1], []byte{9, 9}) {
			t.Fatalf("%s: records must carry the ClientHello and then the rest unchanged", f.Name)
		}
	}
}
