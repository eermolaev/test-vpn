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
	r := &recConn{}
	fc := &fragmentConn{Conn: r, f: Fragments[2]}
	if n, err := fc.Write(append(hello, 9, 9)); err != nil || n != len(hello)+2 {
		t.Fatal(n, err)
	}
	var got []byte
	for i, s := range r.segs[:len(r.segs)-1] {
		if s[0] != 22 || int(s[3])<<8|int(s[4]) != len(s)-5 || len(s)-5 > 30 {
			t.Fatalf("segment %d is not a small TLS record: %v", i, s[:5])
		}
		got = append(got, s[5:]...)
	}
	if !bytes.Equal(got, body) || !bytes.Equal(r.segs[len(r.segs)-1], []byte{9, 9}) {
		t.Fatal("records must carry the ClientHello and then the rest unchanged")
	}
}
