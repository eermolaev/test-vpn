package sniff

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/eermolaev/test-vpn/core/internal/quictest"
)

// clientHelloRecord captures a real TLS ClientHello from crypto/tls.
func clientHelloRecord(t *testing.T, sni string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		cfg := &tls.Config{ServerName: sni, InsecureSkipVerify: sni == "", NextProtos: []string{"h2", "http/1.1"}}
		_ = tls.Client(c1, cfg).Handshake()
	}()
	c2.SetDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c2, hdr); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(c2, body); err != nil {
		t.Fatal(err)
	}
	return append(hdr, body...)
}

func TestTLS(t *testing.T) {
	rec := clientHelloRecord(t, "www.Example.com")
	host, proto, err := Stream(rec)
	if err != nil || host != "www.example.com" || proto != TLS {
		t.Fatalf("got %q %q %v", host, proto, err)
	}
	// Every strict prefix asks for more data or already has the SNI.
	for i := 1; i < len(rec); i += 7 {
		h, err := TLSServerName(rec[:i])
		if err != nil && !errors.Is(err, ErrNeedMore) {
			t.Fatalf("prefix %d: %v", i, err)
		}
		if err == nil && h != "www.example.com" {
			t.Fatalf("prefix %d: host %q", i, h)
		}
	}
	// ClientHello split across two records.
	body := rec[5:]
	split := []byte{0x16, 3, 1, 0, 40}
	split = append(split, body[:40]...)
	rest := len(body) - 40
	split = append(split, 0x16, 3, 1, byte(rest>>8), byte(rest))
	split = append(split, body[40:]...)
	if h, err := TLSServerName(split); err != nil || h != "www.example.com" {
		t.Fatalf("split records: %q %v", h, err)
	}
}

func TestTLSWithoutSNI(t *testing.T) {
	rec := clientHelloRecord(t, "")
	if _, err := TLSServerName(rec); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestHTTP(t *testing.T) {
	req := "GET /path HTTP/1.1\r\nUser-Agent: x\r\nHost: Example.org:8080\r\nAccept: */*\r\n\r\n"
	host, proto, err := Stream([]byte(req))
	if err != nil || host != "example.org" || proto != HTTP {
		t.Fatalf("got %q %q %v", host, proto, err)
	}
	if _, err := HTTPHost([]byte("GE")); !errors.Is(err, ErrNeedMore) {
		t.Fatal("short method must need more")
	}
	if _, err := HTTPHost([]byte("GET / HTTP/1.1\r\nHo")); !errors.Is(err, ErrNeedMore) {
		t.Fatal("partial header must need more")
	}
	if _, _, err := Stream([]byte("SSH-2.0-OpenSSH\r\n")); !errors.Is(err, ErrNotFound) {
		t.Fatal("ssh must not be recognized")
	}
	if _, err := HTTPHost([]byte("GET / HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n")); !errors.Is(err, ErrNotFound) {
		t.Fatal("IP host must be ignored")
	}
}

// RFC 9001, Appendix A.1.
func TestInitialKeysRFC9001(t *testing.T) {
	dcid, _ := hex.DecodeString("8394c8f03e515708")
	key, iv, hp, err := initialKeys(saltV1, "quic ", dcid)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string][2]string{
		"key": {hex.EncodeToString(key), "1f369613dd76d5467730efcbe3b1a22d"},
		"iv":  {hex.EncodeToString(iv), "fa044b2f42a3fd3b46fb255c"},
		"hp":  {hex.EncodeToString(hp), "9f50449e04a0e810283a1e9933adedd2"},
	} {
		if c[0] != c[1] {
			t.Errorf("%s = %s, want %s", name, c[0], c[1])
		}
	}
}

func TestQUIC(t *testing.T) {
	ch := clientHelloRecord(t, "quic.example.net")[5:] // handshake message only
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	for _, v := range []uint32{quictest.V1, quictest.V2} {
		pkt := quictest.Initial(v, dcid, 0, []quictest.CryptoFrame{{Data: ch}})
		host, err := QUICServerName(pkt)
		if err != nil || host != "quic.example.net" {
			t.Fatalf("version %x: %q %v", v, host, err)
		}
	}
	// ClientHello split across two datagrams, frames out of order (Chrome does
	// this on purpose).
	mid := len(ch) / 2
	p1 := quictest.Initial(quictest.V1, dcid, 0, []quictest.CryptoFrame{{Offset: uint64(mid), Data: ch[mid:]}})
	p2 := quictest.Initial(quictest.V1, dcid, 1, []quictest.CryptoFrame{{Data: ch[:20]}, {Offset: 20, Data: ch[20:mid]}})
	var s QUICSniffer
	if _, err := s.Feed(p1); !errors.Is(err, ErrNeedMore) {
		t.Fatalf("first half: %v", err)
	}
	if host, err := s.Feed(p2); err != nil || host != "quic.example.net" {
		t.Fatalf("reassembled: %q %v", host, err)
	}
	// Garbage and short-header packets are not QUIC Initials.
	if _, err := QUICServerName([]byte{0x40, 1, 2, 3, 4, 5, 6, 7}); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	corrupt := quictest.Initial(quictest.V1, dcid, 0, []quictest.CryptoFrame{{Data: ch}})
	corrupt[len(corrupt)-1] ^= 1
	if _, err := QUICServerName(corrupt); !errors.Is(err, ErrNotFound) {
		t.Fatal("corrupted packet must fail authentication")
	}
}
