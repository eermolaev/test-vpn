// Package sniff extracts the destination host name from the first bytes of a
// connection: TLS ClientHello SNI, HTTP Host header, or the SNI inside a QUIC
// Initial packet (SPLIT-002).
package sniff

import (
	"bytes"
	"errors"
	"net"
	"strings"
)

var (
	// ErrNeedMore means the data is a prefix of a recognized protocol message.
	ErrNeedMore = errors.New("sniff: need more data")
	// ErrNotFound means the protocol was not recognized or has no host.
	ErrNotFound = errors.New("sniff: host not found")
)

// Protocol names the source of a sniffed host.
type Protocol string

const (
	TLS  Protocol = "tls"
	HTTP Protocol = "http"
	QUIC Protocol = "quic"
)

// MaxStreamPrefix bounds how many bytes a TCP sniffer buffers.
const MaxStreamPrefix = 16 * 1024

// Stream tries all stream protocols on the data read so far.
func Stream(b []byte) (string, Protocol, error) {
	host, err := TLSServerName(b)
	if err == nil || errors.Is(err, ErrNeedMore) {
		return host, TLS, err
	}
	host, err = HTTPHost(b)
	if err == nil || errors.Is(err, ErrNeedMore) {
		return host, HTTP, err
	}
	return "", "", ErrNotFound
}

// TLSServerName parses a TLS record stream starting with a ClientHello.
// The ClientHello may span several records.
func TLSServerName(b []byte) (string, error) {
	if len(b) == 0 {
		return "", ErrNeedMore
	}
	if b[0] != 0x16 {
		return "", ErrNotFound
	}
	var hs []byte
	for len(b) > 0 {
		if len(b) < 5 {
			return "", ErrNeedMore
		}
		if b[0] != 0x16 || b[1] != 3 {
			return "", ErrNotFound
		}
		n := int(b[3])<<8 | int(b[4])
		if n == 0 || n > 1<<14+256 {
			return "", ErrNotFound
		}
		if len(b) < 5+n {
			// Try to parse what we have; the SNI is usually in the first segment.
			hs = append(hs, b[5:]...)
			host, err := clientHelloServerName(hs)
			if err == nil {
				return host, nil
			}
			if errors.Is(err, ErrNeedMore) {
				return "", ErrNeedMore
			}
			return "", err
		}
		hs = append(hs, b[5:5+n]...)
		b = b[5+n:]
		host, err := clientHelloServerName(hs)
		if !errors.Is(err, ErrNeedMore) {
			return host, err
		}
	}
	return "", ErrNeedMore
}

// clientHelloServerName parses a handshake message stream (no record layer)
// that starts with a ClientHello. It is shared by TLS and QUIC.
func clientHelloServerName(hs []byte) (string, error) {
	r := reader{b: hs}
	typ, ok := r.u8()
	if !ok {
		return "", ErrNeedMore
	}
	if typ != 1 {
		return "", ErrNotFound
	}
	length, ok := r.u24()
	if !ok {
		return "", ErrNeedMore
	}
	if length > 1<<16 {
		return "", ErrNotFound
	}
	// Parse incrementally: the SNI extension is near the start, so a partial
	// message is often enough.
	if !r.skip(2 + 32) { // version, random
		return "", ErrNeedMore
	}
	for _, lenBytes := range []int{1, 2, 1} { // session id, cipher suites, compression
		n, ok := r.uN(lenBytes)
		if !ok || !r.skip(n) {
			return "", ErrNeedMore
		}
	}
	extLen, ok := r.u16()
	if !ok {
		return "", ErrNeedMore
	}
	_ = extLen
	for {
		typ, ok1 := r.u16()
		n, ok2 := r.u16()
		if !ok1 || !ok2 {
			if r.off >= 4+length {
				return "", ErrNotFound
			}
			return "", ErrNeedMore
		}
		if typ != 0 {
			if !r.skip(n) {
				return "", ErrNeedMore
			}
			continue
		}
		data, ok := r.bytes(n)
		if !ok {
			return "", ErrNeedMore
		}
		return parseServerNameExt(data)
	}
}

func parseServerNameExt(data []byte) (string, error) {
	r := reader{b: data}
	listLen, ok := r.u16()
	if !ok || listLen > len(data)-2 {
		return "", ErrNotFound
	}
	for r.off < 2+listLen {
		nameType, ok1 := r.u8()
		n, ok2 := r.u16()
		name, ok3 := r.bytes(n)
		if !ok1 || !ok2 || !ok3 {
			return "", ErrNotFound
		}
		if nameType == 0 {
			return validHost(string(name))
		}
	}
	return "", ErrNotFound
}

var httpMethods = []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}

// HTTPHost returns the Host header of an HTTP/1.x request.
func HTTPHost(b []byte) (string, error) {
	matched := false
	for _, m := range httpMethods {
		if len(b) < len(m) {
			if strings.HasPrefix(m, string(b)) {
				return "", ErrNeedMore
			}
			continue
		}
		if string(b[:len(m)]) == m {
			matched = true
			break
		}
	}
	if !matched {
		return "", ErrNotFound
	}
	end := bytes.Index(b, []byte("\r\n\r\n"))
	head := b
	if end >= 0 {
		head = b[:end]
	}
	lines := bytes.Split(head, []byte("\r\n"))
	for i, line := range lines {
		if i == 0 {
			continue
		}
		if i == len(lines)-1 && end < 0 {
			break // possibly incomplete line
		}
		k, v, ok := bytes.Cut(line, []byte(":"))
		if ok && strings.EqualFold(string(bytes.TrimSpace(k)), "host") {
			h := strings.TrimSpace(string(v))
			if host, _, err := net.SplitHostPort(h); err == nil {
				h = host
			}
			return validHost(h)
		}
	}
	if end < 0 && len(b) < MaxStreamPrefix {
		return "", ErrNeedMore
	}
	return "", ErrNotFound
}

func validHost(h string) (string, error) {
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if h == "" || len(h) > 253 || net.ParseIP(strings.Trim(h, "[]")) != nil {
		return "", ErrNotFound
	}
	for _, c := range h {
		if c <= ' ' || c == '/' || c == '\\' {
			return "", ErrNotFound
		}
	}
	return h, nil
}

type reader struct {
	b   []byte
	off int
}

func (r *reader) u8() (int, bool) {
	if r.off+1 > len(r.b) {
		return 0, false
	}
	v := int(r.b[r.off])
	r.off++
	return v, true
}

func (r *reader) uN(n int) (int, bool) {
	if r.off+n > len(r.b) {
		return 0, false
	}
	v := 0
	for i := 0; i < n; i++ {
		v = v<<8 | int(r.b[r.off+i])
	}
	r.off += n
	return v, true
}

func (r *reader) u16() (int, bool) { return r.uN(2) }
func (r *reader) u24() (int, bool) { return r.uN(3) }

func (r *reader) skip(n int) bool {
	if r.off+n > len(r.b) {
		return false
	}
	r.off += n
	return true
}

func (r *reader) bytes(n int) ([]byte, bool) {
	if r.off+n > len(r.b) {
		return nil, false
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return v, true
}
