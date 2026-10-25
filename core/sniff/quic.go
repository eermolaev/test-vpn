package sniff

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
)

const (
	quicV1 = 0x00000001
	quicV2 = 0x6b3343cf
)

var (
	saltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	saltV2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

// QUICSniffer reassembles the ClientHello from one or more client Initial
// packets (large post-quantum ClientHellos span two datagrams).
type QUICSniffer struct {
	frags   map[uint64][]byte
	packets int
}

// MaxQUICPackets bounds how many Initial datagrams are buffered.
const MaxQUICPackets = 4

// Feed adds a UDP datagram. It returns the SNI, ErrNeedMore, or ErrNotFound.
func (s *QUICSniffer) Feed(datagram []byte) (string, error) {
	if s.frags == nil {
		s.frags = map[uint64][]byte{}
	}
	s.packets++
	if err := s.feed(datagram); err != nil {
		return "", err
	}
	hs := s.contiguous()
	host, err := clientHelloServerName(hs)
	if errors.Is(err, ErrNeedMore) && s.packets >= MaxQUICPackets {
		return "", ErrNotFound
	}
	return host, err
}

// QUICServerName parses a single datagram.
func QUICServerName(datagram []byte) (string, error) {
	var s QUICSniffer
	return s.Feed(datagram)
}

func (s *QUICSniffer) contiguous() []byte {
	offs := make([]uint64, 0, len(s.frags))
	for o := range s.frags {
		offs = append(offs, o)
	}
	sort.Slice(offs, func(i, j int) bool { return offs[i] < offs[j] })
	var out []byte
	for _, o := range offs {
		f := s.frags[o]
		cur := uint64(len(out))
		if o > cur {
			break
		}
		if end := o + uint64(len(f)); end > cur {
			out = append(out, f[cur-o:]...)
		}
	}
	return out
}

func (s *QUICSniffer) feed(b []byte) error {
	found := false
	for len(b) > 0 {
		n, err := s.packet(b)
		if err != nil {
			if found {
				return nil // trailing non-Initial coalesced packets
			}
			return err
		}
		found = true
		b = b[n:]
	}
	return nil
}

// packet decrypts one client Initial packet and stores its CRYPTO frames. It
// returns the packet length.
func (s *QUICSniffer) packet(b []byte) (int, error) {
	if len(b) < 7 || b[0]&0xc0 != 0xc0 {
		return 0, ErrNotFound
	}
	version := binary.BigEndian.Uint32(b[1:5])
	var salt []byte
	var labelPrefix string
	typ := (b[0] >> 4) & 0x03
	switch version {
	case quicV1:
		salt, labelPrefix = saltV1, "quic "
		if typ != 0 {
			return 0, ErrNotFound
		}
	case quicV2:
		salt, labelPrefix = saltV2, "quicv2 "
		if typ != 1 {
			return 0, ErrNotFound
		}
	default:
		return 0, ErrNotFound
	}
	r := reader{b: b, off: 5}
	dcidLen, ok := r.u8()
	if !ok || dcidLen > 20 {
		return 0, ErrNotFound
	}
	dcid, ok := r.bytes(dcidLen)
	if !ok {
		return 0, ErrNotFound
	}
	scidLen, ok := r.u8()
	if !ok || scidLen > 20 || !r.skip(scidLen) {
		return 0, ErrNotFound
	}
	tokenLen, ok := r.varint()
	if !ok || !r.skip(int(tokenLen)) {
		return 0, ErrNotFound
	}
	length, ok := r.varint()
	if !ok {
		return 0, ErrNotFound
	}
	pnOffset := r.off
	end := pnOffset + int(length)
	if end > len(b) || length < 20 {
		return 0, ErrNotFound
	}
	key, iv, hp, err := initialKeys(salt, labelPrefix, dcid)
	if err != nil {
		return 0, ErrNotFound
	}
	// Remove header protection.
	block, err := aes.NewCipher(hp)
	if err != nil {
		return 0, ErrNotFound
	}
	sample := b[pnOffset+4 : pnOffset+20]
	mask := make([]byte, 16)
	block.Encrypt(mask, sample)
	hdr := append([]byte(nil), b[:pnOffset+4]...)
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&0x03) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		hdr[pnOffset+i] ^= mask[1+i]
		pn = pn<<8 | uint64(hdr[pnOffset+i])
	}
	hdr = hdr[:pnOffset+pnLen]
	aead, err := newGCM(key)
	if err != nil {
		return 0, ErrNotFound
	}
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	plain, err := aead.Open(nil, nonce, b[pnOffset+pnLen:end], hdr)
	if err != nil {
		return 0, ErrNotFound
	}
	if err := s.frames(plain); err != nil {
		return 0, err
	}
	return end, nil
}

func (s *QUICSniffer) frames(p []byte) error {
	r := reader{b: p}
	for r.off < len(p) {
		ft, ok := r.varint()
		if !ok {
			return ErrNotFound
		}
		switch ft {
		case 0x00, 0x01: // PADDING, PING
		case 0x02, 0x03: // ACK
			if !r.skipACK(ft == 0x03) {
				return ErrNotFound
			}
		case 0x06: // CRYPTO
			off, ok1 := r.varint()
			n, ok2 := r.varint()
			data, ok3 := r.bytes(int(n))
			if !ok1 || !ok2 || !ok3 {
				return ErrNotFound
			}
			if off+n > 1<<16 {
				return ErrNotFound
			}
			if old, dup := s.frags[off]; !dup || len(old) < len(data) {
				s.frags[off] = append([]byte(nil), data...)
			}
		case 0x1c: // CONNECTION_CLOSE
			return ErrNotFound
		default:
			return nil // stop at frames we do not understand
		}
	}
	return nil
}

func (r *reader) varint() (uint64, bool) {
	if r.off >= len(r.b) {
		return 0, false
	}
	l := 1 << (r.b[r.off] >> 6)
	if r.off+l > len(r.b) {
		return 0, false
	}
	v := uint64(r.b[r.off] & 0x3f)
	for i := 1; i < l; i++ {
		v = v<<8 | uint64(r.b[r.off+i])
	}
	r.off += l
	return v, true
}

func (r *reader) skipACK(ecn bool) bool {
	for i := 0; i < 2; i++ { // largest acknowledged, ack delay
		if _, ok := r.varint(); !ok {
			return false
		}
	}
	count, ok := r.varint()
	if !ok {
		return false
	}
	if _, ok := r.varint(); !ok { // first range
		return false
	}
	for i := uint64(0); i < count*2; i++ {
		if _, ok := r.varint(); !ok {
			return false
		}
	}
	if ecn {
		for i := 0; i < 3; i++ {
			if _, ok := r.varint(); !ok {
				return false
			}
		}
	}
	return true
}

func initialKeys(salt []byte, prefix string, dcid []byte) (key, iv, hp []byte, err error) {
	initial, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return nil, nil, nil, err
	}
	client, err := expandLabel(initial, "client in", 32)
	if err != nil {
		return nil, nil, nil, err
	}
	if key, err = expandLabel(client, prefix+"key", 16); err != nil {
		return
	}
	if iv, err = expandLabel(client, prefix+"iv", 12); err != nil {
		return
	}
	hp, err = expandLabel(client, prefix+"hp", 16)
	return
}

// expandLabel implements HKDF-Expand-Label from TLS 1.3 with an empty context.
func expandLabel(secret []byte, label string, length int) ([]byte, error) {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = append(info, byte(length>>8), byte(length), byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	return hkdf.Expand(sha256.New, secret, string(info), length)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
