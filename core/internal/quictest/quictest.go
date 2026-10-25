// Package quictest builds QUIC client Initial packets for tests, following
// RFC 9001 section 5 independently of the sniffer.
package quictest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"time"
)

const (
	V1 = 0x00000001
	V2 = 0x6b3343cf
)

var (
	saltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	saltV2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

// CryptoFrame is a CRYPTO frame fragment.
type CryptoFrame struct {
	Offset uint64
	Data   []byte
}

// ClientHello returns a TLS ClientHello handshake message (without record
// header) produced by crypto/tls, or nil on failure.
func ClientHello(sni string) []byte {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		_ = tls.Client(c1, &tls.Config{ServerName: sni, NextProtos: []string{"h3"}}).Handshake()
	}()
	c2.SetDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c2, hdr); err != nil {
		return nil
	}
	body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(c2, body); err != nil {
		return nil
	}
	return body
}

func expandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := []byte{byte(length >> 8), byte(length), byte(len(full))}
	info = append(info, full...)
	info = append(info, 0)
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		panic(err)
	}
	return out
}

func putVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, byte(v>>8)|0x40, byte(v))
	default:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	}
}

// Initial builds an encrypted, header-protected client Initial packet padded
// to at least 1200 bytes.
func Initial(version uint32, dcid []byte, pn uint32, frames []CryptoFrame) []byte {
	salt, prefix, typ := saltV1, "quic ", byte(0)
	if version == V2 {
		salt, prefix, typ = saltV2, "quicv2 ", 1
	}
	initial, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		panic(err)
	}
	client := expandLabel(initial, "client in", 32)
	key, iv, hp := expandLabel(client, prefix+"key", 16), expandLabel(client, prefix+"iv", 12), expandLabel(client, prefix+"hp", 16)

	payload := []byte{0x01} // PING
	for _, f := range frames {
		payload = append(payload, 0x06)
		payload = putVarint(payload, f.Offset)
		payload = putVarint(payload, uint64(len(f.Data)))
		payload = append(payload, f.Data...)
	}
	for len(payload) < 1200 {
		payload = append(payload, 0)
	}
	const pnLen = 4
	hdr := []byte{0xc0 | typ<<4 | (pnLen - 1)}
	hdr = binary.BigEndian.AppendUint32(hdr, version)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0, 0) // scid length, token length
	length := pnLen + len(payload) + 16
	hdr = append(hdr, byte(length>>8)|0x40, byte(length))
	pnOff := len(hdr)
	hdr = binary.BigEndian.AppendUint32(hdr, pn)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(uint64(pn) >> (8 * i))
	}
	pkt := aead.Seal(append([]byte(nil), hdr...), nonce, payload, hdr)
	hpBlock, _ := aes.NewCipher(hp)
	mask := make([]byte, 16)
	hpBlock.Encrypt(mask, pkt[pnOff+4:pnOff+20])
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		pkt[pnOff+i] ^= mask[1+i]
	}
	return pkt
}
