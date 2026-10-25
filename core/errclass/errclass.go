// Package errclass classifies connection errors (SEC-NET-004). A timeout alone
// is never reported as "VPN blocked".
package errclass

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"syscall"
)

// Class is a stable error code shown in diagnostics.
type Class string

const (
	None          Class = ""
	DNS           Class = "dns"            // server name did not resolve
	NoNetwork     Class = "no_network"     // no route / interface down
	CaptivePortal Class = "captive_portal" // network requires sign-in
	UDPTimeout    Class = "udp_timeout"    // no AmneziaWG handshake reply
	TCPReset      Class = "tcp_reset"      // connection reset or refused
	TCPTimeout    Class = "tcp_timeout"    // no SYN-ACK / connect timeout
	TLS           Class = "tls_reality"    // TLS/REALITY handshake failed
	AWGMismatch   Class = "awg_mismatch"   // server answers, obfuscation/version differs
	Routing       Class = "routing"        // tunnel up, health check through it fails
	Config        Class = "config"         // invalid profile or settings
	Canceled      Class = "canceled"       // stopped by the user
	Unknown       Class = "unknown"
)

// Error attaches a class to an error.
type Error struct {
	Class Class
	Err   error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return string(e.Class)
	}
	return string(e.Class) + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

// Wrap marks err with class c. Wrap(c, nil) returns nil.
func Wrap(c Class, err error) error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return err // keep the most specific (innermost) class
	}
	return &Error{Class: c, Err: err}
}

// Classify returns the class of err.
func Classify(err error) Class {
	if err == nil {
		return None
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Class
	}
	if errors.Is(err, context.Canceled) {
		return Canceled
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return DNS
	}
	switch {
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.EPIPE):
		return TCPReset
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETDOWN):
		return NoNetwork
	}
	var recErr tls.RecordHeaderError
	var alert tls.AlertError
	if errors.As(err, &recErr) || errors.As(err, &alert) {
		return TLS
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "reality") || strings.Contains(msg, "tls: ") || strings.Contains(msg, "handshake failure") {
		return TLS
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return TCPTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return TCPTimeout
	}
	return Unknown
}

// SkipTransport reports whether retrying the same transport is pointless.
func (c Class) SkipTransport() bool { return c == Config || c == AWGMismatch }

// Message is a user-facing explanation. It deliberately avoids claiming that
// the VPN is blocked when only a timeout was observed.
func (c Class) Message() string {
	switch c {
	case None:
		return "Connected"
	case DNS:
		return "The server name could not be resolved."
	case NoNetwork:
		return "No network connection."
	case CaptivePortal:
		return "This network requires sign-in in a browser."
	case UDPTimeout:
		return "The server did not answer over UDP. UDP may be filtered on this network, or the server may be down."
	case TCPReset:
		return "The connection to the server was reset or refused."
	case TCPTimeout:
		return "The server did not respond in time."
	case TLS:
		return "The secure handshake with the server failed. Check the REALITY key, short ID and server name."
	case AWGMismatch:
		return "The server answered, but AmneziaWG parameters or protocol version do not match."
	case Routing:
		return "The tunnel is up, but traffic does not pass through it."
	case Config:
		return "The profile or settings are invalid."
	case Canceled:
		return "Disconnected."
	}
	return "Connection failed."
}
