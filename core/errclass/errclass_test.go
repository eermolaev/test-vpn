package errclass

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassify(t *testing.T) {
	cases := []struct {
		err  error
		want Class
	}{
		{nil, None},
		{&net.DNSError{Err: "no such host", Name: "x"}, DNS},
		{&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, TCPReset},
		{fmt.Errorf("read: %w", syscall.ECONNRESET), TCPReset},
		{&net.OpError{Op: "dial", Err: syscall.ENETUNREACH}, NoNetwork},
		{&net.OpError{Op: "dial", Err: timeoutErr{}}, TCPTimeout},
		{context.DeadlineExceeded, TCPTimeout},
		{context.Canceled, Canceled},
		{tls.AlertError(40), TLS},
		{errors.New("REALITY: processed invalid connection"), TLS},
		{Wrap(UDPTimeout, timeoutErr{}), UDPTimeout},
		{fmt.Errorf("outer: %w", Wrap(AWGMismatch, errors.New("x"))), AWGMismatch},
		{errors.New("weird"), Unknown},
	}
	for _, c := range cases {
		if got := Classify(c.err); got != c.want {
			t.Errorf("Classify(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

func TestWrapKeepsInner(t *testing.T) {
	err := Wrap(Routing, Wrap(TLS, errors.New("bad")))
	if Classify(err) != TLS {
		t.Fatal("inner class must win")
	}
	if Wrap(TLS, nil) != nil {
		t.Fatal("Wrap(nil) must be nil")
	}
}

func TestTimeoutIsNotBlocking(t *testing.T) {
	for _, c := range []Class{UDPTimeout, TCPTimeout} {
		if strings.Contains(strings.ToLower(c.Message()), "blocked") {
			t.Errorf("%s message claims blocking: %q", c, c.Message())
		}
	}
}
