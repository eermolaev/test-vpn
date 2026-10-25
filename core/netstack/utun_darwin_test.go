//go:build darwin

package netstack

import (
	"testing"

	"golang.org/x/sys/unix"
)

// A failed or stopped tunnel must not close the system-owned utun fd.
func TestUtunIOKeepsOriginalFD(t *testing.T) {
	fds := make([]int, 2)
	if err := unix.Pipe(fds); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	u, err := NewUtunIO(fds[0], 1400)
	if err != nil {
		t.Fatal(err)
	}
	u.Close()
	if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); err != nil {
		t.Fatalf("original fd was closed: %v", err)
	}
	if _, err := NewUtunIO(-1, 1400); err == nil {
		t.Fatal("invalid fd must fail")
	}
}
