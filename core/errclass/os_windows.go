//go:build windows

package errclass

import (
	"errors"

	"golang.org/x/sys/windows"
)

// osClass maps Winsock errors, which do not match the syscall.E* constants.
func osClass(err error) (Class, bool) {
	switch {
	case errors.Is(err, windows.WSAECONNRESET), errors.Is(err, windows.WSAECONNREFUSED), errors.Is(err, windows.WSAECONNABORTED):
		return TCPReset, true
	case errors.Is(err, windows.WSAENETUNREACH), errors.Is(err, windows.WSAEHOSTUNREACH), errors.Is(err, windows.WSAENETDOWN):
		return NoNetwork, true
	case errors.Is(err, windows.WSAETIMEDOUT):
		return TCPTimeout, true
	}
	return "", false
}
