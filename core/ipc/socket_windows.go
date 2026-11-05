//go:build windows

package ipc

import (
	"errors"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

const installHint = "testvpn install in an Administrator terminal"

// DefaultSocket is the daemon socket path (an AF_UNIX socket, supported
// since Windows 10 1803).
var DefaultSocket = filepath.Join(programData(), "TestVPN", "testvpn.sock")

func programData() string {
	if p := os.Getenv("ProgramData"); p != "" {
		return p
	}
	return `C:\ProgramData`
}

func restrictToUID(string, int) error {
	return errors.New("ipc: user IDs are not supported on Windows; use ListenSID")
}

// ListenSID creates the socket at path that only LocalSystem, the
// Administrators group and the user with SID sid (may be empty) can connect
// to: connecting to an AF_UNIX socket needs write access to its file.
func ListenSID(path, sid string, h Handler) (*Server, error) {
	os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
	if sid != "" {
		sddl += "(A;;GA;;;" + sid + ")"
	}
	if err := setDACL(path, sddl); err != nil {
		ln.Close()
		return nil, err
	}
	return serve(ln, -1, h), nil
}

// setDACL replaces the DACL of a file or directory with a protected one
// (no inherited entries) described in SDDL.
func setDACL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// SetDACL is setDACL for the daemon's state directory.
func SetDACL(path, sddl string) error { return setDACL(path, sddl) }
