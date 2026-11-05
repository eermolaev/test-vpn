package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/eermolaev/test-vpn/core/ipc"
	"github.com/eermolaev/test-vpn/core/platform"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName = "TestVPN"
	wintunDLL   = "wintun.dll"
	maxLogSize  = 10 << 20
)

var (
	defaultDir = filepath.Join(envDir("ProgramData", `C:\ProgramData`), "TestVPN")
	binDir     = filepath.Join(envDir("ProgramFiles", `C:\Program Files`), "TestVPN")
	binPath    = filepath.Join(binDir, "testvpn.exe")
	logHint    = filepath.Join(defaultDir, "testvpn.log")
)

func envDir(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func requireRoot() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("this command needs administrator rights: run it in an Administrator terminal")
	}
	return nil
}

// currentUserSID returns the SID of the user running this process; with UAC
// an elevated terminal still runs as the signed-in user.
func currentUserSID() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

// prepareStateDir creates the state directory, which holds profiles with
// keys: only LocalSystem and Administrators get access to its contents; the
// owner may only open the folder itself, to reach the socket.
func prepareStateDir(owner string) error {
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		return err
	}
	sddl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	if owner != "" {
		sddl += "(A;;0x1200a9;;;" + owner + ")" // read and traverse, not inherited
	}
	return ipc.SetDACL(*stateDir, sddl)
}

func readOwnerSID() string {
	b, err := os.ReadFile(ownerFile())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// startService prepares the state directory and starts the daemon with the
// socket restricted to the installing user.
func startService(logw io.Writer) (func(), error) {
	owner := readOwnerSID()
	if err := prepareStateDir(owner); err != nil {
		return nil, err
	}
	return startDaemon(platform.NewWindows(statePath()), logw, func(h ipc.Handler) (*ipc.Server, error) {
		return ipc.ListenSID(*socketPath, owner, h)
	})
}

// openLog opens the service log, starting over when it grew too large, and
// sends the process's stdout and stderr there: a service has no console, and
// engines (Xray) write to stderr directly.
func openLog() io.Writer {
	if fi, err := os.Stat(logHint); err == nil && fi.Size() > maxLogSize {
		os.Rename(logHint, logHint+".old")
	}
	f, err := os.OpenFile(logHint, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return io.Discard
	}
	windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, windows.Handle(f.Fd()))
	windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(f.Fd()))
	os.Stdout, os.Stderr = f, f
	log.SetOutput(f)
	return f
}

func runDaemon() error {
	if err := requireRoot(); err != nil {
		return err
	}
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if isService {
		return svc.Run(serviceName, serviceHandler{})
	}
	// Started from a terminal (debugging): log to stderr until Ctrl+C.
	stop, err := startService(os.Stderr)
	if err != nil {
		return err
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	stop()
	return nil
}

type serviceHandler struct{}

// Execute runs the daemon under the service control manager. On stop and
// shutdown the daemon keeps the desired state, so the next start reconnects.
func (serviceHandler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	os.MkdirAll(*stateDir, 0o700)
	logw := openLog()
	stop, err := startService(logw)
	if err != nil {
		fmt.Fprintln(logw, "start failed:", err)
		return true, 1
	}
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range req {
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			stop()
			return false, 0
		}
	}
	stop()
	return false, 0
}

func openService(m *mgr.Mgr) (*mgr.Service, error) { return m.OpenService(serviceName) }

// stopService stops the service and waits until it has stopped.
func stopService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := openService(m)
	if err != nil {
		return nil // not installed
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil || st.State == svc.Stopped {
		return nil
	}
	fmt.Println("stopping the running service…")
	s.Control(svc.Stop)
	stopped := func() bool {
		st, err := s.Query()
		return err != nil || st.State == svc.Stopped
	}
	if waitUntil(15*time.Second, stopped) {
		return nil
	}
	fmt.Println("the service did not stop in time; killing it")
	if st, err := s.Query(); err == nil && st.ProcessId != 0 {
		if h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, st.ProcessId); err == nil {
			windows.TerminateProcess(h, 1)
			windows.CloseHandle(h)
		}
	}
	if !waitUntil(5*time.Second, stopped) {
		return errors.New("could not stop the running service; try: sc stop " + serviceName)
	}
	return nil
}

// copyWintun puts wintun.dll next to the installed binary. It is taken from
// the directory of the running executable; without it the service starts but
// cannot create the tunnel adapter.
func copyWintun(self string) {
	dst := filepath.Join(binDir, wintunDLL)
	src := filepath.Join(filepath.Dir(self), wintunDLL)
	if _, err := os.Stat(src); err == nil && !strings.EqualFold(src, dst) {
		if err := copyFile(src, dst, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "warning: copy wintun.dll:", err)
		}
		return
	}
	if _, err := os.Stat(dst); err == nil {
		return
	}
	sys32 := filepath.Join(envDir("SystemRoot", `C:\Windows`), "System32", wintunDLL)
	if _, err := os.Stat(sys32); err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "warning: %s not found next to testvpn.exe; download it from https://www.wintun.net (bin\\amd64 or bin\\arm64) and put it into %s, or install again with it next to testvpn.exe\n", wintunDLL, binDir)
}

func install() error {
	if err := requireRoot(); err != nil {
		return err
	}
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := stopService(); err != nil {
		return err
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}
	if !strings.EqualFold(self, binPath) {
		if err := copyFile(self, binPath, 0o755); err != nil {
			return err
		}
	}
	copyWintun(self)
	if err := prepareStateDir(sid); err != nil {
		return err
	}
	if err := os.WriteFile(ownerFile(), []byte(sid+"\n"), 0o600); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := openService(m)
	if err == nil {
		cfg, err := s.Config()
		if err == nil {
			cfg.BinaryPathName = `"` + binPath + `" daemon`
			cfg.StartType = mgr.StartAutomatic
			err = s.UpdateConfig(cfg)
		}
		if err != nil {
			s.Close()
			return fmt.Errorf("update service: %w", err)
		}
	} else {
		s, err = m.CreateService(serviceName, binPath, mgr.Config{
			StartType:   mgr.StartAutomatic,
			DisplayName: "TestVPN",
			Description: "AmneziaWG and VLESS+REALITY VPN client",
		}, "daemon")
		if err != nil {
			return fmt.Errorf("create service: %w", err)
		}
	}
	defer s.Close()
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: time.Second}
	s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 24*60*60)
	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	st, err := waitForService()
	if err != nil {
		return err
	}
	fmt.Printf("installed: service %s is running, build %s\n", serviceName, st.Build)
	fmt.Println("open the dashboard with: testvpn")
	return nil
}

func deleteService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := openService(m)
	if err != nil {
		return nil // not installed
	}
	defer s.Close()
	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	return nil
}

func uninstall(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	purge := len(args) > 0 && args[0] == "--purge"
	disconnectRunning()
	if err := stopService(); err != nil {
		fmt.Fprintln(os.Stderr, "warning:", err)
	}
	if err := deleteService(); err != nil {
		fmt.Fprintln(os.Stderr, "warning:", err)
	}
	os.Remove(*socketPath)
	if err := platform.Unblock(statePath(), nil); err != nil {
		fmt.Fprintln(os.Stderr, "warning:", err)
	}
	if err := os.RemoveAll(binDir); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not remove %s (is it running from there?): %v\n", binDir, err)
	}
	if purge {
		os.RemoveAll(*stateDir)
	}
	fmt.Println("uninstalled")
	return nil
}
