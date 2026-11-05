package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/eermolaev/test-vpn/core/platform"
)

const (
	defaultDir = "/var/lib/testvpn"
	unitName   = "testvpn.service"
	unitPath   = "/etc/systemd/system/" + unitName
	logHint    = "journalctl -u testvpn"
)

func newPlatform() platform.Platform { return platform.NewLinux(statePath(), nil) }

const unitTemplate = `[Unit]
Description=TestVPN daemon (AmneziaWG and VLESS+REALITY client)
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=%s daemon
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
`

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func haveSystemd() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

// daemonRunning reports whether any "testvpn daemon" process is alive.
func daemonRunning() bool {
	return exec.Command("pgrep", "-f", binPath+" daemon").Run() == nil
}

func serviceActive() bool {
	return exec.Command("systemctl", "is-active", "--quiet", unitName).Run() == nil
}

// stopService stops the unit and waits until the old process has exited. On
// SIGTERM the daemon keeps the desired state, so a connected VPN stays
// blocked (no leak) and the next daemon reconnects.
func stopService() error {
	if !serviceActive() && !daemonRunning() {
		return nil
	}
	fmt.Println("stopping the running service…")
	systemctl("stop", unitName)
	if waitUntil(15*time.Second, func() bool { return !serviceActive() && !daemonRunning() }) {
		return nil
	}
	fmt.Println("the service did not stop in time; killing it")
	systemctl("kill", "--signal=SIGKILL", unitName)
	exec.Command("pkill", "-9", "-f", binPath+" daemon").Run()
	if !waitUntil(5*time.Second, func() bool { return !serviceActive() && !daemonRunning() }) {
		return errors.New("could not stop the running service; try: sudo systemctl stop " + unitName)
	}
	return nil
}

func install() error {
	if err := requireRoot(); err != nil {
		return err
	}
	if !haveSystemd() {
		return errors.New("systemd is not running: start the service yourself with `sudo testvpn daemon`")
	}
	uid, err := installerUID()
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
	if err := os.MkdirAll(filepath.Dir(binPath), 0o755); err != nil {
		return err
	}
	if self != binPath {
		if err := copyFile(self, binPath, 0o755); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(ownerFile(), []byte(uid+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(unitPath, []byte(fmt.Sprintf(unitTemplate, binPath)), 0o644); err != nil {
		return err
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if err := systemctl("enable", "--now", unitName); err != nil {
		return err
	}
	st, err := waitForService()
	if err != nil {
		return err
	}
	fmt.Printf("installed: service %s is running, build %s\n", unitName, st.Build)
	fmt.Println("open the dashboard with: testvpn")
	return nil
}

func uninstall(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	purge := len(args) > 0 && args[0] == "--purge"
	disconnectRunning()
	if haveSystemd() {
		systemctl("disable", unitName)
	}
	if err := stopService(); err != nil {
		fmt.Fprintln(os.Stderr, "warning:", err)
	}
	os.Remove(unitPath)
	if haveSystemd() {
		systemctl("daemon-reload")
	}
	os.Remove(*socketPath)
	if err := platform.Unblock(statePath(), nil); err != nil {
		fmt.Fprintln(os.Stderr, "warning:", err)
	}
	os.Remove(binPath)
	if purge {
		os.RemoveAll(*stateDir)
	}
	fmt.Println("uninstalled")
	return nil
}
