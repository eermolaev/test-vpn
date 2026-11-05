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
	defaultDir = "/Library/Application Support/TestVPN"
	label      = "com.testvpn.daemon"
	plistPath  = "/Library/LaunchDaemons/" + label + ".plist"
	logPath    = "/Library/Logs/testvpn.log"
	logHint    = logPath
	service    = "system/" + label
)

func newPlatform() platform.Platform { return platform.NewDarwin(statePath(), nil) }

const plistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>daemon</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`

func launchctl(args ...string) error {
	out, err := exec.Command("launchctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func serviceLoaded() bool { return exec.Command("launchctl", "print", service).Run() == nil }

// daemonRunning reports whether any "testvpn daemon" process is alive.
func daemonRunning() bool {
	return exec.Command("pgrep", "-f", binPath+" daemon").Run() == nil
}

// stopService unloads the LaunchDaemon and waits until the old process has
// exited. On SIGTERM the daemon keeps the desired state, so a connected VPN
// stays blocked (no leak) and the next daemon reconnects.
func stopService() error {
	if !serviceLoaded() && !daemonRunning() {
		return nil
	}
	fmt.Println("stopping the running service…")
	launchctl("bootout", service)
	if waitUntil(15*time.Second, func() bool { return !serviceLoaded() && !daemonRunning() }) {
		return nil
	}
	fmt.Println("the service did not stop in time; killing it")
	launchctl("kill", "SIGKILL", service)
	exec.Command("pkill", "-9", "-f", binPath+" daemon").Run()
	launchctl("bootout", service)
	if !waitUntil(5*time.Second, func() bool { return !serviceLoaded() && !daemonRunning() }) {
		return errors.New("could not stop the running service; try: sudo launchctl bootout " + service)
	}
	return nil
}

func install() error {
	if err := requireRoot(); err != nil {
		return err
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
	plist := fmt.Sprintf(plistTemplate, label, binPath, logPath, logPath)
	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
		return err
	}
	launchctl("enable", service)
	if err := launchctl("bootstrap", "system", plistPath); err != nil {
		return err
	}
	st, err := waitForService()
	if err != nil {
		return err
	}
	fmt.Printf("installed: service %s is running, build %s\n", label, st.Build)
	fmt.Println("open the dashboard with: testvpn")
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
	os.Remove(plistPath)
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
