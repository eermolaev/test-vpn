//go:build darwin

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/eermolaev/test-vpn/core/daemon"
	"github.com/eermolaev/test-vpn/core/ipc"
	"github.com/eermolaev/test-vpn/core/platform"
)

const (
	binPath   = "/usr/local/bin/testvpn"
	plistPath = "/Library/LaunchDaemons/" + label + ".plist"
	logPath   = "/Library/Logs/testvpn.log"
)

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("this command needs root: run it with sudo")
	}
	return nil
}

func ownerFile() string { return filepath.Join(*stateDir, "owner") }
func statePath() string { return filepath.Join(*stateDir, "system-state.json") }

func runDaemon() error {
	if err := requireRoot(); err != nil {
		return err
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		return err
	}
	owner := -1
	if b, err := os.ReadFile(ownerFile()); err == nil {
		owner, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	if owner < 0 {
		owner = 0 // root only until installed by a user
	}
	plat := platform.NewDarwin(statePath(), nil)
	d, err := daemon.New(daemon.Options{Dir: *stateDir, Platform: plat})
	if err != nil {
		return err
	}
	srv, err := ipc.Listen(*socketPath, owner, d.Handle)
	if err != nil {
		return err
	}
	d.Start()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	srv.Close()
	d.Shutdown()
	os.Remove(*socketPath)
	return nil
}

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

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func launchctl(args ...string) error {
	out, err := exec.Command("launchctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func install() error {
	if err := requireRoot(); err != nil {
		return err
	}
	uid := os.Getenv("SUDO_UID")
	if uid == "" {
		return errors.New("run install with sudo from your user account (SUDO_UID is not set)")
	}
	self, err := os.Executable()
	if err != nil {
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
	launchctl("bootout", "system/"+label) // ignore: may not be loaded
	if err := launchctl("bootstrap", "system", plistPath); err != nil {
		return err
	}
	launchctl("enable", "system/"+label)
	fmt.Println("installed: service", label, "is running; open the dashboard with: testvpn")
	return nil
}

func uninstall(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	purge := len(args) > 0 && args[0] == "--purge"
	if c, err := ipc.Dial(*socketPath); err == nil {
		c.Call(daemon.CmdDisconnect, nil, nil)
		c.Close()
	}
	launchctl("bootout", "system/"+label)
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

func unblock() error {
	if err := requireRoot(); err != nil {
		return err
	}
	// Prefer a clean disconnect through a running daemon.
	if c, err := ipc.Dial(*socketPath); err == nil {
		defer c.Close()
		if err := c.Call(daemon.CmdDisconnect, nil, nil); err == nil {
			fmt.Println("disconnected; kill switch removed")
			return nil
		}
	}
	daemon.ResetDesiredState(*stateDir)
	if err := platform.Unblock(statePath(), nil); err != nil {
		return err
	}
	fmt.Println("kill switch removed, DNS restored")
	return nil
}
