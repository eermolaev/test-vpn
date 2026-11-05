//go:build darwin || linux || windows

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/eermolaev/test-vpn/core/daemon"
	"github.com/eermolaev/test-vpn/core/ipc"
	"github.com/eermolaev/test-vpn/core/platform"
)

func ownerFile() string { return filepath.Join(*stateDir, "owner") }
func statePath() string { return filepath.Join(*stateDir, "system-state.json") }

// startDaemon starts the daemon on plat and serves it on the socket opened by
// listen; the returned function stops both.
func startDaemon(plat platform.Platform, logw io.Writer, listen func(ipc.Handler) (*ipc.Server, error)) (func(), error) {
	d, err := daemon.New(daemon.Options{Dir: *stateDir, Platform: plat, LogWriter: logw})
	if err != nil {
		return nil, err
	}
	srv, err := listen(d.Handle)
	if err != nil {
		return nil, err
	}
	d.Start()
	return func() {
		srv.Close()
		d.Shutdown()
		os.Remove(*socketPath)
	}, nil
}

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

func waitUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return cond()
}

// waitForService waits until the new daemon answers on its socket.
func waitForService() (daemon.Status, error) {
	var st daemon.Status
	var lastErr error
	ok := waitUntil(15*time.Second, func() bool {
		c, err := ipc.Dial(*socketPath)
		if err != nil {
			lastErr = err
			return false
		}
		defer c.Close()
		lastErr = c.Call(daemon.CmdStatus, nil, &st)
		return lastErr == nil
	})
	if !ok {
		return st, fmt.Errorf("the service did not start (%v); see %s", lastErr, logHint)
	}
	return st, nil
}

// disconnectRunning asks a running daemon to disconnect, which removes the
// kill switch and restores DNS; it reports whether that worked.
func disconnectRunning() bool {
	c, err := ipc.Dial(*socketPath)
	if err != nil {
		return false
	}
	defer c.Close()
	return c.Call(daemon.CmdDisconnect, nil, nil) == nil
}

func unblock() error {
	if err := requireRoot(); err != nil {
		return err
	}
	// Prefer a clean disconnect through a running daemon.
	if disconnectRunning() {
		fmt.Println("disconnected; kill switch removed")
		return nil
	}
	daemon.ResetDesiredState(*stateDir)
	if err := platform.Unblock(statePath(), nil); err != nil {
		return err
	}
	fmt.Println("kill switch removed, DNS restored")
	return nil
}
