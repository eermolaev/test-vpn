//go:build darwin || linux

package main

import (
	"errors"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/eermolaev/test-vpn/core/ipc"
)

const binPath = "/usr/local/bin/testvpn"

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("this command needs root: run it with sudo")
	}
	return nil
}

// installerUID returns the user who ran `sudo testvpn install`; only that
// user (and root) may talk to the daemon.
func installerUID() (string, error) {
	uid := os.Getenv("SUDO_UID")
	if uid == "" {
		return "", errors.New("run install with sudo from your user account (SUDO_UID is not set)")
	}
	return uid, nil
}

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
	stop, err := startDaemon(newPlatform(), os.Stderr, func(h ipc.Handler) (*ipc.Server, error) {
		return ipc.Listen(*socketPath, owner, h)
	})
	if err != nil {
		return err
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	stop()
	return nil
}
