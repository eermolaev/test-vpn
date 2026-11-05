//go:build !darwin && !linux && !windows

package main

import "errors"

const defaultDir = "/var/lib/testvpn"

var errUnsupported = errors.New("the background service is supported on macOS, Linux and Windows")

func runDaemon() error         { return errUnsupported }
func install() error           { return errUnsupported }
func uninstall([]string) error { return errUnsupported }
func unblock() error           { return errUnsupported }
