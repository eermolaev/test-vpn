//go:build !darwin

package main

import "errors"

var errDarwinOnly = errors.New("the background service is only supported on macOS")

func runDaemon() error         { return errDarwinOnly }
func install() error           { return errDarwinOnly }
func uninstall([]string) error { return errDarwinOnly }
func unblock() error           { return errDarwinOnly }
