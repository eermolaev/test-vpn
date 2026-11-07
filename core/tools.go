//go:build tools

// Package core pins tool dependencies: gomobile bind needs x/mobile in go.mod.
package core

import _ "golang.org/x/mobile/bind"
