//go:build !darwin && !linux

package daemon

func bootTime() int64 { return 0 }
