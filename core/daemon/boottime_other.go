//go:build !darwin && !linux && !windows

package daemon

func bootTime() int64 { return 0 }
