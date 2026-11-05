//go:build !darwin && !linux && !windows

package direct

func bindToInterface(uintptr, int, string) error { return nil }
