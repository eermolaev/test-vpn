//go:build !darwin && !linux

package direct

func bindToInterface(uintptr, int, string) error { return nil }
