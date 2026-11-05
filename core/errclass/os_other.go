//go:build !windows

package errclass

func osClass(error) (Class, bool) { return "", false }
