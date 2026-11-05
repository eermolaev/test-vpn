//go:build windows

package daemon

import (
	"time"

	"golang.org/x/sys/windows"
)

// bootTime derives the boot time from the uptime. It is rounded to 10 s so
// that repeated calls (and small clock corrections) give the same value.
func bootTime() int64 {
	t := time.Now().Add(-windows.DurationSinceBoot()).Unix()
	return (t + 5) / 10 * 10
}
