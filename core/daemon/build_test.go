package daemon

import (
	"runtime/debug"
	"testing"
)

func TestFormatBuild(t *testing.T) {
	got := formatBuild([]debug.BuildSetting{
		{Key: "vcs.revision", Value: "d503238abcdef0123456789"},
		{Key: "vcs.time", Value: "2026-10-25T10:30:00Z"},
		{Key: "vcs.modified", Value: "true"},
	})
	if got != Version+" d503238abcde+dirty (2026-10-25 10:30)" {
		t.Fatal(got)
	}
	if formatBuild(nil) != Version {
		t.Fatal("no vcs info")
	}
}
