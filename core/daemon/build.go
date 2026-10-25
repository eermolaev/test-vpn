package daemon

import (
	"runtime/debug"
	"time"
)

// Build describes the running binary, so that an update can be verified.
func Build() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return Version
	}
	return formatBuild(info.Settings)
}

func formatBuild(settings []debug.BuildSetting) string {
	var rev, when string
	modified := false
	for _, s := range settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.time":
			if t, err := time.Parse(time.RFC3339, s.Value); err == nil {
				when = t.UTC().Format("2006-01-02 15:04")
			}
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	out := Version
	if rev != "" {
		if len(rev) > 12 {
			rev = rev[:12]
		}
		out += " " + rev
		if modified {
			out += "+dirty"
		}
	}
	if when != "" {
		out += " (" + when + ")"
	}
	return out
}
