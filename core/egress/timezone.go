package egress

import (
	_ "embed"
	"strings"
	"sync"
)

//go:embed zone.tab
var zoneTab string

var (
	tzOnce    sync.Once
	tzCountry map[string]string
)

// TimeZoneCountry returns the ISO country of an IANA time zone, or "".
func TimeZoneCountry(tz string) string {
	tzOnce.Do(func() {
		tzCountry = map[string]string{}
		for _, line := range strings.Split(zoneTab, "\n") {
			if line == "" || line[0] == '#' {
				continue
			}
			f := strings.Split(line, "\t")
			if len(f) >= 3 {
				tzCountry[f[2]] = f[0]
			}
		}
	})
	return tzCountry[tz]
}
