package egress

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// DBIPBaseURL serves the free DB-IP Lite databases (CC BY 4.0; the app shows
// the attribution "IP Geolocation by DB-IP").
const DBIPBaseURL = "https://download.db-ip.com/free"

// GeoIPFileName is the file the app stores in its container.
const GeoIPFileName = "dbip-country-lite.mmdb"

const maxDBSize = 64 << 20

// UpdateGeoIP downloads the DB-IP Lite Country database for the current
// month (falling back to the previous month early in a month), validates it
// and atomically replaces dir/GeoIPFileName (GEO-008).
func UpdateGeoIP(ctx context.Context, c *http.Client, baseURL, dir string, now time.Time) (string, error) {
	if c == nil {
		c = &http.Client{Timeout: 2 * time.Minute}
	}
	if baseURL == "" {
		baseURL = DBIPBaseURL
	}
	var lastErr error
	for _, m := range []time.Time{now, now.AddDate(0, -1, 0)} {
		url := fmt.Sprintf("%s/dbip-country-lite-%s.mmdb.gz", baseURL, m.Format("2006-01"))
		path, err := download(ctx, c, url, dir)
		if err == nil {
			return path, nil
		}
		lastErr = err
	}
	return "", lastErr
}

func download(ctx context.Context, c *http.Client, url, dir string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("geoip download: HTTP %d", resp.StatusCode)
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return "", fmt.Errorf("geoip download: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "geoip-*.tmp")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(zr, maxDBSize+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if n > maxDBSize {
		return "", fmt.Errorf("geoip download: database too large")
	}
	g, err := OpenGeoIP(tmp.Name())
	if err != nil {
		return "", fmt.Errorf("geoip download: invalid database: %w", err)
	}
	g.Close()
	dst := filepath.Join(dir, GeoIPFileName)
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return "", err
	}
	return dst, nil
}
