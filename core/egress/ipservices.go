// Package egress verifies the actual exit of the tunnel (GEO-001…GEO-009):
// public IP from several services, its country from a local GeoIP database,
// WebRTC/STUN, IPv6 and bypass checks. It runs in the app process, whose
// traffic goes through the tunnel like any other app's.
package egress

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// IPService returns the caller's public IP.
type IPService struct {
	Name string
	URL  string
	// Parse extracts the IP from the body; nil means the body is the IP.
	Parse func(body string) string
}

// DefaultIPServices are queried over HTTPS through the tunnel (GEO-002).
// Their hosts are protected from exclusions (rules.ProtectedHosts).
var DefaultIPServices = []IPService{
	{Name: "ipify", URL: "https://api.ipify.org"},
	{Name: "icanhazip", URL: "https://icanhazip.com"},
	{Name: "ifconfig.co", URL: "https://ifconfig.co/ip"},
	{Name: "cloudflare", URL: "https://www.cloudflare.com/cdn-cgi/trace", Parse: parseTrace},
}

// IPv6Service answers only over IPv6; it must fail while IPv6 is blocked.
var IPv6Service = IPService{Name: "ipify64", URL: "https://api64.ipify.org"}

func parseTrace(body string) string {
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "ip="); ok {
			return v
		}
	}
	return ""
}

// SourceResult is the answer of one service.
type SourceResult struct {
	Service string `json:"service"`
	IP      string `json:"ip,omitempty"`
	Error   string `json:"error,omitempty"`
}

// IPResult is the consensus of the services.
type IPResult struct {
	IP        string         `json:"ip,omitempty"`
	Confirmed bool           `json:"confirmed"` // at least 2 services agree, none disagree
	Sources   []SourceResult `json:"sources"`
}

func fetchIP(ctx context.Context, c *http.Client, s IPService) (netip.Addr, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("User-Agent", "curl/8")
	resp, err := c.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return netip.Addr{}, err
	}
	text := strings.TrimSpace(string(b))
	if s.Parse != nil {
		text = s.Parse(text)
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(text))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("unexpected answer")
	}
	return ip.Unmap(), nil
}

// ResolveExitIP queries at least min services in random order, concurrently,
// and builds the consensus. A failing service is not a VPN error.
func ResolveExitIP(ctx context.Context, c *http.Client, services []IPService, min int, timeout time.Duration) IPResult {
	svcs := append([]IPService(nil), services...)
	rand.Shuffle(len(svcs), func(i, j int) { svcs[i], svcs[j] = svcs[j], svcs[i] })
	res := make([]SourceResult, len(svcs))
	var wg sync.WaitGroup
	for i, s := range svcs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			ip, err := fetchIP(cctx, c, s)
			res[i] = SourceResult{Service: s.Name}
			if err != nil {
				res[i].Error = err.Error()
			} else {
				res[i].IP = ip.String()
			}
		}()
	}
	wg.Wait()
	counts := map[string]int{}
	for _, r := range res {
		if r.IP != "" {
			counts[r.IP]++
		}
	}
	out := IPResult{Sources: res}
	best := 0
	for ip, n := range counts {
		if n > best {
			out.IP, best = ip, n
		}
	}
	out.Confirmed = best >= min && len(counts) == 1
	return out
}
