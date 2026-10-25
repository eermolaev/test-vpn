package egress

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func ipServer(t *testing.T, body string) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
	t.Cleanup(s.Close)
	return s.URL
}

func services(t *testing.T, bodies ...string) []IPService {
	var out []IPService
	for i, b := range bodies {
		out = append(out, IPService{Name: fmt.Sprint("s", i), URL: ipServer(t, b)})
	}
	return out
}

func TestConsensus(t *testing.T) {
	ctx := context.Background()
	c := http.DefaultClient
	r := ResolveExitIP(ctx, c, services(t, "203.0.113.7\n", "203.0.113.7"), 2, time.Second)
	if r.IP != "203.0.113.7" || !r.Confirmed {
		t.Fatalf("agree: %+v", r)
	}
	r = ResolveExitIP(ctx, c, services(t, "203.0.113.7", "198.51.100.1", "203.0.113.7"), 2, time.Second)
	if r.IP != "203.0.113.7" || r.Confirmed {
		t.Fatalf("disagree must be unconfirmed: %+v", r)
	}
	dead := IPService{Name: "dead", URL: "http://127.0.0.1:1"}
	r = ResolveExitIP(ctx, c, append(services(t, "203.0.113.7"), dead), 2, time.Second)
	if r.Confirmed || r.IP != "203.0.113.7" {
		t.Fatalf("one source is not enough: %+v", r)
	}
	trace := IPService{Name: "trace", URL: ipServer(t, "fl=1\nip=203.0.113.7\nts=1"), Parse: parseTrace}
	r = ResolveExitIP(ctx, c, append(services(t, "203.0.113.7"), trace), 2, time.Second)
	if !r.Confirmed {
		t.Fatalf("cloudflare trace format: %+v", r)
	}
}

func testGeoIP(t *testing.T) *GeoIP {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "DBIP-Country-Lite", BuildEpoch: 1760000000, Description: map[string]string{"en": "DB-IP Lite test"}, RecordSize: 24, IncludeReservedNetworks: true})
	if err != nil {
		t.Fatal(err)
	}
	add := func(cidr, iso, name string) {
		_, n, _ := net.ParseCIDR(cidr)
		tree.Insert(n, mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(iso), "names": mmdbtype.Map{"en": mmdbtype.String(name)}}})
	}
	add("203.0.113.0/24", "FR", "France")
	add("198.51.100.0/24", "DE", "Germany")
	var buf bytes.Buffer
	if _, err := tree.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	g, err := OpenGeoIPBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestGeoIP(t *testing.T) {
	g := testGeoIP(t)
	c := g.Lookup(netip.MustParseAddr("203.0.113.7"))
	if c.ISO != "FR" || c.Name != "France" || c.Source != "DB-IP Lite test" || c.BuildDate.Year() != 2025 {
		t.Fatalf("%+v", c)
	}
	if c := g.Lookup(netip.MustParseAddr("192.0.2.1")); c.Error == "" {
		t.Fatal("unknown address must report an error")
	}
}

// stunServer answers Binding Requests with a fixed mapped address.
func stunServer(t *testing.T, mapped netip.AddrPort) string {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, a, err := pc.ReadFrom(buf)
			if err != nil || n < 20 {
				return
			}
			resp := make([]byte, 20, 32)
			binary.BigEndian.PutUint16(resp[0:], 0x0101)
			binary.BigEndian.PutUint16(resp[2:], 12)
			binary.BigEndian.PutUint32(resp[4:], stunMagic)
			copy(resp[8:20], buf[8:20])
			attr := make([]byte, 12)
			binary.BigEndian.PutUint16(attr[0:], 0x0020)
			binary.BigEndian.PutUint16(attr[2:], 8)
			attr[5] = 0x01
			binary.BigEndian.PutUint16(attr[6:], mapped.Port()^uint16(stunMagic>>16))
			ip := mapped.Addr().As4()
			binary.BigEndian.PutUint32(attr[8:], binary.BigEndian.Uint32(ip[:])^stunMagic)
			pc.WriteTo(append(resp, attr...), a)
		}
	}()
	return pc.LocalAddr().String()
}

func TestSTUN(t *testing.T) {
	addr := stunServer(t, netip.MustParseAddrPort("203.0.113.7:40000"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ap, err := STUNMappedAddress(ctx, &net.Dialer{}, addr)
	if err != nil || ap.String() != "203.0.113.7:40000" {
		t.Fatalf("%v %v", ap, err)
	}
}

func failingClient() *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("blocked by includeAllNetworks")
	}}}
}

func findings(r Result) map[string]Severity {
	m := map[string]Severity{}
	for _, f := range r.Findings {
		m[f.Code] = f.Severity
	}
	return m
}

func TestCheckClean(t *testing.T) {
	r := Check(context.Background(), Config{
		ExpectedCountry: "fr",
		Services:        services(t, "203.0.113.7", "203.0.113.7"),
		IPv6Client:      failingClient(),
		STUNServers:     []string{stunServer(t, netip.MustParseAddrPort("203.0.113.7:1"))},
		GeoIP:           testGeoIP(t),
		BypassClient:    failingClient(),
		TimeZone:        "Europe/Paris",
		Timeout:         time.Second,
	})
	if r.Country.ISO != "FR" || r.CountryMatch == nil || !*r.CountryMatch || !r.IPv6.Blocked || !r.Bypass.Blocked || r.STUN.IP != "203.0.113.7" {
		t.Fatalf("%s", r.JSON())
	}
	if len(r.Findings) != 0 {
		t.Fatalf("clean check has findings: %+v", r.Findings)
	}
}

func TestCheckProblems(t *testing.T) {
	r := Check(context.Background(), Config{
		ExpectedCountry: "DE",
		Services:        services(t, "203.0.113.7", "203.0.113.7"),
		IPv6Service:     &IPService{Name: "v6", URL: ipServer(t, "2001:db8::1")},
		IPv6Client:      http.DefaultClient,
		STUNServers:     []string{stunServer(t, netip.MustParseAddrPort("192.0.2.50:1"))},
		GeoIP:           testGeoIP(t),
		BypassClient:    http.DefaultClient,
		TimeZone:        "Europe/Moscow",
		Exclusions:      3,
		Timeout:         time.Second,
	})
	f := findings(r)
	want := map[string]Severity{
		"country_mismatch":  Warning,
		"ipv6_leak":         Critical,
		"webrtc_leak":       Critical,
		"bypass":            Critical,
		"timezone_mismatch": Info,
		"exclusions_active": Info,
	}
	for code, sev := range want {
		if f[code] != sev {
			t.Errorf("finding %s = %q, want %q", code, f[code], sev)
		}
	}
	// GEO-007: the result shows the real country, not the expected one.
	if r.Country.ISO != "FR" || *r.CountryMatch {
		t.Fatal("country must be the real one")
	}
}

func TestTimeZoneCountry(t *testing.T) {
	for tz, want := range map[string]string{"Europe/Berlin": "DE", "Europe/Moscow": "RU", "America/New_York": "US", "Nowhere/City": ""} {
		if got := TimeZoneCountry(tz); got != want {
			t.Errorf("%s = %q, want %q", tz, got, want)
		}
	}
}

func TestUpdateGeoIP(t *testing.T) {
	tree, _ := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "DBIP-Country-Lite", IncludeReservedNetworks: true})
	_, n, _ := net.ParseCIDR("203.0.113.0/24")
	tree.Insert(n, mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String("FR")}})
	var db bytes.Buffer
	tree.WriteTo(&db)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(db.Bytes())
	zw.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dbip-country-lite-2026-09.mmdb.gz" { // current month not yet published
			http.NotFound(w, r)
			return
		}
		w.Write(gz.Bytes())
	}))
	defer srv.Close()
	dir := t.TempDir()
	path, err := UpdateGeoIP(context.Background(), nil, srv.URL, dir, time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	g, err := OpenGeoIP(path)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if c := g.Lookup(netip.MustParseAddr("203.0.113.9")); c.ISO != "FR" {
		t.Fatalf("%+v", c)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zw := gzip.NewWriter(w)
		zw.Write([]byte("not a database"))
		zw.Close()
	}))
	defer bad.Close()
	if _, err := UpdateGeoIP(context.Background(), nil, bad.URL, dir, time.Now()); err == nil {
		t.Fatal("invalid database must be rejected")
	}
	if g2, err := OpenGeoIP(path); err != nil {
		t.Fatal("previous database must survive a failed update")
	} else {
		g2.Close()
	}
}
