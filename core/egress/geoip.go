package egress

import (
	"net/netip"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Country is the GeoIP answer for an address.
type Country struct {
	ISO       string    `json:"iso,omitempty"`
	Name      string    `json:"name,omitempty"`
	Source    string    `json:"source,omitempty"`   // database type / description
	BuildDate time.Time `json:"buildDate,omitzero"` // GEO-008: data freshness
	Error     string    `json:"error,omitempty"`
}

// GeoIP looks countries up in a local MaxMind-format database (DB-IP Lite
// Country or GeoLite2 Country).
type GeoIP struct {
	r *maxminddb.Reader
}

// OpenGeoIP opens the database file.
func OpenGeoIP(path string) (*GeoIP, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &GeoIP{r: r}, nil
}

// OpenGeoIPBytes opens a database from memory.
func OpenGeoIPBytes(b []byte) (*GeoIP, error) {
	r, err := maxminddb.OpenBytes(b)
	if err != nil {
		return nil, err
	}
	return &GeoIP{r: r}, nil
}

type countryRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
}

// Lookup returns the country of ip.
func (g *GeoIP) Lookup(ip netip.Addr) Country {
	md := g.r.Metadata
	c := Country{Source: md.DatabaseType, BuildDate: time.Unix(int64(md.BuildEpoch), 0).UTC()}
	if d := md.Description["en"]; d != "" {
		c.Source = d
	}
	var rec countryRecord
	res := g.r.Lookup(ip)
	if err := res.Err(); err != nil {
		c.Error = err.Error()
		return c
	}
	if !res.Found() {
		c.Error = "address not in database"
		return c
	}
	if err := res.Decode(&rec); err != nil {
		c.Error = err.Error()
		return c
	}
	c.ISO = rec.Country.ISOCode
	c.Name = rec.Country.Names["en"]
	return c
}

// Close releases the database.
func (g *GeoIP) Close() error { return g.r.Close() }
