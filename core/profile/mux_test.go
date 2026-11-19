package profile

import (
	"errors"
	"strings"
	"testing"
)

func TestMuxLink(t *testing.T) {
	const base = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?security=reality&sni=a.com&pbk=" + testPBK + "&type=tcp"
	p, err := Parse(base + "&mux=8#x")
	if err != nil {
		t.Fatal(err)
	}
	c := p.Transports[0].VLESS
	if c.Mux != 8 {
		t.Fatalf("mux %d", c.Mux)
	}
	if s := p.Summarize().Transports[0].Detail; !strings.Contains(s, "mux") {
		t.Fatalf("summary %q", s)
	}
	if u := FormatVLESSURL(c, "x"); !strings.Contains(u, "mux=8") {
		t.Fatalf("link %s", u)
	}
	// Trojan reads it too.
	p, err = Parse("trojan://secret-pw@1.2.3.4:443?security=reality&sni=a.com&pbk=" + testPBK + "&mux=4")
	if err != nil || p.Transports[0].VLESS.Mux != 4 {
		t.Fatalf("trojan: %v", err)
	}

	for name, link := range map[string]string{
		"with flow": base + "&flow=xtls-rprx-vision&mux=8",
		"negative":  base + "&mux=-1",
		"too large": base + "&mux=5000",
		"not int":   base + "&mux=yes",
	} {
		if _, err := Parse(link); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// xhttp and gRPC multiplex by themselves: mux is dropped.
	p, err = Parse(strings.Replace(base, "type=tcp", "type=xhttp&path=/x", 1) + "&mux=8")
	if err != nil || p.Transports[0].VLESS.Mux != 0 {
		t.Fatalf("xhttp: %v", err)
	}
}

func TestMuxXrayJSON(t *testing.T) {
	js := func(flow, mux string) string {
		return `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"1.2.3.4","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none","flow":"` + flow + `"}]}]},
"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"a.com","publicKey":"` + testPBK + `"}},"mux":` + mux + `}]}`
	}
	for _, tc := range []struct {
		flow, mux string
		want      int
	}{
		{"", `{"enabled":true,"concurrency":16}`, 16},
		{"", `{"enabled":true}`, DefaultMux},
		{"", `{"enabled":false,"concurrency":16}`, 0},
		{"", `{"enabled":true,"concurrency":-1}`, 0},
		{"xtls-rprx-vision", `{"enabled":true,"concurrency":8}`, 0},
	} {
		p, err := Parse(js(tc.flow, tc.mux))
		if err != nil {
			t.Fatalf("%s %s: %v", tc.flow, tc.mux, err)
		}
		if got := p.Transports[0].VLESS.Mux; got != tc.want {
			t.Errorf("%s %s: mux %d, want %d", tc.flow, tc.mux, got, tc.want)
		}
	}
}

// Importing a transport the profile already has updates its settings.
func TestMergeReplaces(t *testing.T) {
	const link = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?security=reality&sni=a.com&pbk=" + testPBK + "&type=tcp"
	p, err := Parse(link + "#main")
	if err != nil {
		t.Fatal(err)
	}
	q, err := Parse(link + "&mux=8")
	if err != nil {
		t.Fatal(err)
	}
	other, _ := Parse("vless://b831381d-6324-4d53-ad4f-8cda48b30811@5.6.7.8:443?security=reality&sni=a.com&pbk=" + testPBK)
	q.Transports = append(q.Transports, other.Transports...)
	p.Merge(q)
	if len(p.Transports) != 2 {
		t.Fatalf("%d transports", len(p.Transports))
	}
	if tr := p.Transports[0]; tr.VLESS.Mux != 8 || tr.Label != "main" {
		t.Fatalf("not updated: mux %d label %q", tr.VLESS.Mux, tr.Label)
	}
}
