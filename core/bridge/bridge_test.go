package vpncore

import (
	"encoding/json"
	"strings"
	"testing"
)

const link = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.10:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=www.microsoft.com&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba8#Srv"

func TestProfileFunctions(t *testing.T) {
	pj, err := ParseProfile(link)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := SummarizeProfile(pj)
	if err != nil || strings.Contains(sum, "b831381d") || !strings.Contains(sum, "vless-reality") {
		t.Fatalf("summary %s %v", sum, err)
	}
	other, err := ParseProfile(strings.Replace(link, "type=tcp&security=reality&flow=xtls-rprx-vision&", "type=xhttp&path=/p&security=reality&", 1))
	if err != nil {
		t.Fatal(err)
	}
	merged, err := MergeProfiles(pj, other)
	if err != nil {
		t.Fatal(err)
	}
	var p struct{ Transports []any }
	json.Unmarshal([]byte(merged), &p)
	if len(p.Transports) != 2 {
		t.Fatalf("merged transports %d", len(p.Transports))
	}
	if _, err := ParseProfile("nonsense"); err == nil {
		t.Fatal("bad input must fail")
	}
}

func TestValidateExclusions(t *testing.T) {
	var out struct {
		Rules      int
		Normalized string
		Errors     []struct {
			Line  int
			Error string
		}
	}
	json.Unmarshal([]byte(ValidateExclusions("Example.COM\nfull:a.b.c\n")), &out)
	if out.Rules != 2 || out.Normalized != "example.com\nfull:a.b.c\n" || len(out.Errors) != 0 {
		t.Fatalf("%+v", out)
	}
	json.Unmarshal([]byte(ValidateExclusions("ok.example\napi.ipify.org\n")), &out)
	if len(out.Errors) != 1 || out.Errors[0].Line != 2 {
		t.Fatalf("%+v", out)
	}
	if !strings.Contains(ProtectedHosts(), "api.ipify.org") {
		t.Fatal("protected hosts")
	}
}

type fakeWriter struct{ n int }

func (f *fakeWriter) WritePacket([]byte) { f.n++ }

func TestStartErrors(t *testing.T) {
	if _, err := StartWithCallbacks("{", &fakeWriter{}, nil, nil, nil); err == nil || ErrorClass(err) != "config" {
		t.Fatalf("bad json: %v", err)
	}
	if _, err := StartWithFD(`{}`, 3, nil, nil, nil); err == nil {
		t.Fatal("fd mode must fail off Darwin")
	}
	if ErrorMessage("udp_timeout") == "" {
		t.Fatal("message")
	}
}
