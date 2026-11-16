package xray

import (
	"context"
	"testing"
	"time"

	"github.com/eermolaev/test-vpn/core/errclass"
	"github.com/eermolaev/test-vpn/core/internal/testenv"
	"github.com/eermolaev/test-vpn/core/profile"
)

func TestVMessAndTrojan(t *testing.T) {
	srv := testenv.StartReality(t)
	echo := testenv.StartEcho(t, "echo:")
	for _, c := range []*profile.VLESSConfig{srv.Trojan, srv.VMess, srv.VMessWS} {
		tr := profile.Transport{VLESS: c}
		if err := tr.Validate(); err != nil {
			t.Fatal(err)
		}
		e, err := Start(c, nil)
		if err != nil {
			t.Fatalf("%s: %v", tr.ID(), err)
		}
		if e.Name() != string(tr.Kind) {
			t.Fatalf("name %q, kind %q", e.Name(), tr.Kind)
		}
		roundTrip(t, e, echo)
		e.Close()
	}
}

func TestVMessAndTrojanWrongCredentials(t *testing.T) {
	srv := testenv.StartReality(t)
	echo := testenv.StartEcho(t, "echo:")
	trojan, vmess := *srv.Trojan, *srv.VMess
	trojan.Password = "wrong"
	vmess.UUID = "00000000-0000-4000-8000-000000000000"
	for _, c := range []*profile.VLESSConfig{&trojan, &vmess} {
		e, err := Start(c, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !failsWithin(e, echo, 4*time.Second) {
			t.Fatalf("%s with wrong credentials must not pass traffic", c.Proto())
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err = e.Diagnose(ctx, echo.UDP)
		cancel()
		if cl := errclass.Classify(err); cl == errclass.None || cl == errclass.Config {
			t.Fatalf("%s diagnose: %v", c.Proto(), err)
		}
		t.Logf("%s: %v", c.Proto(), err)
		e.Close()
	}
}
