package xray

import (
	"context"
	"testing"
	"time"

	"github.com/eermolaev/test-vpn/core/errclass"
	"github.com/eermolaev/test-vpn/core/internal/testenv"
	"github.com/eermolaev/test-vpn/core/profile"
)

func TestProxies(t *testing.T) {
	srv := testenv.StartProxies(t)
	echo := testenv.StartEcho(t, "echo:")
	for _, c := range []struct {
		cfg *profile.ProxyConfig
		udp bool
	}{{srv.SOCKS, true}, {srv.HTTP, false}, {srv.SS, true}, {srv.SS2022, true}} {
		tr := profile.Transport{Proxy: c.cfg}
		if err := tr.Validate(); err != nil {
			t.Fatal(err)
		}
		e, err := StartProxy(c.cfg, tr.Kind, nil)
		if err != nil {
			t.Fatalf("%s: %v", tr.Kind, err)
		}
		if e.Name() != string(tr.Kind) {
			t.Fatalf("name %q", e.Name())
		}
		if c.udp {
			roundTrip(t, e, echo)
		} else {
			tcpRoundTrip(t, e, echo)
		}
		e.Close()
	}
}

func TestProxyWrongPassword(t *testing.T) {
	srv := testenv.StartProxies(t)
	echo := testenv.StartEcho(t, "echo:")
	for _, good := range []*profile.ProxyConfig{srv.SOCKS, srv.HTTP, srv.SS} {
		bad := *good
		bad.Password = "wrong"
		e, err := StartProxy(&bad, profile.KindSOCKS, nil)
		if err != nil {
			t.Fatal(err)
		}
		works := make(chan bool, 1)
		go func() { works <- tcpWorks(e, echo) }()
		ok := false
		select {
		case ok = <-works:
		case <-time.After(4 * time.Second): // a silent server ignores deadlines
		}
		if ok {
			t.Fatalf("%s with a wrong password must not pass traffic", bad.Protocol)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err = e.Diagnose(ctx, echo.UDP)
		cancel()
		if errclass.Classify(err) != errclass.ServerSilent {
			t.Fatalf("diagnose: %v", err)
		}
		e.Close()
	}
}
