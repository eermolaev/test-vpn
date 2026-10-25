package ipc

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sock")
	srv, err := Listen(path, os.Getuid(), func(cmd string, args json.RawMessage) (any, error) {
		switch cmd {
		case "echo":
			var s string
			json.Unmarshal(args, &s)
			return map[string]string{"got": s}, nil
		case "fail":
			return nil, errors.New("boom")
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode: %v %v", fi.Mode(), err)
	}
	cl, err := Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var out map[string]string
			if err := cl.Call("echo", "hi", &out); err != nil || out["got"] != "hi" {
				t.Errorf("echo: %v %v", out, err)
			}
		}()
	}
	wg.Wait()
	if err := cl.Call("fail", nil, nil); err == nil || err.Error() != "boom" {
		t.Fatalf("error: %v", err)
	}
}

func TestPeerCheckRejectsOtherUsers(t *testing.T) {
	if os.Getuid() == 12345 {
		t.Skip()
	}
	path := filepath.Join(t.TempDir(), "s.sock")
	// Allowed uid differs from ours; root is still allowed, so skip as root.
	if os.Getuid() == 0 {
		t.Skip("root is always allowed")
	}
	srv, err := Listen(path, 12345, func(string, json.RawMessage) (any, error) { return "x", nil })
	if err != nil {
		t.Skip("cannot chown socket:", err)
	}
	defer srv.Close()
	cl, err := Dial(path)
	if err != nil {
		return // refused by permissions: fine
	}
	defer cl.Close()
	if err := cl.Call("x", nil, nil); err == nil {
		t.Fatal("other user must be rejected")
	}
}

func TestNotRunning(t *testing.T) {
	if _, err := Dial(filepath.Join(t.TempDir(), "missing.sock")); !errors.Is(err, ErrNotRunning) {
		t.Fatal(err)
	}
}
