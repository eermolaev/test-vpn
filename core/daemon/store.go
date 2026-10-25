package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/eermolaev/test-vpn/core/profile"
)

type storedProfile struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	ExpectedCountry string           `json:"expectedCountry,omitempty"`
	ManualTransport string           `json:"manualTransport,omitempty"`
	Profile         *profile.Profile `json:"profile"`
}

type storeData struct {
	Profiles  []storedProfile   `json:"profiles"`
	Selected  string            `json:"selected,omitempty"`
	Settings  Settings          `json:"settings"`
	Connected bool              `json:"connected"` // desired state, restored after restart
	Memory    map[string]string `json:"memory,omitempty"`
}

// store keeps everything in one root-only JSON file (profiles contain keys).
type store struct {
	path string
	mu   sync.Mutex
	d    storeData
}

func openStore(dir string) (*store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &store{path: filepath.Join(dir, "config.json"), d: storeData{Settings: DefaultSettings()}}
	if b, err := os.ReadFile(s.path); err == nil {
		if err := json.Unmarshal(b, &s.d); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *store) saveLocked() error {
	b, err := json.MarshalIndent(s.d, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *store) update(f func(*storeData) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := f(&s.d); err != nil {
		return err
	}
	return s.saveLocked()
}

func (s *store) view() storeData {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.d
	d.Profiles = append([]storedProfile(nil), s.d.Profiles...)
	return d
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// memoryStore persists the per-network transport memory in the store.
type memoryStore struct{ s *store }

func (m memoryStore) Load() map[string]string {
	return m.s.view().Memory
}

func (m memoryStore) Save(v map[string]string) {
	m.s.update(func(d *storeData) error { d.Memory = v; return nil })
}
