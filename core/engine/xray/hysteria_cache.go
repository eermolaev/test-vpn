package xray

import (
	"sync"
	"unsafe"

	_ "github.com/xtls/xray-core/transport/internet/hysteria" // for the linkname below
)

// xray keeps one Hysteria client per server address for the whole process,
// with the auth, TLS and obfs settings of the first engine that dialed it,
// and never drops it. A later engine for the same address (another password,
// pin or obfs, or a reconnect after a profile edit) would silently reuse the
// old settings, so each new engine evicts the cached client first.

// hyClientManager mirrors hysteria.clientManager; TestHysteriaSettingsChange
// fails if the layout changes in a new xray version.
type hyClientManager struct {
	m     map[string]unsafe.Pointer
	mutex sync.Mutex
}

//go:linkname hyManager github.com/xtls/xray-core/transport/internet/hysteria.manger
var hyManager *hyClientManager

// evictHysteriaClient drops the cached client for addr ("host:port"). Its
// QUIC connection, if any, closes after the idle timeout.
func evictHysteriaClient(addr string) {
	m := hyManager
	if m == nil {
		return
	}
	m.mutex.Lock()
	delete(m.m, addr)
	m.mutex.Unlock()
}
