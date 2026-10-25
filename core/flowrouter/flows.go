package flowrouter

import (
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eermolaev/test-vpn/core/netstack"
)

// FlowInfo is a snapshot of an active flow (for the TUI connection table).
type FlowInfo struct {
	ID    uint64    `json:"id"`
	Proto string    `json:"proto"` // tcp | udp | quic
	Dst   string    `json:"dst"`
	Host  string    `json:"host,omitempty"`
	Route string    `json:"route"` // tunnel | direct
	Start time.Time `json:"start"`
	Up    int64     `json:"up"`
	Down  int64     `json:"down"`
}

type flowEntry struct {
	info     FlowInfo
	up, down atomic.Int64
	direct   bool
	r        *Router
}

// add counts bytes in both the flow and the router totals.
func (f *flowEntry) addUp(n int) {
	f.up.Add(int64(n))
	if f.direct {
		f.r.Stats.BytesDirectUp.Add(int64(n))
	} else {
		f.r.Stats.BytesTunnelUp.Add(int64(n))
	}
}

func (f *flowEntry) addDown(n int) {
	f.down.Add(int64(n))
	if f.direct {
		f.r.Stats.BytesDirectDown.Add(int64(n))
	} else {
		f.r.Stats.BytesTunnelDown.Add(int64(n))
	}
}

// flowTable holds active flows. It only ever contains live flows, so its size
// is bounded by the number of open connections.
type flowTable struct {
	mu     sync.Mutex
	nextID uint64
	m      map[uint64]*flowEntry
}

func (r *Router) track(proto string, f netstack.Flow, d Decision) *flowEntry {
	t := &r.flows
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[uint64]*flowEntry{}
	}
	t.nextID++
	e := &flowEntry{
		info:   FlowInfo{ID: t.nextID, Proto: proto, Dst: f.Dst.String(), Host: d.Host, Route: d.Route.String(), Start: time.Now()},
		direct: d.Route == Direct,
		r:      r,
	}
	t.m[e.info.ID] = e
	return e
}

func (r *Router) untrack(e *flowEntry) {
	r.flows.mu.Lock()
	delete(r.flows.m, e.info.ID)
	r.flows.mu.Unlock()
}

// Flows returns up to n active flows, busiest first (n <= 0: all).
func (r *Router) Flows(n int) []FlowInfo {
	r.flows.mu.Lock()
	out := make([]FlowInfo, 0, len(r.flows.m))
	for _, e := range r.flows.m {
		fi := e.info
		fi.Up, fi.Down = e.up.Load(), e.down.Load()
		out = append(out, fi)
	}
	r.flows.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		ti, tj := out[i].Up+out[i].Down, out[j].Up+out[j].Down
		if ti != tj {
			return ti > tj
		}
		return out[i].ID < out[j].ID
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// ActiveFlows returns the number of active flows.
func (r *Router) ActiveFlows() int {
	r.flows.mu.Lock()
	defer r.flows.mu.Unlock()
	return len(r.flows.m)
}

// copyCounting copies src to dst, reporting progress as it goes so that
// traffic graphs are live, not updated only when a connection ends.
func copyCounting(dst, src net.Conn, buf []byte, add func(int)) error {
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
			add(n)
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
