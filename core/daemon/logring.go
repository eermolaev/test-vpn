package daemon

import (
	"sync"
	"time"
)

const logCapacity = 500

type logRing struct {
	mu    sync.Mutex
	lines []LogLine
	seq   uint64
}

func (r *logRing) add(text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	r.lines = append(r.lines, LogLine{Seq: r.seq, Time: time.Now(), Text: text})
	if len(r.lines) > logCapacity {
		r.lines = r.lines[len(r.lines)-logCapacity:]
	}
}

func (r *logRing) after(seq uint64) []LogLine {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []LogLine{}
	for _, l := range r.lines {
		if l.Seq > seq {
			out = append(out, l)
		}
	}
	return out
}
