package tui

import (
	"fmt"
	"math"
	"os"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
)

// TestSnapshot writes the dashboard to $TUI_SNAPSHOT for visual review.
func TestSnapshot(t *testing.T) {
	path := os.Getenv("TUI_SNAPSHOT")
	if path == "" {
		t.Skip("set TUI_SNAPSHOT to write a snapshot")
	}
	be := connectedBackend()
	m := New(be)
	exec(m, m.Init(), 0)
	for i := 0; i < 120; i++ {
		v := 2e6 + 1.5e6*math.Sin(float64(i)/7) + 8e5*math.Sin(float64(i)/2.3)
		m.down = append(m.down, math.Max(v, 0))
		m.up = append(m.up, math.Max(v/9+1e5*math.Cos(float64(i)/3), 0))
	}
	m.peakDown, m.peakUp = 4.3e6, 5e5
	run(m, key("x"))
	m.w, m.h = 120, 36
	_ = time.Now
	os.WriteFile(path, []byte(ansi.Strip(m.render())), 0o644)
	os.WriteFile(path+".ansi", []byte(m.render()), 0o644)
	fmt.Println("snapshot written")
}
