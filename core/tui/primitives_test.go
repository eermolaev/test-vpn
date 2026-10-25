package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
)

func TestBoxGeometry(t *testing.T) {
	out := box("traffic", "60s", []string{"hello", strings.Repeat("x", 100)}, 30, 5, boxTraf)
	lines := strings.Split(out, "\n")
	if len(lines) != 5 {
		t.Fatalf("height %d", len(lines))
	}
	for i, l := range lines {
		if w := ansi.StringWidth(l); w != 30 {
			t.Fatalf("line %d width %d: %q", i, w, ansi.Strip(l))
		}
	}
	top := ansi.Strip(lines[0])
	if !strings.HasPrefix(top, "╭─┐traffic┌") || !strings.HasSuffix(top, "┐60s┌─╮") {
		t.Fatalf("top %q", top)
	}
	if !strings.Contains(ansi.Strip(lines[2]), "…") {
		t.Fatal("long line must be truncated")
	}
	// Narrow boxes drop the hint but keep their size.
	narrow := strings.Split(box("a very long title", "hint", nil, 12, 3, boxTraf), "\n")
	if ansi.StringWidth(narrow[0]) != 12 {
		t.Fatalf("narrow width %d", ansi.StringWidth(narrow[0]))
	}
}

func TestAreaGraph(t *testing.T) {
	g := areaGraph([]float64{0, 50, 100, 100}, 4, 2, 100, gradDown, false)
	if len(g) != 2 {
		t.Fatal(len(g))
	}
	top, bottom := []rune(ansi.Strip(g[0])), []rune(ansi.Strip(g[1]))
	if len(top) != 4 || len(bottom) != 4 {
		t.Fatalf("width %d %d", len(top), len(bottom))
	}
	// Oldest samples padded with zeros on the left; the last cell is full.
	if top[0] != 0x2800 || bottom[0] != 0x2800 {
		t.Fatal("left padding must be empty")
	}
	if top[3] != 0x28ff || bottom[3] != 0x28ff {
		t.Fatalf("full cell: %U %U", top[3], bottom[3])
	}
	// 0 then 50%: right column fills the bottom row only.
	if bottom[2] != 0x2800|0xb8|0x47 && bottom[2] == 0x2800 {
		t.Fatalf("half cell: %U", bottom[2])
	}
	flipped := areaGraph([]float64{100}, 1, 1, 100, gradUp, true)
	if []rune(ansi.Strip(flipped[0]))[0] != 0x2800|0xb8 {
		t.Fatalf("flipped: %U", []rune(ansi.Strip(flipped[0]))[0])
	}
}

func TestFormat(t *testing.T) {
	for in, want := range map[float64]string{0: "0 B", 1023: "1023 B", 1536: "1.5 KB", 5 << 20: "5.0 MB", 300 << 20: "300 MB"} {
		if got := humanBytes(in); got != want {
			t.Errorf("%v: %q", in, got)
		}
	}
	if humanDuration(3725*time.Second) != "1:02:05" || humanDuration(65*time.Second) != "01:05" {
		t.Fatal("duration")
	}
}
