package tui

import (
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"
)

// Braille dot bits: column 0 rows 0..3 and column 1 rows 0..3.
var brailleBits = [2][4]rune{{0x01, 0x02, 0x04, 0x40}, {0x08, 0x10, 0x20, 0x80}}

// areaGraph renders values (oldest first) as a filled braille area chart of
// w×h cells, two samples per cell, scaled to maxV. Rows are colored with the
// gradient from bottom to top like btop.
func areaGraph(values []float64, w, h int, maxV float64, grad []color.Color, flip bool) []string {
	if w <= 0 || h <= 0 {
		return nil
	}
	n := w * 2
	if len(values) > n {
		values = values[len(values)-n:]
	}
	// Right-align: newest sample at the right edge.
	samples := make([]float64, n)
	copy(samples[n-len(values):], values)
	dots := h * 4
	levels := make([]int, n)
	for i, v := range samples {
		if maxV > 0 && v > 0 {
			l := int(v/maxV*float64(dots) + 0.5)
			levels[i] = min(max(l, 1), dots)
		}
	}
	lines := make([]string, h)
	for row := 0; row < h; row++ {
		// row 0 is the top line unless flipped (upload graph grows downwards)
		var b strings.Builder
		for col := 0; col < w; col++ {
			r := rune(0x2800)
			for side := 0; side < 2; side++ {
				lvl := levels[col*2+side]
				for dy := 0; dy < 4; dy++ {
					var dotFromBottom int
					if flip {
						dotFromBottom = row*4 + dy
					} else {
						dotFromBottom = (h-1-row)*4 + (3 - dy)
					}
					if dotFromBottom < lvl {
						r |= brailleBits[side][dy]
					}
				}
			}
			b.WriteRune(r)
		}
		gi := h - 1 - row
		if flip {
			gi = row
		}
		c := grad[min(len(grad)-1, gi*len(grad)/max(h, 1))]
		lines[row] = lipgloss.NewStyle().Foreground(c).Render(b.String())
	}
	return lines
}

// meter renders a horizontal bar of width w for fraction f (0..1).
func meter(f float64, w int, c color.Color) string {
	f = min(max(f, 0), 1)
	full := int(f*float64(w) + 0.5)
	return lipgloss.NewStyle().Foreground(c).Render(strings.Repeat("■", full)) + stDim.Render(strings.Repeat("■", w-full))
}
