package tui

import (
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// fit truncates or pads s to exactly w cells.
func fit(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if ansi.StringWidth(s) > w {
		s = ansi.Truncate(s, w, "…")
	}
	return s + strings.Repeat(" ", max(0, w-ansi.StringWidth(s)))
}

// box draws a rounded frame of outer size w×h with the title embedded in
// the top border, btop style: ╭─┐title┌──────┐hint┌─╮.
func box(title, hint string, body []string, w, h int, border color.Color) string {
	if w < 6 || h < 2 {
		return ""
	}
	bs := lipgloss.NewStyle().Foreground(border)
	inner := w - 2
	seg := func(label string, st lipgloss.Style) (string, int) {
		if label == "" {
			return "", 0
		}
		return bs.Render("┐") + st.Render(label) + bs.Render("┌"), ansi.StringWidth(label) + 2
	}
	maxTitle := inner - 4
	if ansi.StringWidth(title) > maxTitle {
		title = ansi.Truncate(title, maxTitle, "…")
	}
	left, lw := seg(title, stTitle)
	right, rw := seg(hint, stDim)
	if 1+lw+rw+1 > inner {
		right, rw = "", 0
	}
	fill := inner - 1 - lw - rw
	if rw > 0 {
		fill--
	}
	top := bs.Render("╭─") + left + bs.Render(strings.Repeat("─", max(0, fill))) + right
	if rw > 0 {
		top += bs.Render("─")
	}
	top += bs.Render("╮")
	var b strings.Builder
	b.WriteString(top + "\n")
	for i := 0; i < h-2; i++ {
		line := ""
		if i < len(body) {
			line = body[i]
		}
		b.WriteString(bs.Render("│") + fit(line, inner) + bs.Render("│") + "\n")
	}
	b.WriteString(bs.Render("╰" + strings.Repeat("─", inner) + "╯"))
	return b.String()
}

// joinH places blocks side by side.
func joinH(blocks ...string) string { return lipgloss.JoinHorizontal(lipgloss.Top, blocks...) }

// joinV stacks blocks.
func joinV(blocks ...string) string { return lipgloss.JoinVertical(lipgloss.Left, blocks...) }

// overlay centers fg over bg (dialogs).
func overlay(bg, fgBlock string, w, h int) string {
	bgLines := strings.Split(bg, "\n")
	fgLines := strings.Split(fgBlock, "\n")
	fw := 0
	for _, l := range fgLines {
		fw = max(fw, ansi.StringWidth(l))
	}
	top := max(0, (h-len(fgLines))/2)
	left := max(0, (w-fw)/2)
	for i, l := range fgLines {
		y := top + i
		if y >= len(bgLines) {
			break
		}
		row := bgLines[y]
		prefix := ansi.Truncate(row, left, "")
		prefix += strings.Repeat(" ", max(0, left-ansi.StringWidth(prefix)))
		suffix := ansi.TruncateLeft(row, left+fw, "")
		bgLines[y] = prefix + l + strings.Repeat(" ", max(0, fw-ansi.StringWidth(l))) + suffix
	}
	return strings.Join(bgLines, "\n")
}
