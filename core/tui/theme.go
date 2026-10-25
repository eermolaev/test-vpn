// Package tui is the terminal dashboard of the standalone client, in the
// spirit of btop: framed panels, braille traffic graphs, a live connection
// table and keyboard shortcuts.
package tui

import (
	"image/color"

	"charm.land/lipgloss/v2"
)

// Theme colors (btop "default"-like on a dark terminal).
var (
	colMain     = lipgloss.Color("#cccccc")
	colDim      = lipgloss.Color("#6c6c6c")
	colTitle    = lipgloss.Color("#ee82ee")
	colHi       = lipgloss.Color("#b54040")
	colOK       = lipgloss.Color("#5fd700")
	colWarn     = lipgloss.Color("#ffaf00")
	colBad      = lipgloss.Color("#ff5f5f")
	colTunnel   = lipgloss.Color("#5fafff")
	colDirect   = lipgloss.Color("#ffaf00")
	colSelected = lipgloss.Color("#3a3a3a")

	boxExit   = lipgloss.Color("#5f87af")
	boxTraf   = lipgloss.Color("#5f8787")
	boxConn   = lipgloss.Color("#875f87")
	boxTrans  = lipgloss.Color("#87875f")
	boxLog    = lipgloss.Color("#5f5f87")
	boxDialog = lipgloss.Color("#d7875f")
)

// Graph gradients, bottom to top.
var (
	gradDown = []color.Color{lipgloss.Color("#5fd7af"), lipgloss.Color("#5fafd7"), lipgloss.Color("#5f87ff"), lipgloss.Color("#af5fff")}
	gradUp   = []color.Color{lipgloss.Color("#87d75f"), lipgloss.Color("#d7d75f"), lipgloss.Color("#ffaf5f"), lipgloss.Color("#ff5f5f")}
)

func fg(c color.Color) lipgloss.Style { return lipgloss.NewStyle().Foreground(c) }

var (
	stMain  = fg(colMain)
	stDim   = fg(colDim)
	stTitle = fg(colTitle).Bold(true)
	stKey   = fg(colHi).Bold(true)
	stOK    = fg(colOK)
	stWarn  = fg(colWarn)
	stBad   = fg(colBad).Bold(true)
)
