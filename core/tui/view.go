package tui

import (
	"fmt"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/eermolaev/test-vpn/core/tunnel"
)

func (m *Model) render() string {
	w, h := max(m.w, 40), max(m.h, 12)
	header := m.header(w)
	footer := m.footer(w)
	bodyH := h - 2
	var body string
	if m.statusErr != nil {
		msg := []string{"", "  " + stBad.Render("Cannot reach the VPN service."), "", "  " + stMain.Render(m.statusErr.Error()), "",
			"  " + stDim.Render("Install or start it with: sudo testvpn install")}
		body = box("service", "", msg, w, bodyH, boxDialog)
	} else if w >= 100 {
		leftW := min(40, w/3)
		rightW := w - leftW
		logH := min(8, max(4, bodyH/5))
		topH := bodyH - logH
		exitH := min(14, topH/2+2)
		trafH := min(12, max(8, topH/3))
		left := joinV(m.exitPanel(leftW, exitH), m.transportsPanel(leftW, topH-exitH))
		right := joinV(m.trafficPanel(rightW, trafH), m.connectionsPanel(rightW, topH-trafH))
		body = joinV(joinH(left, right), m.logPanel(w, logH))
	} else {
		body = m.narrowBody(w, bodyH)
	}
	screen := joinV(header, body, footer)
	if m.dialog != nil {
		dw, dh := min(w-4, 86), min(h-4, 26)
		screen = overlay(screen, m.dialog.View(m, dw, dh), w, h)
	}
	return screen
}

// narrowBody stacks the panels for small terminals, dropping the less
// important ones when there is no room.
func (m *Model) narrowBody(w, h int) string {
	type part struct {
		want   int
		render func(w, h int) string
	}
	parts := []part{
		{8, m.trafficPanel},
		{12, m.exitPanel},
		{0, m.connectionsPanel}, // takes the rest
		{5, m.logPanel},
	}
	heights := make([]int, len(parts))
	avail := h
	for _, i := range []int{0, 1, 3} {
		if avail-parts[i].want >= 3 || (i == 0 && avail >= 3) {
			heights[i] = min(parts[i].want, avail)
			avail -= heights[i]
		}
	}
	heights[2] = avail
	if heights[2] < 3 { // no room for connections: give it to the previous panel
		for i := 1; i >= 0; i-- {
			if heights[i] > 0 {
				heights[i] += heights[2]
				break
			}
		}
		heights[2] = 0
	}
	var blocks []string
	for i, p := range parts {
		if heights[i] >= 3 {
			blocks = append(blocks, p.render(w, heights[i]))
		}
	}
	return joinV(blocks...)
}

func stateBadge(state tunnel.State, connected bool) string {
	b := lipgloss.NewStyle().Bold(true).Padding(0, 1)
	switch {
	case state == tunnel.StateConnected:
		return b.Background(colOK).Foreground(lipgloss.Color("#000000")).Render("● CONNECTED")
	case state == tunnel.StateConnecting:
		return b.Background(colWarn).Foreground(lipgloss.Color("#000000")).Render("◌ CONNECTING")
	case state == tunnel.StateReconnecting || state == tunnel.StateFailed || connected:
		return b.Background(colBad).Foreground(lipgloss.Color("#000000")).Render("■ BLOCKED")
	default:
		return b.Background(colDim).Foreground(lipgloss.Color("#000000")).Render("○ OFF")
	}
}

func (m *Model) header(w int) string {
	st := m.status
	var state tunnel.State
	transport, uptime := "", ""
	if st.Tunnel != nil {
		state = st.Tunnel.State
		transport = st.Tunnel.TransportKind
		if state == tunnel.StateConnected {
			uptime = humanDuration(m.now().Sub(st.Tunnel.Since))
		}
	}
	left := stTitle.Render(" TestVPN ") + stateBadge(state, st.Connected)
	if st.Profile != nil {
		left += " " + stMain.Render(st.Profile.Name)
	}
	if transport != "" {
		left += stDim.Render(" · ") + fg(colTunnel).Render(transport)
	}
	if uptime != "" {
		left += stDim.Render(" · ") + stMain.Render(uptime)
	}
	right := ""
	if st.KillSwitch {
		right += stOK.Render("⛨ kill switch") + "  "
	}
	if st.Build != "" && w >= 110 {
		right += stDim.Render(st.Build) + "  "
	}
	right += stDim.Render(m.now().Format("15:04:05")) + " "
	gap := w - lipgloss.Width(left) - lipgloss.Width(right)
	return fit(left+strings.Repeat(" ", max(1, gap))+right, w)
}

func (m *Model) footer(w int) string {
	keys := []struct{ k, label string }{
		{"c", connectLabel(m.status.Connected)}, {"r", "reconnect"}, {"p", "profiles"}, {"e", "exclusions"},
		{"s", "settings"}, {"x", "check exit"}, {"?", "help"}, {"q", "quit"},
	}
	var parts []string
	for _, k := range keys {
		parts = append(parts, stKey.Render(k.k)+" "+stDim.Render(k.label))
	}
	line := " " + strings.Join(parts, "  ")
	if m.busy != "" {
		line = " " + stWarn.Render(m.busy+"…") + "   " + line
	} else if m.flash != "" {
		st := stOK
		if m.flashErr {
			st = stBad
		}
		line = " " + st.Render(m.flash) + "   " + line
	}
	return fit(line, w)
}

func connectLabel(connected bool) string {
	if connected {
		return "disconnect"
	}
	return "connect"
}

func kv(k, v string, kw int) string {
	return stDim.Render(fmt.Sprintf("%-*s", kw, k)) + " " + v
}

func (m *Model) exitPanel(w, h int) string {
	st := m.status
	var lines []string
	add := func(k, v string) { lines = append(lines, kv(k, v, 10)) }
	if t := st.Tunnel; t != nil {
		state := string(t.State)
		switch t.State {
		case tunnel.StateConnected:
			state = stOK.Render(state)
		case tunnel.StateConnecting:
			state = stWarn.Render(fmt.Sprintf("%s (attempt %d, round %d)", state, t.Attempt, t.Round))
		default:
			state = stBad.Render(state)
		}
		add("state", state)
		if t.ErrorMessage != "" && t.State != tunnel.StateConnected {
			lines = append(lines, "  "+stWarn.Render(t.ErrorMessage))
		}
	} else if st.Connected {
		add("state", stBad.Render("blocked")+stDim.Render(" (tunnel down)"))
	} else {
		add("state", stDim.Render("disconnected"))
	}
	if st.LastError != "" {
		lines = append(lines, "  "+stBad.Render(st.LastError))
	}
	for _, wmsg := range st.Warnings {
		for i, l := range wrap(wmsg, w-6) {
			prefix := "⚠ "
			if i > 0 {
				prefix = "  "
			}
			lines = append(lines, stWarn.Render(prefix+l))
		}
	}
	add("dns", strings.Join(st.DNSServers, ", "))
	add("excluded", plural(len(m.settings.Exclusions), "domain"))
	if st.Route.Interface != "" {
		add("network", st.Route.Interface+" via "+st.Route.Gateway.String())
	}
	lines = append(lines, "")
	switch {
	case m.checking:
		lines = append(lines, stWarn.Render("checking exit…"))
	case m.check == nil:
		lines = append(lines, stDim.Render("press ")+stKey.Render("x")+stDim.Render(" to check exit and leaks"))
	default:
		r := m.check
		country := r.Country.ISO
		if r.Country.Name != "" {
			country += " " + r.Country.Name
		}
		if country == "" {
			country = stWarn.Render("unknown")
		} else if r.CountryMatch != nil && !*r.CountryMatch {
			country = stWarn.Render(country + " ≠ " + r.ExpectedCountry)
		} else {
			country = stOK.Render(country)
		}
		add("country", country)
		ip := r.IPv4.IP
		if r.IPv4.Confirmed {
			ip += stOK.Render(" ✓")
		} else {
			ip += stWarn.Render(" ?")
		}
		add("exit ip", ip)
		add("ipv6", okBad(r.IPv6.Blocked, "blocked", "LEAK "+r.IPv6.IP))
		webrtc := stDim.Render("n/a")
		if r.STUN.IP != "" {
			webrtc = okBad(r.STUN.IP == r.IPv4.IP, r.STUN.IP, "LEAK "+r.STUN.IP)
		}
		add("webrtc", webrtc)
		if r.Bypass.Checked {
			add("bypass", okBad(r.Bypass.Blocked, "blocked", "LEAK "+r.Bypass.IP))
		}
		for _, f := range r.Findings {
			icon, st := "•", stDim
			switch f.Severity {
			case "critical":
				icon, st = "✗", stBad
			case "warning":
				icon, st = "!", stWarn
			}
			for i, l := range wrap(f.Message, w-4) {
				prefix := icon + " "
				if i > 0 {
					prefix = "  "
				}
				lines = append(lines, st.Render(prefix+l))
			}
		}
	}
	return box("exit", "x", lines, w, h, boxExit)
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// wrap splits plain text into lines of at most w cells at word boundaries.
func wrap(text string, w int) []string {
	if w < 8 {
		return []string{text}
	}
	var lines []string
	cur := ""
	for _, word := range strings.Fields(text) {
		switch {
		case cur == "":
			cur = word
		case len([]rune(cur))+1+len([]rune(word)) <= w:
			cur += " " + word
		default:
			lines = append(lines, cur)
			cur = word
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

func okBad(ok bool, good, bad string) string {
	if ok {
		return stOK.Render(good)
	}
	return stBad.Render(bad)
}

func (m *Model) transportsPanel(w, h int) string {
	var lines []string
	st := m.status
	if st.Profile == nil {
		lines = append(lines, stDim.Render("no profile — press ")+stKey.Render("p"))
		return box("profile", "p", lines, w, h, boxTrans)
	}
	active := ""
	if st.Tunnel != nil {
		active = st.Tunnel.TransportID
	}
	for _, t := range st.Profile.Summary.Transports {
		marker := stDim.Render("  ")
		name := t.Label
		if name == "" {
			name = string(t.Kind)
		}
		switch {
		case t.ID == active && st.Tunnel.State == tunnel.StateConnected:
			marker = stOK.Render("● ")
		case t.ID == active:
			marker = stWarn.Render("◌ ")
		}
		pin := ""
		if st.Profile.ManualTransport == t.ID {
			pin = stKey.Render(" pinned")
		}
		policy := stDim.Render(string(t.Policy))
		lines = append(lines, marker+stMain.Render(name)+pin)
		lines = append(lines, "    "+stDim.Render(string(t.Kind)+" · "+t.Detail+" · ")+policy)
	}
	if ex := m.settings.Exclusions; len(ex) > 0 {
		lines = append(lines, "", stTitle.Render("excluded")+stDim.Render(" (bypass the VPN)"))
		room := h - 2 - len(lines)
		for i, e := range ex {
			if i == room-1 && len(ex) > room {
				lines = append(lines, stDim.Render(fmt.Sprintf("  … %d more", len(ex)-i)))
				break
			}
			lines = append(lines, "  "+fg(colDirect).Render("↷ ")+stMain.Render(e))
		}
	}
	return box("profile", st.Profile.Name, lines, w, h, boxTrans)
}

func (m *Model) trafficPanel(w, h int) string {
	inner := w - 2
	gh := max(1, (h-3)/2)
	labelW := 22
	gw := max(4, inner-labelW-1)
	// Each direction has its own scale, as in btop: upload is usually an
	// order of magnitude smaller and would be invisible on a shared scale.
	downG := areaGraph(m.down, gw, gh, max(m.peakDown, 1024), gradDown, false)
	upG := areaGraph(m.up, gw, gh, max(m.peakUp, 1024), gradUp, true)
	cur := func(s []float64) float64 {
		if len(s) == 0 {
			return 0
		}
		return s[len(s)-1]
	}
	var lines []string
	stats := m.status.Tunnel
	labels := []string{
		fg(gradDown[1]).Render("▼ ") + stMain.Render(humanRate(cur(m.down))),
		stDim.Render("  peak " + humanRate(m.peakDown)),
	}
	upLabels := []string{
		fg(gradUp[1]).Render("▲ ") + stMain.Render(humanRate(cur(m.up))),
		stDim.Render("  peak " + humanRate(m.peakUp)),
	}
	for i := 0; i < gh; i++ {
		l := ""
		if i < len(labels) {
			l = labels[i]
		}
		lines = append(lines, fit(l, labelW)+" "+downG[i])
	}
	totals := ""
	if stats != nil {
		s := stats.Stats
		totals = fg(colTunnel).Render("tunnel ") + stMain.Render(humanBytes(float64(s.BytesTunnelDown+s.BytesTunnelUp))) +
			stDim.Render("  ·  ") + fg(colDirect).Render("direct ") + stMain.Render(humanBytes(float64(s.BytesDirectDown+s.BytesDirectUp))) +
			stDim.Render(fmt.Sprintf("  ·  %d flows  ·  dns %d", s.ActiveFlows, s.DNSQueries))
	}
	lines = append(lines, stDim.Render(strings.Repeat("┄", inner)))
	for i := 0; i < gh; i++ {
		l := ""
		if i < len(upLabels) {
			l = upLabels[i]
		}
		lines = append(lines, fit(l, labelW)+" "+upG[i])
	}
	lines = append(lines, totals)
	return box("traffic", humanDuration(time.Duration(min(len(m.down), gw*2))*time.Second), lines, w, h, boxTraf)
}

func (m *Model) connectionsPanel(w, h int) string {
	inner := w - 2
	cols := []int{5, 7, 0, 10, 10, 5}
	fixed := 0
	for _, c := range cols {
		fixed += c + 1
	}
	hostW := max(10, inner-fixed)
	head := stDim.Render(fmt.Sprintf("%-5s %-7s %-*s %10s %10s %5s", "proto", "route", hostW, "host", "↓", "↑", "age"))
	lines := []string{head}
	rows := h - 3
	start := 0
	if m.sel >= rows {
		start = m.sel - rows + 1
	}
	for i := start; i < len(m.flows) && i < start+rows; i++ {
		f := m.flows[i]
		host := f.Host
		if host == "" {
			host = f.Dst
		}
		route := fg(colTunnel).Render(fmt.Sprintf("%-7s", f.Route))
		if f.Route == "direct" {
			route = fg(colDirect).Render(fmt.Sprintf("%-7s", f.Route))
		}
		row := stMain.Render(fmt.Sprintf("%-5s ", f.Proto)) + route + " " +
			stMain.Render(fit(host, hostW)) +
			stMain.Render(fmt.Sprintf(" %10s %10s %5s", humanBytes(float64(f.Down)), humanBytes(float64(f.Up)), shortAge(m.now().Sub(f.Start))))
		if i == m.sel {
			row = lipgloss.NewStyle().Background(colSelected).Render(fit(row, inner))
		}
		lines = append(lines, row)
	}
	if len(m.flows) == 0 {
		lines = append(lines, stDim.Render("no active connections"))
	}
	return box("connections", fmt.Sprintf("%d", len(m.flows)), lines, w, h, boxConn)
}

func (m *Model) logPanel(w, h int) string {
	n := h - 2
	var lines []string
	start := max(0, len(m.logs)-n)
	for _, l := range m.logs[start:] {
		lines = append(lines, stDim.Render(l.Time.Format("15:04:05"))+" "+stMain.Render(l.Text))
	}
	return box("log", "", lines, w, h, boxLog)
}
