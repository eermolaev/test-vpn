package tui

import (
	"context"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/eermolaev/test-vpn/core/daemon"
	"github.com/eermolaev/test-vpn/core/egress"
	"github.com/eermolaev/test-vpn/core/flowrouter"
)

const historyLen = 240 // samples kept for graphs (one per second)

// Model is the root Bubble Tea model.
type Model struct {
	be Backend
	w  int
	h  int

	status    daemon.Status
	statusErr error
	flows     []flowrouter.FlowInfo
	logs      []daemon.LogLine
	lastLog   uint64
	settings  daemon.Settings
	profiles  []daemon.ProfileEntry

	down, up   []float64
	lastDown   int64
	lastUp     int64
	lastSample time.Time
	peakDown   float64
	peakUp     float64

	check    *egress.Result
	checking bool
	busy     string

	sel      int
	dialog   dialog
	flash    string
	flashErr bool
	now      func() time.Time
}

// New returns a model using be.
func New(be Backend) *Model {
	return &Model{be: be, now: time.Now, w: 120, h: 40}
}

type (
	tickMsg   time.Time
	updateMsg struct {
		status   daemon.Status
		err      error
		flows    []flowrouter.FlowInfo
		logs     []daemon.LogLine
		settings *daemon.Settings
		profiles []daemon.ProfileEntry
	}
	opMsg struct {
		label string
		err   error
	}
	checkMsg egress.Result
)

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// refresh fetches everything from the daemon in the background.
func (m *Model) refresh(full bool) tea.Cmd {
	be, after := m.be, m.lastLog
	return func() tea.Msg {
		u := updateMsg{}
		u.status, u.err = be.Status()
		if u.err != nil {
			return u
		}
		u.flows, _ = be.Flows(200)
		u.logs, _ = be.Logs(after)
		if full {
			if s, err := be.Settings(); err == nil {
				u.settings = &s
			}
			u.profiles, _ = be.Profiles()
		}
		return u
	}
}

// op runs a daemon action in the background and reports the result.
func (m *Model) op(label string, f func() error) tea.Cmd {
	m.busy = label
	return func() tea.Msg { return opMsg{label: label, err: f()} }
}

func (m *Model) Init() tea.Cmd { return tea.Batch(m.refresh(true), tick()) }

func (m *Model) setFlash(s string, isErr bool) {
	m.flash, m.flashErr = s, isErr
}

func (m *Model) sample(st daemon.Status) {
	now := m.now()
	var down, up int64
	if t := st.Tunnel; t != nil {
		down = t.Stats.BytesTunnelDown + t.Stats.BytesDirectDown
		up = t.Stats.BytesTunnelUp + t.Stats.BytesDirectUp
	}
	if !m.lastSample.IsZero() {
		dt := now.Sub(m.lastSample).Seconds()
		if dt > 0 && down >= m.lastDown && up >= m.lastUp {
			rd, ru := float64(down-m.lastDown)/dt, float64(up-m.lastUp)/dt
			m.down = append(m.down, rd)
			m.up = append(m.up, ru)
			if len(m.down) > historyLen {
				m.down, m.up = m.down[1:], m.up[1:]
			}
		}
	}
	m.lastDown, m.lastUp, m.lastSample = down, up, now
	m.peakDown, m.peakUp = 0, 0
	for i := range m.down {
		m.peakDown = max(m.peakDown, m.down[i])
		m.peakUp = max(m.peakUp, m.up[i])
	}
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		return m, nil
	case tickMsg:
		return m, tea.Batch(m.refresh(m.dialog == nil), tick())
	case updateMsg:
		m.statusErr = msg.err
		if msg.err == nil {
			m.status = msg.status
			m.flows = msg.flows
			m.sample(msg.status)
			if len(msg.logs) > 0 {
				m.logs = append(m.logs, msg.logs...)
				if len(m.logs) > 300 {
					m.logs = m.logs[len(m.logs)-300:]
				}
				m.lastLog = msg.logs[len(msg.logs)-1].Seq
			}
			if msg.settings != nil {
				m.settings = *msg.settings
			}
			if msg.profiles != nil {
				m.profiles = msg.profiles
			}
			if m.sel >= len(m.flows) {
				m.sel = max(0, len(m.flows)-1)
			}
		}
		return m, nil
	case opMsg:
		m.busy = ""
		if msg.err != nil {
			m.setFlash(msg.label+": "+msg.err.Error(), true)
		} else {
			m.setFlash(msg.label+": done", false)
		}
		return m, m.refresh(true)
	case checkMsg:
		res := egress.Result(msg)
		m.check, m.checking = &res, false
		return m, nil
	}
	if m.dialog != nil {
		closed, cmd := m.dialog.Update(m, msg)
		if closed {
			m.dialog = nil
			return m, tea.Batch(cmd, m.refresh(true))
		}
		return m, cmd
	}
	if k, ok := msg.(tea.KeyPressMsg); ok {
		return m, m.handleKey(k.String())
	}
	return m, nil
}

func (m *Model) handleKey(k string) tea.Cmd {
	switch k {
	case "q", "ctrl+c":
		return tea.Quit
	case "c":
		if m.status.Connected {
			return m.op("disconnect", m.be.Disconnect)
		}
		return m.op("connect", m.be.Connect)
	case "r":
		return m.op("reconnect", m.be.Reconnect)
	case "x":
		if m.checking {
			return nil
		}
		m.checking = true
		be, st, n := m.be, m.status, len(m.settings.Exclusions)
		return func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			return checkMsg(be.Check(ctx, st, n))
		}
	case "p":
		m.dialog = newProfilesDialog(m)
	case "e":
		m.dialog = newExclusionsDialog(m)
		return m.dialog.(*exclusionsDialog).focus()
	case "v":
		m.dialog = newListDialog(m, listVPNOnly)
		return m.dialog.(*exclusionsDialog).focus()
	case "s":
		m.dialog = newSettingsDialog(m)
	case "?", "h", "f1":
		m.dialog = &helpDialog{}
	case "up", "k":
		m.sel = max(0, m.sel-1)
	case "down", "j":
		m.sel = min(max(0, len(m.flows)-1), m.sel+1)
	}
	return nil
}

func (m *Model) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	v.WindowTitle = "TestVPN"
	return v
}
