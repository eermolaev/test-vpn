package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"charm.land/bubbles/v2/textarea"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"github.com/eermolaev/test-vpn/core/daemon"
	"github.com/eermolaev/test-vpn/core/rules"
)

// dialog is a modal window over the dashboard.
type dialog interface {
	// Update handles a message; closed=true removes the dialog.
	Update(m *Model, msg tea.Msg) (closed bool, cmd tea.Cmd)
	View(m *Model, w, h int) string
}

func keyOf(msg tea.Msg) (string, bool) {
	k, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return "", false
	}
	return k.String(), true
}

func hints(pairs ...string) string {
	var parts []string
	for i := 0; i+1 < len(pairs); i += 2 {
		parts = append(parts, stKey.Render(pairs[i])+" "+stDim.Render(pairs[i+1]))
	}
	return strings.Join(parts, "  ")
}

// --- help -------------------------------------------------------------------

type helpDialog struct{}

func (helpDialog) Update(m *Model, msg tea.Msg) (bool, tea.Cmd) {
	k, ok := keyOf(msg)
	return ok && k != "", nil
}

func (helpDialog) View(m *Model, w, h int) string {
	rows := [][2]string{
		{"c", "connect / disconnect"},
		{"r", "re-check the tunnel now"},
		{"p", "profiles: import, select, pin transport, expected country"},
		{"e", "domain exclusions (bypass the VPN)"},
		{"s", "settings: DNS, QUIC, local network"},
		{"x", "check exit IP, country and leaks"},
		{"↑ ↓", "select connection"},
		{"q", "quit the dashboard (the VPN keeps running)"},
	}
	lines := []string{""}
	for _, r := range rows {
		lines = append(lines, "  "+stKey.Render(fmt.Sprintf("%-4s", r[0]))+"  "+stMain.Render(r[1]))
	}
	lines = append(lines, "", "  "+stDim.Render("While disconnected or failed, traffic is blocked (kill switch)."),
		"  "+stDim.Render("Emergency: sudo testvpn unblock"), "", "  "+stDim.Render("press any key"))
	return box("help", "", lines, w, len(lines)+2, boxDialog)
}

// --- exclusions -------------------------------------------------------------

type exclusionsDialog struct {
	ta  textarea.Model
	err string
}

func newExclusionsDialog(m *Model) *exclusionsDialog {
	ta := textarea.New()
	ta.ShowLineNumbers = true
	ta.Placeholder = "example.com\nfull:login.example.org"
	ta.SetValue(strings.Join(m.settings.Exclusions, "\n"))
	ta.CharLimit = 0
	return &exclusionsDialog{ta: ta}
}

func (d *exclusionsDialog) focus() tea.Cmd { return d.ta.Focus() }

func (d *exclusionsDialog) Update(m *Model, msg tea.Msg) (bool, tea.Cmd) {
	if k, ok := keyOf(msg); ok {
		switch k {
		case "esc":
			return true, nil
		case "ctrl+s":
			set, errs := rules.ParseList(d.ta.Value())
			if errs != nil {
				d.err = errs[0].Error()
				return false, nil
			}
			s := m.settings
			s.Exclusions = nil
			for _, r := range set.Rules() {
				s.Exclusions = append(s.Exclusions, r.String())
			}
			m.settings = s
			return true, m.op("save exclusions", func() error { return m.be.SetSettings(s) })
		}
	}
	var cmd tea.Cmd
	d.ta, cmd = d.ta.Update(msg)
	return false, cmd
}

func (d *exclusionsDialog) View(m *Model, w, h int) string {
	d.ta.SetWidth(w - 4)
	d.ta.SetHeight(h - 8)
	_, errs := rules.ParseList(d.ta.Value())
	lines := []string{stDim.Render("Traffic to these domains bypasses the VPN; the sites see your real IP.")}
	lines = append(lines, strings.Split(d.ta.View(), "\n")...)
	status := stOK.Render("✓ valid")
	if len(errs) > 0 {
		status = stBad.Render(fmt.Sprintf("✗ %d problem(s): %s", len(errs), errs[0].Error()))
	}
	if d.err != "" {
		status = stBad.Render(d.err)
	}
	lines = append(lines, status, hints("ctrl+s", "save", "esc", "cancel")+stDim.Render("   example.com = with subdomains, full:x = exact"))
	return box("exclusions", "", lines, w, h, boxDialog)
}

// --- settings ---------------------------------------------------------------

var dnsPresets = []struct {
	name    string
	servers []string
}{
	{"Google 8.8.8.8", nil},
	{"Cloudflare 1.1.1.1", []string{"1.1.1.1", "1.0.0.1"}},
	{"Quad9 9.9.9.9", []string{"9.9.9.9", "149.112.112.112"}},
	{"Custom", nil},
}

type settingsDialog struct {
	s      daemon.Settings
	preset int
	custom textinput.Model
	cursor int
	err    string
}

func newSettingsDialog(m *Model) *settingsDialog {
	d := &settingsDialog{s: m.settings, custom: textinput.New()}
	d.custom.Placeholder = "8.8.8.8, 8.8.4.4"
	d.preset = 0
	if len(m.settings.DNSServers) > 0 {
		d.preset = 3
		for i, p := range dnsPresets[1:3] {
			if strings.Join(p.servers, ",") == strings.Join(m.settings.DNSServers, ",") {
				d.preset = i + 1
			}
		}
		if d.preset == 3 {
			d.custom.SetValue(strings.Join(m.settings.DNSServers, ", "))
		}
	}
	return d
}

const (
	setDNS = iota
	setCustom
	setQUIC
	setLAN
	setSave
	setCount
)

func (d *settingsDialog) Update(m *Model, msg tea.Msg) (bool, tea.Cmd) {
	k, ok := keyOf(msg)
	if ok && d.cursor == setCustom && d.preset == 3 && k != "up" && k != "down" && k != "esc" && k != "tab" && k != "enter" && k != "ctrl+s" {
		var cmd tea.Cmd
		d.custom, cmd = d.custom.Update(msg)
		return false, cmd
	}
	if !ok {
		return false, nil
	}
	switch k {
	case "esc":
		return true, nil
	case "up", "shift+tab":
		d.move(-1)
	case "down", "tab":
		d.move(1)
	case "left", "right", "enter", "space", " ":
		switch d.cursor {
		case setDNS:
			step := 1
			if k == "left" {
				step = len(dnsPresets) - 1
			}
			d.preset = (d.preset + step) % len(dnsPresets)
		case setQUIC:
			d.s.BlockQUIC = !d.s.BlockQUIC
		case setLAN:
			d.s.AllowLAN = !d.s.AllowLAN
		case setSave:
			return d.save(m)
		}
	case "ctrl+s":
		return d.save(m)
	}
	if d.cursor == setCustom && d.preset == 3 {
		return false, d.custom.Focus()
	}
	d.custom.Blur()
	return false, nil
}

func (d *settingsDialog) move(step int) {
	for {
		d.cursor = (d.cursor + step + setCount) % setCount
		if d.cursor != setCustom || d.preset == 3 {
			return
		}
	}
}

func (d *settingsDialog) save(m *Model) (bool, tea.Cmd) {
	s := d.s
	switch d.preset {
	case 0:
		s.DNSServers = nil
	case 3:
		var list []string
		for _, f := range strings.FieldsFunc(d.custom.Value(), func(r rune) bool { return r == ',' || r == ' ' }) {
			list = append(list, f)
		}
		if len(list) == 0 || len(list) > 4 {
			d.err = "enter 1 to 4 IPv4 addresses"
			return false, nil
		}
		s.DNSServers = list
	default:
		s.DNSServers = dnsPresets[d.preset].servers
	}
	m.settings = s
	return true, m.op("save settings", func() error { return m.be.SetSettings(s) })
}

func (d *settingsDialog) View(m *Model, w, h int) string {
	row := func(i int, label, value string) string {
		cur := "  "
		if d.cursor == i {
			cur = stKey.Render("▶ ")
		}
		return cur + stDim.Render(fmt.Sprintf("%-22s", label)) + value
	}
	toggle := func(b bool) string {
		if b {
			return stOK.Render("[on] ")
		}
		return stDim.Render("[off]")
	}
	lines := []string{"",
		row(setDNS, "DNS resolver", stMain.Render("◀ "+dnsPresets[d.preset].name+" ▶")),
	}
	if d.preset == 3 {
		d.custom.SetWidth(w - 30)
		lines = append(lines, row(setCustom, "  servers (IPv4)", d.custom.View()))
	}
	lines = append(lines,
		row(setQUIC, "Block QUIC in VLESS", toggle(d.s.BlockQUIC)),
		row(setLAN, "Allow local network", toggle(d.s.AllowLAN)),
		"",
		row(setSave, "", stKey.Render("[ save ]")),
		"",
		stDim.Render("  DNS queries go through the VPN to this resolver. Excluded domains"),
		stDim.Render("  are resolved with it directly. Changes apply without reconnecting."),
	)
	if d.err != "" {
		lines = append(lines, "  "+stBad.Render(d.err))
	}
	lines = append(lines, "", "  "+hints("↑↓", "move", "←→/enter", "change", "ctrl+s", "save", "esc", "cancel"))
	return box("settings", "", lines, w, min(h, len(lines)+2), boxDialog)
}

// --- profiles ---------------------------------------------------------------

type profilesMode int

const (
	pmList profilesMode = iota
	pmImport
	pmRename
	pmCountry
	pmDelete
)

type profilesDialog struct {
	cursor int
	mode   profilesMode
	into   string // import into this profile
	ta     textarea.Model
	ti     textinput.Model
	err    string
}

func newProfilesDialog(m *Model) *profilesDialog {
	d := &profilesDialog{ta: textarea.New(), ti: textinput.New()}
	d.ta.Placeholder = "Paste a vless:// link, AmneziaWG config, vpn:// key or xray JSON,\nor type @/path/to/file"
	d.ta.CharLimit = 0
	for i, p := range m.profiles {
		if p.Selected {
			d.cursor = i
		}
	}
	return d
}

func (d *profilesDialog) current(m *Model) *daemon.ProfileEntry {
	if d.cursor >= 0 && d.cursor < len(m.profiles) {
		return &m.profiles[d.cursor]
	}
	return nil
}

func (d *profilesDialog) Update(m *Model, msg tea.Msg) (bool, tea.Cmd) {
	k, isKey := keyOf(msg)
	switch d.mode {
	case pmImport:
		if isKey && k == "esc" {
			d.mode = pmList
			return false, nil
		}
		if isKey && k == "ctrl+s" {
			text, err := readImport(d.ta.Value())
			if err != nil {
				d.err = err.Error()
				return false, nil
			}
			into := d.into
			if _, err := m.be.Import(text, into); err != nil {
				d.err = err.Error()
				return false, nil
			}
			d.mode, d.err = pmList, ""
			m.profiles, _ = m.be.Profiles()
			m.setFlash("profile imported", false)
			return false, nil
		}
		var cmd tea.Cmd
		d.ta, cmd = d.ta.Update(msg)
		return false, cmd
	case pmRename, pmCountry:
		if isKey && k == "esc" {
			d.mode = pmList
			return false, nil
		}
		if isKey && k == "enter" {
			p := d.current(m)
			if p == nil {
				d.mode = pmList
				return false, nil
			}
			v := strings.TrimSpace(d.ti.Value())
			u := daemon.UpdateProfile{ID: p.ID}
			if d.mode == pmRename {
				u.Name = &v
			} else {
				v = strings.ToUpper(v)
				u.ExpectedCountry = &v
			}
			if err := m.be.UpdateProfile(u); err != nil {
				d.err = err.Error()
			}
			d.mode = pmList
			m.profiles, _ = m.be.Profiles()
			return false, nil
		}
		var cmd tea.Cmd
		d.ti, cmd = d.ti.Update(msg)
		return false, cmd
	case pmDelete:
		if isKey && (k == "y" || k == "Y") {
			if p := d.current(m); p != nil {
				if err := m.be.DeleteProfile(p.ID); err != nil {
					d.err = err.Error()
				}
				m.profiles, _ = m.be.Profiles()
				d.cursor = max(0, min(d.cursor, len(m.profiles)-1))
			}
		}
		if isKey {
			d.mode = pmList
		}
		return false, nil
	}
	if !isKey {
		return false, nil
	}
	d.err = ""
	p := d.current(m)
	switch k {
	case "esc", "q":
		return true, nil
	case "up", "k":
		d.cursor = max(0, d.cursor-1)
	case "down", "j":
		d.cursor = min(len(m.profiles)-1, d.cursor+1)
	case "enter":
		if p != nil {
			if err := m.be.SelectProfile(p.ID); err != nil {
				d.err = err.Error()
				return false, nil
			}
			m.profiles, _ = m.be.Profiles()
			return true, nil
		}
	case "i", "a":
		d.into = ""
		if k == "a" {
			if p == nil {
				return false, nil
			}
			d.into = p.ID
		}
		d.mode = pmImport
		d.ta.SetValue("")
		return false, d.ta.Focus()
	case "n", "g":
		if p == nil {
			return false, nil
		}
		d.mode = pmRename
		d.ti.SetValue(p.Name)
		if k == "g" {
			d.mode = pmCountry
			d.ti.SetValue(p.ExpectedCountry)
		}
		return false, d.ti.Focus()
	case "t":
		if p == nil || len(p.Summary.Transports) == 0 {
			return false, nil
		}
		// Cycle: automatic -> each transport -> automatic.
		next := p.Summary.Transports[0].ID
		if p.ManualTransport != "" {
			next = ""
			for i, t := range p.Summary.Transports {
				if t.ID == p.ManualTransport && i+1 < len(p.Summary.Transports) {
					next = p.Summary.Transports[i+1].ID
				}
			}
		}
		if err := m.be.UpdateProfile(daemon.UpdateProfile{ID: p.ID, ManualTransport: &next}); err != nil {
			d.err = err.Error()
		}
		m.profiles, _ = m.be.Profiles()
	case "d":
		if p != nil {
			d.mode = pmDelete
		}
	}
	return false, nil
}

// readImport accepts pasted text or "@path" to read a file.
func readImport(v string) (string, error) {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "@") {
		path := strings.TrimSpace(v[1:])
		if strings.HasPrefix(path, "~/") {
			home, _ := os.UserHomeDir()
			path = filepath.Join(home, path[2:])
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	if v == "" {
		return "", fmt.Errorf("nothing to import")
	}
	return v, nil
}

func (d *profilesDialog) View(m *Model, w, h int) string {
	var lines []string
	switch d.mode {
	case pmImport:
		d.ta.SetWidth(w - 4)
		d.ta.SetHeight(h - 7)
		title := "Import a new profile"
		if d.into != "" {
			title = "Add transports to " + d.current(m).Name
		}
		lines = append(lines, stMain.Render(title))
		lines = append(lines, strings.Split(d.ta.View(), "\n")...)
		if d.err != "" {
			lines = append(lines, stBad.Render(d.err))
		}
		lines = append(lines, hints("ctrl+s", "import", "esc", "back"))
		return box("profiles", "import", lines, w, h, boxDialog)
	case pmRename, pmCountry:
		label := "Name"
		if d.mode == pmCountry {
			label = "Expected country (ISO code, e.g. DE)"
		}
		d.ti.SetWidth(w - 6)
		lines = append(lines, "", stMain.Render(label), d.ti.View(), "", hints("enter", "save", "esc", "back"))
		return box("profiles", "", lines, w, 8, boxDialog)
	}
	lines = append(lines, "")
	if len(m.profiles) == 0 {
		lines = append(lines, stDim.Render("  No profiles yet. Press ")+stKey.Render("i")+stDim.Render(" to import one."))
	}
	for i, p := range m.profiles {
		cur := "  "
		if i == d.cursor {
			cur = stKey.Render("▶ ")
		}
		sel := ""
		if p.Selected {
			sel = stOK.Render(" ● active")
		}
		country := ""
		if p.ExpectedCountry != "" {
			country = stDim.Render(" [" + p.ExpectedCountry + "]")
		}
		lines = append(lines, cur+stMain.Render(p.Name)+country+sel)
		for _, t := range p.Summary.Transports {
			pin := ""
			if p.ManualTransport == t.ID {
				pin = stKey.Render(" pinned")
			}
			lines = append(lines, "      "+stDim.Render(fmt.Sprintf("%s · %s · %s", t.Kind, t.Detail, t.Policy))+pin)
		}
	}
	if d.mode == pmDelete {
		lines = append(lines, "", stBad.Render("  Delete this profile? y / n"))
	}
	if d.err != "" {
		lines = append(lines, "", "  "+stBad.Render(d.err))
	}
	lines = append(lines, "", "  "+hints("enter", "select", "i", "import", "a", "add transports", "t", "pin transport"),
		"  "+hints("n", "rename", "g", "country", "d", "delete", "esc", "close"))
	return box("profiles", "", lines, w, min(h, len(lines)+2), boxDialog)
}
