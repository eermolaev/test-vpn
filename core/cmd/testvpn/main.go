// Command testvpn is the standalone VPN client for macOS, Linux and Windows:
// a privileged daemon (a LaunchDaemon, a systemd unit or a Windows service)
// and a terminal dashboard.
//
//	testvpn                 open the dashboard
//	testvpn status          print the status
//	testvpn connect | disconnect | reconnect
//	testvpn import FILE     import a profile (FILE or - for stdin)
//	testvpn check           check the exit IP, country and leaks
//	sudo testvpn install    install and start the daemon
//	sudo testvpn uninstall  stop and remove the daemon
//	sudo testvpn unblock    remove the kill switch and DNS override
//	testvpn daemon          run the daemon (used by the service manager)
//
// On Windows the privileged commands run in an Administrator terminal
// instead of with sudo.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/term"
	"github.com/eermolaev/test-vpn/core/daemon"
	"github.com/eermolaev/test-vpn/core/ipc"
	"github.com/eermolaev/test-vpn/core/profile"
	"github.com/eermolaev/test-vpn/core/tui"
)

var (
	socketPath = flag.String("socket", ipc.DefaultSocket, "daemon socket")
	stateDir   = flag.String("dir", defaultDir, "daemon state directory (root only)")
)

func usage() {
	sudo, admin := "sudo ", ""
	if runtime.GOOS == "windows" {
		sudo, admin = "", "\nprivileged commands (install, uninstall, unblock) need an Administrator terminal\n"
	}
	fmt.Fprintf(os.Stderr, `testvpn %[1]s — AmneziaWG and VLESS+REALITY client

usage:
  testvpn                 open the dashboard
  testvpn status          print the status
  testvpn connect | disconnect | reconnect
  testvpn import FILE     import a profile (- for stdin; --into ID to add transports)
  testvpn logs [-f]       print the service log (-f: follow)
  testvpn autoconnect last|restore|off
                          on boot: connect to the last profile / only if it was
                          connected / never
  testvpn failover N|off  switch to the next profile after N failed attempts
                          (default 5)
  testvpn check           check exit IP, country and leaks
  %[2]stestvpn install    install and start the background service
  %[2]stestvpn uninstall  stop and remove the service (--purge also deletes profiles)
  %[2]stestvpn unblock    emergency: remove the kill switch and DNS override
%[3]s`, daemon.Version, sudo, admin)
}

func main() {
	flag.Usage = usage
	flag.Parse()
	cmd := flag.Arg(0)
	args := flag.Args()
	if len(args) > 0 {
		args = args[1:]
	}
	var err error
	switch cmd {
	case "", "tui":
		err = runTUI()
	case "status":
		err = withClient(printStatus)
	case "connect":
		err = withClient(func(c *ipc.Client) error { return c.Call(daemon.CmdConnect, nil, nil) })
	case "disconnect":
		err = withClient(func(c *ipc.Client) error { return c.Call(daemon.CmdDisconnect, nil, nil) })
	case "reconnect":
		err = withClient(func(c *ipc.Client) error { return c.Call(daemon.CmdReconnect, nil, nil) })
	case "import":
		err = importCmd(args)
	case "autoconnect":
		err = withClient(func(c *ipc.Client) error { return autoconnectCmd(c, args) })
	case "failover":
		err = withClient(func(c *ipc.Client) error { return failoverCmd(c, args) })
	case "logs":
		err = withClient(func(c *ipc.Client) error { return logsCmd(c, args) })
	case "check":
		err = withClient(checkCmd)
	case "daemon":
		err = runDaemon()
	case "install":
		err = install()
	case "uninstall":
		err = uninstall(args)
	case "unblock":
		err = unblock()
	case "version", "-v", "--version":
		fmt.Println("testvpn", daemon.Build())
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "testvpn:", err)
		os.Exit(1)
	}
}

func withClient(f func(*ipc.Client) error) error {
	c, err := ipc.Dial(*socketPath)
	if err != nil {
		return err
	}
	defer c.Close()
	return f(c)
}

// userDataDir holds per-user data (the GeoIP database): ~/Library/Application
// Support/TestVPN on macOS, ~/.config/TestVPN on Linux, %AppData%\TestVPN on
// Windows.
func userDataDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "TestVPN")
}

func runTUI() error {
	c, err := ipc.Dial(*socketPath)
	if err != nil {
		return err
	}
	defer c.Close()
	m := tui.New(&tui.IPCBackend{C: c, GeoIPDir: userDataDir()})
	_, err = tea.NewProgram(m).Run()
	return err
}

func printStatus(c *ipc.Client) error {
	var st daemon.Status
	if err := c.Call(daemon.CmdStatus, nil, &st); err != nil {
		return err
	}
	state := "disconnected"
	if st.Tunnel != nil {
		state = string(st.Tunnel.State)
	} else if st.Connected {
		state = "blocked (tunnel down)"
	}
	fmt.Printf("service:     %s\n", st.Build)
	fmt.Printf("state:       %s\n", state)
	if st.Profile != nil {
		fmt.Printf("profile:     %s\n", st.Profile.Name)
	}
	if st.Tunnel != nil {
		fmt.Printf("transport:   %s\n", st.Tunnel.TransportKind)
		if st.Tunnel.ErrorMessage != "" {
			fmt.Printf("last error:  %s\n", st.Tunnel.ErrorMessage)
		}
		s := st.Tunnel.Stats
		fmt.Printf("traffic:     tunnel %d B, direct %d B, %d active flows\n", s.BytesTunnelDown+s.BytesTunnelUp, s.BytesDirectDown+s.BytesDirectUp, s.ActiveFlows)
	}
	fmt.Printf("kill switch: %v\n", st.KillSwitch)
	var set daemon.Settings
	if c.Call(daemon.CmdGetSettings, nil, &set) == nil {
		fmt.Printf("on startup:  %s\n", set.AutoConnectMode())
		fmt.Printf("failover:    %s\n", failoverText(set.Failover()))
	}
	fmt.Printf("dns:         %s\n", strings.Join(st.DNSServers, ", "))
	if st.LastError != "" {
		fmt.Printf("error:       %s\n", st.LastError)
	}
	for _, w := range st.Warnings {
		fmt.Printf("warning:     %s\n", w)
	}
	return nil
}

func importCmd(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	into := fs.String("into", "", "add transports to this profile ID")
	user := fs.String("user", "", "OpenVPN user name (the password is asked for)")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: testvpn import [--into ID] [--user NAME] FILE|-")
	}
	var b []byte
	var err error
	if fs.Arg(0) == "-" {
		b, err = io.ReadAll(os.Stdin)
	} else {
		b, err = os.ReadFile(fs.Arg(0))
	}
	if err != nil {
		return err
	}
	text := string(b)
	if fs.Arg(0) != "-" {
		// An .ovpn file may refer to keys next to it; the daemon cannot read them.
		if text, err = profile.InlineOpenVPNFiles(text, filepath.Dir(fs.Arg(0))); err != nil {
			return err
		}
	}
	if *user != "" {
		fmt.Fprint(os.Stderr, "password for "+*user+": ")
		pw, err := term.ReadPassword(os.Stdin.Fd())
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		text = profile.WithOpenVPNCredentials(text, *user, string(pw))
	}
	return withClient(func(c *ipc.Client) error {
		var p daemon.ProfileEntry
		if err := c.Call(daemon.CmdImport, daemon.ImportArgs{Text: text, Into: *into}, &p); err != nil {
			return err
		}
		fmt.Printf("imported %q (%d transports), id %s\n", p.Name, len(p.Summary.Transports), p.ID)
		return nil
	})
}

func checkCmd(c *ipc.Client) error {
	be := &tui.IPCBackend{C: c, GeoIPDir: userDataDir()}
	st, err := be.Status()
	if err != nil {
		return err
	}
	s, _ := be.Settings()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res := be.Check(ctx, st, len(s.Exclusions))
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	return nil
}

func logsCmd(c *ipc.Client, args []string) error {
	follow := len(args) > 0 && args[0] == "-f"
	var after uint64
	for {
		var lines []daemon.LogLine
		if err := c.Call(daemon.CmdLogs, daemon.LogsArgs{After: after}, &lines); err != nil {
			return err
		}
		for _, l := range lines {
			fmt.Printf("%s %s\n", l.Time.Local().Format("15:04:05"), l.Text)
			after = l.Seq
		}
		if !follow {
			return nil
		}
		time.Sleep(time.Second)
	}
}

func failoverText(n int) string {
	if n == 0 {
		return "off"
	}
	return fmt.Sprintf("next profile after %d failed attempts", n)
}

func failoverCmd(c *ipc.Client, args []string) error {
	var s daemon.Settings
	if err := c.Call(daemon.CmdGetSettings, nil, &s); err != nil {
		return err
	}
	if len(args) == 0 {
		fmt.Println(failoverText(s.Failover()))
		return nil
	}
	if args[0] == "off" {
		s.FailoverAttempts = -1
	} else if n, err := strconv.Atoi(args[0]); err == nil && n > 0 {
		s.FailoverAttempts = n
	} else {
		return fmt.Errorf("usage: testvpn failover N|off")
	}
	if err := c.Call(daemon.CmdSetSettings, s, nil); err != nil {
		return err
	}
	fmt.Println("failover:", failoverText(s.Failover()))
	return nil
}

func autoconnectCmd(c *ipc.Client, args []string) error {
	var s daemon.Settings
	if err := c.Call(daemon.CmdGetSettings, nil, &s); err != nil {
		return err
	}
	if len(args) == 0 {
		fmt.Println(s.AutoConnectMode())
		return nil
	}
	s.AutoConnect = args[0]
	if err := c.Call(daemon.CmdSetSettings, s, nil); err != nil {
		return err
	}
	fmt.Println("on startup:", s.AutoConnect)
	return nil
}
