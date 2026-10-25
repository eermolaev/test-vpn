// Command testvpn is the standalone VPN client for macOS: a root daemon
// (installed as a LaunchDaemon) and a terminal dashboard.
//
//	testvpn                 open the dashboard
//	testvpn status          print the status
//	testvpn connect | disconnect | reconnect
//	testvpn import FILE     import a profile (FILE or - for stdin)
//	testvpn check           check the exit IP, country and leaks
//	sudo testvpn install    install and start the daemon
//	sudo testvpn uninstall  stop and remove the daemon
//	sudo testvpn unblock    remove the kill switch and DNS override
//	testvpn daemon          run the daemon (used by launchd)
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
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/eermolaev/test-vpn/core/daemon"
	"github.com/eermolaev/test-vpn/core/ipc"
	"github.com/eermolaev/test-vpn/core/tui"
)

const (
	defaultDir = "/Library/Application Support/TestVPN"
	label      = "com.testvpn.daemon"
)

var (
	socketPath = flag.String("socket", ipc.DefaultSocket, "daemon socket")
	stateDir   = flag.String("dir", defaultDir, "daemon state directory (root only)")
)

func usage() {
	fmt.Fprintf(os.Stderr, `testvpn %s — AmneziaWG and VLESS+REALITY client

usage:
  testvpn                 open the dashboard
  testvpn status          print the status
  testvpn connect | disconnect | reconnect
  testvpn import FILE     import a profile (- for stdin; --into ID to add transports)
  testvpn logs [-f]       print the service log (-f: follow)
  testvpn check           check exit IP, country and leaks
  sudo testvpn install    install and start the background service
  sudo testvpn uninstall  stop and remove the service (--purge also deletes profiles)
  sudo testvpn unblock    emergency: remove the kill switch and DNS override
`, daemon.Version)
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

func userDataDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Application Support", "TestVPN")
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
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: testvpn import [--into ID] FILE|-")
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
	return withClient(func(c *ipc.Client) error {
		var p daemon.ProfileEntry
		if err := c.Call(daemon.CmdImport, daemon.ImportArgs{Text: string(b), Into: *into}, &p); err != nil {
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
