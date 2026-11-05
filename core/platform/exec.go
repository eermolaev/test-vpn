package platform

import (
	"fmt"
	"os/exec"
	"strings"
)

// Runner executes a command with optional stdin and returns combined output.
type Runner func(stdin string, name string, args ...string) (string, error)

// ExecRunner runs commands with os/exec.
func ExecRunner(stdin string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
