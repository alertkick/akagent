package responder

import (
	"fmt"
	"os/exec"
	"strings"
)

// runCommand executes name with args, surfacing combined output on failure so
// an iptables error (e.g. missing privilege) is actionable in the audit log.
func runCommand(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
