//go:build !linux && !windows

package all

import (
	_ "akagent/checks/cpu"
	_ "akagent/checks/http"
)
