//go:build !linux

package all

import (
	_ "akagent/checks/cpu"
	_ "akagent/checks/http"
)
