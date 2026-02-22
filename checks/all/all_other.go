//go:build !linux

package all

import (
	_ "apagent/checks/cpu"
	_ "apagent/checks/http"
)
