package all

import (
	_ "apagent/checks/cpu"
	_ "apagent/checks/http"
	_ "apagent/checks/load_avg"
	_ "apagent/checks/memory"
	_ "apagent/checks/ports"
	_ "apagent/checks/services"
)
