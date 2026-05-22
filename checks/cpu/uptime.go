package cpu

import (
	"time"

	"github.com/shirou/gopsutil/host"
)

func Uptime() uint64 {
	boot, _ := host.BootTime()
	secondsFromBoot := uint64(time.Now().Unix()) - boot
	// days := secondsFromBoot / DAY
	// hours := (secondsFromBoot % DAY) / HOUR
	// minutes := (secondsFromBoot % HOUR) / MINUTE
	// s := fmt.Sprintf("%v days %v hours %v minutes", days, hours, minutes)

	return secondsFromBoot
}
