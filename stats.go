package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/c9s/goprocinfo/linux"
)

// Stats maintain statistic information.
type Stats struct {
	timer      *time.Ticker
	C          <-chan time.Time
	stamp      time.Time
	accMsgLen  uint64
	nbrMsg     uint64
	cpuTicks   uint64
	idleTicks  uint64
	totalTicks uint64
}

// NewStats returns a Stats object.
func NewStats(displayPeriod time.Duration) *Stats {
	s := &Stats{
		timer: time.NewTicker(displayPeriod),
		stamp: time.Now()}
	s.cpuTicks, s.idleTicks, s.totalTicks = getCPUStats()
	s.C = s.timer.C
	return s
}

// Update accumulates stats.
func (s *Stats) Update(msgLen int) {
	s.accMsgLen += uint64(msgLen)
	s.nbrMsg++
}

// Display log print the current stats.
func (s *Stats) Display() {
	now := time.Now()
	delay := now.Sub(s.stamp)
	accMsgLen := float64(s.accMsgLen)
	nbrMsg := float64(s.nbrMsg)

	mbs := accMsgLen / (1000000. * delay.Seconds())
	rate := nbrMsg / delay.Seconds()
	usmsg := 1000000. / rate
	mLen := accMsgLen / nbrMsg
	if rate == 0. {
		usmsg = 0
		mLen = 0
	}
	cpuTicks, idleTicks, totalTicks := getCPUStats()
	cpu := 100 * float64(cpuTicks-s.cpuTicks) / float64(totalTicks-s.totalTicks)
	idle := 100 * float64(idleTicks-s.idleTicks) / float64(totalTicks-s.totalTicks)
	log.Printf("%.3f usec/msg, %.3f B/msg, %.3f kHz, %.3f MB/s, cpu: %.1f%% idle: %.1f%%\n",
		usmsg, mLen, rate/1000, mbs, cpu, idle)

	s.nbrMsg = 0
	s.accMsgLen = 0
	s.cpuTicks = cpuTicks
	s.idleTicks = idleTicks
	s.totalTicks = totalTicks
	s.stamp = now
}

var procPidStatStr = fmt.Sprintf("/proc/%d/stat", os.Getpid())

func getCPUStats() (cpuTicks, idleTicks, totalTicks uint64) {
	cpuStat, err := ioutil.ReadFile("/proc/stat")
	if err != nil {
		return
	}
	cpuStatStr := string(cpuStat)
	cpuStatStr = cpuStatStr[:strings.IndexByte(cpuStatStr, '\n')]
	fields := strings.Fields(cpuStatStr)
	for i := 1; i < len(fields); i++ {
		val, _ := strconv.ParseUint(fields[i], 10, 64)
		if i == 4 {
			idleTicks = val
		}
		totalTicks += val
	}

	pStats, err := linux.ReadProcessStat(procPidStatStr)
	if err != nil {
		return
	}
	cpuTicks = pStats.Utime + pStats.Stime
	return
}
