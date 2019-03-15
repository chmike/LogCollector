package main

import "time"

func noOutput(msgs chan msgInfo, statsPeriod time.Duration) {
	stats := NewStats(statsPeriod)
	for {
		select {
		case m := <-msgs:
			stats.Update(m.len)
		case <-stats.C:
			stats.Display()
		}
	}
}
