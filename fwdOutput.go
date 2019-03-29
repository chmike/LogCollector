package main

import (
	"encoding/binary"
	"log"
	"time"
)

func fwdOutput(msgs chan msgInfo, statsPeriod time.Duration) {
	var (
		err error
		buf = make([]byte, 8, 512)
	)
	copy(buf, "DLCM")

	stats := NewStats(statsPeriod)
	logCollector := NewLogCollector(*fwdAddrFlag)

	log.Println("forwarding:", *fwdAddrFlag)

	for {
		select {
		case m := <-msgs:
			buf = buf[:8]
			buf, err = m.msg.JSONEncode(buf)
			if err != nil {
				log.Fatalf("fwdOutput: json encode message: %v", err)
			}
			binary.LittleEndian.PutUint32(buf[4:8], uint32(len(buf)-8))
			logCollector.Send(buf)
			if logCollector.RecvAck() == nakCode {
				log.Println("Warning: fwdOutput received NAK")
			}
			stats.Update(m.len)
		case <-stats.C:
			stats.Display()
		}
	}
}
