package main

import (
	"encoding/json"
	"log"
	"net"
	"time"
)

func logstashOutput(msgs chan msgInfo, statsPeriod time.Duration) {
	stats := NewStats(statsPeriod)
	var (
		err  error
		conn net.Conn
	)

	for {
		conn, err = net.Dial("tcp", "127.0.0.1:3001")
		if err == nil {
			break
		}
		log.Println("failed connecting to logstash (localhost:3001):", err, "wait 5 seconds")
		time.Sleep(5 * time.Second)
	}
	buf := make([]byte, 0, 512)
	for {
		select {
		case m := <-msgs:
			buf = jsonEncode(buf, &m.msg)
			_, err = conn.Write(buf)
			if err != nil {
				log.Fatalln("failed forwarding logging message to logstash:", err)
			}
			stats.Update(m.len)
		case <-stats.C:
			stats.Display()
		}
	}
}

func jsonEncode(buf []byte, msg *Msg) []byte {
	jsonMsg, err := json.Marshal(msg)
	if err != nil {
		log.Fatal("failed json encoding logging message")
	}
	buf = append(buf[:0], jsonMsg...)
	for i := range buf {
		if buf[i] == '\n' || buf[i] == '\r' {
			buf[i] = ' '
		}
	}
	return append(buf, '\n')
}
