package main

import (
	l "log"
	"net"
	"os"
	"time"
)

func logstashOutput(msgs chan []byte, address string) {
	var (
		err  error
		conn net.Conn
	)
	log := l.New(os.Stdout, "logstash", l.Flags())

	for {
		conn, err = net.Dial("tcp", address)
		if err == nil {
			break
		}
		log.Printf("failed connecting to logstash (%s): %v, wait 10 seconds", address, err)
		time.Sleep(10 * time.Second)
	}
	blob := make([]byte, 0, 4096)
	ticker := time.NewTicker(flushPeriod)
	for {
		select {
		case msg := <-msgs:
			// normalize json encoding for logstash (one line json)
			for i := range msg {
				if msg[i] == '\n' || msg[i] == '\r' {
					msg[i] = ' '
				}
			}
			blob = append(blob, msg...)
			blob = append(blob, '\n')

		case <-ticker.C:
			_, err = conn.Write(blob) // may block due to backpressure
			if err != nil {
				log.Fatalln("failed forwarding messages to logstash:", err)
			}
			blob = blob[:0]
		}
	}
}
