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
				// drop the first character which is 'J' for json.
				blob = append(blob, msg[1:]...)
				blob = append(blob, '\n')
				// normalize json encoding for logstash (one line json)
				for i := range blob[len(blob)-len(msg) : len(blob)-1] {
					if blob[i] == '\n' || blob[i] == '\r' {
						blob[i] = ' '
					}
				}

			case <-ticker.C:
				_, err = conn.Write(blob) // may block due to backpressure
				if err != nil {
					log.Println("failed forwarding messages to logstash:", err)
					break
				}
				blob = blob[:0]
			}
		}
	}
}
