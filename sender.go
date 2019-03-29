package main

import (
	"crypto/tls"
	"encoding/hex"
	"io"
	"log"
	"net"
	"time"
)

var timeOutDelay = 15 * time.Second

// check that the server’s name in the certificate matches the host name
const serverDNSNameCheck = true

func msgSender(address string, msgs chan []byte) {
	stats := NewStats(time.Duration(*statPeriodFlag) * time.Second)
	logCollector := NewLogCollector(address)
	for {
		select {
		case m := <-msgs:
			logCollector.Send(m)
			if logCollector.RecvAck() == nakCode {
				log.Println("Warning: received NAK")
			}
			stats.Update(len(m))
		case <-stats.C:
			stats.Display()
		}
	}
}

// LogCollector holds a cached connection to the logging collector.
type LogCollector struct {
	addr string
	conn net.Conn
	err  error
}

// NewLogCollector instantiates a LogCollector object used to communicate
// with a LogCollector.
func NewLogCollector(address string) *LogCollector {
	return &LogCollector{addr: address}
}

// Send sends the message m. It will block until the message is sent.
func (l *LogCollector) Send(m []byte) {
	for {
		if l.conn == nil {
			l.connect()
		}
		n, err := l.conn.Write(m)
		if err == nil && n == len(m) {
			break
		}
		if err != nil {
			if err == io.EOF {
				log.Println("warning: connection closed by LogCollector")
			} else {
				log.Println("warning:", err)
			}
		} else {
			log.Printf("warning: short write: expect send %d, sent %d", len(m), n)
		}
		l.conn.Close()
		l.conn = nil
	}
}

// RecvAck return the ackCode, or nakCode received from the LogCollector, or 0 if
// the LogCollector closed the connection. The next send will take care to reopen
// the connection.
func (l *LogCollector) RecvAck() byte {
	var b [1]byte
	err := l.conn.SetReadDeadline(time.Now().Add(timeOutDelay))
	if err != nil {
		log.Println("warning:", err)
		l.conn.Close()
		l.conn = nil
		return 0
	}
	n, err := l.conn.Read(b[:])
	if err == nil && n == 1 {
		return b[0]
	}
	if err != nil {
		if err == io.EOF {
			log.Println("warning: connection closed by LogCollector")
		} else {
			log.Println("warning:", err)
		}
	} else {
		log.Println("warning: short read: expected 1, got", n)
	}
	l.conn.Close()
	l.conn = nil
	return 0
}

func (l *LogCollector) connect() {
	for {
		// reload certificate at each connection attempt to allow key change at run time
		clientCert, err := tls.LoadX509KeyPair(crtFilename, keyFilename)
		if err != nil {
			log.Printf("warning: connect: %s, waiting 60 seconds", err)
			time.Sleep(60 * time.Second)
			continue
		}
		config := tls.Config{
			Certificates:       []tls.Certificate{clientCert},
			InsecureSkipVerify: !serverDNSNameCheck,
			RootCAs:            certPool,
		}
		l.conn, err = tls.Dial("tcp", l.addr, &config)
		if err != nil {
			log.Printf("warning: connect: %s, waiting 5 seconds", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// connection opening handshake
		if err = l.conn.SetWriteDeadline(time.Now().Add(timeOutDelay)); err != nil {
			log.Printf("warning: connect: %s, waiting 5 seconds", err)
			l.conn.Close()
			time.Sleep(5 * time.Second)
			continue
		}
		n, err := l.conn.Write([]byte("DLC\x00"))
		if err != nil {
			if err == io.EOF {
				log.Println("warning: connect: connection closed by LogCollector")
			} else {
				log.Printf("warning: connect: %s, waiting 5 seconds", err)
			}
			l.conn.Close()
			time.Sleep(5 * time.Second)
			continue
		}
		if n != 4 {
			log.Println("warning: connect: short write, waiting 5 seconds")
			l.conn.Close()
			time.Sleep(5 * time.Second)
			continue
		}

		err = l.conn.SetReadDeadline(time.Now().Add(timeOutDelay))
		if err != nil {
			log.Printf("warning: %s, waiting 5 seconds", err)
			l.conn.Close()
			time.Sleep(5 * time.Second)
			continue
		}
		var resp [4]byte
		err = readAll(l.conn, resp[:])
		if err != nil {
			if err == io.EOF {
				log.Println("warning: connect: connection closed by LogCollector")
			} else {
				log.Printf("warning: connect: %s, waiting 5 seconds", err)
			}
			l.conn.Close()
			time.Sleep(5 * time.Second)
			continue
		}
		if string(resp[:]) != "DLCS" {
			log.Printf("warning: connect: expected 'DLGS', got '%s' (0x%s), waiting 5 seconds", string(resp[:]), hex.EncodeToString(resp[:]))
			l.conn.Close()
			time.Sleep(5 * time.Second)
			continue
		}
		break
	}
	l.conn.SetDeadline(time.Time{})
	log.Println("connect:", l.conn.LocalAddr(), "->", l.conn.RemoteAddr(), "OK")
}
