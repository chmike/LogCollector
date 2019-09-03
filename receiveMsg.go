package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	l "log"
	"net"
	"os"
	"strings"
	"time"
)

func receiveMsg(conn net.Conn, msgs chan []byte, printMsg bool, stats *Stats) {
	var (
		hdr  [8]byte
		err  error
		log  = l.New(os.Stdout, "receive ", l.Flags())
		acks = make(chan byte, 1000)
		name = "???"
		host = "???"
	)
	defer func() {
		conn.Close()
		close(acks)
		log.Println("closing connection with", name)
		msgs <- []byte(fmt.Sprintf(`J{"asctime":"%s","levelname":"INFO","componentname":"logCollector","message":"close connection","varmessage":"%s","host":"%s"}`, time.Now().UTC().Format("2006-01-02 15:04:05"), name, host))
	}()

	// open connection handshake
	conn.SetDeadline(time.Now().Add(timeOutDelay))
	err = readAll(conn, hdr[:4])
	if err != nil {
		log.Println("open connection: recv protocol version:", err)
		return
	}
	if string(hdr[:4]) != "DLC\x01" { // protocol version 1
		log.Printf("open connection: expected 'DLC\\x01', got '%s\\x%02x' (0x%s)", string(hdr[:3]), hdr[3], hex.EncodeToString(hdr[:4]))
		return
	}
	err = readAll(conn, hdr[4:])
	if err != nil {
		log.Println("open connection: recv protocol header:", err)
		return
	}
	initMsgLen := int(binary.LittleEndian.Uint32(hdr[4:]))
	initMsg := make([]byte, initMsgLen)
	err = readAll(conn, initMsg)
	if err != nil {
		log.Println("message: recv data:", err)
		return
	}
	name = string(initMsg)
	_, err = conn.Write([]byte("DLCS"))
	if err != nil {
		log.Println("open connection: send header:", err)
		return
	}
	conn.SetDeadline(time.Time{})
	log.Println("accept:", name, conn.RemoteAddr(), "->", conn.LocalAddr(), "OK")

	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		if names, _ := net.LookupAddr(addr.IP.String()); len(names) > 0 {
			host = names[0]
			// remove trailing . if any
			if len(host) > 0 && host[len(host)-1] == '.' {
				host = host[:len(host)-1]
			}
		}
	}

	msgs <- []byte(fmt.Sprintf(`J{"asctime":"%s","levelname":"INFO","componentname":"logCollector","message":"accept connection","varmessage":"%s","host":"%s"}`, time.Now().UTC().Format("2006-01-02 15:04:05"), name, host))
	trailer := fmt.Sprintf(",\"host\":\"%s\"}", host)

	// asynchronous acknowledgment reply
	go func() {
		buf := make([]byte, 0, 10000)
		ticker := time.NewTicker(flushPeriod)
		for {
			select {
			case ack, ok := <-acks:
				if !ok {
					return // terminate when the acks channel is closed
				}
				buf = append(buf, ack)
			case <-ticker.C:
				if len(buf) > 0 {
					n, err := conn.Write(buf)
					if err != nil {
						log.Println("send acknowledgment error:", err)
						continue
					}
					if n != len(buf) {
						log.Printf("send acknowledgment error: short write: expected len %d, got %d", len(buf), n)
						continue
					}
					buf = buf[:0]
				}
			}
		}
	}()

	for {
		err = readAll(conn, hdr[:])
		if err != nil {
			if err == io.EOF {
				err = fmt.Errorf("connection closed by client %s", name)
			}
			log.Println("message: recv header:", err)
			return
		}
		if string(hdr[:4]) != "DLCM" {
			log.Printf("message: recv header: expected 'DLCM', got '%s' (0x%s)", string(hdr[:4]), hex.EncodeToString(hdr[:4]))
			return
		}
		dataLen := int(binary.LittleEndian.Uint32(hdr[4:]))
		buf := make([]byte, dataLen, dataLen+len(trailer)-1)
		err = readAll(conn, buf)
		if err != nil {
			log.Println("message: recv data:", err)
			return
		}

		// add host field to message if not yet present
		if strings.Index(string(buf), "\"host\":\"") == -1 {
			buf = append(buf[:len(buf)-1], trailer...)
		}

		if printMsg {
			log.Println("msg:", string(buf))
		}
		msgs <- buf
		acks <- ackCode
		stats.Update(len(buf))
	}
}
