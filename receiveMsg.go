package main

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	l "log"
	"net"
	"os"
	"time"

	"github.com/pkg/errors"
)

func receiveMsg(conn net.Conn, msgs chan []byte, printMsg bool, stats *Stats) {
	var (
		hdr  [8]byte
		err  error
		log  = l.New(os.Stdout, "receiver", l.Flags())
		acks = make(chan byte, 1000)
	)
	defer func() {
		conn.Close()
		close(acks)
		log.Println("closing connection")
	}()

	// open connection handshake
	conn.SetDeadline(time.Now().Add(timeOutDelay))
	err = readAll(conn, hdr[:4])
	if err != nil {
		log.Println("open connection: recv header:", err)
		return
	}
	if string(hdr[:4]) != "DLC\x00" { // protocol version 0
		log.Printf("open connection: expected 'DLC\\x00', got '%s\\x%02x' (0x%s)", string(hdr[:3]), hdr[3], hex.EncodeToString(hdr[:4]))
		return
	}
	_, err = conn.Write([]byte("DLCS"))
	if err != nil {
		log.Println("open connection: send header:", err)
		return
	}
	conn.SetDeadline(time.Time{})
	log.Println("accept:", conn.LocalAddr(), "<-", conn.RemoteAddr(), "OK")

	// asynchronous acknowledgment reply
	go func() {
		buf := make([]byte, 1024)
		ticker := time.NewTicker(200 * time.Millisecond)
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
				}
			}
		}
	}()

	for {
		err = readAll(conn, hdr[:])
		if err != nil {
			if err == io.EOF {
				err = errors.New("connection closed by client")
			}
			log.Println("message: recv header:", err)
			return
		}
		if string(hdr[:4]) != "DLCM" {
			log.Printf("message: recv header: expected 'DLCM', got '%s' (0x%s)", string(hdr[:4]), hex.EncodeToString(hdr[:4]))
			return
		}
		dataLen := int(binary.LittleEndian.Uint32(hdr[4:]))
		buf := make([]byte, dataLen)
		err = readAll(conn, buf)
		if err != nil {
			log.Println("message: recv data:", err)
			return
		}

		if printMsg {
			log.Println("msg:", string(buf))
		}

		msgs <- buf
		acks <- ackCode
		stats.Update(len(buf))
	}
}
