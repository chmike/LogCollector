package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/pkg/errors"
)

const ackCode byte = 6  // ACK : positive acknowledgment
const nakCode byte = 21 // NAK : negative acknowledgment

type msgInfo struct {
	len int
	msg Msg
}

func runAsServer() {
	log.SetPrefix("server ")

	msgs := make(chan msgInfo, *dbBufLenFlag*10)
	defer close(msgs)

	statsPeriod := time.Duration(*statPeriodFlag) * time.Second

	if *mysqlFlag {
		go mysqlOutput(msgs, statsPeriod)
	} else if *logstashFlag != "" {
		go logstashOutput(msgs, statsPeriod)
	} else {
		go noOutput(msgs, statsPeriod)
	}

	var (
		listener net.Listener
		err      error
	)
	// listen for a TLS connection
	var serverCert tls.Certificate
	serverCert, err = tls.LoadX509KeyPair(serverCRTFilename, serverKeyFilename)
	if err != nil {
		log.Fatal(err)
	}

	config := tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}
	config.Rand = rand.Reader
	listener, err = tls.Listen("tcp", *addressFlag, &config)
	if err != nil {
		log.Fatalln("failed listen:", err)
	}

	log.Println("listen:", *addressFlag)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalln("accept error:", err)
		}
		go handleClient(conn, msgs)
	}
}

func handleClient(conn net.Conn, msgs chan msgInfo) {
	var (
		hdr [8]byte
		err error
		n   int
		m   msgInfo
		buf []byte
		res [1]byte
	)
	defer conn.Close()

	// open connection handshake
	err = readAll(conn, hdr[:4])
	if err != nil {
		log.Println("open connection: recv header:", err)
		return
	}
	if string(hdr[:4]) != "DLC\x00" { // protocol version 0
		log.Printf("open connection: recv header: expected 'DLC'v0, got '%s'v%d (0x%s)", string(hdr[:3]), hdr[3], hex.EncodeToString(hdr[:4]))
		return
	}
	_, err = conn.Write([]byte("DLCS"))
	if err != nil {
		log.Println("open connection: send header:", err)
		return
	}

	for {
		// get message data
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
		if cap(buf) < dataLen {
			buf = make([]byte, dataLen)
		} else {
			buf = buf[:dataLen]
		}
		err = readAll(conn, buf)
		if err != nil {
			log.Println("message: recv data:", err)
			return
		}

		if *dumpFlag {
			byteSliceDump(buf)
			fmt.Println()
		}

		err = m.msg.BinaryDecode(buf)
		if err == ErrUnknownEncoding {
			err = m.msg.JSONDecode(buf)
		}

		if err == nil {
			res[0] = ackCode
		} else {
			log.Printf("message: %v", err)
			res[0] = nakCode
		}

		// pass message to database writer
		m.len = dataLen + len(hdr)
		msgs <- m

		// send acknowledgment
		// if err = conn.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
		// 	log.Println("message: send acknowledgment timeout:", err)
		// 	return
		// }
		n, err = conn.Write(res[:])
		if err != nil {
			log.Println("message: send acknowledgment error:", err)
			return
		}
		if n != 1 {
			log.Printf("message: send acknowledgment error: expected 1 byte send, got %d", n)
			return
		}
	}
}

func readAll(conn net.Conn, buf []byte) error {
	//conn.SetReadDeadline(time.Now().Add(timeOutDelay))
	for len(buf) > 0 {
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}
		buf = buf[n:]
	}
	return nil
}

func byteSliceDump(b []byte) {
	var a [16]byte
	n := (len(b) + 15) &^ 15
	for i := 0; i < n; i++ {
		if i%16 == 0 {
			fmt.Printf("%4d", i)
		}
		if i%8 == 0 {
			fmt.Print(" ")
		}
		if i < len(b) {
			fmt.Printf(" %02X", b[i])
		} else {
			fmt.Print("   ")
		}
		if i >= len(b) {
			a[i%16] = ' '
		} else if b[i] < 32 || b[i] > 126 {
			a[i%16] = '.'
		} else {
			a[i%16] = b[i]
		}
		if i%16 == 15 {
			fmt.Printf("  %s\n", string(a[:]))
		}
	}
}
