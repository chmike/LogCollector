package main

import (
	"encoding/binary"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
)

func runAsClient() {
	log.SetPrefix("client ")
	log.Println("target:", *addressFlag)

	m := Msg{
		Stamp:     time.Now().UTC().Format("2006-01-02 15:04:05"),
		Level:     "info",
		System:    "dmon",
		Component: "test",
		Message:   "no problem",
	}

	msgs := make(chan []byte, 1)
	go msgSender(*addressFlag, msgs)

	for {
		var err error
		m.Stamp = time.Now().UTC().Format("2006-01-02 15:04:05")

		buf := make([]byte, 8, 512)
		copy(buf, "DLCM")
		switch *cliMsgFlag {
		case "json":
			buf, err = m.JSONEncode(buf)
		case "binary":
			buf, err = m.BinaryEncode(buf)
		default:
			err = errors.Errorf("unknown message encoding type: %s", *cliMsgFlag)
		}
		if err != nil {
			log.Fatalf("make message: %v", err)
		}
		binary.LittleEndian.PutUint32(buf[4:8], uint32(len(buf)-8))
		msgs <- buf
	}
}
