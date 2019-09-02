package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func runAsClient(addresses []string, keyFile, crtFile string, certPool *x509.CertPool, stats *Stats) {
	log.SetPrefix("client  ")
	log.Println("target:", *addressFlag)

	m := Msg{
		Stamp:     time.Now().UTC().Format("2006-01-02 15:04:05"),
		Level:     "INFO",
		System:    "dmon",
		Component: "test",
		Message:   "no problem",
	}

	msgs := make(chan []byte, 1000)

	go fwdOutput(msgs, addresses, keyFile, crtFile, certPool)

	for {
		m.Stamp = time.Now().UTC().Format("2006-01-02 15:04:05")
		msg := []byte(fmt.Sprintf(`J{"asctime":"%s","levelname":"%s","name":"%s","componentname":"%s","message":"%s"}`,
			m.Stamp, m.Level, m.System, m.Component, m.Message))
		// msg, err := json.Marshal(m)
		// if err != nil {
		// 	log.Fatalln("json encode:", err)
		// }
		msgs <- msg
		stats.Update(len(msg))
	}
}
