package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
)

type msgInfo struct {
	len int
	msg Msg
}

func runAsServer(addresses []string, keyFile, crtFile string, certPool *x509.CertPool, printMsg bool, stats *Stats) {
	log.SetPrefix("server ")

	if len(addresses) != 1 {
		log.Fatalln("invalid number of addresses in", *addressFlag, "got", len(addresses))
	}

	msgs := make(chan []byte, *dbBufLenFlag*10)
	defer close(msgs)

	if *mysqlFlag {
		go mysqlOutput(msgs)
	} else if *logstashFlag != "" {
		go logstashOutput(msgs, *logstashFlag)
	} else if *fwdAddrFlag != "" {
		go fwdOutput(msgs, splitAddresses(*fwdAddrFlag), *keyFileFlag, *crtFileFlag, certPool)
	} else {
		go noOutput(msgs)
	}

	var (
		listener net.Listener
		err      error
	)
	// listen for a TLS connection
	var serverCert tls.Certificate
	serverCert, err = tls.LoadX509KeyPair(crtFilename, keyFilename)
	if err != nil {
		log.Fatal(err)
	}

	config := tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}
	config.Rand = rand.Reader
	listener, err = tls.Listen("tcp", addresses[0], &config)
	if err != nil {
		log.Fatalln("failed listen:", err)
	}

	log.Println("listen:", *addressFlag)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalln("accept error:", err)
		}
		go receiveMsg(conn, msgs, printMsg, stats)
	}
}
