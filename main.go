package main

import (
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"path/filepath"

	"github.com/pkg/profile"
)

var (
	rootCAFilename = filepath.Join("pki", "rootCA.crt")
	certPool       = x509.NewCertPool()
	serverFlag     = flag.Bool("s", false, "run as server")
	clientFlag     = flag.Bool("c", false, "run as client")
	pkiFlag        = flag.Bool("k", false, "(re)generate private keys and certificates")
	addressFlag    = flag.String("a", "127.0.0.1:3000", "server: listen address, client: message destination")
	cpuFlag        = flag.Bool("cpu", false, "enable CPU profiling")
	mysqlFlag      = flag.Bool("mysql", false, "store logging messages in mysgl database")
	logstashFlag   = flag.Bool("logstash", false, "forward logging messages to logstash (localhost:3001)")
	dbFlushFlag    = flag.Int("dbp", 1000, "database flush period in milliseconds")
	dbBufLenFlag   = flag.Int("dbl", 200, "database buffer length")
	dumpFlag       = flag.Bool("d", false, "display received messages")
	statPeriodFlag = flag.Int("statp", 5, "stat display period in seconds")
	cliMsgFlag     = flag.String("cm", "json", "message type sent by the client")
)

func main() {

	flag.Parse()

	if *cliMsgFlag != "json" && *cliMsgFlag != "binary" {
		log.Fatalln("unknown message encoding type:", *cliMsgFlag)
	}

	if *cpuFlag {
		defer profile.Start().Stop()
	}

	if *pkiFlag {
		log.Println("(re)generating private keys and certificates")
		createPKI()
		return
	}

	data, err := ioutil.ReadFile(rootCAFilename)
	if err != nil {
		log.Fatalln(err)
	}
	if !certPool.AppendCertsFromPEM(data) {
		log.Fatalf("failed to parse rootCA certificate '%s'\n", rootCAFilename)
	}

	switch {
	case *serverFlag:
		runAsServer()
	case *clientFlag:
		runAsClient()
	default:
		flag.Usage()
		log.Fatalf("need either to run as server or as client")
	}
}
