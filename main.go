package main

import (
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"runtime/trace"
	"time"

	_ "net/http/pprof"

	"github.com/pkg/profile"
)

var (
	serverFlag     = flag.Bool("s", false, "run as server")
	clientFlag     = flag.Bool("c", false, "run as client")
	addressFlag    = flag.String("a", "mardirac.in2p3.fr:3000", "server: listen address, client: message destination")
	cpuProfFlag    = flag.Bool("cpuprof", false, "enable CPU profiling")
	memProfFlag    = flag.Bool("memprof", false, "enable memory profiling")
	blockProfFlag  = flag.Bool("blockprof", false, "enable read/write block profiling")
	mtxProfFlag    = flag.Bool("mtxprof", false, "enable mutex locking profiling")
	mysqlFlag      = flag.Bool("mysql", false, "output to mysql")
	logstashFlag   = flag.String("logstash", "", "output to logstash at address (e.g. mardirac.in2p3.fr:3001)")
	fwdAddrFlag    = flag.String("fwd", "", "output to logCollector at address (e.g. mardirac.in2p3.fr:3001)")
	dbFlushFlag    = flag.Int("dbp", 1000, "database flush period in milliseconds")
	dbBufLenFlag   = flag.Int("dbl", 200, "database buffer length")
	dumpFlag       = flag.Bool("d", false, "display received messages")
	statPeriodFlag = flag.Int("statp", 5, "stat display period in seconds")
	keyFileFlag    = flag.String("key", "pki/key.pem", "private key file")
	crtFileFlag    = flag.String("crt", "pki/crt.pem", "certificate file")
	casFileFlag    = flag.String("cas", "pki/cas.pem", "certificate authorities file")
	pkiFlag        = flag.String("pki", "", "(re)generate A CA, a private key and a certificate for the specified host")
	pkiDirFlag     = flag.String("pkiDir", "pki", "directory where the private and public keys are stored")
	traceFlag      = flag.String("trace", "", "trace date into specified file")
)

func main() {

	flag.Parse()

	if *cpuProfFlag {
		defer profile.Start().Stop()
	} else if *memProfFlag {
		defer profile.Start(profile.MemProfile).Stop()
	} else if *blockProfFlag {
		defer profile.Start(profile.BlockProfile).Stop()
	} else if *mtxProfFlag {
		defer profile.Start(profile.MutexProfile).Stop()
	}

	if *pkiFlag != "" {
		log.Println("(re)generating private keys and certificates")
		createPKI(*pkiDirFlag, *pkiFlag)
		return
	}

	data, err := ioutil.ReadFile(*casFileFlag)
	if err != nil {
		log.Fatalln(err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(data) {
		log.Fatalf("failed to parse rootCA certificate '%s'\n", *casFileFlag)
	}

	if *traceFlag != "" {
		go func() {
			log.Println("trace into", *traceFlag)
			file, err := os.Create(*traceFlag)
			if err != nil {
				log.Fatal(err)
			}
			trace.Start(file)
			sigchan := make(chan os.Signal, 1)
			signal.Notify(sigchan, os.Interrupt)
			<-sigchan
			trace.Stop()
			file.Close()
			log.Println("trace done")
			os.Exit(0)
		}()
	}

	stats := NewStats(time.Duration(*statPeriodFlag) * time.Second)

	switch {
	case *serverFlag:
		runAsServer(splitAddresses(*addressFlag), *keyFileFlag, *crtFileFlag, certPool, *dumpFlag, stats)
	case *clientFlag:
		runAsClient(splitAddresses(*addressFlag), *keyFileFlag, *crtFileFlag, certPool, stats)
	default:
		flag.Usage()
		log.Fatalf("need either to run as server or as client")
	}
}
