package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"io"
	l "log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pkg/errors"
)

// check that the server’s name in the certificate matches the host name
const serverDNSNameCheck = true
const maxMsgs = 10000

func fwdOutput(msgs chan []byte, addresses []string, cliKey, cliCrt string, certPool *x509.CertPool) {
	f := newFwdState(addresses, cliKey, cliCrt, certPool)
	go f.runFlushes(flushPeriod)
	for {
		f.send(<-msgs)
	}
}

// fwdState holds the current state of the forwarding message task.
type fwdState struct {
	addresses []string
	cliKey    string
	cliCrt    string
	certPool  *x509.CertPool
	qMtx      sync.Mutex
	bMtx      sync.Mutex
	cond      *sync.Cond
	msgs      [][]byte
	first     int
	last      int
	len       int
	conn      net.Conn
	blobIn    []byte
	blobOut   []byte
	log       *l.Logger
	done      chan struct{}
}

// newFwdState creates a new fwdState instance.
func newFwdState(addresses []string, cliKey, cliCrt string, certPool *x509.CertPool) *fwdState {
	f := &fwdState{
		addresses: addresses,
		cliKey:    cliKey,
		cliCrt:    cliCrt,
		certPool:  certPool,
		msgs:      make([][]byte, maxMsgs),
		blobIn:    make([]byte, 0, 4096),
		blobOut:   make([]byte, 0, 4096),
		log:       l.New(os.Stdout, "forward ", l.Flags()),
	}
	f.cond = sync.NewCond(&f.qMtx)
	return f
}

// runRecvAcks fetches acknowledgements and pops messages from the message queue.
// Returns when an error is detected on the connection.
func (f *fwdState) runRecvAcks() {
	buf := make([]byte, 4096)
	for {
		n, err := f.conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				f.log.Println("runRecvAcks: connection closed by remote peer")
			} else {
				f.log.Printf("runRecvAcks error: %s, closing connection", err)
			}
			f.conn.Close()
			close(f.done)
			return
		}
		f.pop(n)
	}
}

// Push adds a new message to send
func (f *fwdState) send(msg []byte) {
	f.qMtx.Lock()
	for f.len == len(f.msgs) {
		f.cond.Wait()
	}
	if f.last == len(f.msgs) {
		f.last = 0
	}
	f.msgs[f.last] = msg
	f.last++
	f.len++
	f.qMtx.Unlock()
	f.bMtx.Lock()
	f.appendToBlobIn(msg)
	f.bMtx.Unlock()
}

func (f *fwdState) appendToBlobIn(msg []byte) {
	var hdr = [8]byte{'D', 'L', 'C', 'M', 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(len(msg)))
	f.blobIn = append(f.blobIn, hdr[:]...)
	f.blobIn = append(f.blobIn, msg...)
}

// Pop removes n messages from front of msg queue.
func (f *fwdState) pop(n int) {
	f.qMtx.Lock()
	if f.len == len(f.msgs) {
		f.cond.Signal()
	}
	if n > f.len {
		f.log.Fatalf("underflow: expected at most %d acks, got %d", f.len, n)
	}
	newFirst := f.first + n
	if newFirst <= len(f.msgs) {
		for i := f.first; i < newFirst; i++ {
			f.msgs[i] = nil
		}
	} else {
		for i := f.first; i < len(f.msgs); i++ {
			f.msgs[i] = nil
		}
		newFirst -= len(f.msgs)
		for i := 0; i < newFirst; i++ {
			f.msgs[i] = nil
		}
	}
	f.first = newFirst
	f.len -= n
	f.qMtx.Unlock()
}

// Flush sends queue messages and reconnect if required.
func (f *fwdState) runFlushes(flushPeriod time.Duration) {
	ticker := time.NewTicker(flushPeriod)
	for {
		<-ticker.C
		if f.len == 0 {
			continue
		}
		if f.conn == nil {
			f.connect()
			f.qMtx.Lock()
			f.bMtx.Lock()
			f.blobIn = f.blobIn[:0]
			if f.last > f.first {
				for i := f.first; i < f.last; i++ {
					f.appendToBlobIn(f.msgs[i])
				}
			} else if f.len != 0 {
				for i := f.first; i < cap(f.msgs); i++ {
					f.appendToBlobIn(f.msgs[i])
				}
				for i := 0; i < f.last; i++ {
					f.appendToBlobIn(f.msgs[i])
				}
			}
			f.done = make(chan struct{})
			go f.runRecvAcks()
			f.bMtx.Unlock()
			f.qMtx.Unlock()
		}
		f.bMtx.Lock()
		// swap blobIn and blobOut
		f.blobOut = f.blobOut[:0]
		f.blobIn, f.blobOut = f.blobOut, f.blobIn
		f.bMtx.Unlock()
		n, err := f.conn.Write(f.blobOut)
		if err == nil && n == len(f.blobOut) {
			continue
		}
		f.conn.Close()
		if n != len(f.blobOut) {
			f.log.Printf("flush short write: expect %d bytes, got %d", len(f.blobOut), n)
		}
		if err == io.EOF {
			f.log.Println("flush: connection closed by remote peer")
		} else {
			f.log.Println("flush error:", err)
		}
		// wait termination of runRecvAcks goroutine
		<-f.done
		f.conn = nil
	}
}

func (f *fwdState) connect() {
	for {
		for _, address := range f.addresses {
			err := f.connectTo(address)
			if err == nil {
				return
			}
			f.log.Printf("failed connecting to %s: %v", address, err)
		}
		f.log.Printf("retry connecting in 15 seconds")
		time.Sleep(15 * time.Second)
	}
}

func (f *fwdState) connectTo(address string) error {
	// reload certificate at each connection attempt to allow key change at run time
	clientCert, err := tls.LoadX509KeyPair(f.cliCrt, f.cliKey)
	if err != nil {
		return errors.Wrap(err, "load certificate and private key")
	}
	config := tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: !serverDNSNameCheck,
		RootCAs:            f.certPool,
	}
	f.conn, err = tls.Dial("tcp", address, &config)
	if err != nil {
		return errors.Wrap(err, "connect error")
	}
	if err = f.conn.SetDeadline(time.Now().Add(timeOutDelay)); err != nil {
		return errors.Wrap(err, "set time out limit")
	}

	name, err := os.Hostname()
	hdrMsg := make([]byte, 8+len(name))
	copy(hdrMsg[:4], "DLC\x01")
	binary.LittleEndian.PutUint32(hdrMsg[4:], uint32(len(name)))
	copy(hdrMsg[8:], name)
	_, err = f.conn.Write(hdrMsg)
	if err != nil {
		if err == io.EOF {
			return errors.New("connect: connection closed by remote peer")
		}
		return errors.Wrap(err, "send connect handshake")
	}

	var resp [4]byte
	err = readAll(f.conn, resp[:])
	if err != nil {
		if err == io.EOF {
			return errors.New("connect: connection closed by remote peer")
		}
		return errors.Wrap(err, "receive connect handshake")
	}
	if string(resp[:]) != "DLCS" {
		return errors.Errorf("warning: connect: expected 'DLGS', got '%s' (0x%s)", string(resp[:]), hex.EncodeToString(resp[:]))
	}
	f.conn.SetDeadline(time.Time{})
	f.log.Println("connect:", f.conn.LocalAddr(), "->", f.conn.RemoteAddr(), "OK")
	return nil
}
