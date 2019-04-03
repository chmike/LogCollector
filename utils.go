package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

const ackCode byte = 6  // ACK : positive acknowledgment
const nakCode byte = 21 // NAK : negative acknowledgment
const timeOutDelay = 15 * time.Second
const flushPeriod = 250 * time.Millisecond

// readAll is a blocking read for all data to be received.
func readAll(conn net.Conn, buf []byte) error {
	for len(buf) > 0 {
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}
		buf = buf[n:]
	}
	return nil
}

// ByteSliceDump prints the content of b in hexadecimal and ASCII.
func ByteSliceDump(b []byte) {
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

// splitAddresses splits and trims addresses into a slice of addresses.
func splitAddresses(addresses string) []string {
	res := make([]string, 0, len(addresses))
	for _, address := range strings.Split(addresses, ",") {
		if address := strings.Trim(address, " \n\r\t"); address != "" {
			res = append(res, address)
		}
	}
	return res
}

// copyFile copy the srcFile into dstFile, overriding dstFile if it exist.
func copyFile(dstFile, srcFile string) (int64, error) {
	sourceFileStat, err := os.Stat(srcFile)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", srcFile)
	}

	source, err := os.Open(srcFile)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dstFile)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}
