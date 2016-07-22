package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"sync/atomic"
	"time"
)

func signRSA(what []byte, hash crypto.Hash, privateKey *rsa.PrivateKey) (s []byte, err error) {
	return
}

func testSigning(buffersize int, privateKey *rsa.PrivateKey) {
	buffer := make([]byte, buffersize)
	hash := sha256.Sum256(buffer)
	rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
}

func generateRSAKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

var counter uint64

func main() {
	tckr := time.NewTicker(1 * time.Second)
	privateKey, err := generateRSAKey(2048)
	if err != nil {
		fmt.Println(err)
		return
	}
	go func() {
		for {
			testSigning(64, privateKey)
			atomic.AddUint64(&counter, 1)
		}
	}()
	go func() {
		for {
			testSigning(64, privateKey)
			atomic.AddUint64(&counter, 1)
		}
	}()
	go func() {
		for {
			testSigning(64, privateKey)
			atomic.AddUint64(&counter, 1)
		}
	}()
	for {
		select {
		case <-tckr.C:
			fmt.Println(atomic.SwapUint64(&counter, 0))
		default:
			testSigning(64, privateKey)
			atomic.AddUint64(&counter, 1)
		}
	}

}
