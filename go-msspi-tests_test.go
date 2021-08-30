package msspitests

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func clientGet(t *testing.T, host string, uri string) []byte {
	conn, err := net.DialTimeout("tcp", host, 2*time.Second)
	if err != nil {
		t.Fatalf("Unexpected error on dial: %v", err)
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	defer tlsConn.Close()

	wbuf := []byte("GET " + uri + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
	if wlen, err := tlsConn.Write(wbuf); wlen != len(wbuf) || err != nil {
		t.Fatalf("Error sending: %v", err)
	}

	rbuf := make([]byte, 16384)
	if rlen, err := tlsConn.Read(rbuf); rlen == 0 || err != nil {
		t.Fatalf("Error reading: %v", err)
		return nil
	} else {
		return rbuf[:rlen]
	}
}

func TestMsspiClient(t *testing.T) {
	if rbuf := clientGet(t, "gost.cryptopro.ru:443", "/"); len(rbuf) == 0 {
		t.Fatalf("clientGet() failed.")
	} else {
		s := string(rbuf)
		ms := "ssl_cipher</td><td class=\"wr\"><b>"
		me := "</b>"
		c1 := strings.Index(s, ms)
		if c1 == -1 {
			t.Fatalf("Marker not found")
		}
		c2 := strings.Index(s[c1:], me)
		if c2 == -1 {
			t.Fatalf("Marker not found")
		}
		fmt.Printf("Cipher: %v\n", string(rbuf[c1+len(ms):c1+c2]))
	}
}
