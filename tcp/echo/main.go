package main

import (
	"github.com/izolight/go-network-programming/util"
	"net"
)

// Server that implements the Echo Protocol (RFC 862)

func main() {
	service := ":7"
	tcpAddr, err := net.ResolveTCPAddr("tcp4", service)
	util.CheckError(err)

	listener, err := net.ListenTCP("tcp", tcpAddr)
	util.CheckError(err)

	for {
		conn, err := listener.Accept()
		util.CheckError(err)
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()

	var buf [1024]byte
	for {
		n, err := conn.Read(buf[0:])
		if err != nil {
			return
		}

		_, err = conn.Write(buf[0:n])
		util.CheckError(err)
	}
}
