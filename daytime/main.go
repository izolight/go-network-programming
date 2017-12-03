package main

import (
	"github.com/izolight/go-network-programming/util"
	"net"
	"time"
)

// Server that implements the Daytime Protocol (RFC 867)

func main() {
	service := ":13"
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

	daytime := time.Now().String()
	_, err := conn.Write([]byte(daytime))
	util.CheckError(err)
	return
}
