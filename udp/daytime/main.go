package main

import (
	"github.com/izolight/go-network-programming/util"
	"net"
	"time"
)

// Server that implements the Daytime Protocol (RFC 867)

func main() {
	service := ":13"
	udpAddr, err := net.ResolveUDPAddr("udp4", service)
	util.CheckError(err)

	conn, err := net.ListenUDP("udp", udpAddr)
	util.CheckError(err)

	for {
		handleClient(conn)
	}
}

func handleClient(conn *net.UDPConn) {
	var buf [1024]byte

	_, addr, err := conn.ReadFromUDP(buf[0:])
	if err != nil {
		return
	}

	daytime := time.Now().String()
	_, err = conn.WriteToUDP([]byte(daytime), addr)
	util.CheckError(err)
}
