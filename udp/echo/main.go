package main

import (
	"github.com/izolight/go-network-programming/util"
	"net"
)

// Server that implements the Echo Protocol (RFC 862)

func main() {
	service := ":7"
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
	for {
		n, addr, err := conn.ReadFromUDP(buf[0:])
		if err != nil {
			return
		}

		_, err = conn.WriteToUDP(buf[0:n], addr)
		util.CheckError(err)
	}
}
