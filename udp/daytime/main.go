package main

import (
	"fmt"
	"github.com/izolight/go-network-programming/util"
	"net"
	"runtime"
	"time"
)

// Server that implements the Daytime Protocol (RFC 867)

func main() {
	service := ":13"
	udpAddr, err := net.ResolveUDPAddr("udp4", service)
	util.CheckError(err)

	conn, err := net.ListenUDP("udp", udpAddr)
	util.CheckError(err)

	quit := make(chan struct{})
	for i := 0; i < runtime.NumCPU(); i++ {
		go handleClient(conn, quit)
	}
	<-quit
}

func handleClient(conn *net.UDPConn, quit chan struct{}) {
	buf := make([]byte, 1500)
	err := error(nil)
	for err == nil {
		_, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		daytime := time.Now().String()
		_, err = conn.WriteToUDP([]byte(daytime), addr)
	}
	fmt.Println("listener failed - ", err)
	quit <- struct{}{}
}
