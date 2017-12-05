package main

import (
	"fmt"
	"github.com/izolight/go-network-programming/util"
	"net"
	"os"
)

type IcmpPacket struct {
	Type 		int
	Code		int
	Checksum	int
	Identifier 	int
	Sequence 	int
	Message 	[]byte
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage ./ping <IP>")
		os.Exit(1)
	}
	addr, err := net.ResolveIPAddr("ip", os.Args[1])
	if err != nil {
		fmt.Printf("Can't resolve %s\n", err.Error())
		os.Exit(1)
	}

	conn, err := net.DialIP("ip4:icmp", nil, addr)
	util.CheckError(err)

	var pkt IcmpPacket
	pkt.Type = 8
	pkt.Code = 0
	pkt.Identifier = 12
	pkt.Sequence = 34
	pkt.Message = []byte("test1234")

	msg := pkt.toBytes()

	_, err = conn.Write(msg)
	util.CheckError(err)

	buf := make([]byte, 500)
	n, err := conn.Read(buf)
	util.CheckError(err)

	fmt.Println("Got response")
	fmt.Printf("% 02x\n",buf[:n])

	os.Exit(0)
}

func (i *IcmpPacket) toBytes() []byte {
	b := []byte{byte(i.Type), byte(i.Code), 0, 0, byte(i.Identifier), byte(i.Identifier >> 8), byte(i.Sequence), byte(i.Sequence >> 8)}
	if i.Message != nil {
		b = append(b, i.Message...)
	}
	checksum := checkSum(b)
	b[2] = byte(checksum)
	b[3] = byte(checksum >> 8)
	return b
}

func checkSum(b []byte) uint16 {
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	return ^uint16(s)
}
