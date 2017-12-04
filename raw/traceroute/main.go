package main

import (
	"net"
	"encoding/binary"
	"syscall"
	"log"
	//"fmt"
	"fmt"
)

// from golan.org/x/net/ipv4/header.go
type Header struct {
	Version  int         // protocol version
	Len      int         // header length
	TOS      int         // type-of-service
	TotalLen int         // packet total length
	ID       int         // identification
	Flags    int		 // flags
	FragOff  int         // fragment offset
	TTL      int         // time-to-live
	Protocol int         // next protocol
	Checksum int         // checksum
	Src      net.IP      // source address
	Dst      net.IP      // destination address
}

type IcmpPacket struct {
	Type 		int
	Code		int
	Checksum	int
	Identifier 	int
	Sequence 	int
	Message 	[]byte
}

type IPPacket struct {
	Header 	Header
	Data 	IcmpPacket
}

func main() {
	var err error
	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	addr := syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{8, 8, 8, 8},
	}
	h := Header{}
	h.defaultHeader()
	h.Dst = net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	d := IcmpPacket{}
	d.defaultPacket()

	p := IPPacket{
		Header: h,
		Data: d,
	}

	for ttl := 1; ttl < 10; ttl++{
		p.Header.TTL = ttl
		p.Data.Identifier = ttl
		err = syscall.Sendto(fd, p.toBytes(), 0, &addr)
		if err != nil {
			log.Fatal("Sendto:", err)
		}

/*		buf := make([]byte, 500)
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(buf[:n])*/
	}
}

func (h *Header) defaultHeader() {
	h.Version 	= 4 // ipv4
	h.Len 		= 5 // default
	h.TOS		= 0 // best effort
	h.Flags		= 1 << 1 // don't fragment
	h.FragOff	= 0
	h.TTL		= 1
	h.Protocol	= 1 // icmp
}

func (i *IcmpPacket) defaultPacket() {
	i.Type = 8
	i.Code = 0
	i.Identifier = 1
	i.Sequence = 1
	i.Message = []byte("Test")
}

func (p *IPPacket) toBytes() []byte {
	data := p.Data.toBytes()
	p.Header.TotalLen = 20 + len(data)
	b := make([]byte, p.Header.TotalLen)
	b[0] = byte(p.Header.Version << 4 | p.Header.Len)
	b[1] = byte(p.Header.TOS)
	b[2] = byte(p.Header.TotalLen)
	binary.BigEndian.PutUint16(b[2:4], uint16(p.Header.TotalLen))
	binary.BigEndian.PutUint16(b[4:6], uint16(p.Header.ID))
	flagsAndFragOff := (p.Header.FragOff & 0x1fff) | int(p.Header.Flags<<13)
	binary.BigEndian.PutUint16(b[6:8], uint16(flagsAndFragOff))
	b[8] = byte(p.Header.TTL)
	b[9] = byte(p.Header.Protocol)
	binary.BigEndian.PutUint16(b[10:12], uint16(p.Header.Checksum))
	copy(b[12:16], p.Header.Src)
	copy(b[16:20], p.Header.Dst[12:])
	copy(b[20:p.Header.TotalLen], data)

	return b
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