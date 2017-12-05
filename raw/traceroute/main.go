package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"syscall"
)

// from golan.org/x/net/ipv4/header.go
type Header struct {
	Version  int    // protocol version
	Len      int    // header length
	TOS      int    // type-of-service
	TotalLen int    // packet total length
	ID       int    // identification
	Flags    int    // flags
	FragOff  int    // fragment offset
	TTL      int    // time-to-live
	Protocol int    // next protocol
	Checksum int    // checksum
	Src      net.IP // source address
	Dst      net.IP // destination address
}

type IcmpPacket struct {
	Type       int
	Code       int
	Checksum   int
	Identifier int
	Sequence   int
	Message    []byte
}

type IPPacket struct {
	Header Header
	Data   IcmpPacket
}

func main() {
	rawsock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatalf("Could not create socket: %s", err)

	}
	err = syscall.SetsockoptInt(rawsock, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		log.Fatalf("Error setting sockopts: %s", err)
	}
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
		Data:   d,
	}

	responses := make([]IPPacket, 20)
	for ttl := 1; ttl < 20; ttl++ {
		p.Header.TTL = ttl
		p.Data.Identifier = ttl
		err = syscall.Sendto(rawsock, p.toBytes(), 0, &addr)
		if err != nil {
			log.Fatal("Sendto:", err)
		}

		icmpsock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
		buf := make([]byte, 500)
		n, err := syscall.Read(icmpsock, buf)
		if err != nil {
			log.Fatalf("Error receiving data: %s", err)
		}
		responses[ttl] = fromBytes(buf[:n])
		fmt.Println(responses[ttl].Header, responses[ttl].Data)
		//fmt.Println(i)
		//fmt.Printf("% 02x\n", buf[:n])
	}
}

func (h *Header) defaultHeader() {
	h.Version = 4    // ipv4
	h.Len = 5        // default
	h.TOS = 0        // best effort
	h.Flags = 1 << 1 // don't fragment
	h.FragOff = 0
	h.TTL = 1
	h.Protocol = 1 // icmp
}

func (h Header) String() string {
	s := fmt.Sprintf("Version: %v, Len: %v, TOS: %v, TotalLen: %v, ID: %v, Flags: %v, FragOffset: %v," +
		" TTL: %v, Protocol: %v, Checksum: %v, Src: %v, Dst: %v",
			h.Version, h.Len, h.TOS, h.TotalLen, h.ID, h.Flags, h.FragOff, h.TTL, h.Protocol, h.Checksum, h.Src, h.Dst)
	return s
}

func (i IcmpPacket) String() string {
	s := fmt.Sprintf("Type: %v, Code: %v, Checksum: %v, Identifier: %v, Sequence: %v, Message: %v",
		i.Type, i.Code, i.Checksum, i.Identifier, i.Sequence, i.Message)
	return s
}

func fromBytes(b [] byte) IPPacket{
	var i IPPacket
	i.Header.Version = int(b[0] >> 4)
	i.Header.Len = int(b[0] & 0x0f)
	i.Header.TOS = int(b[1])
	i.Header.TotalLen = int(binary.BigEndian.Uint16(b[2:4]))
	i.Header.ID = int(binary.BigEndian.Uint16(b[4:6]))
	i.Header.Flags = int(b[7]>>5)
	b[7] = b[7] & 0x1f
	i.Header.FragOff = int(binary.BigEndian.Uint16([]byte(b[6:8])))
	i.Header.TTL = int(b[8])
	i.Header.Protocol = int(b[9])
	i.Header.Checksum = int(binary.BigEndian.Uint16(b[10:12]))
	i.Header.Src = net.IPv4(b[12], b[13], b[14], b[15])
	i.Header.Dst = net.IPv4(b[16], b[17], b[18], b[19])
// Works atm for ttl message
	i.Data.Type = int(b[20])
	i.Data.Code = int(b[21])
	i.Data.Checksum = int(binary.LittleEndian.Uint16(b[22:24]))
	i.Data.Identifier = int(binary.LittleEndian.Uint16(b[52:54]))
	i.Data.Sequence = int(binary.LittleEndian.Uint16(b[52:54]))
	//copy(i.Data.Message, b[52:])

	return i
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
	b[0] = byte(p.Header.Version<<4 | p.Header.Len)
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
