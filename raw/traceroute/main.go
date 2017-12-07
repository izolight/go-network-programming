package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"syscall"
)

// from golan.org/x/net/ipv4/header.go
type IPHeader struct {
	Version        int    // protocol version
	IHL            int    // header length
	ToS            int    // type-of-service
	TotalLength    int    // packet total length
	ID             int    // identification
	Flags          int    // flags
	FragmentOffset int    // fragment offset
	TTL            int    // time-to-live
	Protocol       int    // next protocol
	Checksum       int    // checksum
	Source         net.IP // source address
	Destination    net.IP // destination address
}

type ICMPHeader struct {
	Type       int
	Code       int
	Checksum   int
	Identifier int
	Sequence   int
}

type Packet struct {
	IPHeader   IPHeader
	ICMPHeader ICMPHeader
	Data       []byte
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
	iph := NewIPHeader()
	iph.Destination = net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	icmph := NewICMPHeader()

	p := NewPacket(&iph, &icmph, []byte("test"))

	//responses := make([]Packet, 10)
	for ttl := 1; ttl < 2; ttl++ {
		p.IPHeader.TTL = ttl
		p.ICMPHeader.Identifier = ttl
		payload, err := p.MarshalBinary()
		if err != nil {
			log.Fatalf("Error marshalling packet %s", err)
		}
		err = syscall.Sendto(rawsock, payload, 0, &addr)
		if err != nil {
			log.Fatal("Sendto:", err)
		}

		icmpsock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
		buf := make([]byte, 500)
		n, err := syscall.Read(icmpsock, buf)
		if err != nil {
			log.Fatalf("Error receiving data: %s", err)
		}
		// responses[ttl] = fromBytes(buf[:n])
		fmt.Println(buf[:n])
		//fmt.Println(responses[ttl].Header, responses[ttl].Data)
		//fmt.Println(i)
		//fmt.Printf("% 02x\n", buf[:n])
	}
}



func (p Packet) MarshalBinary() ([]byte, error) {
	enc := make([]byte, p.IPHeader.TotalLength)
	h, err := p.IPHeader.MarshalBinary()
	if err != nil {
		log.Fatalf("Error marshalling ip header %s\n", err)
	}
	copy(enc[:4*p.IPHeader.IHL], h)
	i, err := p.ICMPHeader.MarshalBinary()
	if err != nil {
		log.Fatalf("Error marshalling icmp header %s\n", err)
	}
	copy(enc[4*p.IPHeader.IHL:p.IPHeader.IHL*4+8], i)
	copy(enc[p.IPHeader.IHL*4+8:p.IPHeader.TotalLength], p.Data)
	return enc, nil
}

func (ih IPHeader) String() string {
	s := fmt.Sprintf("Version: %v, IHL: %v, ToS: %v, TotalLen: %v, ID: %v, Flags: %v, FragOffset: %v,"+
		" TTL: %v, Protocol: %v, Checksum: %v, Source: %v, Destination: %v\n",
		ih.Version, ih.IHL, ih.ToS, ih.TotalLength, ih.ID, ih.Flags, ih.FragmentOffset, ih.TTL, ih.Protocol,
		ih.Checksum, ih.Source, ih.Destination)
	return s
}

func (ih IPHeader) MarshalBinary() ([]byte, error) {
	enc := make([]byte, 20)
	enc[0] = byte(ih.Version<<4 | ih.IHL)
	enc[1] = byte(ih.ToS)
	binary.BigEndian.PutUint16(enc[2:4], uint16(ih.TotalLength))
	binary.BigEndian.PutUint16(enc[4:6], uint16(ih.ID))
	flagsAndFragOff := (ih.FragmentOffset & 0x1fff) | int(ih.Flags<<13)
	binary.BigEndian.PutUint16(enc[6:8], uint16(flagsAndFragOff))
	enc[8] = byte(ih.TTL)
	enc[9] = byte(ih.Protocol)
	binary.BigEndian.PutUint16(enc[10:12], uint16(ih.Checksum))
	copy(enc[12:16], ih.Source)
	copy(enc[16:20], ih.Destination[12:])

	return enc, nil
}

func (ih ICMPHeader) String() string {
	s := fmt.Sprintf("Type: %v, Code: %v, Checksum: %v",
		ih.Type, ih.Code, ih.Checksum)
	switch ih.Type {
	case 0, 8, 13, 14, 15, 16:
		s = fmt.Sprintf("%s, Indentifier: %s, Sequence: %s\n", s, ih.Identifier, ih.Sequence)
	}
	return s
}

func (ih ICMPHeader) MarshalBinary() ([]byte, error) {
	enc := make([] byte, 8)
	enc[0] = byte(ih.Type)
	enc[1] = byte(ih.Code)
	enc[2] = byte(ih.Checksum)
	enc[3] = byte(ih.Checksum >> 8)
	switch ih.Type {
	case 0, 8, 13, 14, 15, 16:
		enc[4] = byte(ih.Identifier)
		enc[5] = byte(ih.Identifier >> 8)
		enc[6] = byte(ih.Sequence)
		enc[7] = byte(ih.Sequence >> 8)
	default:
		copy(enc[4:8], []byte{0, 0, 0, 0})
	}

	return enc, nil
}

func NewPacket(h *IPHeader, i *ICMPHeader, data []byte) Packet {
	payload := make([]byte, 8+len(data))
	ib, err := i.MarshalBinary()
	if err != nil {
		log.Fatalf("Error marshaling to bytes: %s", err)
	}
	copy(payload[:8], ib)
	copy(payload[8:], data)
	checksum := checkSum(payload)
	i.Checksum = int(checksum)
	h.TotalLength = h.IHL*4 + 8 + len(data)

	return Packet{
		IPHeader:   *h,
		ICMPHeader: *i,
		Data:       data,
	}
}

func NewIPHeader() IPHeader {
	return IPHeader{
		Version:        4,      // ipv4
		IHL:            5,      // default
		ToS:            0,      // best effort
		Flags:          1 << 1, // don't fragment
		FragmentOffset: 0,
		TTL:            1,
		Protocol:       1, // icmp
	}
}

func NewICMPHeader() ICMPHeader {
	return ICMPHeader{
		Type:       8, // Echo Request
		Code:       0,
		Identifier: 1,
		Sequence:   1,
	}
}

/*func fromBytes(b [] byte) IPPacket {
	var i IPPacket
	i.Header.Version = int(b[0] >> 4)
	i.Header.Len = int(b[0] & 0x0f)
	i.Header.TOS = int(b[1])
	i.Header.TotalLen = int(binary.BigEndian.Uint16(b[2:4]))
	i.Header.ID = int(binary.BigEndian.Uint16(b[4:6]))
	i.Header.Flags = int(b[7] >> 5)
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
}*/

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
