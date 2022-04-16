package goudpscan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"

	"golang.org/x/sys/unix"
)

type iphdr struct {
	vhl   uint8
	tos   uint8
	iplen uint16
	id    uint16
	off   uint16
	ttl   uint8
	proto uint8
	csum  uint16
	src   [4]byte
	dst   [4]byte
}

type udphdr struct {
	src  uint16
	dst  uint16
	ulen uint16
	csum uint16
}

type pseudohdr struct {
	ipsrc   [4]byte
	ipdst   [4]byte
	zero    uint8
	ipproto uint8
	plen    uint16
}

func checksum(buf []byte) uint16 {
	sum := uint32(0)

	for ; len(buf) >= 2; buf = buf[2:] {
		sum += uint32(buf[0])<<8 | uint32(buf[1])
	}
	if len(buf) > 0 {
		sum += uint32(buf[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	csum := ^uint16(sum)
	if csum == 0 {
		csum = 0xffff
	}

	return csum
}

func (h *iphdr) checksum() {
	h.csum = 0
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, h)
	h.csum = checksum(b.Bytes())
}

func (u *udphdr) checksum(ip *iphdr, payload []byte) {
	u.csum = 0
	phdr := pseudohdr{
		ipsrc:   ip.src,
		ipdst:   ip.dst,
		zero:    0,
		ipproto: ip.proto,
		plen:    u.ulen,
	}
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, &phdr)
	binary.Write(&b, binary.BigEndian, u)
	binary.Write(&b, binary.BigEndian, &payload)
	u.csum = checksum(b.Bytes())
}

func ComposeUDPPacket(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, payload []byte) []byte {
	ip := iphdr{
		vhl:   0x45,
		tos:   0,
		id:    0x1234, // the kernel overwrites id if it is zero
		off:   0,
		ttl:   64,
		proto: unix.IPPROTO_UDP,
	}
	copy(ip.src[:], srcIP.To4())
	copy(ip.dst[:], dstIP.To4())

	udp := udphdr{
		src: uint16(srcPort),
		dst: uint16(dstPort),
	}
	udplen := 8 + len(payload)
	totalLen := 20 + udplen
	if totalLen > 0xffff {
		panic(fmt.Errorf(
			"Message is too big to fit into a packet: %d",
			totalLen,
		))
	}
	ip.iplen = uint16(totalLen)
	ip.checksum()
	udp.ulen = uint16(udplen)
	udp.checksum(&ip, payload)

	var b bytes.Buffer
	err := binary.Write(&b, binary.BigEndian, &ip)
	if err != nil {
		panic(fmt.Errorf(
			"Error encoding the IP header: %s",
			err,
		))
	}
	err = binary.Write(&b, binary.BigEndian, &udp)
	if err != nil {
		panic(fmt.Errorf(
			"Error encoding the UDP header: %s",
			err,
		))
	}
	err = binary.Write(&b, binary.BigEndian, &payload)
	if err != nil {
		panic(fmt.Errorf(
			"Error encoding the payload: %s",
			err,
		))
	}
	bb := b.Bytes()

	if runtime.GOOS == "darwin" {
		bb[2], bb[3] = bb[3], bb[2]
	}

	return bb
}
