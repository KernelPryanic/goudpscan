package goudpscan

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type UDPFrameOptions struct {
	sourceIP, destIP net.IP
	destPort         uint16
	isIPv6           bool
	payloadBytes     []byte
}

type SerializableNetworkLayer interface {
	gopacket.NetworkLayer
	gopacket.SerializableLayer
}

func CreateSerializedUDPFrame(opts *UDPFrameOptions) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	serializeOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	var ip SerializableNetworkLayer
	if !opts.isIPv6 {
		ip = &layers.IPv4{
			SrcIP:    opts.sourceIP,
			DstIP:    opts.destIP,
			Protocol: layers.IPProtocolUDP,
			Version:  4,
			TTL:      32,
		}
	} else {
		ip = &layers.IPv6{
			SrcIP:      opts.sourceIP,
			DstIP:      opts.destIP,
			NextHeader: layers.IPProtocolUDP,
			Version:    6,
			HopLimit:   32,
		}
		ip.LayerType()
	}

	udp := &layers.UDP{
		DstPort: layers.UDPPort(opts.destPort),
	}
	udp.SetNetworkLayerForChecksum(ip)
	err := gopacket.SerializeLayers(buf, serializeOpts, ip, udp, gopacket.Payload(opts.payloadBytes))
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
